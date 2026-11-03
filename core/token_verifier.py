"""RFC 7519 Token Authentication & Configuration Verifier (API2:2023 Broken Authentication).

Verifies whether an API properly enforces JWT signature integrity, algorithm
whitelisting, and expiration time claims on protected endpoints.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


def b64url_decode(segment: str) -> bytes:
    """Decode base64url string with proper padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment)


def b64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class TokenInspection(BaseModel):
    """Structural breakdown and metadata of a JWT token."""

    raw_token: str
    header: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    algorithm: str = "unknown"
    has_exp: bool = False
    exp_timestamp: Optional[int] = None
    is_expired: bool = False


class TokenVerifier:
    """Verifies RFC 7519 compliance and authentication security on API endpoints."""

    @staticmethod
    def inspect_token(raw_token: str) -> Optional[TokenInspection]:
        token = raw_token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parts = token.split(".")
        if len(parts) != 3:
            return None

        try:
            header_json = json.loads(b64url_decode(parts[0]).decode("utf-8"))
            payload_json = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        except Exception:
            return None

        alg = header_json.get("alg", "unknown")
        exp = payload_json.get("exp")
        has_exp = isinstance(exp, (int, float))
        exp_ts = int(exp) if has_exp else None
        now_ts = int(time.time())
        is_expired = has_exp and exp_ts < now_ts

        return TokenInspection(
            raw_token=token,
            header=header_json,
            payload=payload_json,
            algorithm=alg,
            has_exp=has_exp,
            exp_timestamp=exp_ts,
            is_expired=is_expired,
        )

    @classmethod
    def generate_verification_probes(cls, raw_token: str, extended: bool = False) -> dict[str, str]:
        """Generate RFC 7519 compliance verification probe tokens.

        Returns:
            Dict mapping probe_name -> generated token string
        """
        inspection = cls.inspect_token(raw_token)
        if not inspection:
            return {}

        probes: dict[str, str] = {}
        header = dict(inspection.header)
        payload = dict(inspection.payload)

        # Probe 1: Alg None (RFC 7519 compliance: server must reject alg=none)
        header_none = {**header, "alg": "none"}
        h_bytes = b64url_encode(json.dumps(header_none, separators=(",", ":")).encode("utf-8"))
        p_bytes = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        probes["alg_none"] = f"{h_bytes}.{p_bytes}."

        # Probe 2: Stripped Signature (server must reject unsigned token)
        h_orig = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        probes["stripped_signature"] = f"{h_orig}.{p_bytes}."

        # Probe 3: Expired Token (server must reject expired exp claim)
        expired_payload = {**payload, "exp": int(time.time()) - 86400}  # Expired 24h ago
        exp_bytes = b64url_encode(json.dumps(expired_payload, separators=(",", ":")).encode("utf-8"))
        probes["expired_claim"] = f"{h_orig}.{exp_bytes}.invalid_sig_probe"

        # Probe 4: Tampered Role Claim with Original Signature (optional extended probe)
        if extended:
            tampered_payload = dict(payload)
            tampered_payload["role"] = "admin"
            tampered_payload["is_admin"] = True
            t_bytes = b64url_encode(json.dumps(tampered_payload, separators=(",", ":")).encode("utf-8"))
            orig_sig = inspection.raw_token.split(".")[2] if len(inspection.raw_token.split(".")) == 3 else "probe_sig"
            probes["tampered_payload"] = f"{h_orig}.{t_bytes}.{orig_sig}"

        return probes

    async def verify_endpoint(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str,
        valid_auth_header: str,
        base_url: str,
        run_id: str,
        require_auth_challenge: bool = False,
    ) -> list[Finding]:
        """Test a protected endpoint with verification probe tokens.
        
        If require_auth_challenge is True, an unauthenticated baseline check is first
        performed to verify that the route actually requires authentication, avoiding
        false positives on public/unauthenticated endpoints.
        """
        inspection = self.inspect_token(valid_auth_header)
        if not inspection:
            return []

        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"

        # Enterprise False-Positive Guard: Verify route is truly authenticated
        if require_auth_challenge:
            try:
                unauth_resp = await client.request(
                    method=method.upper(),
                    url=full_url,
                    headers={},  # Zero auth headers
                )
                # If endpoint responds with success without credentials, it is a public endpoint
                if unauth_resp.status_code in (200, 201, 204):
                    return []
            except Exception:
                pass

        probes = self.generate_verification_probes(valid_auth_header)
        findings: list[Finding] = []

        for probe_name, probe_token in probes.items():
            probe_header = {"Authorization": f"Bearer {probe_token}"}
            started = time.perf_counter()

            try:
                resp = await client.request(
                    method=method.upper(),
                    url=full_url,
                    headers=probe_header,
                )
                elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

                # An authenticated endpoint should reject these probe tokens with 401/403
                if resp.status_code == 200:
                    desc_map = {
                        "alg_none": "Accepted token with alg=none (Broken Authentication)",
                        "stripped_signature": "Accepted token without signature verification",
                        "expired_claim": "Accepted token with expired 'exp' timestamp claim",
                        "tampered_payload": "Accepted modified payload without verifying cryptographic signature",
                    }
                    evidence_text = f"HTTP 200 OK; {desc_map.get(probe_name, 'Token accepted')}"
                    finding = Finding(
                        finding_id=stable_finding_id(
                            "token_verifier", method, clean_ep, "BROKEN_AUTHENTICATION", probe_name,
                        ),
                        run_id=run_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        tool="token_verifier",
                        target_app="token_verifier",
                        endpoint=clean_ep,
                        method=method.upper(),
                        attack_type="BROKEN_AUTHENTICATION",
                        owasp_category="API2:2023",
                        payload={"probe_type": probe_name, "token_header": probe_header},
                        status_code=resp.status_code,
                        response_time_ms=elapsed_ms,
                        evidence=Evidence(
                            status_code=resp.status_code,
                            response_headers=redact_headers(dict(resp.headers)),
                            response_signal=[evidence_text],
                            response_time_ms=elapsed_ms,
                            payload_hash=content_hash(probe_token),
                            request_hash=content_hash(full_url),
                            endpoint=clean_ep,
                        ),
                        severity="high",
                        confidence=0.95,
                        confirmed=True,
                        lifecycle="confirmed",
                        fingerprint=content_hash(f"{method}|{clean_ep}|{probe_name}"),
                    )
                    findings.append(finding)
            except Exception:
                continue

        return findings
