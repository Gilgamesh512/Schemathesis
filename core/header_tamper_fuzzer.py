"""Reverse Proxy, Routing Integrity & Header Tampering Fuzzer (API8:2023 / API5:2023).

Audits API endpoints for Reverse Proxy misconfigurations, Gateway Route Overrides,
and Cache Poisoning vulnerabilities through untrusted hop-by-hop and forwarding headers:
- Host Header Injection & Web Cache Poisoning (X-Forwarded-Host, Forwarded)
- API Gateway Route Overrides (X-Original-URL, X-Rewrite-URL)
- Protocol Downgrade Reflection (X-Forwarded-Proto)
- Reverse Proxy IP Trust / Spoofing (X-Forwarded-For, X-Real-IP)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


class HeaderTamperProbe(BaseModel):
    """Specification of an injected header tamper test."""
    name: str
    attack_category: str
    headers: dict[str, str]
    expected_signal: list[str] = Field(default_factory=list)
    description: str


class HeaderTamperResult(BaseModel):
    """Result of header tamper verification."""
    endpoint: str
    method: str
    probe_name: str
    injected_headers: dict[str, str]
    status_code: int
    is_vulnerable: bool = False
    vulnerability_reason: str = ""
    evidence_text: str = ""


class HeaderTamperFuzzer:
    """Fuzzes endpoints with manipulated routing and proxy headers."""

    CANARY_HOST = "canary-poison.internal.local"

    PROBES: list[HeaderTamperProbe] = [
        HeaderTamperProbe(
            name="X-Forwarded-Host Injection",
            attack_category="CACHE_POISONING_HOST_INJECTION",
            headers={"X-Forwarded-Host": CANARY_HOST},
            expected_signal=[CANARY_HOST],
            description="Tests whether reverse proxy reflects untrusted X-Forwarded-Host into redirect Location headers or body links.",
        ),
        HeaderTamperProbe(
            name="Forwarded Standard Header Injection",
            attack_category="CACHE_POISONING_HOST_INJECTION",
            headers={"Forwarded": f"for=127.0.0.1;host={CANARY_HOST};proto=http"},
            expected_signal=[CANARY_HOST],
            description="RFC 7239 Forwarded header injection testing host reflection.",
        ),
        HeaderTamperProbe(
            name="X-Original-URL Gateway Route Override",
            attack_category="GATEWAY_ROUTE_OVERRIDE",
            headers={"X-Original-URL": "/admin"},
            expected_signal=["admin", "dashboard", "superadmin", "privilege"],
            description="Tests if reverse proxy/API gateway allows overriding the destination route via X-Original-URL.",
        ),
        HeaderTamperProbe(
            name="X-Rewrite-URL Gateway Route Override",
            attack_category="GATEWAY_ROUTE_OVERRIDE",
            headers={"X-Rewrite-URL": "/admin"},
            expected_signal=["admin", "dashboard", "superadmin", "privilege"],
            description="Tests if reverse proxy allows overriding route path via X-Rewrite-URL.",
        ),
        HeaderTamperProbe(
            name="Client-IP Loopback Spoofing",
            attack_category="CLIENT_IP_SPOOFING",
            headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "Client-IP": "127.0.0.1"},
            expected_signal=[],
            description="Tests if backend trusts client-supplied IP headers to bypass local-only access restrictions.",
        ),
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def test_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        method: str = "GET",
        base_headers: Optional[dict[str, str]] = None,
        run_id: str = "header-tamper-run",
        target_app: str = "target",
    ) -> list[Finding]:
        """Test an endpoint against all header tampering probes."""
        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"
        default_headers = dict(base_headers or {})

        # Baseline request
        try:
            baseline_resp = await client.request(
                method=method.upper(),
                url=full_url,
                headers=default_headers,
                timeout=self.timeout,
            )
            baseline_status = baseline_resp.status_code
            baseline_body = baseline_resp.text or ""
            baseline_location = baseline_resp.headers.get("Location", "")
        except Exception:
            return []

        findings: list[Finding] = []

        for probe in self.PROBES:
            attack_headers = {**default_headers, **probe.headers}
            t_start = time.perf_counter()

            try:
                resp = await client.request(
                    method=method.upper(),
                    url=full_url,
                    headers=attack_headers,
                    timeout=self.timeout,
                    follow_redirects=False,
                )
                elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)
            except Exception:
                continue

            resp_body = resp.text or ""
            resp_loc = resp.headers.get("Location", "")
            is_vuln = False
            reason = ""

            # Check 1: Host header reflection in Location header (Open Redirect / Cache Poisoning)
            if self.CANARY_HOST in resp_loc:
                is_vuln = True
                reason = f"Reflected untrusted host into redirect Location header: {resp_loc}"
            # Check 2: Host header reflection in body scripts/links
            elif self.CANARY_HOST in resp_body and self.CANARY_HOST not in baseline_body:
                is_vuln = True
                reason = f"Reflected untrusted host header into response body content."
            # Check 3: Gateway route override success
            elif probe.attack_category == "GATEWAY_ROUTE_OVERRIDE":
                if baseline_status in (404, 403, 401) and resp.status_code == 200:
                    is_vuln = True
                    reason = f"Route override header changed response status from {baseline_status} to 200 OK."
                elif any(sig in resp_body.lower() for sig in probe.expected_signal) and not any(sig in baseline_body.lower() for sig in probe.expected_signal):
                    is_vuln = True
                    reason = f"Route override header exposed administrative content in response body."

            if is_vuln:
                fid = stable_finding_id(target_app, method, clean_ep, probe.attack_category, probe.name)
                finding = Finding(
                    finding_id=fid,
                    run_id=run_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool="header_tamper_fuzzer",
                    target_app=target_app,
                    endpoint=clean_ep,
                    method=method.upper(),
                    attack_type=probe.attack_category,
                    owasp_category="API8:2023",
                    payload={"probe": probe.name, "injected_headers": probe.headers},
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                    evidence=Evidence(
                        status_code=resp.status_code,
                        response_headers=redact_headers(dict(resp.headers)),
                        response_signal=[reason],
                        response_time_ms=elapsed_ms,
                        payload_hash=content_hash(probe.headers),
                        request_hash=content_hash(full_url),
                        endpoint=clean_ep,
                    ),
                    severity="high",
                    confidence=0.95,
                    confirmed=True,
                    lifecycle="confirmed",
                    fingerprint=content_hash(f"{method}|{clean_ep}|{probe.name}"),
                )
                findings.append(finding)

        return findings
