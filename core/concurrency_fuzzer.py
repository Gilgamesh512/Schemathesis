"""Race Condition & Concurrency Fuzzing Engine (OWASP API4:2023).

Detects concurrency flaws, Time-of-Check to Time-of-Use (TOCTOU) bugs,
and rate/limit bypasses on sensitive endpoints (coupons, checkout, transfers, votes)
via high-velocity synchronized burst requests.
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

try:
    from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id
except (ImportError, ValueError):
    from core.evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


RACE_SENSITIVE_KEYWORDS = {
    "coupon", "voucher", "redeem", "apply", "checkout", "pay",
    "transfer", "order", "orders", "cart", "vote", "like", "book",
    "claim", "reset", "reset-password", "resend", "withdraw", "deposit",
}


class ConcurrencyBurstResult(BaseModel):
    """Result of a burst request test on an API endpoint."""

    endpoint: str
    method: str
    burst_size: int
    success_count: int
    client_error_count: int
    server_error_count: int
    status_codes: list[int] = Field(default_factory=list)
    latencies_ms: list[float] = Field(default_factory=list)
    is_vulnerable: bool = False
    vulnerability_reason: str = ""
    evidence_details: dict[str, Any] = Field(default_factory=dict)


class ConcurrencyFuzzer:
    """Synchronized burst request runner for detecting Race Condition vulnerabilities."""

    def __init__(self, burst_size: int = 5, timeout: float = 5.0):
        self.burst_size = max(2, burst_size)
        self.timeout = timeout

    @staticmethod
    def is_candidate_endpoint(endpoint: str, method: str) -> bool:
        """Identify if an endpoint is susceptible to race condition flaws."""
        if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return False
        clean_ep = endpoint.lower()
        tokens = re.split(r"[/_\-\?\&=]+", clean_ep)
        return any(tok in RACE_SENSITIVE_KEYWORDS for tok in tokens)

    async def _send_synchronized_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        headers: dict[str, str],
        json_data: Any,
        data: Any,
        req_id: int,
    ) -> tuple[int, int, float, str, dict[str, str]]:
        """Send a single request with precise latency tracking."""
        t_start = time.perf_counter()
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                data=data,
                timeout=self.timeout,
            )
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            body_preview = resp.text[:500] if resp.text else ""
            return req_id, resp.status_code, round(elapsed_ms, 2), body_preview, dict(resp.headers)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            return req_id, 0, round(elapsed_ms, 2), f"Connection error: {exc}", {}

    async def execute_burst(
        self,
        base_url: str,
        endpoint: str,
        method: str = "POST",
        headers: Optional[dict[str, str]] = None,
        json_data: Any = None,
        data: Any = None,
    ) -> ConcurrencyBurstResult:
        """Execute a synchronized parallel burst against the target endpoint."""
        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"
        req_headers = dict(headers or {})

        async with httpx.AsyncClient(verify=False) as client:
            tasks = [
                self._send_synchronized_request(
                    client=client,
                    url=full_url,
                    method=method.upper(),
                    headers=req_headers,
                    json_data=json_data,
                    data=data,
                    req_id=i,
                )
                for i in range(self.burst_size)
            ]
            responses = await asyncio.gather(*tasks)

        status_codes = [r[1] for r in responses]
        latencies = [r[2] for r in responses]
        success_count = sum(1 for sc in status_codes if 200 <= sc < 300)
        client_errors = sum(1 for sc in status_codes if 400 <= sc < 500)
        server_errors = sum(1 for sc in status_codes if 500 <= sc < 600)

        is_vuln = False
        reason = ""

        # Assessment logic:
        # If single-use/sensitive endpoint receives multiple 2xx OK in identical burst
        tokens = re.split(r"[/_\-\?\&=]+", endpoint.lower())
        single_use_action = any(k in tokens for k in ("coupon", "voucher", "redeem", "apply", "claim", "reset"))

        if single_use_action and success_count > 1:
            is_vuln = True
            reason = (
                f"Single-use action allowed multiple successful executions ({success_count}/{self.burst_size} HTTP 200/201/204). "
                "Possible Race Condition / Limit Bypass."
            )
        elif server_errors >= 2 and any("deadlock" in r[3].lower() or "internal" in r[3].lower() for r in responses):
            is_vuln = True
            reason = (
                f"Concurrent burst caused {server_errors}/{self.burst_size} HTTP 500 server errors or database deadlocks."
            )

        details = {
            "burst_size": self.burst_size,
            "status_distribution": status_codes,
            "success_count": success_count,
            "responses_preview": [
                {"req_id": r[0], "status": r[1], "latency_ms": r[2], "body": r[3][:120]}
                for r in responses
            ],
        }

        return ConcurrencyBurstResult(
            endpoint=endpoint,
            method=method.upper(),
            burst_size=self.burst_size,
            success_count=success_count,
            client_error_count=client_errors,
            server_error_count=server_errors,
            status_codes=status_codes,
            latencies_ms=latencies,
            is_vulnerable=is_vuln,
            vulnerability_reason=reason,
            evidence_details=details,
        )

    def convert_to_finding(
        self,
        result: ConcurrencyBurstResult,
        target_app: str,
        run_id: str,
    ) -> Optional[Finding]:
        """Convert a confirmed race condition burst result into an OASIS/SARIF Finding."""
        if not result.is_vulnerable:
            return None

        clean_ep = "/" + result.endpoint.lstrip("/")
        now_iso = datetime.now(timezone.utc).isoformat()
        fp = f"race_{target_app}_{clean_ep}_{result.method}"

        evidence = Evidence(
            status_code=result.status_codes[0] if result.status_codes else 200,
            response_headers={},
            response_signal=["race_condition_limit_bypass", f"success_count_{result.success_count}"],
            response_time_ms=sum(result.latencies_ms) / len(result.latencies_ms) if result.latencies_ms else 0.0,
            endpoint=clean_ep,
            payload={"burst_size": result.burst_size, "evidence": result.evidence_details},
            auth_context={"burst_testing": True},
        )

        return Finding(
            finding_id=stable_finding_id(target_app, clean_ep, result.method, "RACE_CONDITION"),
            run_id=run_id,
            timestamp=now_iso,
            target_app=target_app,
            endpoint=clean_ep,
            method=result.method,
            tool="concurrency_fuzzer",
            attack_type="RACE_CONDITION",
            owasp_category="API4:2023",
            payload=result.evidence_details,
            status_code=result.status_codes[0] if result.status_codes else 200,
            response_time_ms=evidence.response_time_ms,
            evidence=evidence,
            severity="HIGH",
            confidence=0.9,
            confirmed=True,
            lifecycle="confirmed",
            fingerprint=fp,
            cve_matches=["CVE-2023-API4-RACE"],
            cve_match_type="OWASP-API4-BURST",
            cve_confidence=0.9,
        )
