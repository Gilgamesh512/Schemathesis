"""Unrestricted Resource Consumption & DoS Fuzzer (OWASP API4:2023).

Tests API resilience against resource exhaustion, denial of service, and memory/CPU starvation:
- ReDoS (Regular Expression Catastrophic Backtracking)
- Large Payload Inflation & Deeply Nested JSON Objects (Billion Laughs style JSON bomb)
- Pagination Limit Overflow & Batch Array Exhaustion
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


class ResourceProbeResult(BaseModel):
    """Execution output of a single resource consumption probe."""
    probe_type: str
    endpoint: str
    method: str
    status_code: int
    elapsed_ms: float
    is_vulnerable: bool = False
    reason: str = ""
    evidence_text: str = ""


class ResourceExhaustionFuzzer:
    """Probes endpoints for lack of resource consumption limits."""

    REDOS_PAYLOADS = [
        # Catastrophic backtracking on common evil regexes like (a+)+b
        "a" * 15000 + "!",
        "1" * 12000 + "X",
        "user." + "a" * 10000 + "@evil.domain",
    ]

    def __init__(self, timeout: float = 8.0, redos_latency_threshold_ms: float = 3500.0):
        self.timeout = timeout
        self.redos_latency_threshold_ms = redos_latency_threshold_ms

    @staticmethod
    def generate_nested_json_bomb(depth: int = 250) -> dict[str, Any]:
        """Generate deeply nested JSON object to trigger recursion/stack overflow."""
        root: dict[str, Any] = {"value": "exhaustion_probe"}
        curr = root
        for i in range(depth):
            curr["nested"] = {"level": i}
            curr = curr["nested"]
        return root

    @staticmethod
    def generate_large_json_payload(size_kb: int = 1500) -> dict[str, Any]:
        """Generate an oversized JSON payload (e.g. 1.5MB) to test body size limits."""
        chunk = "A" * 1024
        return {
            "probe": "large_body_inflation",
            "data": [chunk for _ in range(size_kb)],
        }

    async def test_redos(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        param_name: str,
        param_location: str = "query",
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        run_id: str = "redos-run",
        target_app: str = "target",
    ) -> list[Finding]:
        """Test parameter for ReDoS CPU starvation."""
        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"
        req_headers = dict(headers or {})

        # Baseline request
        try:
            t0 = time.perf_counter()
            base_resp = await client.request(
                method=method.upper(),
                url=full_url,
                headers=req_headers,
                params={param_name: "normal_test"} if param_location == "query" else None,
                timeout=self.timeout,
            )
            base_time_ms = (time.perf_counter() - t0) * 1000
        except Exception:
            return []

        findings: list[Finding] = []

        for idx, payload in enumerate(self.REDOS_PAYLOADS):
            t_start = time.perf_counter()
            is_vuln = False
            reason = ""
            status_code = 0
            elapsed_ms = 0.0

            try:
                if param_location == "query":
                    resp = await client.request(
                        method=method.upper(),
                        url=full_url,
                        headers=req_headers,
                        params={param_name: payload},
                        timeout=self.timeout,
                    )
                else:
                    resp = await client.request(
                        method=method.upper(),
                        url=full_url,
                        headers=req_headers,
                        json={param_name: payload},
                        timeout=self.timeout,
                    )
                elapsed_ms = (time.perf_counter() - t_start) * 1000
                status_code = resp.status_code

                # Significant latency spike indicates CPU catastrophic backtracking
                delta_ms = elapsed_ms - base_time_ms
                if elapsed_ms >= self.redos_latency_threshold_ms and delta_ms >= 2500.0:
                    is_vuln = True
                    reason = (
                        f"ReDoS probe caused severe server latency delay: {round(elapsed_ms, 1)}ms "
                        f"(baseline was {round(base_time_ms, 1)}ms, delta +{round(delta_ms, 1)}ms). "
                        "Susceptible to Regex Catastrophic Backtracking CPU exhaustion."
                    )
            except (httpx.TimeoutException, httpx.ConnectTimeout):
                elapsed_ms = self.timeout * 1000
                status_code = 504
                is_vuln = True
                reason = (
                    f"ReDoS probe triggered HTTP Timeout (> {self.timeout}s). "
                    "Server CPU likely hung in catastrophic backtracking loop."
                )
            except Exception:
                continue

            if is_vuln:
                fid = stable_finding_id(target_app, method, clean_ep, "RESOURCE_EXHAUSTION_REDOS", param_name)
                findings.append(Finding(
                    finding_id=fid,
                    run_id=run_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool="resource_exhaustion_fuzzer",
                    target_app=target_app,
                    endpoint=clean_ep,
                    method=method.upper(),
                    attack_type="UNRESTRICTED_RESOURCE_CONSUMPTION",
                    owasp_category="API4:2023",
                    payload={"param": param_name, "redos_sample": payload[:30] + "..."},
                    status_code=status_code,
                    response_time_ms=round(elapsed_ms, 1),
                    evidence=Evidence(
                        status_code=status_code,
                        response_headers={},
                        response_signal=[reason],
                        response_time_ms=round(elapsed_ms, 1),
                        payload_hash=content_hash(payload),
                        request_hash=content_hash(full_url),
                        endpoint=clean_ep,
                    ),
                    severity="high",
                    confidence=0.90,
                    confirmed=True,
                    lifecycle="confirmed",
                    fingerprint=content_hash(f"{method}|{clean_ep}|REDOS|{param_name}"),
                ))
                break  # Confirmed on one probe is sufficient

        return findings

    async def test_body_inflation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        method: str = "POST",
        headers: Optional[dict[str, str]] = None,
        run_id: str = "inflation-run",
        target_app: str = "target",
    ) -> Optional[Finding]:
        """Test API Gateway / server response to oversized payload inflation."""
        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"
        req_headers = dict(headers or {})
        nested_bomb = self.generate_nested_json_bomb(depth=300)

        t_start = time.perf_counter()
        is_vuln = False
        reason = ""
        status_code = 0
        elapsed_ms = 0.0

        try:
            resp = await client.request(
                method=method.upper(),
                url=full_url,
                headers=req_headers,
                json=nested_bomb,
                timeout=self.timeout,
            )
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            status_code = resp.status_code
            body = (resp.text or "").lower()

            # Server crashed with 500 or recursion error instead of cleanly rejecting with 413 or 400
            if status_code in (500, 502, 503):
                if any(k in body for k in ("recursion", "stack overflow", "maximum depth", "out of memory", "oom")):
                    is_vuln = True
                    reason = f"Deeply nested JSON object caused server crash HTTP {status_code} with recursion/memory error: {body[:150]}"
                else:
                    is_vuln = True
                    reason = f"Deeply nested JSON object caused unhandled server crash HTTP {status_code}."
        except (httpx.TimeoutException, httpx.ConnectTimeout):
            elapsed_ms = self.timeout * 1000
            status_code = 504
            is_vuln = True
            reason = f"Deeply nested JSON bomb caused server timeout (> {self.timeout}s)."
        except Exception:
            return None

        if is_vuln:
            fid = stable_finding_id(target_app, method, clean_ep, "RESOURCE_EXHAUSTION_JSON_BOMB", "")
            return Finding(
                finding_id=fid,
                run_id=run_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool="resource_exhaustion_fuzzer",
                target_app=target_app,
                endpoint=clean_ep,
                method=method.upper(),
                attack_type="UNRESTRICTED_RESOURCE_CONSUMPTION",
                owasp_category="API4:2023",
                payload={"type": "deeply_nested_json_bomb", "depth": 300},
                status_code=status_code,
                response_time_ms=round(elapsed_ms, 1),
                evidence=Evidence(
                    status_code=status_code,
                    response_headers={},
                    response_signal=[reason],
                    response_time_ms=round(elapsed_ms, 1),
                    payload_hash=content_hash("nested_json_300"),
                    request_hash=content_hash(full_url),
                    endpoint=clean_ep,
                ),
                severity="high",
                confidence=0.90,
                confirmed=True,
                lifecycle="confirmed",
                fingerprint=content_hash(f"{method}|{clean_ep}|JSON_BOMB"),
            )
        return None
