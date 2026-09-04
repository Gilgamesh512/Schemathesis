"""Shared security evidence, finding identity, and redaction helpers."""

from __future__ import annotations

import hashlib
import json
import re
import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel, Field


class RequestScheduler:
    """Shared concurrency and pacing guard for REST and GraphQL requests."""

    def __init__(self, concurrency: int = 10, global_rps: float = 0,
                 per_target_rps: Optional[dict[str, float]] = None,
                 max_retries: int = 2):
        self.sem = asyncio.Semaphore(max(1, concurrency))
        self.global_interval = 1 / global_rps if global_rps > 0 else 0
        self.target_intervals = {
            name.lower(): 1 / rps for name, rps in (per_target_rps or {}).items()
            if rps > 0
        }
        self._last_global = 0.0
        self._last_target: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self.max_retries = max(0, max_retries)

    async def _pace(self, target: str) -> None:
        async with self._lock:
            now = time.monotonic()
            target_key = target.lower()
            interval = max(self.global_interval, self.target_intervals.get(target_key, 0))
            last = max(self._last_global, self._last_target.get(target_key, 0))
            delay = max(0, interval - (now - last))
            if delay:
                await asyncio.sleep(delay)
            timestamp = time.monotonic()
            self._last_global = timestamp
            self._last_target[target_key] = timestamp

    async def request(self, target: str, operation):
        async with self.sem:
            for attempt in range(self.max_retries + 1):
                await self._pace(target)
                response = await operation()
                if response.status_code not in (429, 503) or attempt >= self.max_retries:
                    return response
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2 ** attempt
                except ValueError:
                    delay = 2 ** attempt
                await asyncio.sleep(delay + random.uniform(0, 0.25))
        return response


def stable_finding_id(
    target: str, method: str, endpoint: str, attack_type: str, parameter: str = ""
) -> str:
    normalized_endpoint = re.sub(r"//+", "/", endpoint.strip().lower()).rstrip("/") or "/"
    raw = "|".join((target.lower(), method.upper(), normalized_endpoint,
                     attack_type.lower().replace(" ", ""), parameter.lower()))
    return "F-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def content_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def redact_headers(headers: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not headers:
        return {}
    secret_names = {"authorization", "cookie", "set-cookie", "x-api-key"}
    redacted: dict[str, Any] = {}
    for key, value in headers.items():
        if key.lower() in secret_names:
            redacted[key] = "<REDACTED>"
            redacted[f"{key}_hash"] = content_hash(str(value))
        else:
            redacted[key] = value
    return redacted


class Evidence(BaseModel):
    status_code: Optional[int] = None
    response_headers: dict[str, Any] = Field(default_factory=dict)
    response_signal: list[str] = Field(default_factory=list)
    response_time_ms: Optional[float] = None
    payload_hash: str = ""
    request_hash: str = ""
    endpoint: str = ""
    payload: Any = None
    auth_context: dict[str, Any] = Field(default_factory=dict)
    previous_observations: list[dict[str, Any]] = Field(default_factory=list)


def compare_responses(baseline: Any, attack: Any) -> dict[str, Any]:
    """Return deterministic behavioral differences for confirmation/replay."""
    differences = {}
    for field in ("status_code", "body_hash", "headers_hash"):
        baseline_value = getattr(baseline, field, None)
        attack_value = getattr(attack, field, None)
        if baseline_value != attack_value:
            differences[field] = {"baseline": baseline_value, "attack": attack_value}
    baseline_time = getattr(baseline, "response_time_ms", None)
    attack_time = getattr(attack, "response_time_ms", None)
    if baseline_time is not None and attack_time is not None:
        differences["response_time_ms"] = {
            "baseline": baseline_time, "attack": attack_time,
        }
    return differences


@dataclass
class ResponseObservation:
    status_code: int
    body_hash: str
    headers_hash: str
    response_time_ms: float


def confirmation_result(baseline: Optional[ResponseObservation],
                        attack: ResponseObservation,
                        candidate: bool) -> tuple[bool, float, dict[str, Any]]:
    """Confirm a candidate only when attack behavior differs from baseline."""
    if baseline is None:
        return False, 0.35 if candidate else 0.1, {}
    differences = compare_responses(baseline, attack)
    if not candidate:
        return False, 0.2 if differences else 0.1, differences
    strong_difference = any(name in differences for name in ("status_code", "body_hash"))
    return strong_difference, 0.9 if strong_difference else 0.55, differences


class Finding(BaseModel):
    finding_id: str
    run_id: str
    timestamp: str
    target_app: str
    endpoint: str
    method: str
    tool: str
    attack_type: str
    owasp_category: Optional[str] = None
    payload: Any = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    evidence: Evidence
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    confirmed: bool = False
    lifecycle: str = "new"
    fingerprint: str
    cve_matches: list[str] = Field(default_factory=list)
    cve_match_type: str = ""
    cve_confidence: float = 0.0
