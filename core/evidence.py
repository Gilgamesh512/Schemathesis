"""Shared request scheduling, evidence, finding identity, and redaction helpers."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from .validation_policy import normalize_validation_verdict

logger = logging.getLogger(__name__)


class CircuitBreakerTrippedError(RuntimeError):
    """Raised when the target API encounters excessive consecutive 5xx server errors or timeouts."""
    pass


class RequestScheduler:
    """Shared concurrency, pacing, and circuit breaker guard for REST and GraphQL requests."""

    def __init__(self, concurrency: int = 10, global_rps: float = 0,
                 per_target_rps: Optional[dict[str, float]] = None,
                 max_retries: int = 2,
                 pause_threshold: int = 5,
                 abort_threshold: int = 15,
                 pause_duration: float = 15.0,
                 proxy_rotator: Optional[Any] = None,
                 session_keeper: Optional[Any] = None):
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
        self.consecutive_server_errors: dict[str, int] = {}
        self.circuit_tripped: dict[str, bool] = {}
        self.pause_threshold = pause_threshold
        self.abort_threshold = abort_threshold
        self.pause_duration = pause_duration
        self.proxy_rotator = proxy_rotator
        self.session_keeper = session_keeper

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

    async def request(self, target: str, operation, role: str = "default", proxy_url: Optional[str] = None):
        target_key = target.lower()
        if self.circuit_tripped.get(target_key, False):
            raise CircuitBreakerTrippedError(
                f"Target '{target}' is currently HALTED: Circuit Breaker was tripped due to target instability."
            )

        async with self.sem:
            response = None
            last_exc = None
            for attempt in range(self.max_retries + 1):
                await self._pace(target)
                try:
                    response = await operation()
                    last_exc = None
                except Exception as exc:
                    last_exc = exc
                    response = None

                status = getattr(response, "status_code", None)
                is_server_error = (status in (500, 502, 503, 504)) or (last_exc is not None)

                # Track consecutive failures for Circuit Breaker
                async with self._lock:
                    if is_server_error:
                        err_count = self.consecutive_server_errors.get(target_key, 0) + 1
                        self.consecutive_server_errors[target_key] = err_count
                        if err_count >= self.abort_threshold:
                            self.circuit_tripped[target_key] = True
                            raise CircuitBreakerTrippedError(
                                f"Target '{target}' failed with {err_count} consecutive 5xx/timeout errors. "
                                f"Circuit Breaker TRIPPED to prevent cascading downtime on the target service."
                            )
                        elif err_count % self.pause_threshold == 0:
                            import sys
                            print(
                                f"\n[!] CIRCUIT BREAKER: Target '{target}' encountered {err_count} consecutive 5xx errors. "
                                f"Pausing scan for {self.pause_duration}s to protect target availability...",
                                file=sys.stderr,
                            )
                            await asyncio.sleep(self.pause_duration)
                    else:
                        # Successful request or normal client error (2xx, 3xx, 4xx except 5xx) resets error streak
                        self.consecutive_server_errors[target_key] = 0

                # Reactive Session Refresh on 401/403
                if status in (401, 403) and self.session_keeper is not None and attempt < self.max_retries:
                    refreshed, _ = await self.session_keeper.handle_response(status, role=role)
                    if refreshed:
                        continue

                # Proxy Rotator notification on Throttled / Blocked
                if status in (429, 403, 503) and self.proxy_rotator is not None:
                    await self.proxy_rotator.report_response(proxy_url, status)

                if last_exc is not None:
                    # Only retry transient transport/timeout errors; surface deterministic errors immediately.
                    is_transient = isinstance(last_exc, (TimeoutError, ConnectionError, OSError)) or (
                        "timeout" in type(last_exc).__name__.lower()
                        or "connect" in type(last_exc).__name__.lower()
                        or "transport" in type(last_exc).__name__.lower()
                        or "network" in type(last_exc).__name__.lower()
                        or "protocol" in type(last_exc).__name__.lower()
                    )
                    if not is_transient or attempt >= self.max_retries:
                        raise last_exc
                    await asyncio.sleep(min((2 ** attempt) * 0.5 + random.uniform(0.05, 0.25), 5.0))
                    continue

                is_throttled = status in (429, 503)
                if not is_throttled or attempt >= self.max_retries:
                    return response

                retry_after = getattr(response, "headers", {}).get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else (2 ** attempt) + random.uniform(0.2, 0.7)
                except ValueError:
                    delay = (2 ** attempt) + random.uniform(0.2, 0.7)
                # Adaptive pacing: slow down future requests for this target
                async with self._lock:
                    current_int = self.target_intervals.get(target_key, 0.1)
                    self.target_intervals[target_key] = max(current_int, min(current_int * 1.5, 3.0))
                await asyncio.sleep(delay)
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


def sanitize_body(body: Any) -> Any:
    """Sanitize sensitive secrets (passwords, tokens, keys, card numbers) from response body/payload."""
    if not body:
        return body
    try:
        from .pii_detector import PiiDetector
        if isinstance(body, str):
            return PiiDetector.mask_text(body)
        elif isinstance(body, dict):
            raw = json.dumps(body, ensure_ascii=False)
            masked = PiiDetector.mask_text(raw)
            return json.loads(masked)
        elif isinstance(body, list):
            raw = json.dumps(body, ensure_ascii=False)
            masked = PiiDetector.mask_text(raw)
            return json.loads(masked)
    except Exception as exc:
        logger.debug("Body sanitization skipped due to error: %s", exc)
    return body


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
    for field in ("graphql_errors", "data_shape"):
        baseline_value = getattr(baseline, field, ())
        attack_value = getattr(attack, field, ())
        if baseline_value != attack_value:
            differences[field] = {"baseline": baseline_value, "attack": attack_value}
    baseline_time = getattr(baseline, "response_time_ms", None)
    attack_time = getattr(attack, "response_time_ms", None)
    if baseline_time is not None and attack_time is not None:
        delta = round(attack_time - baseline_time, 1)
        resp_time_diff = {
            "baseline": baseline_time,
            "attack": attack_time,
        }
        if delta >= 3500.0 and attack_time >= 3500.0:
            resp_time_diff["significant_delay"] = True
            resp_time_diff["delta_ms"] = delta
        differences["response_time_ms"] = resp_time_diff
    return differences


def snapshot_response(response: Any, elapsed_ms: float,
                      graphql: bool = False) -> Optional[ResponseSnapshot]:
    if response is None:
        return None
    errors: tuple[str, ...] = ()
    data_shape: tuple[str, ...] = ()
    if graphql:
        try:
            document = response.json() if hasattr(response, "json") else json.loads(response.text)
            raw_errors = document.get("errors", []) if isinstance(document, dict) else []
            errors = tuple(
                str(item.get("message", item)) if isinstance(item, dict) else str(item)
                for item in raw_errors
            )
            data = document.get("data") if isinstance(document, dict) else None
            data_shape = tuple(sorted(data.keys())) if isinstance(data, dict) else ()
        except (AttributeError, TypeError, ValueError):
            pass
    return ResponseSnapshot(
        status_code=response.status_code,
        body_hash=content_hash(response.text or ""),
        headers_hash=content_hash(dict(response.headers)),
        response_time_ms=round(elapsed_ms, 1),
        graphql_errors=errors,
        data_shape=data_shape,
    )


class DetectionResult(BaseModel):
    """Structured evidence gathered from comparing baseline and attack responses."""

    attack_type: str
    target_endpoint: str = ""
    has_baseline: bool = False
    baseline_limitation: Optional[str] = None
    status_code: Optional[int] = None
    baseline_status_code: Optional[int] = None
    response_differences: dict[str, Any] = Field(default_factory=dict)
    new_expected_signals: list[str] = Field(default_factory=list)
    preexisting_expected_signals: list[str] = Field(default_factory=list)
    ignored_generic_signals: list[str] = Field(default_factory=list)
    technical_signals: list[str] = Field(default_factory=list)
    new_technical_signals: list[str] = Field(default_factory=list)
    payload_reflected: bool = False
    reflection_only_signals: list[str] = Field(default_factory=list)
    validation_barrier: bool = False
    barrier_framework: Optional[str] = None
    barrier_details: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    evidence_summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ValidationDecision(BaseModel):
    """Policy verdict derived from DetectionResult without conflating evidence with severity."""

    outcome: str = "rejected"  # "confirmed" | "candidate" | "rejected" | "inconclusive" | "error"
    confidence: float = Field(default=0.1, ge=0.0, le=1.0)
    severity: str = "info"
    reason: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    is_candidate: bool = False
    is_confirmed: bool = False


class ConfirmationEngine:
    """Execute baseline and attack through protocol-specific async adapters."""

    @staticmethod
    def _invoke_detector(candidate, attack_response, baseline_response):
        if not callable(candidate):
            return candidate
        try:
            params = [
                p for p in inspect.signature(candidate).parameters.values()
                if p.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
            ]
            has_varargs = any(
                p.kind == inspect.Parameter.VAR_POSITIONAL
                for p in inspect.signature(candidate).parameters.values()
            )
            if has_varargs or len(params) >= 2:
                return candidate(attack_response, baseline_response)
        except (TypeError, ValueError):
            pass
        return candidate(attack_response)

    async def confirm(self, candidate, execute_baseline, execute_attack,
                      snapshot=snapshot_response) -> ConfirmationResult:
        baseline_response = None
        baseline_snapshot = None
        if execute_baseline is not None:
            started = time.perf_counter()
            try:
                baseline_response = await execute_baseline()
                baseline_snapshot = snapshot(
                    baseline_response, (time.perf_counter() - started) * 1000,
                )
            except (asyncio.CancelledError, CircuitBreakerTrippedError):
                raise
            except Exception:
                baseline_response = None
                baseline_snapshot = None

        started = time.perf_counter()
        try:
            attack_response = await execute_attack()
        except (asyncio.CancelledError, CircuitBreakerTrippedError):
            raise
        except Exception as exc:
            err_msg = str(exc) or exc.__class__.__name__
            return ConfirmationResult(
                False, False, 0.0, {"error": err_msg},
                baseline_snapshot, None, error=err_msg,
            )

        if attack_response is None:
            err_msg = "No HTTP response received"
            return ConfirmationResult(
                False, False, 0.0, {"error": err_msg},
                baseline_snapshot, None, error=err_msg,
            )

        attack_snapshot = snapshot(
            attack_response, (time.perf_counter() - started) * 1000,
        )
        if attack_snapshot is None:
            err_msg = "Could not snapshot empty attack response"
            return ConfirmationResult(
                False, False, 0.0, {"error": err_msg},
                baseline_snapshot, None, error=err_msg,
            )

        detector_out = self._invoke_detector(candidate, attack_response, baseline_response)
        detection_obj: Optional[DetectionResult] = None
        decision_obj: Optional[ValidationDecision] = None
        if isinstance(detector_out, tuple) and len(detector_out) == 2:
            maybe_det, maybe_dec = detector_out
            if isinstance(maybe_det, DetectionResult):
                detection_obj = maybe_det
            if isinstance(maybe_dec, ValidationDecision):
                decision_obj = maybe_dec
                is_candidate = decision_obj.is_candidate
            else:
                is_candidate = bool(maybe_dec)
        elif isinstance(detector_out, ValidationDecision):
            decision_obj = detector_out
            is_candidate = decision_obj.is_candidate
        else:
            is_candidate = bool(detector_out)

        res = confirmation_result(baseline_snapshot, attack_snapshot, is_candidate)
        res.detection = detection_obj
        res.decision = decision_obj
        return res


@dataclass
class ResponseSnapshot:
    status_code: int
    body_hash: str
    headers_hash: str
    response_time_ms: float
    graphql_errors: tuple[str, ...] = ()
    data_shape: tuple[str, ...] = ()


ResponseObservation = ResponseSnapshot


@dataclass
class ConfirmationResult:
    candidate: bool
    confirmed: bool
    confidence: float
    evidence: dict[str, Any]
    baseline: Optional[ResponseSnapshot]
    attack: Optional[ResponseSnapshot]
    error: Optional[str] = None
    detection: Optional[DetectionResult] = None
    decision: Optional[ValidationDecision] = None


def confirmation_result(baseline: Optional[ResponseSnapshot],
                        attack: ResponseSnapshot,
                        candidate: bool) -> ConfirmationResult:
    """Keep candidates unconfirmed until vulnerability-specific validation."""
    if baseline is None:
        return ConfirmationResult(
            candidate, False, 0.35 if candidate else 0.1,
            {}, None, attack,
        )

    differences = compare_responses(baseline, attack)

    if not candidate:
        return ConfirmationResult(
            False, False, 0.2 if differences else 0.1,
            differences, baseline, attack,
        )

    # Behavioral differences are supporting evidence, not proof of exploitation.
    # A vulnerability-specific validation strategy is required for confirmation.
    confidence = 0.55 if differences else 0.35
    return ConfirmationResult(
        True, False, confidence, differences, baseline, attack,
    )


LIFECYCLE_RANK: dict[str, int] = {
    "new": 0,
    "error": 1,
    "rejected": 2,
    "inconclusive": 3,
    "candidate": 4,
    "confirmed": 5,
}


class Observation(BaseModel):
    """Single probe execution observation attached to an aggregated Finding."""

    observation_id: str
    timestamp: str
    role: str = "attack"
    payload: Any = None
    payload_hash: str = ""
    request_hash: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    response_headers: dict[str, Any] = Field(default_factory=dict)
    signals: list[str] = Field(default_factory=list)
    differences: dict[str, Any] = Field(default_factory=dict)
    baseline_status_code: Optional[int] = None
    baseline_response_time_ms: Optional[float] = None
    outcome: str = "inconclusive"
    severity: str = "info"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_result: str = "not_run"
    error: Optional[str] = None

    @field_validator("outcome", mode="before")
    @classmethod
    def _normalize_outcome(cls, value: Any) -> str:
        val = str(value or "inconclusive").strip().lower()
        if val in {"confirmed", "candidate", "inconclusive", "rejected", "error"}:
            return val
        return "inconclusive"

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_obs_severity(cls, value: Any) -> str:
        sev = str(value or "info").strip().lower()
        if sev in {"critical", "high", "medium", "low", "info", "unknown"}:
            return sev
        return "info"


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
    curl_command: Optional[str] = None
    observations: list[Observation] = Field(default_factory=list)
    observation_count: int = 0
    error_count: int = 0

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: Any) -> str:
        sev = str(value or "info").strip().lower()
        if sev in {"critical", "high", "medium", "low", "info", "unknown"}:
            return sev
        return "info"


def summarize_lifecycle(outcomes: list[str]) -> str:
    """Compute overall Finding lifecycle from individual Observation outcomes."""
    if not outcomes:
        return "new"
    best = max(
        (str(o).strip().lower() for o in outcomes),
        key=lambda val: LIFECYCLE_RANK.get(val, 0),
    )
    return best if best in LIFECYCLE_RANK else "inconclusive"


def _select_representative_observation(observations: list[Observation]) -> Observation:
    """Select the highest-precedence observation to summarize top-level Finding fields."""
    return max(
        observations,
        key=lambda obs: (
            LIFECYCLE_RANK.get(obs.outcome, 0),
            obs.confidence,
            1 if obs.status_code is not None else 0,
        ),
    )


def synthesize_observation_from_finding(finding: Finding) -> Observation:
    """Convert a legacy Finding without observations into an equivalent Observation."""
    if finding.confirmed:
        outcome = "confirmed"
    elif finding.lifecycle in LIFECYCLE_RANK and finding.lifecycle != "new":
        outcome = finding.lifecycle
    else:
        outcome = "inconclusive"

    baseline_status = None
    baseline_time = None
    differences: dict[str, Any] = {}
    for prev in finding.evidence.previous_observations:
        if isinstance(prev, dict) and prev.get("role") == "baseline":
            baseline_status = prev.get("status_code")
            baseline_time = prev.get("response_time_ms")
            if isinstance(prev.get("differences"), dict):
                differences = dict(prev["differences"])
            break

    norm = normalize_validation_verdict(
        outcome=outcome,
        severity=finding.severity,
        confidence=finding.confidence,
        confirmed=finding.confirmed if outcome == "confirmed" else False,
        has_baseline=baseline_status is not None,
        has_independent_evidence=True,
    )

    obs_id = "OBS-" + content_hash({
        "finding_id": finding.finding_id,
        "timestamp": finding.timestamp,
        "payload_hash": finding.evidence.payload_hash,
        "request_hash": finding.evidence.request_hash,
        "status_code": finding.status_code,
        "signals": finding.evidence.response_signal,
    })
    return Observation(
        observation_id=obs_id,
        timestamp=finding.timestamp,
        role="error" if norm.outcome == "error" else "attack",
        payload=finding.payload if finding.payload is not None else finding.evidence.payload,
        payload_hash=finding.evidence.payload_hash or content_hash(finding.payload),
        request_hash=finding.evidence.request_hash or content_hash({
            "target": finding.target_app,
            "method": finding.method,
            "endpoint": finding.endpoint,
            "payload": finding.payload,
        }),
        status_code=finding.status_code if finding.status_code is not None else finding.evidence.status_code,
        response_time_ms=(
            finding.response_time_ms
            if finding.response_time_ms is not None
            else finding.evidence.response_time_ms
        ),
        response_headers=dict(finding.evidence.response_headers),
        signals=list(finding.evidence.response_signal),
        differences=differences,
        baseline_status_code=baseline_status,
        baseline_response_time_ms=baseline_time,
        outcome=norm.outcome,
        severity=norm.severity,
        confidence=norm.confidence,
        validation_result=norm.outcome,
        error=(
            "; ".join(finding.evidence.response_signal)
            if norm.outcome == "error" and finding.evidence.response_signal
            else None
        ),
    )


def build_finding_from_observations(
    *,
    finding_id: str,
    run_id: str,
    timestamp: str,
    target_app: str,
    endpoint: str,
    method: str,
    tool: str,
    attack_type: str,
    fingerprint: str,
    observations: list[Observation],
    owasp_category: Optional[str] = None,
    auth_context: Optional[dict[str, Any]] = None,
    cve_matches: Optional[list[str]] = None,
    cve_match_type: str = "",
    cve_confidence: float = 0.0,
    curl_command: Optional[str] = None,
    extra_previous_observations: Optional[list[dict[str, Any]]] = None,
) -> Finding:
    """Aggregate one or more Observations into a single canonical Finding."""
    if not observations:
        raise ValueError("observations must contain at least one Observation")

    normalized_observations: list[Observation] = []
    for obs in observations:
        norm = normalize_validation_verdict(
            outcome=obs.outcome,
            severity=obs.severity,
            confidence=obs.confidence,
            confirmed=(True if obs.outcome == "confirmed" else False),
            has_baseline=True,
            has_independent_evidence=True,
        )
        normalized_observations.append(
            obs.model_copy(
                update={
                    "outcome": norm.outcome,
                    "severity": norm.severity,
                    "confidence": norm.confidence,
                    "validation_result": "error" if norm.outcome == "error" else norm.outcome,
                }
            )
        )

    rep = _select_representative_observation(normalized_observations)
    lifecycle = summarize_lifecycle([o.outcome for o in normalized_observations])
    confirmed = lifecycle == "confirmed"
    error_count = sum(1 for o in normalized_observations if o.outcome == "error")

    rep_verdict = normalize_validation_verdict(
        outcome=lifecycle,
        severity=rep.severity,
        confidence=rep.confidence,
        confirmed=confirmed,
        has_baseline=True,
        has_independent_evidence=True,
    )

    prev_obs: list[dict[str, Any]] = []
    if rep.baseline_status_code is not None:
        prev_obs.append({
            "role": "baseline",
            "status_code": rep.baseline_status_code,
            "response_time_ms": rep.baseline_response_time_ms,
            "differences": rep.differences,
        })
    if extra_previous_observations:
        prev_obs.extend(extra_previous_observations)

    signals = list(rep.signals)
    if not signals and rep.error:
        signals = [rep.error]

    evidence_model = Evidence(
        status_code=rep.status_code,
        response_headers=dict(rep.response_headers),
        response_signal=signals,
        response_time_ms=rep.response_time_ms,
        payload_hash=rep.payload_hash,
        request_hash=rep.request_hash,
        endpoint=endpoint,
        payload=rep.payload,
        auth_context=dict(auth_context or {}),
        previous_observations=prev_obs,
    )

    return Finding(
        finding_id=finding_id,
        run_id=run_id,
        timestamp=timestamp,
        target_app=target_app,
        endpoint=endpoint,
        method=method,
        tool=tool,
        attack_type=attack_type,
        owasp_category=owasp_category,
        payload=rep.payload,
        status_code=rep.status_code,
        response_time_ms=rep.response_time_ms,
        evidence=evidence_model,
        severity=rep_verdict.severity,
        confidence=rep_verdict.confidence,
        confirmed=rep_verdict.confirmed,
        lifecycle=rep_verdict.outcome,
        fingerprint=fingerprint,
        cve_matches=list(dict.fromkeys(cve_matches or [])),
        cve_match_type=cve_match_type,
        cve_confidence=cve_confidence,
        curl_command=curl_command,
        observations=normalized_observations,
        observation_count=len(normalized_observations),
        error_count=error_count,
    )


def merge_findings(existing: Finding, incoming: Finding) -> Finding:
    """Merge two Findings sharing (run_id, fingerprint) without losing observations or conflicts."""
    existing_obs = list(existing.observations) if existing.observations else [
        synthesize_observation_from_finding(existing)
    ]
    incoming_obs = list(incoming.observations) if incoming.observations else [
        synthesize_observation_from_finding(incoming)
    ]

    merged_obs: list[Observation] = []
    seen_obs_ids: set[str] = set()
    for obs in existing_obs + incoming_obs:
        if obs.observation_id in seen_obs_ids:
            continue
        seen_obs_ids.add(obs.observation_id)
        merged_obs.append(obs)

    conflict_notes: list[dict[str, Any]] = []
    for item in existing.evidence.previous_observations + incoming.evidence.previous_observations:
        if isinstance(item, dict) and item.get("role") == "metadata_conflict":
            if item not in conflict_notes:
                conflict_notes.append(item)

    conflict_fields: dict[str, dict[str, Any]] = {}
    for field_name in ("finding_id", "target_app", "endpoint", "method", "attack_type", "owasp_category", "tool"):
        val_a = getattr(existing, field_name)
        val_b = getattr(incoming, field_name)
        if val_a and val_b and str(val_a).lower() != str(val_b).lower():
            conflict_fields[field_name] = {"existing": val_a, "incoming": val_b}
    if conflict_fields:
        logger.warning(
            "Metadata conflict merging findings for fingerprint=%s run_id=%s: %s",
            existing.fingerprint,
            existing.run_id,
            conflict_fields,
        )
        conflict_entry = {"role": "metadata_conflict", "fields": conflict_fields}
        if conflict_entry not in conflict_notes:
            conflict_notes.append(conflict_entry)

    # Prefer the higher-precedence finding's identity/metadata if non-empty, preserving conflicts above.
    primary = (
        incoming
        if LIFECYCLE_RANK.get(incoming.lifecycle, 0) > LIFECYCLE_RANK.get(existing.lifecycle, 0)
        else existing
    )
    secondary = existing if primary is incoming else incoming

    merged_cves = list(dict.fromkeys((existing.cve_matches or []) + (incoming.cve_matches or [])))
    if incoming.cve_confidence >= existing.cve_confidence:
        cve_type = incoming.cve_match_type or existing.cve_match_type
        cve_conf = incoming.cve_confidence
    else:
        cve_type = existing.cve_match_type or incoming.cve_match_type
        cve_conf = existing.cve_confidence

    auth_ctx = dict(primary.evidence.auth_context or secondary.evidence.auth_context or {})

    return build_finding_from_observations(
        finding_id=primary.finding_id or secondary.finding_id,
        run_id=primary.run_id or secondary.run_id,
        timestamp=max(existing.timestamp, incoming.timestamp),
        target_app=primary.target_app or secondary.target_app,
        endpoint=primary.endpoint or secondary.endpoint,
        method=primary.method or secondary.method,
        tool=primary.tool or secondary.tool,
        attack_type=primary.attack_type or secondary.attack_type,
        owasp_category=primary.owasp_category or secondary.owasp_category,
        fingerprint=primary.fingerprint or secondary.fingerprint,
        observations=merged_obs,
        auth_context=auth_ctx,
        cve_matches=merged_cves,
        cve_match_type=cve_type,
        cve_confidence=cve_conf,
        curl_command=primary.curl_command or secondary.curl_command,
        extra_previous_observations=conflict_notes or None,
    )


def verify_deep_state_persistence(
    get_url: str,
    expected_field: str,
    expected_value: Any,
    headers: Optional[dict[str, Any]] = None,
    timeout: float = 5.0,
    verify_ssl: bool = True,
) -> tuple[bool, str]:
    """Deep State Loopback Verification: issue a corresponding GET request to verify whether
    the mutated data actually persisted in the backend datastore.

    Eliminates false positives where the server returns HTTP 200/201 while silently
    ignoring extra properties or echoing a DTO without persisting changes.
    Returns (is_persisted, details_message).
    """
    import requests
    try:
        resp = requests.get(get_url, headers=headers or {}, timeout=timeout, verify=verify_ssl)
        if resp.status_code != 200:
            return False, f"Loopback GET returned HTTP {resp.status_code}"

        try:
            data = resp.json()
        except Exception:
            return False, "Loopback GET response is not valid JSON"

        # Recursively search for the target field and value in the JSON payload
        def _check_in_dict(obj: Any) -> bool:
            if isinstance(obj, dict):
                if expected_field in obj:
                    val = obj[expected_field]
                    if expected_value is None:
                        return True
                    if isinstance(expected_value, bool):
                        if isinstance(val, bool) and val is expected_value:
                            return True
                    elif not isinstance(val, bool) and str(val).lower() == str(expected_value).lower():
                        return True
                return any(_check_in_dict(v) for v in obj.values())
            elif isinstance(obj, list):
                return any(_check_in_dict(item) for item in obj)
            return False

        if _check_in_dict(data):
            return True, f"Verified: Field '{expected_field}' with value '{expected_value}' actively persisted in DB state."
        else:
            return False, f"Unpersisted: Field '{expected_field}' was NOT found or did not match in DB state (Echo DTO / Ignored)."
    except Exception as exc:
        return False, f"Loopback verification failed with exception: {exc}"

