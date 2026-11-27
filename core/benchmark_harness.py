"""P1.6 Benchmark & Ground Truth Evaluation Harness.

Evaluates real DAST findings against a deterministic Ground Truth manifest on
unique ``(method, endpoint, vuln_class)`` pairs without double-counting,
distinguishing ``confirmed`` vs ``candidate`` vs ``rejected`` vs ``inconclusive``
vs ``error`` vs ``skipped``, and tracking cross-class false positives.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from pathlib import Path
from typing import Any, Iterable, Optional

import httpx
from pydantic import BaseModel, Field, field_validator

from .bola_validator import BolaValidator, extract_user_hint_from_token
from .evidence import LIFECYCLE_RANK

_CLASS_ALIASES: dict[str, str] = {
    "BOLA": "BOLA",
    "IDOR": "BOLA",
    "INTEGER_OVERFLOW": "BOUNDARY",
    "BOUNDARY_ANALYSIS": "BOUNDARY",
    "BOUNDARY": "BOUNDARY",
    "SSTI": "SSTI",
    "MASS_ASSIGNMENT": "MASS_ASSIGNMENT",
    "SQL_INJECTION": "SQLI",
    "SQLI": "SQLI",
    "TIME_BASED_SQLI": "SQLI",
}


def normalize_endpoint(endpoint: str) -> str:
    """Normalize URL path for consistent ground-truth matching."""
    cleaned = re.sub(r"//+", "/", str(endpoint or "/").strip())
    return cleaned.rstrip("/") or "/"


def normalize_vuln_class(raw_class: str) -> str:
    """Deterministically normalize known vulnerability class aliases without arbitrary mapping."""
    token = re.sub(r"[\s\-]+", "_", str(raw_class or "").strip().upper())
    if not token:
        raise ValueError("vuln_class must be a non-empty string")
    return _CLASS_ALIASES.get(token, token)


def _safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


class GroundTruthExpectation(BaseModel):
    case_id: str
    method: str
    endpoint: str
    vuln_class: str
    vulnerable: bool
    applicable: bool = True
    exclusion_reason: Optional[str] = None
    expected_confirmation: bool = False
    description: str = ""

    @field_validator("method", mode="before")
    @classmethod
    def _norm_method(cls, value: Any) -> str:
        val = str(value or "").strip().upper()
        if val not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"Invalid HTTP method in ground truth: {value!r}")
        return val

    @field_validator("endpoint", mode="before")
    @classmethod
    def _norm_endpoint(cls, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw.startswith("/"):
            raise ValueError(f"Endpoint must start with '/': {value!r}")
        return normalize_endpoint(raw)

    @field_validator("vuln_class", mode="before")
    @classmethod
    def _norm_vuln_class(cls, value: Any) -> str:
        return normalize_vuln_class(str(value or ""))


class NoiseControlEndpoint(BaseModel):
    case_id: str
    method: str
    endpoint: str
    description: str = ""

    @field_validator("method", mode="before")
    @classmethod
    def _norm_method(cls, value: Any) -> str:
        return str(value or "GET").strip().upper()

    @field_validator("endpoint", mode="before")
    @classmethod
    def _norm_endpoint(cls, value: Any) -> str:
        return normalize_endpoint(str(value or "/"))


class GroundTruthManifest(BaseModel):
    benchmark_version: str
    target_version: str = "1.0.0"
    target_app: str = "benchmark_lab"
    evaluated_classes: list[str] = Field(default_factory=lambda: ["BOLA", "BOUNDARY", "SSTI", "MASS_ASSIGNMENT"])
    expectations: list[GroundTruthExpectation]
    noise_control_endpoints: list[NoiseControlEndpoint] = Field(default_factory=list)
    cross_class_policy: str = "any_unexpected_positive_is_fp"

    @field_validator("evaluated_classes", mode="before")
    @classmethod
    def _norm_eval_classes(cls, value: Any) -> list[str]:
        return [normalize_vuln_class(str(v)) for v in (value or [])]

    @field_validator("expectations")
    @classmethod
    def _check_unique_expectations(cls, value: list[GroundTruthExpectation]) -> list[GroundTruthExpectation]:
        if not value:
            raise ValueError("GroundTruthManifest.expectations must not be empty")
        seen_pairs: set[tuple[str, str, str]] = set()
        seen_ids: set[str] = set()
        for exp in value:
            if exp.case_id in seen_ids:
                raise ValueError(f"Duplicate case_id in manifest: {exp.case_id}")
            seen_ids.add(exp.case_id)
            pair = (exp.method, exp.endpoint, exp.vuln_class)
            if pair in seen_pairs:
                raise ValueError(f"Duplicate (method, endpoint, vuln_class) in manifest: {pair}")
            seen_pairs.add(pair)
        return value


def load_ground_truth_manifest(path: str | Path) -> GroundTruthManifest:
    """Load and validate a Ground Truth JSON manifest from disk."""
    manifest_path = Path(path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    return GroundTruthManifest.model_validate(raw)


class ClassEvaluationMetrics(BaseModel):
    vuln_class: str
    status: str = "evaluated"  # "evaluated" | "incomplete_auth_unavailable"
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    confirmed_tp: int = 0
    confirmed_fp: int = 0
    candidate_tp: int = 0
    candidate_fp: int = 0
    rejected_tn: int = 0
    rejected_fn: int = 0
    inconclusive: int = 0
    error: int = 0
    missed: int = 0
    skipped: int = 0
    cross_class_fp: int = 0
    total_vulnerable: int = 0
    total_secure: int = 0
    applicable_pairs: int = 0
    tested_pairs: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    fpr: Optional[float] = None
    confirmation_precision: Optional[float] = None
    confirmed_recall: Optional[float] = None
    candidate_recall: Optional[float] = None
    error_rate: Optional[float] = None
    coverage: Optional[float] = None
    expected_confirmation_rate: Optional[float] = None


class CrossClassFalsePositive(BaseModel):
    method: str
    endpoint: str
    expected_classes: list[str]
    actual_class: str
    lifecycle: str
    confidence: float
    finding_id: str = ""
    fingerprint: str = ""


class SkippedPairInfo(BaseModel):
    method: str
    endpoint: str
    vuln_class: str
    reason: str


class OperationalErrorRecord(BaseModel):
    method: str
    endpoint: str
    vuln_class: str
    error_type: str
    stage: str
    reason: str


class FindingTraceRecord(BaseModel):
    finding_id: str
    fingerprint: str
    method: str
    endpoint: str
    attack_type: str
    vuln_class: str
    lifecycle: str
    severity: str
    confidence: float
    confirmed: bool
    evidence: str


class AuthPreflightResult(BaseModel):
    status: str  # "passed" | "auth_prerequisite_unavailable"
    dual_token_supported: bool
    alice_verified: bool = False
    bob_verified: bool = False
    unauth_verified: bool = False
    ownership_contrast_verified: bool = False
    scanner_wiring_verified: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


def run_auth_preflight(
    base_url: str,
    user1_headers: Optional[dict[str, str]],
    user2_headers: Optional[dict[str, str]],
    execute_scan_fn: Optional[Any] = None,
) -> AuthPreflightResult:
    """Verify both lab identity separation and scanner dual-token wiring before benchmark."""
    details: dict[str, Any] = {}
    auth_mode = BolaValidator.detect_auth_mode(user1_headers, user2_headers)
    u1_sub = extract_user_hint_from_token(user1_headers)
    u2_sub = extract_user_hint_from_token(user2_headers)
    details["detected_auth_mode"] = auth_mode
    details["user1_sub"] = u1_sub
    details["user2_sub"] = u2_sub

    scanner_wiring = False
    if execute_scan_fn is not None:
        try:
            sig = inspect.signature(execute_scan_fn)
            scanner_wiring = "user2_headers" in sig.parameters and "headers" in sig.parameters
        except (TypeError, ValueError):
            scanner_wiring = False
    else:
        scanner_wiring = True
    details["scanner_wiring_verified"] = scanner_wiring

    unauth_ok = False
    alice_ok = False
    bob_ok = False
    contrast_ok = False

    try:
        with httpx.Client(base_url=base_url, timeout=5.0) as client:
            r_unauth = client.get("/api/bola/vuln/orders/1")
            unauth_ok = r_unauth.status_code == 401
            details["unauth_status"] = r_unauth.status_code

            if user1_headers:
                r_alice = client.get("/api/bola/vuln/orders/1", headers=user1_headers)
                alice_ok = r_alice.status_code == 200 and r_alice.json().get("owner_id") == u1_sub
                details["alice_order1_status"] = r_alice.status_code

            if user2_headers:
                r_bob_own = client.get("/api/bola/secure/orders/2", headers=user2_headers)
                r_bob_cross = client.get("/api/bola/secure/orders/1", headers=user2_headers)
                bob_ok = r_bob_own.status_code == 200 and r_bob_own.json().get("owner_id") == u2_sub
                contrast_ok = r_bob_cross.status_code == 403
                details["bob_order2_status"] = r_bob_own.status_code
                details["bob_secure_order1_status"] = r_bob_cross.status_code
    except Exception as exc:
        details["preflight_error"] = f"{type(exc).__name__}: {exc}"

    dual_ok = (
        auth_mode == "dual_token"
        and bool(u1_sub)
        and bool(u2_sub)
        and u1_sub != u2_sub
        and scanner_wiring
        and unauth_ok
        and alice_ok
        and bob_ok
        and contrast_ok
    )
    return AuthPreflightResult(
        status="passed" if dual_ok else "auth_prerequisite_unavailable",
        dual_token_supported=dual_ok,
        alice_verified=alice_ok,
        bob_verified=bob_ok,
        unauth_verified=unauth_ok,
        ownership_contrast_verified=contrast_ok,
        scanner_wiring_verified=scanner_wiring,
        details=details,
    )


def snapshot_files_integrity(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    """Capture existence, size, mtime_ns, and SHA-256 hash of files for isolation proofs."""
    snap: dict[str, dict[str, Any]] = {}
    for p in paths:
        key = str(p)
        if not p.exists():
            snap[key] = {"exists": False}
            continue
        data = p.read_bytes()
        stat = p.stat()
        snap[key] = {
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return snap


def verify_isolation(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Compare before/after snapshots to prove main results artifacts were untouched."""
    changed: list[str] = []
    for key in sorted(set(before) | set(after)):
        b = before.get(key)
        a = after.get(key)
        if b != a:
            changed.append(key)
    return {
        "verified": len(changed) == 0,
        "changed_files": changed,
        "checked_files": sorted(set(before) | set(after)),
    }


def _extract_finding_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if hasattr(item, "model_dump"):
        return item.model_dump()
    raise TypeError(f"Unsupported finding object: {type(item).__name__}")


def _finding_evidence_text(f_dict: dict[str, Any]) -> str:
    ev = f_dict.get("evidence")
    if isinstance(ev, dict):
        sigs = ev.get("response_signal") or []
        if isinstance(sigs, list):
            return "; ".join(str(s) for s in sigs if s)
        return json.dumps(ev, ensure_ascii=False)
    return str(ev or "")


def _finalize_metrics(m: ClassEvaluationMetrics) -> ClassEvaluationMetrics:
    m.precision = _safe_ratio(m.tp, m.tp + m.fp)
    m.recall = _safe_ratio(m.tp, m.tp + m.fn)
    m.fpr = _safe_ratio(m.fp, m.fp + m.tn)
    m.confirmation_precision = _safe_ratio(m.confirmed_tp, m.confirmed_tp + m.confirmed_fp)
    m.confirmed_recall = _safe_ratio(m.confirmed_tp, m.total_vulnerable)
    m.candidate_recall = _safe_ratio(m.candidate_tp, m.total_vulnerable)
    m.error_rate = _safe_ratio(m.error, m.applicable_pairs)
    m.coverage = _safe_ratio(m.tested_pairs, m.applicable_pairs)
    return m


class BenchmarkEvaluator:
    """Evaluates emitted Findings against a GroundTruthManifest on unique endpoint-class pairs."""

    @classmethod
    def evaluate(
        cls,
        manifest: GroundTruthManifest,
        findings: Iterable[Any],
        *,
        planned_pairs: Optional[Iterable[tuple[str, str, str]]] = None,
        auth_preflight: Optional[AuthPreflightResult] = None,
    ) -> dict[str, Any]:
        exp_by_pair: dict[tuple[str, str, str], GroundTruthExpectation] = {}
        expected_classes_by_ep: dict[tuple[str, str], list[str]] = {}
        main_endpoints: set[tuple[str, str]] = set()
        for exp in manifest.expectations:
            pair = (exp.method, exp.endpoint, exp.vuln_class)
            exp_by_pair[pair] = exp
            ep_key = (exp.method, exp.endpoint)
            main_endpoints.add(ep_key)
            if exp.vulnerable:
                expected_classes_by_ep.setdefault(ep_key, []).append(exp.vuln_class)

        noise_endpoints: set[tuple[str, str]] = {
            (nc.method, nc.endpoint) for nc in manifest.noise_control_endpoints
        }

        normalized_planned: set[tuple[str, str, str]] = set()
        for m, ep, vc in (planned_pairs or ()):
            norm_vc = normalize_vuln_class(vc)
            if norm_vc == "SCHEMA_GENERATED":
                continue
            normalized_planned.add((str(m).upper().strip(), normalize_endpoint(ep), norm_vc))

        # Collapse findings to one canonical record per unique (method, endpoint, vuln_class)
        # using highest LIFECYCLE_RANK then confidence to avoid double-counting.
        finding_by_pair: dict[tuple[str, str, str], dict[str, Any]] = {}
        trace_records: list[FindingTraceRecord] = []

        for raw_f in findings:
            f = _extract_finding_dict(raw_f)
            attack_raw = str(f.get("attack_type") or "").strip()
            if not attack_raw or attack_raw.lower() == "schema-generated":
                continue
            method = str(f.get("method") or "GET").strip().upper()
            endpoint = normalize_endpoint(str(f.get("endpoint") or "/"))
            vuln_class = normalize_vuln_class(attack_raw)
            lifecycle = str(
                f.get("lifecycle") or f.get("outcome") or ("confirmed" if f.get("confirmed") else "inconclusive")
            ).strip().lower()
            confidence = float(f.get("confidence") or 0.0)
            severity = str(f.get("severity") or "info").strip().lower()
            confirmed = bool(f.get("confirmed", False))
            ev_text = _finding_evidence_text(f)

            trace_records.append(FindingTraceRecord(
                finding_id=str(f.get("finding_id") or ""),
                fingerprint=str(f.get("fingerprint") or ""),
                method=method,
                endpoint=endpoint,
                attack_type=attack_raw,
                vuln_class=vuln_class,
                lifecycle=lifecycle,
                severity=severity,
                confidence=confidence,
                confirmed=confirmed,
                evidence=ev_text,
            ))

            pair = (method, endpoint, vuln_class)
            candidate_entry = {
                "method": method,
                "endpoint": endpoint,
                "vuln_class": vuln_class,
                "lifecycle": lifecycle,
                "confidence": confidence,
                "severity": severity,
                "confirmed": confirmed,
                "finding_id": str(f.get("finding_id") or ""),
                "fingerprint": str(f.get("fingerprint") or ""),
                "evidence": ev_text,
            }
            existing = finding_by_pair.get(pair)
            if existing is None:
                finding_by_pair[pair] = candidate_entry
            else:
                new_key = (LIFECYCLE_RANK.get(lifecycle, 0), confidence)
                old_key = (LIFECYCLE_RANK.get(existing["lifecycle"], 0), existing["confidence"])
                if new_key > old_key:
                    finding_by_pair[pair] = candidate_entry

        all_pairs = sorted(set(exp_by_pair) | set(finding_by_pair) | normalized_planned)

        per_class: dict[str, ClassEvaluationMetrics] = {
            vc: ClassEvaluationMetrics(vuln_class=vc)
            for vc in manifest.evaluated_classes
        }
        overall = ClassEvaluationMetrics(vuln_class="OVERALL")
        cross_class_fps: list[CrossClassFalsePositive] = []
        noise_control_fps: list[CrossClassFalsePositive] = []
        skipped_pairs: list[SkippedPairInfo] = []
        operational_errors: list[OperationalErrorRecord] = []

        bola_auth_unavailable = (
            auth_preflight is not None and not auth_preflight.dual_token_supported
        )
        if bola_auth_unavailable and "BOLA" in per_class:
            per_class["BOLA"].status = "incomplete_auth_unavailable"

        expected_confirm_total_by_class: dict[str, int] = {}
        expected_confirm_hit_by_class: dict[str, int] = {}
        expected_confirm_total_overall = 0
        expected_confirm_hit_overall = 0

        for pair in all_pairs:
            method, endpoint, vuln_class = pair
            exp = exp_by_pair.get(pair)
            f = finding_by_pair.get(pair)
            lc = f["lifecycle"] if f is not None else None

            if vuln_class not in per_class:
                per_class[vuln_class] = ClassEvaluationMetrics(vuln_class=vuln_class)
            cm = per_class[vuln_class]

            # If BOLA auth prerequisite is unavailable, mark BOLA expectations incomplete
            # instead of counting false negatives or valid coverage.
            if bola_auth_unavailable and vuln_class == "BOLA" and exp is not None:
                if f is not None and lc in ("confirmed", "candidate"):
                    # Keep tracking unexpected positive if any occurred anyway
                    pass
                else:
                    cm.skipped += 1
                    overall.skipped += 1
                    skipped_pairs.append(SkippedPairInfo(
                        method=method,
                        endpoint=endpoint,
                        vuln_class=vuln_class,
                        reason="auth_prerequisite_unavailable",
                    ))
                    continue

            if exp is not None and not exp.applicable:
                if f is None:
                    cm.skipped += 1
                    overall.skipped += 1
                    skipped_pairs.append(SkippedPairInfo(
                        method=method,
                        endpoint=endpoint,
                        vuln_class=vuln_class,
                        reason=exp.exclusion_reason or "not_applicable",
                    ))
                    continue
                # An excluded pair still emitted a finding
                cm.applicable_pairs += 1
                overall.applicable_pairs += 1
                cm.tested_pairs += 1
                overall.tested_pairs += 1
                if lc in ("confirmed", "candidate"):
                    cm.total_secure += 1
                    overall.total_secure += 1
                    cm.fp += 1
                    overall.fp += 1
                    if lc == "confirmed":
                        cm.confirmed_fp += 1
                        overall.confirmed_fp += 1
                    else:
                        cm.candidate_fp += 1
                        overall.candidate_fp += 1
                elif lc == "rejected":
                    cm.total_secure += 1
                    overall.total_secure += 1
                    cm.tn += 1
                    overall.tn += 1
                    cm.rejected_tn += 1
                    overall.rejected_tn += 1
                elif lc == "inconclusive":
                    cm.total_secure += 1
                    overall.total_secure += 1
                    cm.inconclusive += 1
                    overall.inconclusive += 1
                elif lc == "error":
                    cm.total_secure += 1
                    overall.total_secure += 1
                    cm.error += 1
                    overall.error += 1
                    operational_errors.append(OperationalErrorRecord(
                        method=method,
                        endpoint=endpoint,
                        vuln_class=vuln_class,
                        error_type="probe_error",
                        stage="execution",
                        reason=f["evidence"] or "Execution error",
                    ))
                continue

            if exp is not None:
                # Applicable explicit ground-truth expectation
                cm.applicable_pairs += 1
                overall.applicable_pairs += 1
                if f is not None:
                    cm.tested_pairs += 1
                    overall.tested_pairs += 1

                if exp.vulnerable:
                    cm.total_vulnerable += 1
                    overall.total_vulnerable += 1
                    if exp.expected_confirmation:
                        expected_confirm_total_by_class[vuln_class] = expected_confirm_total_by_class.get(vuln_class, 0) + 1
                        expected_confirm_total_overall += 1

                    if lc == "confirmed":
                        cm.tp += 1
                        overall.tp += 1
                        cm.confirmed_tp += 1
                        overall.confirmed_tp += 1
                        if exp.expected_confirmation:
                            expected_confirm_hit_by_class[vuln_class] = expected_confirm_hit_by_class.get(vuln_class, 0) + 1
                            expected_confirm_hit_overall += 1
                    elif lc == "candidate":
                        cm.tp += 1
                        overall.tp += 1
                        cm.candidate_tp += 1
                        overall.candidate_tp += 1
                    elif lc == "rejected":
                        cm.fn += 1
                        overall.fn += 1
                        cm.rejected_fn += 1
                        overall.rejected_fn += 1
                    elif lc == "inconclusive":
                        cm.fn += 1
                        overall.fn += 1
                        cm.inconclusive += 1
                        overall.inconclusive += 1
                    elif lc == "error":
                        cm.fn += 1
                        overall.fn += 1
                        cm.error += 1
                        overall.error += 1
                        operational_errors.append(OperationalErrorRecord(
                            method=method,
                            endpoint=endpoint,
                            vuln_class=vuln_class,
                            error_type="probe_error",
                            stage="execution",
                            reason=f["evidence"] or "Execution error",
                        ))
                    else:
                        cm.fn += 1
                        overall.fn += 1
                        cm.missed += 1
                        overall.missed += 1
                else:
                    cm.total_secure += 1
                    overall.total_secure += 1
                    if lc == "confirmed":
                        cm.fp += 1
                        overall.fp += 1
                        cm.confirmed_fp += 1
                        overall.confirmed_fp += 1
                    elif lc == "candidate":
                        cm.fp += 1
                        overall.fp += 1
                        cm.candidate_fp += 1
                        overall.candidate_fp += 1
                    elif lc == "rejected":
                        cm.tn += 1
                        overall.tn += 1
                        cm.rejected_tn += 1
                        overall.rejected_tn += 1
                    elif lc == "inconclusive":
                        # Inconclusive is NOT counted as TN.
                        cm.inconclusive += 1
                        overall.inconclusive += 1
                    elif lc == "error":
                        # Error is NOT counted as TN.
                        cm.error += 1
                        overall.error += 1
                        operational_errors.append(OperationalErrorRecord(
                            method=method,
                            endpoint=endpoint,
                            vuln_class=vuln_class,
                            error_type="probe_error",
                            stage="execution",
                            reason=f["evidence"] or "Execution error",
                        ))
                    else:
                        if normalized_planned and pair not in normalized_planned:
                            cm.skipped += 1
                            overall.skipped += 1
                            skipped_pairs.append(SkippedPairInfo(
                                method=method,
                                endpoint=endpoint,
                                vuln_class=vuln_class,
                                reason="not_planned_by_test_planner",
                            ))
                        else:
                            cm.missed += 1
                            overall.missed += 1
                continue

            # Case B: pair not explicitly listed in manifest.expectations
            # (cross-class probe on a lab endpoint, or any probe on Noise Control)
            ep_key = (method, endpoint)
            is_noise = ep_key in noise_endpoints
            is_cross_class = (not is_noise) and (ep_key in main_endpoints)

            cm.applicable_pairs += 1
            overall.applicable_pairs += 1
            if f is not None:
                cm.tested_pairs += 1
                overall.tested_pairs += 1

            cm.total_secure += 1
            overall.total_secure += 1
            if lc in ("confirmed", "candidate"):
                cm.fp += 1
                overall.fp += 1
                if lc == "confirmed":
                    cm.confirmed_fp += 1
                    overall.confirmed_fp += 1
                else:
                    cm.candidate_fp += 1
                    overall.candidate_fp += 1

                fp_rec = CrossClassFalsePositive(
                    method=method,
                    endpoint=endpoint,
                    expected_classes=expected_classes_by_ep.get(ep_key, []),
                    actual_class=vuln_class,
                    lifecycle=lc,
                    confidence=float(f["confidence"]),
                    finding_id=f["finding_id"],
                    fingerprint=f["fingerprint"],
                )
                if is_cross_class:
                    cm.cross_class_fp += 1
                    overall.cross_class_fp += 1
                    cross_class_fps.append(fp_rec)
                else:
                    noise_control_fps.append(fp_rec)
            elif lc == "rejected":
                cm.tn += 1
                overall.tn += 1
                cm.rejected_tn += 1
                overall.rejected_tn += 1
            elif lc == "inconclusive":
                cm.inconclusive += 1
                overall.inconclusive += 1
            elif lc == "error":
                cm.error += 1
                overall.error += 1
                operational_errors.append(OperationalErrorRecord(
                    method=method,
                    endpoint=endpoint,
                    vuln_class=vuln_class,
                    error_type="probe_error",
                    stage="execution",
                    reason=f["evidence"] or "Execution error",
                ))
            else:
                cm.missed += 1
                overall.missed += 1

        for vc, cm in per_class.items():
            _finalize_metrics(cm)
            cm.expected_confirmation_rate = _safe_ratio(
                expected_confirm_hit_by_class.get(vc, 0),
                expected_confirm_total_by_class.get(vc, 0),
            )
        _finalize_metrics(overall)
        overall.expected_confirmation_rate = _safe_ratio(
            expected_confirm_hit_overall,
            expected_confirm_total_overall,
        )

        lifecycle_breakdown = {
            "confirmed": overall.confirmed_tp + overall.confirmed_fp,
            "candidate": overall.candidate_tp + overall.candidate_fp,
            "rejected": overall.rejected_tn + overall.rejected_fn,
            "inconclusive": overall.inconclusive,
            "error": overall.error,
            "skipped": overall.skipped,
            "missed": overall.missed,
        }

        return {
            "overall": overall.model_dump(),
            "per_class": {vc: cm.model_dump() for vc, cm in sorted(per_class.items())},
            "lifecycle_breakdown": lifecycle_breakdown,
            "cross_class_false_positives": [r.model_dump() for r in cross_class_fps],
            "noise_control_false_positives": [r.model_dump() for r in noise_control_fps],
            "skipped_pairs": [s.model_dump() for s in skipped_pairs],
            "operational_errors": [e.model_dump() for e in operational_errors],
            "raw_findings_trace": [t.model_dump() for t in trace_records],
            "initial_quality_gate": {
                "rule": "confirmed_fp == 0",
                "passed": overall.confirmed_fp == 0,
                "confirmed_fp": overall.confirmed_fp,
            },
        }


__all__ = [
    "AuthPreflightResult",
    "BenchmarkEvaluator",
    "ClassEvaluationMetrics",
    "CrossClassFalsePositive",
    "FindingTraceRecord",
    "GroundTruthExpectation",
    "GroundTruthManifest",
    "NoiseControlEndpoint",
    "OperationalErrorRecord",
    "SkippedPairInfo",
    "load_ground_truth_manifest",
    "normalize_endpoint",
    "normalize_vuln_class",
    "run_auth_preflight",
    "snapshot_files_integrity",
    "verify_isolation",
]
