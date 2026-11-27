"""Central validation verdict normalization and invariant enforcement policy (P1.5).

Defines a single deterministic, idempotent contract across REST detection,
specialized validators, Finding aggregation, reporting, SARIF, and Quality Gate:

  - outcome="confirmed"    -> confirmed=True,  severity in {critical, high, medium, low}, confidence >= 0.85
  - outcome="candidate"    -> confirmed=False, severity in {low, medium},                 confidence <= 0.75 (<= 0.50 without baseline or independent evidence)
  - outcome="inconclusive" -> confirmed=False, severity == "info",                        confidence <= 0.30
  - outcome="rejected"     -> confirmed=False, severity == "info",                        confidence <= 0.15
  - outcome="error"        -> confirmed=False, severity == "unknown",                     confidence == 0.0

Confidence represents *vulnerability confidence* (likelihood that the vulnerability
exists), never confidence that a probe executed or that a benign endpoint was
correctly rejected. Normalization never upgrades severity, never increases
confidence, and never promotes an unconfirmed verdict to confirmed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

VALID_OUTCOMES = frozenset({"confirmed", "candidate", "inconclusive", "rejected", "error"})
ACTIONABLE_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
ALL_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})

ALLOWED_SEVERITIES_BY_OUTCOME: dict[str, tuple[str, ...]] = {
    "confirmed": ("critical", "high", "medium", "low"),
    "candidate": ("medium", "low"),
    "inconclusive": ("info",),
    "rejected": ("info",),
    "error": ("unknown",),
}

CONFIRMED_MIN_CONFIDENCE = 0.85
CANDIDATE_MAX_CONFIDENCE = 0.75
CANDIDATE_NO_BASELINE_MAX_CONFIDENCE = 0.50
INCONCLUSIVE_MAX_CONFIDENCE = 0.30
REJECTED_MAX_CONFIDENCE = 0.15


@dataclass(frozen=True)
class NormalizedVerdict:
    """Normalized verdict enforcing P1.5 outcome, confirmed, severity, and confidence invariants."""

    outcome: str
    confirmed: bool
    severity: str
    confidence: float
    downgraded: bool = False
    normalization_notes: tuple[str, ...] = field(default_factory=tuple)


def sanitize_confidence(value: Any, *, default: float = 0.0) -> tuple[float, bool]:
    """Parse *value* as a finite float clamped into [0.0, 1.0].

    Returns ``(clamped_value, is_valid)`` where ``is_valid`` is False for
    booleans, non-numeric values, NaN, and +/-Inf.
    """
    if isinstance(value, bool) or value is None:
        return default, False
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default, False
    if not math.isfinite(numeric):
        return default, False
    if numeric < 0.0:
        return 0.0, True
    if numeric > 1.0:
        return 1.0, True
    return numeric, True


def normalize_validation_verdict(
    *,
    outcome: Any,
    severity: Any,
    confidence: Any,
    confirmed: Optional[bool] = None,
    has_baseline: bool = True,
    has_independent_evidence: bool = False,
    has_validation_evidence: bool = True,
) -> NormalizedVerdict:
    """Enforce deterministic, idempotent verdict invariants without inflating severity or confidence."""
    notes: list[str] = []
    downgraded = False

    norm_outcome = str(outcome or "").strip().lower()
    if norm_outcome not in VALID_OUTCOMES:
        notes.append(f"invalid outcome '{norm_outcome or 'empty'}' normalized to 'inconclusive'")
        norm_outcome = "inconclusive"
        downgraded = True

    norm_severity = str(severity or "").strip().lower()
    if norm_severity not in ALL_SEVERITIES:
        fallback_sev = "unknown" if norm_outcome == "error" else "info"
        notes.append(f"invalid severity '{norm_severity or 'empty'}' normalized to '{fallback_sev}'")
        norm_severity = fallback_sev

    norm_conf, conf_valid = sanitize_confidence(confidence, default=0.0)
    if not conf_valid:
        notes.append("non-finite or malformed confidence sanitized to 0.0")

    # Contradictory confirmed=False on a confirmed outcome cannot be promoted.
    if norm_outcome == "confirmed" and confirmed is False:
        downgraded = True
        if norm_conf >= 0.30 and norm_severity in ACTIONABLE_SEVERITIES:
            norm_outcome = "candidate"
            notes.append("outcome='confirmed' contradicted confirmed=False; downgraded to 'candidate'")
        else:
            norm_outcome = "inconclusive"
            notes.append("outcome='confirmed' contradicted confirmed=False; downgraded to 'inconclusive'")

    # Confirmed verdicts require validation evidence, actionable severity, and confidence >= 0.85.
    if norm_outcome == "confirmed":
        if not has_validation_evidence or norm_conf < CONFIRMED_MIN_CONFIDENCE or norm_severity not in ACTIONABLE_SEVERITIES:
            downgraded = True
            if norm_conf >= 0.30 and norm_severity in ACTIONABLE_SEVERITIES:
                norm_outcome = "candidate"
                notes.append(
                    "confirmed verdict lacked required evidence or confidence >= 0.85; downgraded to 'candidate'"
                )
            else:
                norm_outcome = "inconclusive"
                notes.append(
                    "confirmed verdict lacked actionable severity or sufficient confidence; downgraded to 'inconclusive'"
                )

    if norm_outcome == "error":
        if norm_severity != "unknown":
            norm_severity = "unknown"
            notes.append("error verdict severity set to 'unknown'")
        if norm_conf != 0.0:
            norm_conf = 0.0
            notes.append("error verdict confidence set to 0.0")
        return NormalizedVerdict(
            outcome="error",
            confirmed=False,
            severity="unknown",
            confidence=0.0,
            downgraded=downgraded,
            normalization_notes=tuple(notes),
        )

    if norm_outcome == "rejected":
        if norm_severity != "info":
            norm_severity = "info"
            notes.append("rejected verdict severity capped to 'info'")
        if norm_conf > REJECTED_MAX_CONFIDENCE:
            norm_conf = REJECTED_MAX_CONFIDENCE
            notes.append(f"rejected verdict vulnerability confidence capped at {REJECTED_MAX_CONFIDENCE:.2f}")
        return NormalizedVerdict(
            outcome="rejected",
            confirmed=False,
            severity="info",
            confidence=norm_conf,
            downgraded=downgraded,
            normalization_notes=tuple(notes),
        )

    if norm_outcome == "inconclusive":
        if norm_severity != "info":
            norm_severity = "info"
            notes.append("inconclusive verdict severity set to 'info'")
        if norm_conf > INCONCLUSIVE_MAX_CONFIDENCE:
            norm_conf = INCONCLUSIVE_MAX_CONFIDENCE
            notes.append(f"inconclusive verdict confidence capped at {INCONCLUSIVE_MAX_CONFIDENCE:.2f}")
        return NormalizedVerdict(
            outcome="inconclusive",
            confirmed=False,
            severity="info",
            confidence=norm_conf,
            downgraded=downgraded,
            normalization_notes=tuple(notes),
        )

    if norm_outcome == "candidate":
        if norm_severity in ("critical", "high"):
            norm_severity = "medium"
            notes.append("unconfirmed candidate severity capped at 'medium'")
        elif norm_severity not in ("medium", "low"):
            # Never upgrade severity (e.g. 'info' -> 'low'); downgrade outcome to inconclusive instead.
            downgraded = True
            capped_conf = min(norm_conf, INCONCLUSIVE_MAX_CONFIDENCE)
            notes.append(
                f"candidate with non-actionable severity '{norm_severity}' downgraded to 'inconclusive'"
            )
            return NormalizedVerdict(
                outcome="inconclusive",
                confirmed=False,
                severity="info",
                confidence=capped_conf,
                downgraded=True,
                normalization_notes=tuple(notes),
            )

        max_conf = (
            CANDIDATE_NO_BASELINE_MAX_CONFIDENCE
            if (not has_baseline and not has_independent_evidence)
            else CANDIDATE_MAX_CONFIDENCE
        )
        if norm_conf > max_conf:
            norm_conf = max_conf
            notes.append(f"candidate confidence capped at {max_conf:.2f}")

        return NormalizedVerdict(
            outcome="candidate",
            confirmed=False,
            severity=norm_severity,
            confidence=norm_conf,
            downgraded=downgraded,
            normalization_notes=tuple(notes),
        )

    # norm_outcome == "confirmed"
    return NormalizedVerdict(
        outcome="confirmed",
        confirmed=True,
        severity=norm_severity,
        confidence=norm_conf,
        downgraded=downgraded,
        normalization_notes=tuple(notes),
    )


__all__ = [
    "ACTIONABLE_SEVERITIES",
    "ALL_SEVERITIES",
    "ALLOWED_SEVERITIES_BY_OUTCOME",
    "CANDIDATE_MAX_CONFIDENCE",
    "CANDIDATE_NO_BASELINE_MAX_CONFIDENCE",
    "CONFIRMED_MIN_CONFIDENCE",
    "INCONCLUSIVE_MAX_CONFIDENCE",
    "NormalizedVerdict",
    "REJECTED_MAX_CONFIDENCE",
    "VALID_OUTCOMES",
    "normalize_validation_verdict",
    "sanitize_confidence",
]
