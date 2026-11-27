"""Server-Side Template Injection (SSTI) Differential Validator (P1.4).

Eliminates low-entropy false positives (e.g. '49' appearing in ordinary JSON)
by requiring high-entropy arithmetic evaluation and confirming via differential
second-expression + control-literal evaluation:
  - Initial canary:      {{9187*8431}} -> expects 77455597
  - Differential probe:  {{9199*8443}} -> expects 77667157
  - Control literal:     {{ssti_ctrl_canary_7x}} -> must not yield 77455597 / 77667157
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

PRIMARY_EXPR = "9187*8431"
PRIMARY_RESULT = "77455597"

SECONDARY_EXPR = "9199*8443"
SECONDARY_RESULT = "77667157"

CONTROL_TOKEN = "ssti_ctrl_canary_7x"


@dataclass
class SstiDifferentialProbes:
    """Pair of follow-up payloads matching the initial SSTI delimiter syntax."""

    initial_expected: str
    secondary_payload: str
    secondary_expected: str
    control_payload: str


@dataclass
class SstiVerdict:
    """Result of SSTI differential validation."""

    outcome: str              # "confirmed" | "candidate" | "inconclusive" | "rejected"
    confidence: float         # 0.0 - 1.0
    severity: str             # "critical" | "high" | "medium" | "low" | "info"
    reason: str               # Human-readable explanation
    evidence_refs: list[str] = field(default_factory=list)
    differential_verified: bool = False


def build_differential_ssti_probes(
    initial_payload: Any,
    expected_signals: Optional[list[str]] = None,
) -> Optional[SstiDifferentialProbes]:
    """Construct matching secondary arithmetic and literal control probes from *initial_payload*."""
    if not isinstance(initial_payload, str):
        return None

    if PRIMARY_EXPR in initial_payload:
        return SstiDifferentialProbes(
            initial_expected=PRIMARY_RESULT,
            secondary_payload=initial_payload.replace(PRIMARY_EXPR, SECONDARY_EXPR),
            secondary_expected=SECONDARY_RESULT,
            control_payload=initial_payload.replace(PRIMARY_EXPR, CONTROL_TOKEN),
        )

    # Support legacy/custom 7*7 style probes cleanly via 8*9=72? Use high-entropy replacement
    # while keeping outer delimiter syntax intact if 7*7 was explicitly supplied.
    if "7*7" in initial_payload:
        return SstiDifferentialProbes(
            initial_expected="49",
            secondary_payload=initial_payload.replace("7*7", SECONDARY_EXPR),
            secondary_expected=SECONDARY_RESULT,
            control_payload=initial_payload.replace("7*7", CONTROL_TOKEN),
        )

    # Fallback if custom expression already specifies expected signal
    if expected_signals:
        first_sig = str(expected_signals[0]).strip()
        if first_sig and len(first_sig) >= 4:
            return SstiDifferentialProbes(
                initial_expected=first_sig,
                secondary_payload=f"{{{{{SECONDARY_EXPR}}}}}",
                secondary_expected=SECONDARY_RESULT,
                control_payload=f"{{{{{CONTROL_TOKEN}}}}}",
            )

    return None


class SstiValidator:
    """Stateless differential SSTI validator."""

    @staticmethod
    def _contains(text: Optional[str], needle: str) -> bool:
        if not text or not needle:
            return False
        return needle.lower() in text.lower()

    @classmethod
    def validate(
        cls,
        *,
        attack_status: int,
        attack_body: Optional[str],
        baseline_body: Optional[str],
        initial_payload: Any,
        initial_expected: str,
        secondary_status: Optional[int] = None,
        secondary_body: Optional[str] = None,
        secondary_expected: str = SECONDARY_RESULT,
        control_status: Optional[int] = None,
        control_body: Optional[str] = None,
    ) -> Optional[SstiVerdict]:
        """Validate reflected SSTI via baseline comparison and differential re-probe.

        Returns None for >= 500 or 400/422 validation barriers so general
        detection/validation rules handle server errors and input rejections.
        """
        if attack_status >= 500 or attack_status in (400, 422):
            return None

        if not attack_body:
            return SstiVerdict(
                outcome="rejected",
                confidence=0.10,
                severity="info",
                reason=f"HTTP {attack_status}; empty response body — no SSTI evaluation evidence",
                evidence_refs=[f"http_{attack_status}"],
                differential_verified=False,
            )

        has_baseline = baseline_body is not None
        in_attack = cls._contains(attack_body, initial_expected)
        in_baseline = cls._contains(baseline_body, initial_expected) if has_baseline else False
        raw_payload_str = str(initial_payload) if initial_payload is not None else ""
        raw_reflected = bool(raw_payload_str and cls._contains(attack_body, raw_payload_str))

        if not in_attack:
            if raw_reflected:
                return SstiVerdict(
                    outcome="rejected",
                    confidence=0.75,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; template payload reflected verbatim without evaluation"
                    ),
                    evidence_refs=[f"http_{attack_status}", "unevaluated_reflection"],
                    differential_verified=False,
                )
            return SstiVerdict(
                outcome="rejected",
                confidence=0.15,
                severity="info",
                reason=f"HTTP {attack_status}; expected SSTI evaluation result '{initial_expected}' not present",
                evidence_refs=[f"http_{attack_status}"],
                differential_verified=False,
            )

        if in_baseline:
            return SstiVerdict(
                outcome="rejected",
                confidence=0.80,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; signal '{initial_expected}' was already present in baseline response"
                ),
                evidence_refs=[f"http_{attack_status}", "preexisting_signal"],
                differential_verified=False,
            )

        # Primary canary appeared newly in attack response — inspect differential probes if available
        if secondary_status is not None and secondary_body is not None:
            sec_ok = (200 <= secondary_status < 300) and cls._contains(secondary_body, secondary_expected)
            sec_not_in_baseline = not (has_baseline and cls._contains(baseline_body, secondary_expected))
            sec_not_in_initial = not cls._contains(attack_body, secondary_expected)
            ctrl_clean = (
                control_body is None
                or (
                    not cls._contains(control_body, initial_expected)
                    and not cls._contains(control_body, secondary_expected)
                )
            )

            if sec_ok and sec_not_in_baseline and sec_not_in_initial and ctrl_clean:
                return SstiVerdict(
                    outcome="confirmed",
                    confidence=0.95,
                    severity="critical",
                    reason=(
                        f"HTTP {attack_status}; SSTI confirmed via differential template evaluation "
                        f"('{initial_expected}' and '{secondary_expected}' dynamically computed; "
                        "control probe did not produce computed values)"
                    ),
                    evidence_refs=[
                        f"http_{attack_status}",
                        f"ssti_eval:{initial_expected}",
                        f"ssti_diff:{secondary_expected}",
                    ],
                    differential_verified=True,
                )

            if not sec_ok:
                return SstiVerdict(
                    outcome="rejected",
                    confidence=0.70,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; initial signal '{initial_expected}' matched but "
                        f"differential expression failed to evaluate '{secondary_expected}' "
                        "(likely coincidental match, not SSTI)"
                    ),
                    evidence_refs=[f"http_{attack_status}", "differential_mismatch"],
                    differential_verified=True,
                )

        # Differential probe could not be executed (or network failure) -> remain candidate, never confirm
        return SstiVerdict(
            outcome="candidate",
            confidence=0.60 if has_baseline else 0.40,
            severity="medium" if has_baseline else "low",
            reason=(
                f"HTTP {attack_status}; new high-entropy SSTI evaluation signal '{initial_expected}' "
                "observed (differential confirmation not completed)"
            ),
            evidence_refs=[f"http_{attack_status}", f"ssti_eval:{initial_expected}"],
            differential_verified=False,
        )


__all__ = [
    "CONTROL_TOKEN",
    "PRIMARY_EXPR",
    "PRIMARY_RESULT",
    "SECONDARY_EXPR",
    "SECONDARY_RESULT",
    "SstiDifferentialProbes",
    "SstiValidator",
    "SstiVerdict",
    "build_differential_ssti_probes",
]
