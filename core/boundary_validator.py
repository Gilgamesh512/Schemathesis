"""Numeric Boundary & Integer Overflow Validator (P1.3).

Validates HTTP 2xx responses for INTEGER_OVERFLOW and BOUNDARY_ANALYSIS probes
without relying on generic keyword matching or 5xx-only heuristics:
  - Integer wraparound (e.g. INT32_MAX -> negative, -1 -> 2^32-1 / 2^64-1)
  - Unbounded pagination / full-table dump (e.g. limit=-1 or limit=2147483647)
  - Safe clamping / empty-offset rejection (e.g. skip=2147483647 -> 0 items)
  - Accepted negative values on state-changing or numeric business parameters
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

_PAGINATION_PARAM_NAMES = frozenset({
    "limit", "size", "count", "per_page", "perpage", "page_size", "pagesize",
    "top", "take", "max", "max_results", "maxresults", "offset", "skip",
})

_BUSINESS_NUMERIC_PARAM_NAMES = frozenset({
    "limit", "size", "count", "per_page", "perpage", "page_size", "pagesize",
    "offset", "skip", "amount", "quantity", "qty", "price", "total", "discount",
    "balance", "credit", "credits", "transfer_amount", "fee", "rate",
})

_COLLECTION_KEYS = (
    "items", "data", "results", "records", "rows", "entries",
    "products", "users", "posts", "comments", "orders", "list",
)

_LIMIT_KEYS = ("limit", "page_size", "pagesize", "per_page", "perpage", "size")
_TOTAL_KEYS = ("total", "total_count", "totalcount", "total_items", "totalitems")

_WRAPAROUND_MARKERS = frozenset({
    -2147483648,
    -2147483647,
    4294967295,
    4294967294,
    18446744073709551615,
    18446744073709551614,
})


@dataclass
class BoundaryVerdict:
    """Result of numeric boundary / overflow validation."""

    outcome: str              # "confirmed" | "candidate" | "inconclusive" | "rejected"
    confidence: float         # 0.0 - 1.0
    severity: str             # "critical" | "high" | "medium" | "low" | "info"
    reason: str               # Human-readable explanation
    evidence_refs: list[str] = field(default_factory=list)
    anomaly_kind: Optional[str] = None


def _parse_numeric(value: Any) -> Optional[int | float]:
    """Parse integer/float strictly, ignoring booleans and non-numeric strings."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            if "." in raw or "e" in raw.lower():
                return float(raw)
            return int(raw)
        except ValueError:
            return None
    return None


def _iter_numeric_fields(body: Any, prefix: str = "") -> list[tuple[str, int | float]]:
    """Collect (field_name, numeric_value) pairs recursively from parsed JSON."""
    results: list[tuple[str, int | float]] = []
    if isinstance(body, dict):
        for k, v in body.items():
            key_str = str(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                results.append((key_str, v))
            elif isinstance(v, (dict, list)):
                results.extend(_iter_numeric_fields(v, f"{prefix}.{key_str}" if prefix else key_str))
    elif isinstance(body, list):
        for item in body[:50]:
            if isinstance(item, (dict, list)):
                results.extend(_iter_numeric_fields(item, prefix))
    return results


def _extract_collection_metrics(body: Any) -> dict[str, Optional[int]]:
    """Extract primary list length and pagination metadata from a response body."""
    metrics: dict[str, Optional[int]] = {
        "item_count": None,
        "echoed_limit": None,
        "total": None,
    }
    if isinstance(body, list):
        metrics["item_count"] = len(body)
        return metrics
    if not isinstance(body, dict):
        return metrics

    lowered = {str(k).lower(): v for k, v in body.items()}

    for key in _COLLECTION_KEYS:
        val = lowered.get(key)
        if isinstance(val, list):
            metrics["item_count"] = len(val)
            break

    if metrics["item_count"] is None:
        list_lengths = [len(v) for v in body.values() if isinstance(v, list)]
        if list_lengths:
            metrics["item_count"] = max(list_lengths)

    for key in _LIMIT_KEYS:
        val = _parse_numeric(lowered.get(key))
        if val is not None:
            metrics["echoed_limit"] = int(val)
            break

    for key in _TOTAL_KEYS:
        val = _parse_numeric(lowered.get(key))
        if val is not None:
            metrics["total"] = int(val)
            break

    return metrics


class BoundaryValidator:
    """Stateless validator for numeric boundary, pagination, and integer overflow probes."""

    @classmethod
    def validate(
        cls,
        *,
        attack_status: int,
        baseline_status: Optional[int] = None,
        attack_body: Any = None,
        baseline_body: Any = None,
        param_name: str = "",
        param_location: str = "query",
        payload_value: Any = None,
        method: str = "GET",
        endpoint: str = "",
    ) -> Optional[BoundaryVerdict]:
        """Validate a numeric boundary / overflow probe response.

        Returns None for non-2xx statuses so general validation policy
        (400/422 barrier, 404 rejection, 5xx server error) remains authoritative.
        """
        if not (200 <= attack_status < 300):
            return None

        payload_num = _parse_numeric(payload_value)
        if payload_num is None:
            return BoundaryVerdict(
                outcome="rejected",
                confidence=0.15,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; non-numeric boundary probe "
                    f"returned success without server error"
                ),
                evidence_refs=[f"http_{attack_status}", "non_numeric_boundary"],
            )

        param_lower = (param_name or "").strip().lower()
        method_upper = (method or "GET").strip().upper()
        loc_lower = (param_location or "query").strip().lower()
        has_baseline_2xx = baseline_status is not None and (200 <= baseline_status < 300)

        # 1. Check integer wraparound in returned numeric fields
        wraparound = cls._check_wraparound(
            payload_num=payload_num,
            param_lower=param_lower,
            attack_body=attack_body,
            baseline_body=baseline_body if has_baseline_2xx else None,
            attack_status=attack_status,
        )
        if wraparound is not None:
            return wraparound

        # 2. Check collection / pagination overflow or negative limit bypass
        attack_metrics = _extract_collection_metrics(attack_body)
        baseline_metrics = (
            _extract_collection_metrics(baseline_body)
            if has_baseline_2xx and baseline_body is not None
            else {"item_count": None, "echoed_limit": None, "total": None}
        )
        collection_verdict = cls._check_collection_boundary(
            payload_num=payload_num,
            param_lower=param_lower,
            attack_status=attack_status,
            has_baseline_2xx=has_baseline_2xx,
            attack_metrics=attack_metrics,
            baseline_metrics=baseline_metrics,
        )
        if collection_verdict is not None:
            return collection_verdict

        # 3. Check accepted/echoed negative or extreme numeric value on state-changing or business params
        business_verdict = cls._check_accepted_numeric_anomaly(
            payload_num=payload_num,
            param_lower=param_lower,
            loc_lower=loc_lower,
            method_upper=method_upper,
            attack_status=attack_status,
            attack_body=attack_body,
        )
        if business_verdict is not None:
            return business_verdict

        # 4. Safe handling: 2xx without wraparound, unbounded expansion, or accepted anomaly
        return BoundaryVerdict(
            outcome="rejected",
            confidence=0.20 if has_baseline_2xx else 0.15,
            severity="info",
            reason=(
                f"HTTP {attack_status}; numeric boundary value {payload_num} handled safely "
                "without wraparound, unbounded expansion, or accepted numeric anomaly"
            ),
            evidence_refs=[f"http_{attack_status}", "boundary_safe"],
        )

    @staticmethod
    def _check_wraparound(
        *,
        payload_num: int | float,
        param_lower: str,
        attack_body: Any,
        baseline_body: Any,
        attack_status: int,
    ) -> Optional[BoundaryVerdict]:
        attack_nums = _iter_numeric_fields(attack_body)
        if not attack_nums:
            return None

        baseline_map: dict[str, list[int | float]] = {}
        for k, v in _iter_numeric_fields(baseline_body):
            baseline_map.setdefault(k.lower(), []).append(v)

        for field_name, val in attack_nums:
            f_lower = field_name.lower()
            # Skip unrelated fields if baseline didn't exist and value isn't an explicit wraparound marker
            if val in _WRAPAROUND_MARKERS and val != payload_num:
                return BoundaryVerdict(
                    outcome="confirmed",
                    confidence=0.90,
                    severity="medium",
                    reason=(
                        f"HTTP {attack_status}; integer wraparound detected on field '{field_name}' "
                        f"(payload={payload_num} -> response value={val})"
                    ),
                    evidence_refs=[f"http_{attack_status}", "integer_wraparound", f"field:{field_name}"],
                    anomaly_kind="integer_wraparound",
                )

            base_vals = baseline_map.get(f_lower, [])
            is_tracked_field = f_lower == param_lower or f_lower in _BUSINESS_NUMERIC_PARAM_NAMES
            if payload_num >= 2147483647 and val < 0:
                if (is_tracked_field and any(bv >= 0 for bv in base_vals)) or f_lower == param_lower:
                    return BoundaryVerdict(
                        outcome="confirmed",
                        confidence=0.88,
                        severity="medium",
                        reason=(
                            f"HTTP {attack_status}; signed integer overflow wraparound on '{field_name}' "
                            f"(positive boundary {payload_num} produced negative value {val})"
                        ),
                        evidence_refs=[f"http_{attack_status}", "signed_wraparound", f"field:{field_name}"],
                        anomaly_kind="integer_wraparound",
                    )

            if payload_num < 0 and val >= 2147483648:
                if (is_tracked_field and any(0 <= bv < 2147483648 for bv in base_vals)) or f_lower == param_lower:
                    return BoundaryVerdict(
                        outcome="confirmed",
                        confidence=0.88,
                        severity="medium",
                        reason=(
                            f"HTTP {attack_status}; unsigned integer underflow wraparound on '{field_name}' "
                            f"(negative boundary {payload_num} wrapped to {val})"
                        ),
                        evidence_refs=[f"http_{attack_status}", "unsigned_wraparound", f"field:{field_name}"],
                        anomaly_kind="integer_wraparound",
                    )

        return None

    @staticmethod
    def _check_collection_boundary(
        *,
        payload_num: int | float,
        param_lower: str,
        attack_status: int,
        has_baseline_2xx: bool,
        attack_metrics: dict[str, Optional[int]],
        baseline_metrics: dict[str, Optional[int]],
    ) -> Optional[BoundaryVerdict]:
        attack_count = attack_metrics.get("item_count")
        baseline_count = baseline_metrics.get("item_count")
        echoed_limit = attack_metrics.get("echoed_limit")
        total = attack_metrics.get("total")

        is_pagination_param = param_lower in _PAGINATION_PARAM_NAMES
        if attack_count is None and echoed_limit is None:
            return None

        # Explicit server-side pagination clamping or safe default fallback
        if payload_num >= 1000 and echoed_limit is not None and 0 < echoed_limit <= 100:
            if attack_count is None or attack_count <= echoed_limit:
                return BoundaryVerdict(
                    outcome="rejected",
                    confidence=0.75,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; server safely bounded pagination "
                        f"(requested {param_lower or 'limit'}={payload_num}, enforced limit={echoed_limit})"
                    ),
                    evidence_refs=[f"http_{attack_status}", "pagination_clamped"],
                )

        # Negative boundary returning expanded or full collection (e.g. SQLite LIMIT -1)
        if payload_num < 0 and attack_count is not None:
            # If server clearly fell back to a safe bounded page size != payload_num, reject
            if echoed_limit is not None and 0 < echoed_limit <= 100 and echoed_limit != payload_num:
                if attack_count <= echoed_limit and (total is None or total > attack_count):
                    return BoundaryVerdict(
                        outcome="rejected",
                        confidence=0.70,
                        severity="info",
                        reason=(
                            f"HTTP {attack_status}; server fell back to bounded limit={echoed_limit} "
                            f"for negative {param_lower}={payload_num}"
                        ),
                        evidence_refs=[f"http_{attack_status}", "pagination_clamped"],
                    )

            expanded_vs_baseline = (
                has_baseline_2xx
                and baseline_count is not None
                and baseline_count >= 1
                and attack_count > baseline_count
                and (attack_count >= baseline_count * 2 or attack_count >= 50)
            )
            full_table_dump = (
                total is not None
                and total >= 5
                and attack_count >= total
                and (baseline_count is None or attack_count > baseline_count)
            )
            if (is_pagination_param or expanded_vs_baseline) and (expanded_vs_baseline or full_table_dump or echoed_limit == payload_num):
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.75 if has_baseline_2xx else 0.55,
                    severity="medium",
                    reason=(
                        f"HTTP {attack_status}; negative numeric boundary ({param_lower or 'param'}={payload_num}) "
                        f"bypassed pagination cap (returned {attack_count} items"
                        f"{f', baseline={baseline_count}' if baseline_count is not None else ''})"
                    ),
                    evidence_refs=[f"http_{attack_status}", "negative_limit_bypass"],
                    anomaly_kind="unbounded_collection",
                )

        # Large positive boundary accepted verbatim or returning unbounded dataset
        if payload_num >= 100000:
            if echoed_limit is not None and echoed_limit >= 10000:
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.70,
                    severity="medium",
                    reason=(
                        f"HTTP {attack_status}; server accepted extreme pagination limit={echoed_limit} "
                        "without upper-bound clamping (OWASP API4:2023)"
                    ),
                    evidence_refs=[f"http_{attack_status}", "unclamped_limit"],
                    anomaly_kind="unbounded_collection",
                )

            if attack_count is not None and attack_count >= 500:
                if baseline_count is None or attack_count > baseline_count:
                    return BoundaryVerdict(
                        outcome="candidate",
                        confidence=0.70 if has_baseline_2xx else 0.55,
                        severity="medium",
                        reason=(
                            f"HTTP {attack_status}; extreme numeric boundary ({param_lower or 'param'}={payload_num}) "
                            f"returned large unthrottled collection ({attack_count} items"
                            f"{f', baseline={baseline_count}' if baseline_count is not None else ''})"
                        ),
                        evidence_refs=[f"http_{attack_status}", "large_unbounded_collection"],
                        anomaly_kind="unbounded_collection",
                    )

            if (
                is_pagination_param
                and param_lower in ("limit", "size", "count", "per_page", "perpage", "page_size", "pagesize", "top", "take", "max", "max_results", "maxresults")
                and attack_count is not None
                and total is not None
                and attack_count >= 100
                and attack_count >= total
                and (baseline_count is None or attack_count > baseline_count)
            ):
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.65 if has_baseline_2xx else 0.50,
                    severity="medium",
                    reason=(
                        f"HTTP {attack_status}; {param_lower}={payload_num} returned all {attack_count}/{total} "
                        f"records without server-side page size cap"
                        f"{f' (baseline={baseline_count})' if baseline_count is not None else ''}"
                    ),
                    evidence_refs=[f"http_{attack_status}", "full_dataset_dump"],
                    anomaly_kind="unbounded_collection",
                )

            # Raw JSON array [...] without total/limit metadata: detect large relative expansion (>= 5x, >= 100 items)
            # only when baseline itself had >= 5 items (avoids false positives when baseline guessed limit=1).
            if (
                is_pagination_param
                and param_lower in ("limit", "size", "count", "per_page", "perpage", "page_size", "pagesize", "top", "take", "max", "max_results", "maxresults")
                and attack_count is not None
                and has_baseline_2xx
                and baseline_count is not None
                and baseline_count >= 5
                and attack_count >= 100
                and attack_count >= baseline_count * 5
            ):
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.60,
                    severity="medium",
                    reason=(
                        f"HTTP {attack_status}; {param_lower}={payload_num} expanded raw collection to "
                        f"{attack_count} items ({round(attack_count / baseline_count, 1)}x baseline={baseline_count}) "
                        "without pagination cap"
                    ),
                    evidence_refs=[f"http_{attack_status}", "raw_array_unbounded_expansion"],
                    anomaly_kind="unbounded_collection",
                )

        # Empty or shrunk collection (e.g. skip=2147483647 -> 0 items)
        if attack_count is not None and baseline_count is not None and attack_count <= baseline_count:
            return BoundaryVerdict(
                outcome="rejected",
                confidence=0.60,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; boundary probe returned {attack_count} items "
                    f"(<= baseline {baseline_count}); no unbounded expansion"
                ),
                evidence_refs=[f"http_{attack_status}", "bounded_collection"],
            )

        return None

    @staticmethod
    def _check_accepted_numeric_anomaly(
        *,
        payload_num: int | float,
        param_lower: str,
        loc_lower: str,
        method_upper: str,
        attack_status: int,
        attack_body: Any,
    ) -> Optional[BoundaryVerdict]:
        if not isinstance(attack_body, (dict, list)) or not param_lower:
            return None

        attack_nums = _iter_numeric_fields(attack_body)
        matching_vals = [val for fname, val in attack_nums if fname.lower() == param_lower]
        if not matching_vals:
            return None

        if payload_num < 0 and any(v == payload_num for v in matching_vals):
            is_state_changing = method_upper in ("POST", "PUT", "PATCH") and loc_lower == "body"
            is_business_param = param_lower in _BUSINESS_NUMERIC_PARAM_NAMES
            if is_state_changing or is_business_param:
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.65 if is_state_changing else 0.55,
                    severity="medium" if is_state_changing else "low",
                    reason=(
                        f"HTTP {attack_status}; endpoint accepted negative numeric value "
                        f"{param_lower}={payload_num} in response state"
                    ),
                    evidence_refs=[f"http_{attack_status}", "negative_value_accepted", f"field:{param_lower}"],
                    anomaly_kind="negative_value_accepted",
                )

        if payload_num >= 2147483647 and any(v == payload_num for v in matching_vals):
            if method_upper in ("POST", "PUT", "PATCH") and param_lower in _BUSINESS_NUMERIC_PARAM_NAMES:
                return BoundaryVerdict(
                    outcome="candidate",
                    confidence=0.60,
                    severity="low",
                    reason=(
                        f"HTTP {attack_status}; state-changing endpoint accepted extreme numeric boundary "
                        f"{param_lower}={payload_num}"
                    ),
                    evidence_refs=[f"http_{attack_status}", "extreme_boundary_accepted", f"field:{param_lower}"],
                    anomaly_kind="extreme_boundary_accepted",
                )

        return None


__all__ = [
    "BoundaryValidator",
    "BoundaryVerdict",
]
