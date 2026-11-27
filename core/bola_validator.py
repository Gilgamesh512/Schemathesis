"""BOLA/IDOR Vulnerability Validator.

Implements authorization-context-aware validation logic for
Broken Object Level Authorization (API1:2023) findings.

Three operating modes:
  - dual_token:   user1 owns resource, user2 probes → strongest signal
  - single_token: one auth context, no cross-user contrast → limited
  - anonymous:    no auth headers at all → public endpoint detection
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_AUTH_HEADER_KEYS = frozenset({
    "authorization", "cookie", "x-api-key", "x-auth-token",
})


@dataclass
class BolaVerdict:
    """Result of BOLA-specific validation."""

    outcome: str              # "confirmed" | "candidate" | "inconclusive" | "rejected"
    confidence: float         # 0.0 – 1.0
    severity: str             # "critical" | "high" | "medium" | "low" | "info"
    reason: str               # Human-readable explanation
    evidence_refs: list[str] = field(default_factory=list)
    ownership_checked: bool = False
    auth_mode: str = "anonymous"


def _has_auth_key(headers: Optional[dict[str, str]]) -> bool:
    if not headers:
        return False
    return any(k.lower() in _AUTH_HEADER_KEYS for k in headers)


def _body_contains(body: Any, marker: str) -> bool:
    """Check whether *marker* appears anywhere inside a parsed JSON body."""
    if marker is None:
        return False
    marker_lower = str(marker).strip().lower()
    if not marker_lower:
        return False

    if isinstance(body, str):
        return marker_lower in body.lower()
    if isinstance(body, (int, float, bool)):
        return marker_lower == str(body).lower()
    if isinstance(body, dict):
        for k, v in body.items():
            if marker_lower in str(k).lower():
                return True
            if _body_contains(v, marker):
                return True
        return False
    if isinstance(body, (list, tuple)):
        return any(_body_contains(item, marker) for item in body)
    return False


def extract_user_hint_from_token(headers: Optional[dict[str, str]]) -> Optional[str]:
    """Try to extract a user identity hint from auth headers.

    If the Authorization header carries a JWT, decode its payload (unverified)
    and return the first identity claim found (sub, email, user_id, …).
    Returns None when the token is opaque, encrypted, or absent.
    """
    if not headers:
        return None

    auth_val: Optional[str] = None
    for k, v in headers.items():
        if k.lower() == "authorization":
            auth_val = v
            break
    if not auth_val:
        return None

    token = auth_val
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token:
        return None

    try:
        from core.session_keeper import decode_jwt_unverified
        payload = decode_jwt_unverified(token)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    for claim in ("sub", "email", "user_id", "userId", "preferred_username", "username"):
        val = payload.get(claim)
        if val is not None:
            return str(val)
    return None


class BolaValidator:
    """Stateless BOLA/IDOR validator with pluggable auth mode detection."""

    # ------------------------------------------------------------------
    # Auth mode detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_auth_mode(
        user1_headers: Optional[dict[str, str]],
        user2_headers: Optional[dict[str, str]],
    ) -> str:
        """Determine operating mode from available auth headers."""
        has_user1 = _has_auth_key(user1_headers)
        has_user2 = _has_auth_key(user2_headers)
        if has_user1 and has_user2:
            return "dual_token"
        if has_user1 or has_user2:
            return "single_token"
        return "anonymous"

    # ------------------------------------------------------------------
    # Endpoint auth requirement inference
    # ------------------------------------------------------------------

    @staticmethod
    def infer_endpoint_requires_auth(
        baseline_status: Optional[int],
        unauth_status: Optional[int],
    ) -> Optional[bool]:
        """Infer whether endpoint requires authentication.

        - baseline (authenticated) 2xx AND unauth 401/403 → True
        - baseline 2xx AND unauth 2xx → False (public)
        - Insufficient data → None
        """
        if baseline_status is None:
            return None
        if not (200 <= baseline_status < 300):
            return None
        if unauth_status is not None:
            if unauth_status in (401, 403):
                return True
            if 200 <= unauth_status < 300:
                return False
        return None

    # ------------------------------------------------------------------
    # Ownership mismatch heuristic
    # ------------------------------------------------------------------

    @staticmethod
    def check_ownership_mismatch(
        attack_response_body: Any,
        resource_id: Optional[str],
        user1_identifier: Optional[str],
        user2_identifier: Optional[str],
    ) -> tuple[bool, str]:
        """Check if response body indicates cross-user data leakage.

        Returns (is_mismatch, detail_message).
        """
        if attack_response_body is None:
            return False, "No response body available for ownership check"

        # Heuristic 1: user2 sees user1's data → confirmed mismatch
        if user1_identifier and _body_contains(attack_response_body, user1_identifier):
            # But also check if user2 identifier is present (shared/self data)
            if user2_identifier and _body_contains(attack_response_body, user2_identifier):
                return False, (
                    f"Response contains both user1 ('{user1_identifier}') and "
                    f"user2 ('{user2_identifier}') identifiers — ambiguous"
                )
            return True, f"Response contains user1 identifier '{user1_identifier}' accessed by user2"

        # Heuristic 2: user2 sees own data → not BOLA
        if user2_identifier and _body_contains(attack_response_body, user2_identifier):
            return False, f"Response contains user2's own identifier '{user2_identifier}'"

        # Heuristic 3: resource ID returned but no identity markers
        if resource_id and _body_contains(attack_response_body, resource_id):
            return True, (
                f"Resource '{resource_id}' returned data without user2 self-reference "
                "(potential cross-user access)"
            )

        # Heuristic 4: insufficient information
        return False, "Insufficient identity markers for ownership determination"

    # ------------------------------------------------------------------
    # Main validation entry point
    # ------------------------------------------------------------------

    @classmethod
    def validate(
        cls,
        *,
        attack_status: int,
        baseline_status: Optional[int] = None,
        unauth_status: Optional[int] = None,
        attack_response_body: Any = None,
        baseline_response_body: Any = None,
        user1_headers: Optional[dict[str, str]] = None,
        user2_headers: Optional[dict[str, str]] = None,
        resource_id: Optional[str] = None,
        endpoint: str = "",
        method: str = "",
    ) -> BolaVerdict:
        """Validate a BOLA/IDOR probe result.

        Handles three operating modes (dual_token, single_token, anonymous)
        and returns a verdict with outcome, severity, and evidence.
        """
        auth_mode = cls.detect_auth_mode(user1_headers, user2_headers)

        # ---- Non-2xx early exits ----
        if attack_status in (400, 401, 403, 404):
            return BolaVerdict(
                outcome="rejected",
                confidence=0.10,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; authorization probe rejected or access denied"
                ),
                evidence_refs=[f"http_{attack_status}"],
                ownership_checked=False,
                auth_mode=auth_mode,
            )

        if attack_status >= 500:
            # Server errors are not BOLA-specific — delegate to generic decide_validation
            return BolaVerdict(
                outcome="inconclusive",
                confidence=0.15,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; server error on BOLA probe — "
                    "not BOLA-specific, requires generic error analysis"
                ),
                evidence_refs=[f"http_{attack_status}"],
                ownership_checked=False,
                auth_mode=auth_mode,
            )

        if not (200 <= attack_status < 300):
            return BolaVerdict(
                outcome="inconclusive",
                confidence=0.10,
                severity="info",
                reason=f"HTTP {attack_status}; unexpected status for BOLA analysis",
                evidence_refs=[f"http_{attack_status}"],
                ownership_checked=False,
                auth_mode=auth_mode,
            )

        # ---- HTTP 2xx: mode-specific validation ----

        if auth_mode == "anonymous":
            return cls._validate_anonymous(attack_status)

        if auth_mode == "single_token":
            return cls._validate_single_token(
                attack_status=attack_status,
                baseline_status=baseline_status,
                unauth_status=unauth_status,
                attack_response_body=attack_response_body,
                baseline_response_body=baseline_response_body,
            )

        # dual_token
        return cls._validate_dual_token(
            attack_status=attack_status,
            unauth_status=unauth_status,
            attack_response_body=attack_response_body,
            user1_headers=user1_headers,
            user2_headers=user2_headers,
            resource_id=resource_id,
            endpoint=endpoint,
        )

    # ------------------------------------------------------------------
    # Mode-specific validators
    # ------------------------------------------------------------------

    @classmethod
    def _validate_anonymous(cls, attack_status: int) -> BolaVerdict:
        """Anonymous mode: no auth tokens at all."""
        if 200 <= attack_status < 300:
            return BolaVerdict(
                outcome="rejected",
                confidence=0.10,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; no authentication headers provided — "
                    "endpoint is publicly accessible (no BOLA applicable)"
                ),
                evidence_refs=[f"http_{attack_status}", "no_auth"],
                ownership_checked=False,
                auth_mode="anonymous",
            )
        return BolaVerdict(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=(
                f"HTTP {attack_status}; anonymous request — "
                "endpoint requires auth or returned error"
            ),
            evidence_refs=[f"http_{attack_status}", "no_auth"],
            ownership_checked=False,
            auth_mode="anonymous",
        )

    @classmethod
    def _validate_single_token(
        cls,
        *,
        attack_status: int,
        baseline_status: Optional[int],
        unauth_status: Optional[int] = None,
        attack_response_body: Any,
        baseline_response_body: Any,
    ) -> BolaVerdict:
        """Single-token mode: one auth context, limited analysis."""
        # 1. Public endpoint suppression even with only 1 token
        if unauth_status is not None and 200 <= unauth_status < 300:
            return BolaVerdict(
                outcome="rejected",
                confidence=0.10,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; unauthenticated request also returned "
                    f"HTTP {unauth_status} — public endpoint, no BOLA applicable"
                ),
                evidence_refs=[
                    f"http_{attack_status}",
                    f"unauth_http_{unauth_status}",
                    "single_token",
                    "public_endpoint",
                ],
                ownership_checked=False,
                auth_mode="single_token",
            )

        if baseline_status is None or not (200 <= baseline_status < 300):
            return BolaVerdict(
                outcome="inconclusive",
                confidence=0.15,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; single auth token without successful baseline — "
                    "cannot distinguish own-resource vs cross-user access"
                ),
                evidence_refs=[f"http_{attack_status}", "single_token", "no_baseline"],
                ownership_checked=False,
                auth_mode="single_token",
            )

        # Both attack and baseline returned 2xx — compare bodies
        attack_body_str = _serialize_body(attack_response_body)
        baseline_body_str = _serialize_body(baseline_response_body)

        if attack_body_str is not None and baseline_body_str is not None:
            if attack_body_str == baseline_body_str:
                return BolaVerdict(
                    outcome="rejected",
                    confidence=0.10,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; single-token BOLA probe returned identical "
                        "response as baseline (same content = no cross-user data leak)"
                    ),
                    evidence_refs=[f"http_{attack_status}", "single_token", "identical_body"],
                    ownership_checked=True,
                    auth_mode="single_token",
                )
            else:
                return BolaVerdict(
                    outcome="inconclusive",
                    confidence=0.25,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; single-token BOLA probe returned different "
                        "response from baseline, but cannot confirm cross-user access "
                        "without second user context"
                    ),
                    evidence_refs=[f"http_{attack_status}", "single_token", "body_differs"],
                    ownership_checked=True,
                    auth_mode="single_token",
                )

        return BolaVerdict(
            outcome="inconclusive",
            confidence=0.15,
            severity="info",
            reason=(
                f"HTTP {attack_status}; single auth token — "
                "insufficient context for cross-user BOLA determination"
            ),
            evidence_refs=[f"http_{attack_status}", "single_token"],
            ownership_checked=False,
            auth_mode="single_token",
        )

    @classmethod
    def _validate_dual_token(
        cls,
        *,
        attack_status: int,
        unauth_status: Optional[int],
        attack_response_body: Any,
        user1_headers: Optional[dict[str, str]],
        user2_headers: Optional[dict[str, str]],
        resource_id: Optional[str],
        endpoint: str,
    ) -> BolaVerdict:
        """Dual-token mode: strongest signal via cross-user + unauthenticated control."""

        # 1. Public endpoint suppression
        if unauth_status is not None and 200 <= unauth_status < 300:
            return BolaVerdict(
                outcome="rejected",
                confidence=0.10,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; unauthenticated request also returned "
                    f"HTTP {unauth_status} — public endpoint, no BOLA applicable"
                ),
                evidence_refs=[
                    f"http_{attack_status}",
                    f"unauth_http_{unauth_status}",
                    "public_endpoint",
                ],
                ownership_checked=False,
                auth_mode="dual_token",
            )

        # 2. Unauthenticated denied → endpoint requires auth → check ownership
        if unauth_status is not None and unauth_status in (401, 403):
            user1_id = extract_user_hint_from_token(user1_headers)
            user2_id = extract_user_hint_from_token(user2_headers)

            is_mismatch, ownership_detail = cls.check_ownership_mismatch(
                attack_response_body, resource_id, user1_id, user2_id,
            )

            if is_mismatch:
                return BolaVerdict(
                    outcome="confirmed",
                    confidence=0.95,
                    severity="high",
                    reason=(
                        f"HTTP {attack_status}; BOLA confirmed via dual-token validation — "
                        f"unauthenticated returned HTTP {unauth_status}, "
                        f"ownership check: {ownership_detail}"
                    ),
                    evidence_refs=[
                        f"http_{attack_status}",
                        f"unauth_http_{unauth_status}",
                        "ownership_mismatch",
                    ],
                    ownership_checked=True,
                    auth_mode="dual_token",
                )

            # Ownership check returned no-mismatch with user2's own data
            if user2_id and attack_response_body is not None and _body_contains(
                attack_response_body, user2_id
            ):
                return BolaVerdict(
                    outcome="rejected",
                    confidence=0.10,
                    severity="info",
                    reason=(
                        f"HTTP {attack_status}; user2 accessed own data — "
                        f"ownership check: {ownership_detail}"
                    ),
                    evidence_refs=[
                        f"http_{attack_status}",
                        f"unauth_http_{unauth_status}",
                        "user2_own_data",
                    ],
                    ownership_checked=True,
                    auth_mode="dual_token",
                )

            # No ownership markers available → candidate
            return BolaVerdict(
                outcome="candidate",
                confidence=0.70,
                severity="medium",
                reason=(
                    f"HTTP {attack_status}; dual-token BOLA candidate — "
                    f"unauthenticated returned HTTP {unauth_status}, "
                    f"secondary user accessed protected resource; "
                    f"ownership check: {ownership_detail}"
                ),
                evidence_refs=[
                    f"http_{attack_status}",
                    f"unauth_http_{unauth_status}",
                    "no_ownership_markers",
                ],
                ownership_checked=True,
                auth_mode="dual_token",
            )

        # 3. Unauthenticated control returned unexpected status or failed
        if unauth_status is not None:
            return BolaVerdict(
                outcome="inconclusive",
                confidence=0.25,
                severity="info",
                reason=(
                    f"HTTP {attack_status}; unauthenticated control returned "
                    f"HTTP {unauth_status} — ambiguous authorization state"
                ),
                evidence_refs=[
                    f"http_{attack_status}",
                    f"unauth_http_{unauth_status}",
                ],
                ownership_checked=False,
                auth_mode="dual_token",
            )

        # 4. Unauthenticated control request failed entirely (unauth_status=None)
        return BolaVerdict(
            outcome="inconclusive",
            confidence=0.20,
            severity="info",
            reason=(
                f"HTTP {attack_status}; unauthenticated control request failed — "
                "cannot determine endpoint authorization requirements"
            ),
            evidence_refs=[f"http_{attack_status}", "unauth_failed"],
            ownership_checked=False,
            auth_mode="dual_token",
        )


def _serialize_body(body: Any) -> Optional[str]:
    """Serialize a response body to a comparable string."""
    if body is None:
        return None
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(body)


__all__ = [
    "BolaValidator",
    "BolaVerdict",
    "extract_user_hint_from_token",
]
