"""Tests for core.bola_validator — BOLA/IDOR Validator (P1.2).

Covers:
  - Auth mode detection (dual/single/anonymous)
  - Endpoint auth requirement inference
  - Ownership mismatch heuristic
  - Full validation for all 3 modes + edge cases
  - extract_user_hint_from_token
  - decide_validation BOLA 2xx rule integration
"""

from __future__ import annotations

import base64
import json

import pytest

from core.bola_validator import (
    BolaValidator,
    BolaVerdict,
    extract_user_hint_from_token,
)


# ======================================================================
# Auth mode detection
# ======================================================================


class TestDetectAuthMode:
    def test_dual_token(self):
        h1 = {"Authorization": "Bearer token1"}
        h2 = {"Authorization": "Bearer token2"}
        assert BolaValidator.detect_auth_mode(h1, h2) == "dual_token"

    def test_single_token_user1_only(self):
        h1 = {"Authorization": "Bearer token1"}
        assert BolaValidator.detect_auth_mode(h1, None) == "single_token"

    def test_single_token_user2_only(self):
        h2 = {"X-Api-Key": "key123"}
        assert BolaValidator.detect_auth_mode(None, h2) == "single_token"

    def test_anonymous_no_headers(self):
        assert BolaValidator.detect_auth_mode(None, None) == "anonymous"

    def test_anonymous_non_auth_headers(self):
        h1 = {"Content-Type": "application/json", "Accept": "text/html"}
        assert BolaValidator.detect_auth_mode(h1, None) == "anonymous"

    def test_dual_token_cookie(self):
        h1 = {"Cookie": "session=abc"}
        h2 = {"Cookie": "session=xyz"}
        assert BolaValidator.detect_auth_mode(h1, h2) == "dual_token"


# ======================================================================
# Endpoint auth requirement inference
# ======================================================================


class TestInferEndpointRequiresAuth:
    def test_requires_auth(self):
        assert BolaValidator.infer_endpoint_requires_auth(200, 403) is True

    def test_requires_auth_401(self):
        assert BolaValidator.infer_endpoint_requires_auth(200, 401) is True

    def test_public_endpoint(self):
        assert BolaValidator.infer_endpoint_requires_auth(200, 200) is False

    def test_no_baseline(self):
        assert BolaValidator.infer_endpoint_requires_auth(None, 403) is None

    def test_baseline_failed(self):
        assert BolaValidator.infer_endpoint_requires_auth(500, 403) is None

    def test_no_unauth_status(self):
        assert BolaValidator.infer_endpoint_requires_auth(200, None) is None


# ======================================================================
# Ownership mismatch heuristic
# ======================================================================


class TestCheckOwnershipMismatch:
    def test_user1_data_leaked(self):
        body = {"user_id": 42, "email": "alice@example.com", "name": "Alice"}
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            body, resource_id="42", user1_identifier="alice@example.com", user2_identifier="bob@example.com"
        )
        assert is_mismatch is True
        assert "alice@example.com" in detail

    def test_user2_sees_own_data(self):
        body = {"user_id": 99, "email": "bob@example.com", "name": "Bob"}
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            body, resource_id="42", user1_identifier="alice@example.com", user2_identifier="bob@example.com"
        )
        assert is_mismatch is False
        assert "bob@example.com" in detail

    def test_both_identifiers_present(self):
        body = {"users": [{"email": "alice@example.com"}, {"email": "bob@example.com"}]}
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            body, resource_id=None, user1_identifier="alice@example.com", user2_identifier="bob@example.com"
        )
        assert is_mismatch is False
        assert "ambiguous" in detail.lower()

    def test_resource_id_without_identity(self):
        body = {"id": 42, "title": "Secret Document"}
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            body, resource_id="42", user1_identifier=None, user2_identifier=None
        )
        assert is_mismatch is True
        assert "42" in detail

    def test_no_body(self):
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            None, resource_id="42", user1_identifier="alice", user2_identifier="bob"
        )
        assert is_mismatch is False
        assert "No response body" in detail

    def test_insufficient_markers(self):
        body = {"data": "some content"}
        is_mismatch, detail = BolaValidator.check_ownership_mismatch(
            body, resource_id=None, user1_identifier=None, user2_identifier=None
        )
        assert is_mismatch is False
        assert "Insufficient" in detail


# ======================================================================
# Full validation — Dual-token mode
# ======================================================================


class TestValidateDualToken:
    def test_public_endpoint_suppression(self):
        """attack 200, unauth 200 → rejected (public endpoint)."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=200,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        )
        assert v.outcome == "rejected"
        assert v.auth_mode == "dual_token"
        assert "public" in v.reason.lower()

    def test_confirmed_bola_with_ownership(self):
        """attack 200, unauth 401, body contains user1 id → confirmed."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=401,
            attack_response_body={"email": "alice@ex.com", "data": "secret"},
            user1_headers={"Authorization": "Bearer " + _make_jwt({"sub": "alice@ex.com"})},
            user2_headers={"Authorization": "Bearer " + _make_jwt({"sub": "bob@ex.com"})},
            resource_id="42",
        )
        assert v.outcome == "confirmed"
        assert v.severity == "high"
        assert v.confidence >= 0.90
        assert v.ownership_checked is True

    def test_candidate_no_ownership_data(self):
        """attack 200, unauth 403, no identity markers → candidate."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=403,
            attack_response_body={"data": "some content"},
            user1_headers={"Authorization": "Bearer opaque-token-1"},
            user2_headers={"Authorization": "Bearer opaque-token-2"},
            resource_id=None,
        )
        assert v.outcome == "candidate"
        assert v.severity == "medium"
        assert v.confidence >= 0.60

    def test_user2_sees_own_data_rejected(self):
        """attack 200, unauth 401, body contains user2 id → rejected."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=401,
            attack_response_body={"email": "bob@ex.com", "name": "Bob"},
            user1_headers={"Authorization": "Bearer " + _make_jwt({"sub": "alice@ex.com"})},
            user2_headers={"Authorization": "Bearer " + _make_jwt({"sub": "bob@ex.com"})},
        )
        assert v.outcome == "rejected"
        assert v.ownership_checked is True

    def test_attack_denied(self):
        """attack 403 → rejected regardless of mode."""
        v = BolaValidator.validate(
            attack_status=403,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        )
        assert v.outcome == "rejected"
        assert v.severity == "info"

    def test_unauth_control_ambiguous(self):
        """attack 200, unauth returned 500 → inconclusive."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=500,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        )
        assert v.outcome == "inconclusive"

    def test_unauth_control_failed(self):
        """attack 200, unauth_status=None (request failed) → inconclusive."""
        v = BolaValidator.validate(
            attack_status=200,
            unauth_status=None,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        )
        assert v.outcome == "inconclusive"


# ======================================================================
# Full validation — Single-token mode
# ======================================================================


class TestValidateSingleToken:
    def test_no_baseline(self):
        """attack 200, no baseline → inconclusive."""
        v = BolaValidator.validate(
            attack_status=200,
            baseline_status=None,
            user1_headers={"Authorization": "Bearer t1"},
        )
        assert v.outcome == "inconclusive"
        assert v.auth_mode == "single_token"

    def test_identical_body(self):
        """attack 200, baseline 200, same body → rejected."""
        body = {"id": 1, "title": "Post"}
        v = BolaValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_response_body=body,
            baseline_response_body=body,
            user1_headers={"Authorization": "Bearer t1"},
        )
        assert v.outcome == "rejected"
        assert "identical" in v.reason.lower()

    def test_different_body(self):
        """attack 200, baseline 200, different body → inconclusive."""
        v = BolaValidator.validate(
            attack_status=200,
            baseline_status=200,
            unauth_status=401,
            attack_response_body={"id": 2, "title": "Other Post"},
            baseline_response_body={"id": 1, "title": "My Post"},
            user1_headers={"Authorization": "Bearer t1"},
        )
        assert v.outcome == "inconclusive"
        assert "body_differs" in v.evidence_refs

    def test_public_endpoint_suppression_in_single_token(self):
        """attack 200, unauth 200 in single-token mode → rejected (public endpoint)."""
        v = BolaValidator.validate(
            attack_status=200,
            baseline_status=200,
            unauth_status=200,
            attack_response_body={"id": 2},
            baseline_response_body={"id": 1},
            user1_headers={"Authorization": "Bearer t1"},
        )
        assert v.outcome == "rejected"
        assert v.auth_mode == "single_token"
        assert "public_endpoint" in v.evidence_refs


# ======================================================================
# Full validation — Anonymous mode
# ======================================================================


class TestValidateAnonymous:
    def test_attack_200_public(self):
        """attack 200, no auth → rejected (public)."""
        v = BolaValidator.validate(attack_status=200)
        assert v.outcome == "rejected"
        assert v.auth_mode == "anonymous"
        assert "public" in v.reason.lower()

    def test_attack_401_requires_auth(self):
        """attack 401, no auth → rejected."""
        v = BolaValidator.validate(attack_status=401)
        assert v.outcome == "rejected"


# ======================================================================
# Full validation — Edge cases
# ======================================================================


class TestValidateEdgeCases:
    def test_attack_500_server_error(self):
        """Server error → inconclusive (not BOLA-specific)."""
        v = BolaValidator.validate(
            attack_status=500,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        )
        assert v.outcome == "inconclusive"
        assert "server error" in v.reason.lower()

    def test_attack_404(self):
        v = BolaValidator.validate(attack_status=404)
        assert v.outcome == "rejected"

    def test_attack_301_unexpected(self):
        v = BolaValidator.validate(attack_status=301)
        assert v.outcome in ("inconclusive", "rejected")


# ======================================================================
# extract_user_hint_from_token
# ======================================================================


class TestExtractUserHint:
    def test_valid_jwt_sub(self):
        token = _make_jwt({"sub": "user-42", "iat": 1700000000})
        hint = extract_user_hint_from_token({"Authorization": f"Bearer {token}"})
        assert hint == "user-42"

    def test_valid_jwt_email(self):
        token = _make_jwt({"email": "alice@example.com"})
        hint = extract_user_hint_from_token({"Authorization": f"Bearer {token}"})
        assert hint == "alice@example.com"

    def test_opaque_token(self):
        hint = extract_user_hint_from_token({"Authorization": "Bearer opaque-secret-key"})
        assert hint is None

    def test_no_headers(self):
        assert extract_user_hint_from_token(None) is None

    def test_no_auth_header(self):
        assert extract_user_hint_from_token({"Content-Type": "application/json"}) is None

    def test_api_key_not_jwt(self):
        assert extract_user_hint_from_token({"X-Api-Key": "sk-123456"}) is None


# ======================================================================
# decide_validation integration: BOLA 2xx → inconclusive
# ======================================================================


class TestDecideValidationBolaRule:
    """Verify that the BOLA 2xx rule in decide_validation works correctly."""

    def test_bola_200_returns_inconclusive(self):
        from modules.rest.run_schemathesis1 import Payload, DetectionResult, decide_validation

        detection = DetectionResult(
            attack_type="BOLA",
            target_endpoint="/users/42",
            has_baseline=True,
            status_code=200,
            baseline_status_code=200,
            response_differences={"body_changed": True},
        )
        payload = Payload(
            endpoint="/users/42", method="GET", attack_type="BOLA",
            payload_value=42, expected_signal=[],
        )
        decision = decide_validation(detection, payload)
        assert decision.outcome == "inconclusive"
        assert "BOLA" in decision.reason or "authorization validator" in decision.reason

    def test_bola_403_still_rejected(self):
        from modules.rest.run_schemathesis1 import Payload, DetectionResult, decide_validation

        detection = DetectionResult(
            attack_type="BOLA",
            target_endpoint="/users/42",
            has_baseline=True,
            status_code=403,
            baseline_status_code=200,
        )
        payload = Payload(
            endpoint="/users/42", method="GET", attack_type="BOLA",
            payload_value=42, expected_signal=[],
        )
        decision = decide_validation(detection, payload)
        assert decision.outcome == "rejected"

    def test_bola_201_returns_inconclusive(self):
        from modules.rest.run_schemathesis1 import Payload, DetectionResult, decide_validation

        detection = DetectionResult(
            attack_type="IDOR",
            target_endpoint="/orders/1",
            has_baseline=False,
            status_code=201,
        )
        payload = Payload(
            endpoint="/orders/1", method="GET", attack_type="IDOR",
            payload_value=1, expected_signal=[],
        )
        decision = decide_validation(detection, payload)
        assert decision.outcome == "inconclusive"


# ======================================================================
# E2E process_fingerprint_group integration
# ======================================================================


class _FakeCase:
    def __init__(self, path: str, item_id: int | str = 1):
        self.path = path
        self.item_id = item_id

    def as_transport_kwargs(self, base_url: str) -> dict:
        return {
            "method": "GET",
            "url": f"{base_url.rstrip('/')}{self.path.replace('{id}', str(self.item_id))}",
            "headers": {},
        }


class TestProcessFingerprintGroupBola:
    def test_single_token_protected_different_body_is_inconclusive(self, tmp_path):
        import asyncio
        import httpx
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            if not request.headers.get("Authorization"):
                return httpx.Response(401, json={"error": "unauthorized"})
            if request.url.path.endswith("/2"):
                return httpx.Response(200, json={"id": 2, "owner": "user2"})
            return httpx.Response(200, json={"id": 1, "owner": "user1"})

        pc = rest.PreparedCase(
            "fp-st-1",
            "test_app",
            "http://api.test",
            _FakeCase("/items/{id}", 1),
            _FakeCase("/items/{id}", 2),
            rest.Payload(
                endpoint="/items/{id}",
                method="GET",
                target_param="id",
                param_location="path",
                attack_type="BOLA",
                payload_value=2,
                expected_signal=[],
            ),
        )

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-st-1", [pc],
                    {"Authorization": "Bearer user1"}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].lifecycle == "inconclusive"
        assert findings[0].confirmed is False
        assert "single-token" in findings[0].evidence.response_signal[0].lower()

    def test_single_token_public_endpoint_is_rejected(self, tmp_path):
        import asyncio
        import httpx
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": 2, "public": True})

        pc = rest.PreparedCase(
            "fp-st-pub",
            "test_app",
            "http://api.test",
            _FakeCase("/items/{id}", 1),
            _FakeCase("/items/{id}", 2),
            rest.Payload(
                endpoint="/items/{id}",
                method="GET",
                target_param="id",
                param_location="path",
                attack_type="BOLA",
                payload_value=2,
                expected_signal=[],
            ),
        )

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-st-pub", [pc],
                    {"Authorization": "Bearer user1"}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].lifecycle == "rejected"
        assert findings[0].confirmed is False

    def test_anonymous_bola_public_endpoint_is_rejected(self, tmp_path):
        import asyncio
        import httpx
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": 1})

        pc = rest.PreparedCase(
            "fp-anon",
            "test_app",
            "http://api.test",
            _FakeCase("/items/{id}", 1),
            _FakeCase("/items/{id}", 2),
            rest.Payload(
                endpoint="/items/{id}",
                method="GET",
                target_param="id",
                param_location="path",
                attack_type="BOLA",
                payload_value=2,
                expected_signal=[],
            ),
        )

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-anon", [pc],
                    {}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].lifecycle == "rejected"
        assert findings[0].confirmed is False

    def test_bola_group_500_does_not_leak_prior_verdict(self, tmp_path):
        import asyncio
        import httpx
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/99"):
                return httpx.Response(500, text="Internal Server Error")
            if not request.headers.get("Authorization"):
                return httpx.Response(401)
            return httpx.Response(200, json={"id": 1})

        group = [
            rest.PreparedCase(
                "fp-mix",
                "test_app",
                "http://api.test",
                _FakeCase("/items/{id}", 1),
                _FakeCase("/items/{id}", 1),
                rest.Payload(
                    endpoint="/items/{id}",
                    method="GET",
                    target_param="id",
                    param_location="path",
                    attack_type="BOLA",
                    payload_value=1,
                    expected_signal=[],
                ),
            ),
            rest.PreparedCase(
                "fp-mix",
                "test_app",
                "http://api.test",
                _FakeCase("/items/{id}", 1),
                _FakeCase("/items/{id}", 99),
                rest.Payload(
                    endpoint="/items/{id}",
                    method="GET",
                    target_param="id",
                    param_location="path",
                    attack_type="BOLA",
                    payload_value=99,
                    expected_signal=[],
                ),
            ),
        ]

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-mix", group,
                    {"Authorization": "Bearer user1"}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].observation_count == 2
        assert findings[0].observations[0].outcome == "rejected"
        assert findings[0].observations[1].outcome == "candidate"
        assert findings[0].lifecycle == "candidate"


# ======================================================================
# Helpers
# ======================================================================


def _make_jwt(payload: dict) -> str:
    """Build a minimal unsigned JWT (alg=none) for testing."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."
