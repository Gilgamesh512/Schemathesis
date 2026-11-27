"""Tests for core.boundary_validator — Numeric Boundary / Overflow Validator (P1.3)."""

from __future__ import annotations

import asyncio
import httpx

from core.boundary_validator import BoundaryValidator, BoundaryVerdict


class TestBoundaryValidatorWraparound:
    def test_signed_int32_wraparound_to_negative_is_confirmed(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"quantity": -2147483648, "total": -100},
            baseline_body={"quantity": 1, "total": 100},
            param_name="quantity",
            param_location="body",
            payload_value=2147483647,
            method="POST",
        )
        assert isinstance(verdict, BoundaryVerdict)
        assert verdict.outcome == "confirmed"
        assert verdict.severity == "medium"
        assert verdict.confidence >= 0.85
        assert verdict.anomaly_kind == "integer_wraparound"

    def test_unsigned_underflow_wraparound_from_negative_is_confirmed(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"limit": 4294967295, "items": []},
            baseline_body={"limit": 10, "items": [{"id": 1}]},
            param_name="limit",
            param_location="query",
            payload_value=-1,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "confirmed"
        assert verdict.anomaly_kind == "integer_wraparound"

    def test_positive_overflow_causing_negative_business_field_vs_baseline_is_confirmed(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"balance": -50},
            baseline_body={"balance": 500},
            param_name="amount",
            param_location="body",
            payload_value=2147483647,
            method="POST",
        )
        assert verdict is not None
        assert verdict.outcome == "confirmed"
        assert verdict.anomaly_kind == "integer_wraparound"

    def test_unrelated_negative_field_not_flagged_as_wraparound(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"latitude": -33.8},
            baseline_body={"latitude": 37.7},
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"

    def test_matching_param_positive_to_negative_is_confirmed(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"amount": -50},
            baseline_body={"amount": 10},
            param_name="amount",
            param_location="body",
            payload_value=2147483647,
            method="POST",
        )
        assert verdict is not None
        assert verdict.outcome == "confirmed"
        assert verdict.anomaly_kind == "integer_wraparound"


class TestBoundaryValidatorCollectionPagination:
    def test_negative_limit_returning_full_dataset_is_candidate(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"items": [{"id": i} for i in range(25)], "total": 25},
            baseline_body={"items": [{"id": 1}, {"id": 2}], "total": 25},
            param_name="limit",
            param_location="query",
            payload_value=-1,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "candidate"
        assert verdict.severity == "medium"
        assert verdict.anomaly_kind == "unbounded_collection"

    def test_large_limit_accepted_verbatim_in_metadata_is_candidate(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"products": [{"id": i} for i in range(50)], "limit": 2147483647, "total": 50},
            baseline_body={"products": [{"id": 1}], "limit": 1, "total": 50},
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "candidate"
        assert verdict.severity == "medium"

    def test_large_limit_safely_clamped_by_server_is_rejected(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"products": [{"id": i} for i in range(30)], "limit": 30, "total": 194},
            baseline_body={"products": [{"id": 1}], "limit": 1, "total": 194},
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"
        assert "bounded pagination" in verdict.reason.lower()

    def test_large_skip_returning_empty_list_is_rejected(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"products": [], "total": 194, "skip": 2147483647, "limit": 30},
            baseline_body={"products": [{"id": 1}, {"id": 2}], "total": 194, "skip": 0, "limit": 30},
            param_name="skip",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"

    def test_large_limit_massive_unthrottled_list_without_metadata_is_candidate(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body=[{"id": i} for i in range(550)],
            baseline_body=[{"id": 1}, {"id": 2}],
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "candidate"
        assert verdict.severity == "medium"

    def test_raw_array_150_items_vs_baseline_10_items_is_candidate(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body=[{"id": i} for i in range(150)],
            baseline_body=[{"id": i} for i in range(10)],
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "candidate"
        assert verdict.severity == "medium"
        assert "raw_array_unbounded_expansion" in verdict.evidence_refs

    def test_raw_array_30_items_vs_baseline_1_item_is_rejected_not_fp(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body=[{"id": i} for i in range(30)],
            baseline_body=[{"id": 1}],
            param_name="limit",
            param_location="query",
            payload_value=2147483647,
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"


class TestBoundaryValidatorBusinessNumericAndSafeCases:
    def test_negative_quantity_accepted_in_post_body_is_candidate(self):
        verdict = BoundaryValidator.validate(
            attack_status=201,
            baseline_status=201,
            attack_body={"order_id": 10, "quantity": -1, "status": "created"},
            baseline_body={"order_id": 9, "quantity": 1, "status": "created"},
            param_name="quantity",
            param_location="body",
            payload_value=-1,
            method="POST",
        )
        assert verdict is not None
        assert verdict.outcome == "candidate"
        assert verdict.severity == "medium"
        assert verdict.anomaly_kind == "negative_value_accepted"

    def test_non_2xx_returns_none_to_preserve_general_validation_policy(self):
        assert BoundaryValidator.validate(attack_status=400, payload_value=-1, param_name="limit") is None
        assert BoundaryValidator.validate(attack_status=404, payload_value=2147483647, param_name="id") is None
        assert BoundaryValidator.validate(attack_status=500, payload_value=2147483647, param_name="id") is None

    def test_non_numeric_date_boundary_returns_rejected(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"date": "1970-01-01"},
            baseline_body={"date": "2026-01-01"},
            param_name="created_at",
            param_location="query",
            payload_value="1970-01-01",
            method="GET",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"

    def test_boolean_payload_not_treated_as_int(self):
        verdict = BoundaryValidator.validate(
            attack_status=200,
            baseline_status=200,
            attack_body={"ok": True},
            baseline_body={"ok": True},
            param_name="flag",
            param_location="body",
            payload_value=True,
            method="POST",
        )
        assert verdict is not None
        assert verdict.outcome == "rejected"


class _FakeBoundaryCase:
    def __init__(self, path: str, query: dict):
        self.path = path
        self.query = query

    def as_transport_kwargs(self, base_url: str) -> dict:
        return {
            "method": "GET",
            "url": f"{base_url.rstrip('/')}{self.path}",
            "params": self.query,
            "headers": {},
        }


class TestProcessFingerprintGroupBoundaryIntegration:
    def test_e2e_negative_limit_full_dump_surfaces_candidate(self, tmp_path):
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            lim = int(request.url.params.get("limit", "2"))
            if lim == -1:
                return httpx.Response(200, json={"items": [{"id": i} for i in range(20)], "total": 20})
            if lim >= 1000:
                return httpx.Response(200, json={"items": [{"id": 1}, {"id": 2}], "limit": 20, "total": 20})
            return httpx.Response(200, json={"items": [{"id": 1}, {"id": 2}], "total": 20})

        group = [
            rest.PreparedCase(
                "fp-limit",
                "test_app",
                "http://api.test",
                _FakeBoundaryCase("/items", {"limit": "2"}),
                _FakeBoundaryCase("/items", {"limit": "2147483647"}),
                rest.Payload(
                    endpoint="/items",
                    method="GET",
                    target_param="limit",
                    param_location="query",
                    attack_type="INTEGER_OVERFLOW",
                    payload_value=2147483647,
                    expected_signal=[],
                ),
            ),
            rest.PreparedCase(
                "fp-limit",
                "test_app",
                "http://api.test",
                _FakeBoundaryCase("/items", {"limit": "2"}),
                _FakeBoundaryCase("/items", {"limit": "-1"}),
                rest.Payload(
                    endpoint="/items",
                    method="GET",
                    target_param="limit",
                    param_location="query",
                    attack_type="INTEGER_OVERFLOW",
                    payload_value=-1,
                    expected_signal=[],
                ),
            ),
        ]

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-limit", group,
                    {}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].observation_count == 2
        assert findings[0].observations[0].outcome == "rejected"
        assert findings[0].observations[1].outcome == "candidate"
        assert findings[0].lifecycle == "candidate"
        assert findings[0].severity == "medium"

    def test_e2e_safe_clamped_and_empty_skip_remain_rejected(self, tmp_path):
        import modules.rest.run_schemathesis1 as rest
        from core.run_state import RunState

        def handler(request: httpx.Request) -> httpx.Response:
            skip = int(request.url.params.get("skip", "0"))
            if skip >= 1000:
                return httpx.Response(200, json={"products": [], "total": 194, "skip": skip, "limit": 30})
            return httpx.Response(200, json={"products": [{"id": 1}, {"id": 2}], "total": 194, "skip": 0, "limit": 30})

        pc = rest.PreparedCase(
            "fp-skip",
            "test_app",
            "http://api.test",
            _FakeBoundaryCase("/products", {"skip": "0"}),
            _FakeBoundaryCase("/products", {"skip": "2147483647"}),
            rest.Payload(
                endpoint="/products",
                method="GET",
                target_param="skip",
                param_location="query",
                attack_type="INTEGER_OVERFLOW",
                payload_value=2147483647,
                expected_signal=[],
            ),
        )

        async def _run():
            state = RunState(tmp_path / "state.json")
            scheduler = rest.RequestScheduler(max_retries=0)
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-skip", [pc],
                    {}, None, state, 0.0,
                )

        findings = asyncio.run(_run())
        assert len(findings) == 1
        assert findings[0].lifecycle == "rejected"
        assert findings[0].severity == "info"
