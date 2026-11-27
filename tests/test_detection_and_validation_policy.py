"""Tests for DetectionResult/ValidationDecision contracts and false-positive validation policy."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from core import (
    ConfirmationEngine,
    DetectionResult,
    RunState,
    ValidationDecision,
    snapshot_response,
)
from modules.rest import run_schemathesis1 as rest
from modules.security import rules_engine


class _DummyCase:
    def __init__(self, path: str, query: dict | None = None):
        self.path = path
        self.query = query or {}

    def as_transport_kwargs(self, base_url: str) -> dict:
        return {
            "method": "GET",
            "url": f"{base_url.rstrip('/')}{self.path}",
            "params": self.query,
        }


def _make_payload(
    attack_type: str = "BOLA",
    expected_signal: list[str] | None = None,
    payload_value="1",
    endpoint: str = "/items",
) -> rest.Payload:
    return rest.Payload(
        endpoint=endpoint,
        method="GET",
        target_param="q",
        param_location="query",
        attack_type=attack_type,
        payload_value=payload_value,
        expected_signal=expected_signal or [],
        target_app="test_api",
    )


def test_generic_json_words_and_short_numbers_never_create_candidate():
    normal_json = {
        "id": 49,
        "user": "alice",
        "admin": False,
        "notes": "No exception thrown, invalid input prevented",
        "items": [{"id": 1, "age": 49}],
    }
    resp = httpx.Response(200, json=normal_json)
    baseline = httpx.Response(200, json=normal_json)

    for attack_type, signals, pval in [
        ("BOLA", ["admin", "user", "id"], "1"),
        ("INTEGER_OVERFLOW", ["exception", "overflow", "invalid", "negative"], "2147483647"),
        ("SSTI", ["49"], "{{7*7}}"),
        ("MASS_ASSIGNMENT", ["admin", "role", "success", "true"], "admin"),
    ]:
        payload = _make_payload(attack_type=attack_type, expected_signal=signals, payload_value=pval)
        detection, _ = rest.detect_response(resp, payload, rules=None, baseline_resp=baseline)
        decision = rest.decide_validation(detection, payload)

        assert isinstance(detection, DetectionResult)
        assert isinstance(decision, ValidationDecision)
        assert detection.new_expected_signals == []
        assert decision.is_candidate is False
        assert decision.is_confirmed is False
        # BOLA/IDOR 200 goes to inconclusive (deferred to BolaValidator), others to rejected
        if attack_type == "BOLA":
            assert decision.outcome == "inconclusive"
        else:
            assert decision.outcome == "rejected"
        assert decision.severity == "info"


def test_http_400_422_validation_barriers_are_rejected_unless_meaningful_technical_fault():
    # Generic 400 validation barrier containing "invalid" must NOT become candidate
    barrier_resp = httpx.Response(
        400,
        json={"message": "Invalid 'skip' - should be a positive number"},
    )
    overflow_payload = _make_payload(
        attack_type="INTEGER_OVERFLOW",
        expected_signal=["invalid", "negative"],
        payload_value="-1",
    )
    det_barrier, _ = rest.detect_response(barrier_resp, overflow_payload)
    dec_barrier = rest.decide_validation(det_barrier, overflow_payload)

    assert det_barrier.validation_barrier is True
    assert dec_barrier.is_candidate is False
    assert dec_barrier.outcome == "rejected"
    assert dec_barrier.severity == "info"

    # Pydantic 422 barrier must also reject generic noise
    pydantic_422 = httpx.Response(
        422,
        json={"detail": [{"loc": ["query", "limit"], "msg": "Input should be a valid integer", "type": "int_parsing"}]},
    )
    det_422, _ = rest.detect_response(pydantic_422, overflow_payload)
    dec_422 = rest.decide_validation(det_422, overflow_payload)
    assert det_422.validation_barrier is True
    assert dec_422.is_candidate is False
    assert dec_422.outcome == "rejected"

    # Non-absolutist rule: genuine SQL syntax error inside 400 response for SQLi still surfaces as candidate
    sqli_400 = httpx.Response(
        400,
        json={"error": "You have an error in your SQL syntax near ''1'"},
    )
    sqli_payload = _make_payload(attack_type="SQL_INJECTION", payload_value="1'")
    det_sqli, _ = rest.detect_response(sqli_400, sqli_payload)
    dec_sqli = rest.decide_validation(det_sqli, sqli_payload)
    assert det_sqli.validation_barrier is True
    assert dec_sqli.is_candidate is True
    assert dec_sqli.is_confirmed is False
    assert dec_sqli.outcome == "candidate"


def test_generic_response_differences_alone_never_establish_vulnerability():
    baseline = httpx.Response(200, json={"page": 1, "items": ["a", "b"]})
    attack = httpx.Response(404, json={"error": "resource not found for id 999999"})
    payload = _make_payload(attack_type="BOUNDARY_ANALYSIS", expected_signal=[], payload_value="999999")

    detection, _ = rest.detect_response(
        attack,
        payload,
        baseline_resp=baseline,
        response_differences={"status_code": {"baseline": 200, "attack": 404}, "body_hash": {"baseline": "a", "attack": "b"}},
    )
    decision = rest.decide_validation(detection, payload)

    assert detection.has_baseline is True
    assert "status_changed" in detection.anomalies
    assert decision.is_candidate is False
    assert decision.is_confirmed is False
    assert decision.outcome == "rejected"
    assert decision.severity == "info"


def test_confirmation_engine_passes_baseline_and_attack_and_distinguishes_preexisting_content():
    canary = "unique-canary-token-98765"
    payload = _make_payload(attack_type="XSS", expected_signal=[canary], payload_value=canary)

    async def _run(baseline_body: dict, attack_body: dict):
        async def exec_base():
            return httpx.Response(200, json=baseline_body)

        async def exec_att():
            return httpx.Response(200, json=attack_body)

        def detector(attack_resp, baseline_resp=None):
            det, _ = rest.detect_response(attack_resp, payload, baseline_resp=baseline_resp)
            dec = rest.decide_validation(det, payload)
            return det, dec

        return await ConfirmationEngine().confirm(detector, exec_base, exec_att, snapshot_response)

    # Case 1: Canary was ALREADY present in baseline -> preexisting -> rejected
    res_pre = asyncio.run(_run({"existing": canary}, {"existing": canary, "extra": 1}))
    assert res_pre.detection is not None
    assert res_pre.decision is not None
    assert res_pre.detection.has_baseline is True
    assert res_pre.detection.preexisting_expected_signals == [canary]
    assert res_pre.detection.new_expected_signals == []
    assert res_pre.candidate is False
    assert res_pre.confirmed is False
    assert res_pre.decision.outcome == "rejected"

    # Case 2: Canary is genuinely NEW compared to baseline -> candidate (low severity, not auto-medium)
    res_new = asyncio.run(_run({"existing": "clean"}, {"reflected": canary}))
    assert res_new.detection is not None
    assert res_new.decision is not None
    assert res_new.detection.new_expected_signals == [canary]
    assert res_new.candidate is True
    assert res_new.confirmed is False
    assert res_new.decision.outcome == "candidate"
    assert res_new.decision.severity == "low"
    assert res_new.decision.confidence == 0.55


def test_missing_baseline_is_explicitly_recorded_as_evidence_limitation():
    canary = "unique-canary-token-54321"
    payload = _make_payload(attack_type="XSS", expected_signal=[canary], payload_value=canary)
    attack = httpx.Response(200, json={"reflected": canary})

    detection, _ = rest.detect_response(attack, payload, baseline_resp=None)
    decision = rest.decide_validation(detection, payload)

    assert detection.has_baseline is False
    assert detection.baseline_limitation is not None
    assert "Baseline response unavailable" in detection.baseline_limitation
    assert "Baseline response unavailable" in decision.reason
    assert decision.confidence <= 0.35
    assert decision.is_confirmed is False


def test_observation_aggregation_preserved_under_validation_policy(tmp_path: Path):
    fp = "fp-p1-1-p0-compat"
    group = [
        rest.PreparedCase(
            fp,
            "test_api",
            "http://api.test",
            _DummyCase("/items", {"q": "normal"}),
            _DummyCase("/items", {"q": "1"}),
            _make_payload(attack_type="BOLA", expected_signal=["id", "user", "admin"], payload_value="1"),
        ),
        rest.PreparedCase(
            fp,
            "test_api",
            "http://api.test",
            _DummyCase("/items", {"q": "normal"}),
            _DummyCase("/items", {"q": "timeout"}),
            _make_payload(attack_type="BOLA", expected_signal=[], payload_value="timeout"),
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("q") == "timeout":
            raise httpx.ReadTimeout("timeout", request=request)
        return httpx.Response(200, json={"id": 1, "user": "alice", "admin": False})

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, fp, group, {}, None, state, 0.0
            ), state

    findings, state = asyncio.run(_run())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.observation_count == 2
    assert finding.error_count == 1
    # Generic "id/user/admin" probe was rejected, second probe errored -> overall lifecycle is rejected (error != rejected)
    assert [o.outcome for o in finding.observations] == ["rejected", "error"]
    assert finding.lifecycle == "rejected"
    assert finding.confirmed is False
    assert finding.severity == "info"
    assert state.status(fp) == "rejected"


def test_real_rules_json_does_not_suppress_ssrf_expected_signals(tmp_path: Path):
    rules_path = Path(__file__).resolve().parents[1] / "config" / "rules.json"
    rules = rules_engine.load_rules(str(rules_path))

    fp = "fp-ssrf-rules"
    payload = _make_payload(
        attack_type="SSRF",
        expected_signal=["localhost", "127.0.0.1", "connection refused"],
        payload_value="http://127.0.0.1:80/canary",
        endpoint="/fetch",
    )
    pc = rest.PreparedCase(
        fp,
        "test_api",
        "http://api.test",
        _DummyCase("/fetch", {"q": "https://example.com"}),
        _DummyCase("/fetch", {"q": "http://127.0.0.1:80/canary"}),
        payload,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if "127.0.0.1" in q:
            return httpx.Response(200, json={"fetch_error": "dial tcp 127.0.0.1:80: connection refused"})
        return httpx.Response(200, json={"status": "fetched ok"})

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, fp, [pc], {}, rules, state, 0.0
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "candidate"
    assert findings[0].confirmed is False
    assert findings[0].severity == "low"
    assert "connection refused" in findings[0].evidence.response_signal[0]


def test_baseline_5xx_and_slow_baseline_produce_inconclusive_not_candidate():
    # 1. Baseline 500 vs Attack 500 without new signals -> inconclusive
    base_500 = httpx.Response(500, text="upstream error")
    att_500 = httpx.Response(500, text="upstream error")
    p_500 = _make_payload(attack_type="SQL_INJECTION", payload_value="'")
    det_500, _ = rest.detect_response(att_500, p_500, baseline_resp=base_500)
    dec_500 = rest.decide_validation(det_500, p_500)
    assert dec_500.outcome == "inconclusive"
    assert dec_500.is_candidate is False
    assert dec_500.severity == "info"

    # 2. Slow baseline (3600ms) vs Attack (3800ms) -> delta 200ms < 3500ms -> inconclusive
    base_slow = httpx.Response(200, text="ok")
    base_slow.elapsed_ms = 3600.0  # type: ignore[attr-defined]
    att_slow = httpx.Response(200, text="ok")
    att_slow.elapsed_ms = 3800.0  # type: ignore[attr-defined]
    p_time = _make_payload(attack_type="TIME_BASED_SQLI", payload_value="1' AND SLEEP(4)--")

    det_slow, _ = rest.detect_response(att_slow, p_time, baseline_resp=base_slow)
    dec_slow = rest.decide_validation(det_slow, p_time)
    assert dec_slow.outcome == "inconclusive"
    assert dec_slow.is_candidate is False

    # 3. Fast baseline (50ms) vs Attack (4100ms) -> delta 4050ms >= 3500ms -> candidate
    base_fast = httpx.Response(200, text="ok")
    base_fast.elapsed_ms = 50.0  # type: ignore[attr-defined]
    att_fast = httpx.Response(200, text="ok")
    att_fast.elapsed_ms = 4100.0  # type: ignore[attr-defined]
    det_fast, _ = rest.detect_response(att_fast, p_time, baseline_resp=base_fast)
    dec_fast = rest.decide_validation(det_fast, p_time)
    assert dec_fast.outcome == "candidate"
    assert dec_fast.is_candidate is True


def test_non_sqli_meaningful_signal_inside_400_422_surfaces_as_candidate():
    # Path traversal / traceback inside a 400 error should not be silently dropped
    canary = "root:x:0:0:root:/root"
    p_lfi = _make_payload(attack_type="PATH_TRAVERSAL", expected_signal=[canary], payload_value="../../etc/passwd")
    resp_400 = httpx.Response(400, json={"error": f"Invalid path contents: {canary}"})
    det_lfi, _ = rest.detect_response(resp_400, p_lfi, baseline_resp=httpx.Response(200, json={"ok": True}))
    dec_lfi = rest.decide_validation(det_lfi, p_lfi)
    assert det_lfi.validation_barrier is True
    assert dec_lfi.outcome == "candidate"
    assert dec_lfi.is_candidate is True
    assert dec_lfi.severity == "low"

    # Non-SQLi unhandled Python traceback leaked in 422 response
    p_ssti = _make_payload(attack_type="SSTI", payload_value="{{bad}}")
    resp_422 = httpx.Response(422, json={"error": "Traceback (most recent call last): TemplateSyntaxError"})
    det_tb, _ = rest.detect_response(resp_422, p_ssti, baseline_resp=httpx.Response(200, json={"ok": True}))
    dec_tb = rest.decide_validation(det_tb, p_ssti)
    assert dec_tb.outcome == "candidate"
    assert dec_tb.is_candidate is True


def test_e2e_process_fingerprint_group_mixed_candidate_rejected_error_and_bola_inconclusive(tmp_path: Path):
    # 1. Mixed candidate + rejected + error -> candidate
    fp = "fp-e2e-mixed"
    canary = "xss-canary-xyz-991"
    group = [
        rest.PreparedCase(
            fp, "test_api", "http://api.test",
            _DummyCase("/search", {"q": "normal"}),
            _DummyCase("/search", {"q": canary}),
            _make_payload(attack_type="XSS", expected_signal=[canary], payload_value=canary, endpoint="/search"),
        ),
        rest.PreparedCase(
            fp, "test_api", "http://api.test",
            _DummyCase("/search", {"q": "normal"}),
            _DummyCase("/search", {"q": "clean"}),
            _make_payload(attack_type="XSS", expected_signal=[canary], payload_value="clean", endpoint="/search"),
        ),
        rest.PreparedCase(
            fp, "test_api", "http://api.test",
            _DummyCase("/search", {"q": "normal"}),
            _DummyCase("/search", {"q": "boom"}),
            _make_payload(attack_type="XSS", expected_signal=[canary], payload_value="boom", endpoint="/search"),
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if q == "boom":
            raise httpx.ReadTimeout("timeout", request=request)
        if q == canary:
            return httpx.Response(200, json={"echo": canary})
        return httpx.Response(200, json={"echo": "normal"})

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, fp, group, {}, None, state, 0.0
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "candidate"
    assert findings[0].observation_count == 3
    assert findings[0].error_count == 1
    assert [o.outcome for o in findings[0].observations] == ["candidate", "rejected", "error"]

    # 2. Dual-user BOLA when unauth control returns 500 -> inconclusive (not rejected/medium)
    fp_bola = "fp-bola-inconclusive"
    bola_pc = rest.PreparedCase(
        fp_bola, "test_api", "http://api.test",
        _DummyCase("/orders/1"),
        _DummyCase("/orders/1"),
        _make_payload(attack_type="BOLA", expected_signal=[], payload_value="1", endpoint="/orders/1"),
    )

    def bola_handler(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("Authorization"):
            return httpx.Response(500, json={"error": "auth service unavailable"})
        return httpx.Response(200, json={"order": 1})

    async def _run_bola():
        state = RunState(tmp_path / "state_bola.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(bola_handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, fp_bola, [bola_pc],
                {"Authorization": "Bearer u1"}, None, state, 0.0,
                user2_headers={"Authorization": "Bearer u2"},
            )

    bola_findings = asyncio.run(_run_bola())
    assert len(bola_findings) == 1
    assert bola_findings[0].lifecycle == "inconclusive"
    assert bola_findings[0].confirmed is False
    assert bola_findings[0].severity == "info"

