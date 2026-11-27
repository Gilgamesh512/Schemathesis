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


def test_reflected_sqli_email_and_nosqli_operator_do_not_trigger_candidates_while_real_db_errors_do():
    from core.semantic_mutator import SemanticMutationEngine

    email_schema = SemanticMutationEngine.inspect_param("email", "query", {"type": "string", "format": "email"})
    sqli_email_probe = next(
        p for p in SemanticMutationEngine.generate_probes(email_schema)
        if p.attack_type == "SQL_INJECTION"
    )
    str_schema = SemanticMutationEngine.inspect_param("q", "query", {"type": "string"})
    nosql_probe = next(
        p for p in SemanticMutationEngine.generate_probes(str_schema)
        if p.attack_type == "NOSQL_INJECTION"
    )

    sqli_payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=sqli_email_probe.expected_signal,
        payload_value=sqli_email_probe.payload_value,
        endpoint="/invite",
    )
    nosql_payload = _make_payload(
        attack_type="NOSQL_INJECTION",
        expected_signal=nosql_probe.expected_signal,
        payload_value=nosql_probe.payload_value,
        endpoint="/search",
    )

    # 1. Ordinary HTTP 200 JSON reflection must remain rejected
    base_email = httpx.Response(200, json={"invited": "user@example.com"})
    echo_email = httpx.Response(200, json={"invited": str(sqli_email_probe.payload_value)})
    det_sqli_echo, _ = rest.detect_response(echo_email, sqli_payload, baseline_resp=base_email)
    dec_sqli_echo = rest.decide_validation(det_sqli_echo, sqli_payload)
    assert dec_sqli_echo.outcome == "rejected"
    assert dec_sqli_echo.is_candidate is False

    base_q = httpx.Response(200, json={"rendered": "hello"})
    echo_nosql = httpx.Response(200, json={"rendered": str(nosql_probe.payload_value)})
    det_nosql_echo, _ = rest.detect_response(echo_nosql, nosql_payload, baseline_resp=base_q)
    dec_nosql_echo = rest.decide_validation(det_nosql_echo, nosql_payload)
    assert dec_nosql_echo.outcome == "rejected"
    assert dec_nosql_echo.is_candidate is False

    # 2. Realistic DB / parser error responses still raise candidates
    real_sqli_err = httpx.Response(200, json={"error": "sqlite3.OperationalError: near \"'\": syntax error"})
    det_sqli_real, _ = rest.detect_response(real_sqli_err, sqli_payload, baseline_resp=base_email)
    dec_sqli_real = rest.decide_validation(det_sqli_real, sqli_payload)
    assert dec_sqli_real.outcome == "candidate"
    assert dec_sqli_real.is_candidate is True

    real_nosql_err = httpx.Response(200, json={"error": "MongoServerError: unknown top level operator: $ne"})
    det_nosql_real, _ = rest.detect_response(real_nosql_err, nosql_payload, baseline_resp=base_q)
    dec_nosql_real = rest.decide_validation(det_nosql_real, nosql_payload)
    assert dec_nosql_real.outcome == "candidate"
    assert dec_nosql_real.is_candidate is True


def test_p164_ssrf_reflection_verbatim_and_urlencoded_rejected_on_200_and_422():
    from core.semantic_mutator import SemanticMutationEngine

    uri_schema = SemanticMutationEngine.inspect_param("webhook_url", "query", {"type": "string", "format": "uri"})
    ssrf_probe = next(
        p for p in SemanticMutationEngine.generate_probes(uri_schema)
        if p.attack_type == "SSRF" and "127.0.0.1" in str(p.payload_value)
    )
    payload = _make_payload(
        attack_type="SSRF",
        expected_signal=ssrf_probe.expected_signal,
        payload_value=ssrf_probe.payload_value,
        endpoint="/webhooks",
    )
    baseline = httpx.Response(200, json={"webhook_url": "https://example.com/hook"})

    # Verbatim JSON echo in HTTP 200
    resp_200 = httpx.Response(200, json={"webhook_url": str(ssrf_probe.payload_value)})
    det_200, _ = rest.detect_response(resp_200, payload, baseline_resp=baseline)
    dec_200 = rest.decide_validation(det_200, payload)
    assert det_200.payload_reflected is True
    assert "127.0.0.1" in det_200.reflection_only_signals
    assert det_200.new_expected_signals == []
    assert dec_200.outcome == "rejected"
    assert dec_200.is_candidate is False
    assert dec_200.severity == "info"

    # URL-encoded echo in HTTP 422 validation barrier and HTTP 200
    from urllib.parse import quote
    encoded = quote(str(ssrf_probe.payload_value), safe="")
    for status_code, body in (
        (200, {"error": f"Unsupported URL: {encoded}"}),
        (422, {"detail": [{"loc": ["query", "webhook_url"], "msg": f"Invalid URL: {encoded}", "type": "value_error"}]}),
    ):
        resp_enc = httpx.Response(status_code, json=body)
        det_enc, _ = rest.detect_response(resp_enc, payload, baseline_resp=baseline)
        dec_enc = rest.decide_validation(det_enc, payload)
        assert det_enc.payload_reflected is True
        assert "127.0.0.1" in det_enc.reflection_only_signals
        assert det_enc.new_expected_signals == []
        assert dec_enc.outcome == "rejected"
        assert dec_enc.is_candidate is False


def test_p164_bfla_superuser_reflection_rejected():
    from core.semantic_mutator import SemanticMutationEngine

    role_schema = SemanticMutationEngine.inspect_param(
        "role", "query", {"type": "string", "enum": ["user", "superuser"]}
    )
    bfla_probe = next(
        p for p in SemanticMutationEngine.generate_probes(role_schema)
        if p.attack_type == "BFLA" and str(p.payload_value).lower() == "superuser"
    )
    payload = _make_payload(
        attack_type="BFLA",
        expected_signal=bfla_probe.expected_signal,
        payload_value=bfla_probe.payload_value,
        endpoint="/profile",
    )
    baseline = httpx.Response(200, json={"role": "user"})
    echo_200 = httpx.Response(200, json={"echo": "superuser", "status": "ignored"})
    det, _ = rest.detect_response(echo_200, payload, baseline_resp=baseline)
    dec = rest.decide_validation(det, payload)
    assert det.payload_reflected is True
    assert det.reflection_only_signals == ["superuser"]
    assert det.new_expected_signals == []
    assert dec.outcome == "rejected"
    assert dec.is_candidate is False


def test_p164_technical_signal_reflection_raw_and_json_escaped_rejected():
    baseline = httpx.Response(200, json={"query": "hello"})

    # Custom payload containing technical tokens echoed raw or JSON-escaped (with quotes/backslashes)
    raw_payload_val = '1" OR "sqlite"="1'
    payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=[],
        payload_value=raw_payload_val,
        endpoint="/search",
    )
    json_escaped_resp = httpx.Response(200, json={"echo": raw_payload_val})
    for base in (baseline, None):
        det, _ = rest.detect_response(json_escaped_resp, payload, baseline_resp=base)
        dec = rest.decide_validation(det, payload)
        assert det.payload_reflected is True
        assert "sqlite" in det.reflection_only_signals
        assert det.technical_signals == []
        assert det.new_technical_signals == []
        assert dec.outcome == "rejected"
        assert dec.is_candidate is False

    # HTML-escaped technical payload reflection must also stay rejected
    html_payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=[],
        payload_value="1' OR 'sqlite'='1",
        endpoint="/search",
    )
    resp_html_esc = httpx.Response(200, text="<div>Invalid: 1&#x27; OR &#x27;sqlite&#x27;=&#x27;1</div>")
    det_html_esc, _ = rest.detect_response(resp_html_esc, html_payload, baseline_resp=baseline)
    dec_html_esc = rest.decide_validation(det_html_esc, html_payload)
    assert det_html_esc.payload_reflected is True
    assert det_html_esc.new_technical_signals == []
    assert dec_html_esc.outcome == "rejected"

    # Validation barrier echoing a payload with traceback keyword must still stay rejected
    tb_payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=[],
        payload_value="user_traceback_probe",
        endpoint="/search",
    )
    resp_400 = httpx.Response(400, json={"error": "Rejected token: user_traceback_probe"})
    det_400, _ = rest.detect_response(resp_400, tb_payload, baseline_resp=baseline)
    dec_400 = rest.decide_validation(det_400, tb_payload)
    assert det_400.validation_barrier is True
    assert det_400.payload_reflected is True
    assert "traceback" in det_400.reflection_only_signals
    assert det_400.new_technical_signals == []
    assert dec_400.outcome == "rejected"


def test_p164_mixed_reflection_and_independent_evidence_preserves_candidate():
    # 1. SSRF: echoes URL containing 127.0.0.1 AND independently reports dial error with 127.0.0.1 + connection refused
    ssrf_val = "http://127.0.0.1:80/canary_ssrf_probe"
    ssrf_payload = _make_payload(
        attack_type="SSRF",
        expected_signal=["localhost", "127.0.0.1", "connection refused"],
        payload_value=ssrf_val,
        endpoint="/fetch",
    )
    baseline = httpx.Response(200, json={"url": "https://example.com", "status": "ok"})
    mixed_ssrf = httpx.Response(
        200,
        json={"url": ssrf_val, "error": "dial tcp 127.0.0.1:80: connection refused"},
    )
    det_ssrf, _ = rest.detect_response(mixed_ssrf, ssrf_payload, baseline_resp=baseline)
    dec_ssrf = rest.decide_validation(det_ssrf, ssrf_payload)
    assert det_ssrf.payload_reflected is True
    assert "127.0.0.1" in det_ssrf.new_expected_signals
    assert "connection refused" in det_ssrf.new_expected_signals
    assert dec_ssrf.outcome == "candidate"
    assert dec_ssrf.is_candidate is True

    # 2. SQLi: echoes payload containing "sqlite" AND independently leaks "sqlite" / "sql syntax" error
    sqli_val = "1' OR 'sqlite'='1"
    sqli_payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=[],
        payload_value=sqli_val,
        endpoint="/items",
    )
    mixed_sqli = httpx.Response(
        200,
        json={"input": sqli_val, "error": "sqlite3.OperationalError: near \"'\": sql syntax error"},
    )
    det_sqli, _ = rest.detect_response(mixed_sqli, sqli_payload, baseline_resp=baseline)
    dec_sqli = rest.decide_validation(det_sqli, sqli_payload)
    assert det_sqli.payload_reflected is True
    assert "sqlite" in det_sqli.new_technical_signals
    assert dec_sqli.outcome == "candidate"
    assert dec_sqli.severity == "medium"

    # 3. Baseline pre-existing signal stays preexisting even when also reflected
    base_with_sig = httpx.Response(200, json={"host": "127.0.0.1"})
    echo_with_sig = httpx.Response(200, json={"host": "127.0.0.1", "url": ssrf_val})
    det_pre, _ = rest.detect_response(
        echo_with_sig,
        _make_payload(attack_type="SSRF", expected_signal=["127.0.0.1"], payload_value=ssrf_val),
        baseline_resp=base_with_sig,
    )
    dec_pre = rest.decide_validation(
        det_pre,
        _make_payload(attack_type="SSRF", expected_signal=["127.0.0.1"], payload_value=ssrf_val),
    )
    assert "127.0.0.1" in det_pre.preexisting_expected_signals
    assert det_pre.new_expected_signals == []
    assert dec_pre.outcome == "rejected"


def test_p164_gap_concatenation_and_primitive_payload_safety():
    # Gap concatenation: removing "_gap_" must NOT happen and must NOT synthesize "sqlite"
    gap_payload = _make_payload(
        attack_type="SQL_INJECTION",
        expected_signal=[],
        payload_value="_gap_",
        endpoint="/search",
    )
    gap_resp = httpx.Response(200, json={"msg": "sq_gap_lite"})
    det_gap, _ = rest.detect_response(gap_resp, gap_payload, baseline_resp=httpx.Response(200, json={"msg": "ok"}))
    dec_gap = rest.decide_validation(det_gap, gap_payload)
    assert det_gap.payload_reflected is True
    assert det_gap.technical_signals == []
    assert det_gap.new_technical_signals == []
    assert dec_gap.outcome == "rejected"

    # Primitive / short payloads must never create reflection spans or mask real signals
    for prim in (1, 0, True, False, None, "", "   ", "ab", "true", "false"):
        prim_payload = _make_payload(
            attack_type="SQL_INJECTION",
            expected_signal=[],
            payload_value=prim,
            endpoint="/items",
        )
        resp_real_err = httpx.Response(200, json={"id": prim, "error": "sqlite3 error near 1"})
        det_prim, _ = rest.detect_response(
            resp_real_err,
            prim_payload,
            baseline_resp=httpx.Response(200, json={"ok": True}),
        )
        dec_prim = rest.decide_validation(det_prim, prim_payload)
        assert det_prim.payload_reflected is False
        assert "sqlite" in det_prim.new_technical_signals
        assert dec_prim.outcome == "candidate"


def test_p164_xss_and_ssti_behaviors_preserved():
    # XSS reflection remains candidate in P1.6.4 (Content-Type validation belongs to P1.6.5)
    xss_val = "<script>alert(1)</script>"
    xss_payload = _make_payload(
        attack_type="XSS",
        expected_signal=[xss_val],
        payload_value=xss_val,
        endpoint="/echo",
    )
    xss_resp = httpx.Response(200, json={"rendered": f"Echo: {xss_val}"})
    det_xss, _ = rest.detect_response(xss_resp, xss_payload, baseline_resp=httpx.Response(200, json={"rendered": "Echo: hi"}))
    dec_xss = rest.decide_validation(det_xss, xss_payload)
    assert det_xss.payload_reflected is True
    assert det_xss.new_expected_signals == [xss_val]
    assert dec_xss.outcome == "candidate"

    # SSTI evaluated output is not masked, and unevaluated reflection remains rejected
    ssti_payload = _make_payload(
        attack_type="SSTI",
        expected_signal=["77455597"],
        payload_value="{{9187*8431}}",
        endpoint="/render",
    )
    ssti_eval = httpx.Response(200, json={"rendered": "77455597"})
    det_ssti, _ = rest.detect_response(ssti_eval, ssti_payload, baseline_resp=httpx.Response(200, json={"rendered": "hello"}))
    assert det_ssti.new_expected_signals == ["77455597"]

    from core.ssti_validator import SstiValidator
    ssti_echo_verdict = SstiValidator.validate(
        attack_status=200,
        attack_body='{"rendered": "Echo: {{9187*8431}}"}',
        baseline_body='{"rendered": "Echo: hello"}',
        initial_payload="{{9187*8431}}",
        initial_expected="77455597",
    )
    assert ssti_echo_verdict is not None
    assert ssti_echo_verdict.outcome == "rejected"
