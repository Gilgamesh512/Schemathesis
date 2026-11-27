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
    # Under P1.6.5, XSS candidates require an executable HTML context rather than JSON reflection.
    canary = "<script>xss_canary_98765</script>"
    payload = _make_payload(attack_type="XSS", expected_signal=[canary], payload_value=canary)

    async def _run(baseline_html: str, attack_html: str):
        async def exec_base():
            return httpx.Response(200, text=baseline_html, headers={"Content-Type": "text/html; charset=utf-8"})

        async def exec_att():
            return httpx.Response(200, text=attack_html, headers={"Content-Type": "text/html; charset=utf-8"})

        def detector(attack_resp, baseline_resp=None):
            det, _ = rest.detect_response(attack_resp, payload, baseline_resp=baseline_resp)
            dec = rest.decide_validation(det, payload)
            return det, dec

        return await ConfirmationEngine().confirm(detector, exec_base, exec_att, snapshot_response)

    # Case 1: Canary was ALREADY present in baseline -> preexisting -> rejected
    res_pre = asyncio.run(_run(f"<html><body>{canary}</body></html>", f"<html><body>{canary}<p>1</p></body></html>"))
    assert res_pre.detection is not None
    assert res_pre.decision is not None
    assert res_pre.detection.has_baseline is True
    assert res_pre.detection.preexisting_expected_signals == [canary]
    assert res_pre.detection.new_expected_signals == []
    assert res_pre.candidate is False
    assert res_pre.confirmed is False
    assert res_pre.decision.outcome == "rejected"

    # Case 2: Canary is genuinely NEW in HTML body compared to baseline -> candidate (low severity, not auto-medium)
    res_new = asyncio.run(_run("<html><body>clean</body></html>", f"<html><body>{canary}</body></html>"))
    assert res_new.detection is not None
    assert res_new.decision is not None
    assert res_new.detection.new_expected_signals == [canary]
    assert res_new.candidate is True
    assert res_new.confirmed is False
    assert res_new.decision.outcome == "candidate"
    assert res_new.decision.severity == "low"
    assert res_new.decision.confidence == 0.55


def test_missing_baseline_is_explicitly_recorded_as_evidence_limitation():
    canary = "<script>xss_canary_54321</script>"
    payload = _make_payload(attack_type="XSS", expected_signal=[canary], payload_value=canary)
    attack = httpx.Response(
        200,
        text=f"<html><body>{canary}</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )

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
    # 1. Mixed candidate + rejected + error -> candidate (HTML response for valid XSS context)
    fp = "fp-e2e-mixed"
    canary = "<script>xss_canary_991</script>"
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
            return httpx.Response(
                200,
                text=f"<html><body>{canary}</body></html>",
                headers={"Content-Type": "text/html; charset=utf-8"},
            )
        return httpx.Response(
            200,
            text="<html><body>normal</body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

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
    # Under P1.6.5, XSS reflection in application/json is rejected while unencoded HTML reflection is candidate
    xss_val = "<script>alert(1)</script>"
    xss_payload = _make_payload(
        attack_type="XSS",
        expected_signal=[xss_val],
        payload_value=xss_val,
        endpoint="/echo",
    )
    xss_json_resp = httpx.Response(200, json={"rendered": f"Echo: {xss_val}"})
    det_xss_json, _ = rest.detect_response(
        xss_json_resp, xss_payload, baseline_resp=httpx.Response(200, json={"rendered": "Echo: hi"})
    )
    dec_xss_json = rest.decide_validation(det_xss_json, xss_payload)
    assert det_xss_json.payload_reflected is True
    assert det_xss_json.metadata.get("xss_context") == "json_reflection"
    assert det_xss_json.new_expected_signals == []
    assert dec_xss_json.outcome == "rejected"

    xss_html_resp = httpx.Response(
        200,
        text=f"<html><body>Echo: {xss_val}</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    det_xss_html, _ = rest.detect_response(
        xss_html_resp,
        xss_payload,
        baseline_resp=httpx.Response(200, text="<html><body>Echo: hi</body></html>", headers={"Content-Type": "text/html"}),
    )
    dec_xss_html = rest.decide_validation(det_xss_html, xss_payload)
    assert det_xss_html.metadata.get("xss_context") == "html_text"
    assert det_xss_html.new_expected_signals == [xss_val]
    assert dec_xss_html.outcome == "candidate"
    assert dec_xss_html.is_confirmed is False

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


def test_p165_xss_json_reflection_raw_escaped_and_mime_params_rejected(tmp_path: Path):
    xss_val = "<script>alert(1)</script>"
    email_xss_val = "probe+<script>alert(1)</script>@example.com"
    base_json = httpx.Response(200, json={"rendered": "hello"})

    for payload_val, ct, body_text, status_code in (
        (xss_val, "application/json", json.dumps({"rendered": f"Echo: {xss_val}"}), 200),
        (xss_val, "application/json; charset=utf-8", json.dumps({"rendered": xss_val}), 200),
        (email_xss_val, "application/problem+json; charset=utf-8", json.dumps({"invited": email_xss_val}), 200),
        (xss_val, "application/json", json.dumps({"escaped": xss_val.replace("<", r"\u003c").replace(">", r"\u003e")}), 200),
        (xss_val, "application/json", json.dumps({"detail": [{"loc": ["query", "q"], "msg": f"Invalid: {xss_val}", "type": "value_error"}]}), 422),
    ):
        payload = _make_payload(attack_type="XSS", expected_signal=[xss_val], payload_value=payload_val, endpoint="/echo")
        resp = httpx.Response(status_code, text=body_text, headers={"Content-Type": ct})
        det, _ = rest.detect_response(resp, payload, baseline_resp=base_json)
        dec = rest.decide_validation(det, payload)
        assert det.new_expected_signals == []
        assert dec.outcome == "rejected"
        assert dec.is_candidate is False
        assert dec.is_confirmed is False
        assert dec.severity == "info"

    # Full E2E pipeline check: process_fingerprint_group + RunState must NOT promote JSON XSS reflection
    fp = "fp-p165-json-xss"
    pc = rest.PreparedCase(
        fp,
        "test_api",
        "http://api.test",
        _DummyCase("/echo", {"tpl": "hello"}),
        _DummyCase("/echo", {"tpl": xss_val}),
        _make_payload(attack_type="XSS", expected_signal=[xss_val], payload_value=xss_val, endpoint="/echo"),
    )

    def json_handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("tpl", "")
        return httpx.Response(200, json={"rendered": f"Echo: {q}"})

    async def _run():
        state = RunState(tmp_path / "state_p165.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(json_handler)) as client:
            return await rest.process_fingerprint_group(client, scheduler, fp, [pc], {}, None, state, 0.0)

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "rejected"
    assert findings[0].confirmed is False
    assert findings[0].severity == "info"
    assert findings[0].confidence <= 0.15


def test_p165_xss_html_contexts_escaped_mixed_and_ambiguous():
    base_html = httpx.Response(200, text="<html><body>hello</body></html>", headers={"Content-Type": "text/html"})

    # Scenario B: HTML text context (unencoded markup -> candidate/low, never confirmed; plain text -> rejected)
    xss_val = "<script>alert(1)</script>"
    p_html = _make_payload(attack_type="XSS", expected_signal=[xss_val], payload_value=xss_val, endpoint="/page")
    resp_html_text = httpx.Response(
        200,
        text=f"<html><body><div>Hello {xss_val}</div></body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    det_text, _ = rest.detect_response(resp_html_text, p_html, baseline_resp=base_html)
    dec_text = rest.decide_validation(det_text, p_html)
    assert det_text.metadata.get("xss_context") == "html_text"
    assert dec_text.outcome == "candidate"
    assert dec_text.severity == "low"
    assert dec_text.is_confirmed is False

    p_plain = _make_payload(attack_type="XSS", expected_signal=["plain_token_xyz"], payload_value="plain_token_xyz")
    resp_plain = httpx.Response(
        200,
        text="<html><body><div>Hello plain_token_xyz</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_plain, _ = rest.detect_response(resp_plain, p_plain, baseline_resp=base_html)
    dec_plain = rest.decide_validation(det_plain, p_plain)
    assert det_plain.metadata.get("xss_context") == "html_text_plain"
    assert dec_plain.outcome == "rejected"

    # Scenario C: HTML-escaped reflection -> rejected; mixed escaped + raw -> candidate
    resp_escaped = httpx.Response(
        200,
        text="<html><body><div>Hello &lt;script&gt;alert(1)&lt;/script&gt;</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_esc, _ = rest.detect_response(resp_escaped, p_html, baseline_resp=base_html)
    dec_esc = rest.decide_validation(det_esc, p_html)
    assert det_esc.metadata.get("xss_context") == "html_escaped"
    assert det_esc.new_expected_signals == []
    assert dec_esc.outcome == "rejected"

    p_inner_sig = _make_payload(attack_type="XSS", expected_signal=["alert(1)"], payload_value=xss_val)
    det_esc_inner, _ = rest.detect_response(resp_escaped, p_inner_sig, baseline_resp=base_html)
    dec_esc_inner = rest.decide_validation(det_esc_inner, p_inner_sig)
    assert det_esc_inner.metadata.get("xss_context") == "html_escaped"
    assert dec_esc_inner.outcome == "rejected"

    resp_mixed = httpx.Response(
        200,
        text=f"<html><body><span>&lt;script&gt;alert(1)&lt;/script&gt;</span><div>{xss_val}</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_mix, _ = rest.detect_response(resp_mixed, p_html, baseline_resp=base_html)
    dec_mix = rest.decide_validation(det_mix, p_html)
    assert det_mix.metadata.get("xss_context") == "html_text"
    assert dec_mix.outcome == "candidate"
    assert dec_mix.is_confirmed is False

    # Scenario D: HTML attribute breakout, safe quoted attribute, JS context, and ambiguous tag context
    attr_payload_val = '" onmouseover="alert(1)'
    p_attr = _make_payload(attack_type="XSS", expected_signal=[attr_payload_val], payload_value=attr_payload_val)
    resp_attr_exec = httpx.Response(
        200,
        text=f'<html><body><input type="text" value="{attr_payload_val}"></body></html>',
        headers={"Content-Type": "application/xhtml+xml; charset=utf-8"},
    )
    det_attr, _ = rest.detect_response(resp_attr_exec, p_attr, baseline_resp=base_html)
    dec_attr = rest.decide_validation(det_attr, p_attr)
    assert det_attr.metadata.get("xss_context") == "html_attribute"
    assert dec_attr.outcome == "candidate"
    assert dec_attr.is_confirmed is False

    p_attr_safe = _make_payload(attack_type="XSS", expected_signal=["safe_attr_val"], payload_value="safe_attr_val")
    resp_attr_safe = httpx.Response(
        200,
        text='<html><body><input type="text" value="safe_attr_val"></body></html>',
        headers={"Content-Type": "text/html"},
    )
    det_attr_safe, _ = rest.detect_response(resp_attr_safe, p_attr_safe, baseline_resp=base_html)
    dec_attr_safe = rest.decide_validation(det_attr_safe, p_attr_safe)
    assert det_attr_safe.metadata.get("xss_context") == "html_attribute_quoted"
    assert dec_attr_safe.outcome == "inconclusive"
    assert dec_attr_safe.is_candidate is False

    js_payload_val = "a';alert(1);//"
    p_js = _make_payload(attack_type="XSS", expected_signal=[js_payload_val], payload_value=js_payload_val)
    resp_js = httpx.Response(
        200,
        text=f"<html><body><script>var q = '{js_payload_val}';</script></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_js, _ = rest.detect_response(resp_js, p_js, baseline_resp=base_html)
    dec_js = rest.decide_validation(det_js, p_js)
    assert det_js.metadata.get("xss_context") == "html_js_context"
    assert dec_js.outcome == "candidate"
    assert dec_js.is_confirmed is False

    p_ambig = _make_payload(attack_type="XSS", expected_signal=["ambig_tok_99"], payload_value="ambig_tok_99")
    resp_ambig = httpx.Response(
        200,
        text="<html><body><div data-raw ambig_tok_99>ok</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_ambig, _ = rest.detect_response(resp_ambig, p_ambig, baseline_resp=base_html)
    dec_ambig = rest.decide_validation(det_ambig, p_ambig)
    assert det_ambig.metadata.get("xss_context") == "unknown"
    assert dec_ambig.outcome == "inconclusive"
    assert dec_ambig.is_candidate is False


def test_p165_xss_unknown_content_type_mismatch_baseline_and_independent_evidence():
    xss_val = "<script>alert(1)</script>"
    p_xss = _make_payload(attack_type="XSS", expected_signal=[xss_val], payload_value=xss_val)
    base_clean = httpx.Response(200, text="clean", headers={"Content-Type": "text/plain"})

    # Scenario E: missing, malformed, and text/plain Content-Type never become candidate/confirmed
    for hdrs, body, expected_outcome in (
        ({}, f"<!DOCTYPE html><html><body>{xss_val}</body></html>", "inconclusive"),
        ({"Content-Type": "malformed-mime;;;"}, f"<div>{xss_val}</div>", "inconclusive"),
        ({"Content-Type": "text/plain; charset=utf-8"}, xss_val, "rejected"),
    ):
        resp_e = httpx.Response(200, text=body, headers=hdrs)
        det_e, _ = rest.detect_response(resp_e, p_xss, baseline_resp=base_clean)
        dec_e = rest.decide_validation(det_e, p_xss)
        assert dec_e.outcome == expected_outcome
        assert dec_e.is_candidate is False
        assert dec_e.is_confirmed is False

    # Scenario F: Header / body mismatch -> inconclusive, never candidate or confirmed
    mismatch_json_hdr = httpx.Response(
        200,
        text=f"<html><body><p>Echo: {xss_val}</p></body></html>",
        headers={"Content-Type": "application/json"},
    )
    det_m1, _ = rest.detect_response(mismatch_json_hdr, p_xss, baseline_resp=base_clean)
    dec_m1 = rest.decide_validation(det_m1, p_xss)
    assert det_m1.metadata.get("content_type_mismatch") == "json_header_html_body"
    assert dec_m1.outcome == "inconclusive"
    assert dec_m1.is_candidate is False
    assert dec_m1.is_confirmed is False

    mismatch_html_hdr = httpx.Response(
        200,
        text=json.dumps({"echo": xss_val}),
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    det_m2, _ = rest.detect_response(mismatch_html_hdr, p_xss, baseline_resp=base_clean)
    dec_m2 = rest.decide_validation(det_m2, p_xss)
    assert det_m2.metadata.get("content_type_mismatch") == "html_header_json_body"
    assert dec_m2.outcome == "inconclusive"
    assert dec_m2.is_candidate is False
    assert dec_m2.is_confirmed is False

    # Scenario G: Pre-existing baseline reflection in HTML stays rejected
    html_with_xss = httpx.Response(
        200,
        text=f"<html><body>{xss_val}</body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_base, _ = rest.detect_response(html_with_xss, p_xss, baseline_resp=html_with_xss)
    dec_base = rest.decide_validation(det_base, p_xss)
    assert det_base.preexisting_expected_signals == [xss_val]
    assert det_base.new_expected_signals == []
    assert dec_base.outcome == "rejected"

    # Scenario H: JSON XSS reflection + independent backend error or non-reflected signal still detected
    resp_indep_tech = httpx.Response(
        500,
        json={"echo": xss_val, "error": "Traceback (most recent call last): TemplateError"},
    )
    det_ind1, _ = rest.detect_response(resp_indep_tech, p_xss, baseline_resp=httpx.Response(200, json={"ok": True}))
    dec_ind1 = rest.decide_validation(det_ind1, p_xss)
    assert "traceback" in det_ind1.new_technical_signals
    assert dec_ind1.outcome == "candidate"
    assert dec_ind1.severity == "medium"

    p_xss_plus = _make_payload(
        attack_type="XSS",
        expected_signal=[xss_val, "independent-backend-canary-8841"],
        payload_value=xss_val,
    )
    resp_indep_sig = httpx.Response(
        200,
        json={"echo": xss_val, "leak": "independent-backend-canary-8841"},
    )
    det_ind2, _ = rest.detect_response(resp_indep_sig, p_xss_plus, baseline_resp=httpx.Response(200, json={"ok": True}))
    dec_ind2 = rest.decide_validation(det_ind2, p_xss_plus)
    assert det_ind2.new_expected_signals == ["independent-backend-canary-8841"]
    assert xss_val in det_ind2.reflection_only_signals
    assert dec_ind2.outcome == "candidate"


def test_p165_quoted_attribute_with_angle_brackets_does_not_become_candidate():
    base_html = httpx.Response(200, text="<html><body>Hello</body></html>", headers={"Content-Type": "text/html"})

    # 1. Quoted attribute containing <script> without quote breakout -> inconclusive (not candidate/confirmed)
    script_payload = "<script>alert(1)</script>"
    p_script = _make_payload(attack_type="XSS", expected_signal=[script_payload], payload_value=script_payload)
    resp_quoted_script = httpx.Response(
        200,
        text=f'<html><body><div title="{script_payload}">Hello</div></body></html>',
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    det_qs, _ = rest.detect_response(resp_quoted_script, p_script, baseline_resp=base_html)
    dec_qs = rest.decide_validation(det_qs, p_script)
    assert det_qs.metadata.get("xss_context") == "html_attribute_quoted"
    assert det_qs.new_expected_signals == []
    assert dec_qs.outcome == "inconclusive"
    assert dec_qs.is_candidate is False
    assert dec_qs.is_confirmed is False

    # 2. Quoted attribute containing < and > without executable context -> inconclusive
    angle_payload = "1 < 2 > 0"
    p_angle = _make_payload(attack_type="XSS", expected_signal=[angle_payload], payload_value=angle_payload)
    resp_quoted_angle = httpx.Response(
        200,
        text=f"<html><body><div data-expr='{angle_payload}'>Hello</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_qa, _ = rest.detect_response(resp_quoted_angle, p_angle, baseline_resp=base_html)
    dec_qa = rest.decide_validation(det_qa, p_angle)
    assert det_qa.metadata.get("xss_context") == "html_attribute_quoted"
    assert det_qa.new_expected_signals == []
    assert dec_qa.outcome == "inconclusive"
    assert dec_qa.is_candidate is False
    assert dec_qa.is_confirmed is False

    # 3. Attribute quote breakout remains candidate (never confirmed)
    breakout_payload = '" onmouseover="alert(1)'
    p_brk = _make_payload(attack_type="XSS", expected_signal=[breakout_payload], payload_value=breakout_payload)
    resp_brk = httpx.Response(
        200,
        text=f'<html><body><input type="text" value="{breakout_payload}"></body></html>',
        headers={"Content-Type": "text/html"},
    )
    det_brk, _ = rest.detect_response(resp_brk, p_brk, baseline_resp=base_html)
    dec_brk = rest.decide_validation(det_brk, p_brk)
    assert det_brk.metadata.get("xss_context") == "html_attribute"
    assert dec_brk.outcome == "candidate"
    assert dec_brk.is_confirmed is False

    # 4. HTML text-context XSS candidate remains unchanged
    resp_html_txt = httpx.Response(
        200,
        text=f"<html><body><div>{script_payload}</div></body></html>",
        headers={"Content-Type": "text/html"},
    )
    det_txt, _ = rest.detect_response(resp_html_txt, p_script, baseline_resp=base_html)
    dec_txt = rest.decide_validation(det_txt, p_script)
    assert det_txt.metadata.get("xss_context") == "html_text"
    assert dec_txt.outcome == "candidate"
    assert dec_txt.is_confirmed is False

    # 5. JSON reflection remains rejected
    resp_json = httpx.Response(200, json={"title": script_payload})
    det_json, _ = rest.detect_response(resp_json, p_script, baseline_resp=httpx.Response(200, json={"title": "ok"}))
    dec_json = rest.decide_validation(det_json, p_script)
    assert det_json.metadata.get("xss_context") == "json_reflection"
    assert dec_json.outcome == "rejected"
    assert dec_json.is_candidate is False

    # 6. Unknown context remains inconclusive
    resp_unk = httpx.Response(
        200,
        text=f"<html><body>{script_payload}</body></html>",
        headers={"Content-Type": "invalid-mime"},
    )
    det_unk, _ = rest.detect_response(resp_unk, p_script, baseline_resp=base_html)
    dec_unk = rest.decide_validation(det_unk, p_script)
    assert det_unk.metadata.get("xss_context") == "unknown"
    assert dec_unk.outcome == "inconclusive"
    assert dec_unk.is_candidate is False
