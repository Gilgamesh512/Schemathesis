"""Regression tests for AST fixes, auth forwarding, hardcode removal, and FP suppression."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from core.concurrency_fuzzer import ConcurrencyFuzzer
from core.dependency_graph import ApiDependencyGraph
from core.graphql_advanced_auditor import GraphQLAdvancedAuditor
from core.header_tamper_fuzzer import HeaderTamperFuzzer
from core.pii_detector import PiiDetector
from core.target_manager import TargetManager
from modules.graphql.run_graphql_fuzz1 import generate_builtin_graphql_payloads
from modules.rest import run_schemathesis1 as rest
from modules.security import run_security_tests


# ---------------------------------------------------------------------------
# 1. Missing imports, UnboundLocalError, Auth forwarding & Hardcode removal
# ---------------------------------------------------------------------------

def test_auth_env_for_serializes_extra_headers():
    tm = TargetManager()
    tm.add_target(
        "extra_hdr_api",
        name="Extra Header API",
        base_url="https://api.example.test",
        schema_source="tests/fixtures/sample_openapi.yaml",
        auth={"token_env": "MY_TOK", "headers": {"X-Tenant": "acme", "X-Client": "ci"}},
        settings={"protocol": "rest"},
    )
    env = run_security_tests.auth_env_for("extra_hdr_api", {"MY_TOK": "Bearer abc"}, targets=tm)
    assert env is not None
    assert json.loads(env["FUZZ_EXTRA_HEADERS_JSON"]) == {"X-Tenant": "acme", "X-Client": "ci"}


def test_run_pii_audit_executes_without_time_name_error():
    async def mock_request(self, method, url, headers=None, **kwargs):
        return httpx.Response(
            200,
            json={"aws": "AKIAIOSFODNN7EXAMPLE"},
            request=httpx.Request(method, url),
        )

    with patch.object(httpx.AsyncClient, "request", new=mock_request):
        findings = run_security_tests.run_pii_audit(
            base_url="https://api.example.test",
            endpoints=[("GET", "/debug")],
            auth_token="tok123",
        )
    assert len(findings) == 1
    assert findings[0].confirmed is True


def test_main_login_body_parses_json_without_unbound_local_error():
    with patch.object(run_security_tests, "run_dynamic_target", return_value=0) as mock_dyn:
        rc = run_security_tests.main([
            "--url", "https://api.example.test",
            "--schema", "tests/fixtures/sample_openapi.yaml",
            "--login-url", "https://api.example.test/login",
            "--login-body", '{"email":"sec@example.test","password":"secret"}',
        ])
    assert rc == 0
    auth_auto = mock_dyn.call_args.kwargs["auth_automation"]
    assert auth_auto["payload"] == {"email": "sec@example.test", "password": "secret"}


def test_run_callback_audit_forwards_auth_headers():
    with patch("core.callback_verifier.CallbackVerifier.verify_endpoint_url_parameter", new_callable=AsyncMock) as mock_v:
        mock_v.return_value = None
        run_security_tests.run_callback_audit(
            base_url="https://api.example.test",
            candidate_params=[("POST", "/webhooks", "callback_url", "body")],
            auth_token="jwt_abc",
            custom_headers={"X-Tenant": "acme"},
        )
    mock_v.assert_called_once()
    passed_headers = mock_v.call_args.kwargs["headers"]
    assert passed_headers["Authorization"] == "Bearer jwt_abc"
    assert passed_headers["X-Tenant"] == "acme"


def test_concurrency_audit_uses_schema_derived_body_instead_of_hardcoded(tmp_path: Path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Wallet API", "version": "1.0.0"},
        "paths": {
            "/wallet/withdraw": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "integer", "minimum": 10},
                                        "currency": {"type": "string", "enum": ["USD", "EUR"]},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    spec_path = tmp_path / "wallet.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    extracted = run_security_tests._extract_audit_targets_from_schema(str(spec_path))
    assert ("POST", "/wallet/withdraw") in extracted["race_candidates"]
    body = extracted["race_bodies"][("POST", "/wallet/withdraw")]
    assert body == {"amount": 10, "currency": "USD"}
    assert "PROMO2026" not in str(body)

    captured_bodies = []

    async def fake_burst(self, *, base_url, endpoint, method="POST", headers=None, json_data=None, data=None):
        captured_bodies.append(json_data)
        return ConcurrencyFuzzer(burst_size=2).convert_to_finding  # dummy placeholder avoided below

    with patch.object(ConcurrencyFuzzer, "execute_burst", new_callable=AsyncMock) as mock_burst:
        from core.concurrency_fuzzer import ConcurrencyBurstResult
        mock_burst.return_value = ConcurrencyBurstResult(
            endpoint="/wallet/withdraw",
            method="POST",
            burst_size=2,
            success_count=1,
            client_error_count=1,
            server_error_count=0,
            status_codes=[200, 409],
            latencies_ms=[10.0, 12.0],
        )
        run_security_tests.run_concurrency_audit(
            base_url="https://api.example.test",
            candidate_endpoints=extracted["race_candidates"],
            sample_bodies=extracted["race_bodies"],
            burst_size=2,
        )
    assert mock_burst.call_args.kwargs["json_data"] == {"amount": 10, "currency": "USD"}


def test_graphql_command_injection_has_no_dvga_marker(tmp_path: Path):
    schema = {
        "data": {
            "__schema": {
                "queryType": {
                    "fields": [
                        {"name": "runTool", "args": [{"name": "cmd"}]}
                    ]
                }
            }
        }
    }
    schema_path = tmp_path / "gql.json"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    payloads = generate_builtin_graphql_payloads("generic_target", schema_path)
    cmd_payloads = [p for p in payloads if p.attack_type == "COMMAND_INJECTION"]
    assert cmd_payloads
    for p in cmd_payloads:
        assert "DVGA_MARKER" not in p.query
        assert "DVGA_MARKER" not in p.expected_signal


# ---------------------------------------------------------------------------
# 2. False Positive Suppression: PII, Concurrency, GraphQL Batch, Headers
# ---------------------------------------------------------------------------

def test_pii_suppresses_non_secret_high_entropy_and_order_ids():
    benign = json.dumps({
        "next_page_cursor": "eyJsYXN0X2lkIjogOTg3NjU0MzIxLCAib2Zmc2V0IjogMjB9",
        "trace_id": "a9B8c7D6e5F4g3H2i1J0k9L8m7N6o5P4",
        "etag": "W8kLm9NpQr2StUv4WxYz6AbCd8EfGh0J",
        "s3_key": "uploads/2026/a9B8c7D6e5F4g3H2i1J0k9L8m7N6o5P4.png",
        "order_id": "012123456789",
        "transaction_id": "099299123456",
    })
    res = PiiDetector.scan(benign)
    assert res.has_pii is False

    # High-entropy value WITH secret key context is still surfaced as candidate, not confirmed high
    secret_ctx = json.dumps({"api_secret_token": "Xk9mP2qR7vW4zB8nC3fH6jL1sT5yA0dE"})
    finding = PiiDetector.audit_response(200, secret_ctx, "/cfg", "GET", "r1")
    assert finding is not None
    assert finding.confirmed is False
    assert finding.lifecycle == "candidate"
    assert finding.severity == "medium"


def test_concurrency_suppresses_idempotent_routes_and_generic_500():
    async def _run():
        fuzzer = ConcurrencyFuzzer(burst_size=3)

        # 1. Idempotent /password/reset returning 200 multiple times should NOT be flagged
        async def reset_send(self, client, url, method, headers, json_data, data, req_id, barrier=None):
            return req_id, 200, 10.0, '{"status":"ok"}', {}

        with patch.object(ConcurrencyFuzzer, "_send_synchronized_request", new=reset_send):
            res_reset = await fuzzer.execute_burst("https://api.test", "/password/reset", "POST")
        assert res_reset.is_vulnerable is False

        # 2. Generic 500 Internal Server Error should NOT be flagged as deadlock race condition
        async def err500_send(self, client, url, method, headers, json_data, data, req_id, barrier=None):
            return req_id, 500, 10.0, '{"error":"Internal Server Error"}', {}

        with patch.object(ConcurrencyFuzzer, "_send_synchronized_request", new=err500_send):
            res_500 = await fuzzer.execute_burst("https://api.test", "/orders", "POST")
        assert res_500.is_vulnerable is False

        # 3. Single-use coupon/redeem returning multiple 200s IS flagged
        async def redeem_send(self, client, url, method, headers, json_data, data, req_id, barrier=None):
            return req_id, 200, 10.0, '{"redeemed":true}', {}

        with patch.object(ConcurrencyFuzzer, "_send_synchronized_request", new=redeem_send):
            res_redeem = await fuzzer.execute_burst("https://api.test", "/coupon/redeem", "POST")
        assert res_redeem.is_vulnerable is True

    asyncio.run(_run())


def test_graphql_batching_ignores_all_error_arrays(monkeypatch):
    auditor = GraphQLAdvancedAuditor()

    async def mock_post(self, url, json=None, headers=None, **kwargs):
        if isinstance(json, list):
            return httpx.Response(
                200,
                json=[{"errors": [{"message": "Batching disabled"}]} for _ in json],
                request=httpx.Request("POST", url),
            )
        return httpx.Response(400, json={"errors": [{"message": "Refused"}]}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)
    result = asyncio.run(auditor.audit_endpoint("http://test.local", "/graphql", batch_size=10, alias_count=10))
    assert result.batching_enabled is False
    assert not any(f.attack_type == "GraphQL Query Batching" for f in result.findings)


def test_header_tamper_ignores_404_error_reflection():
    async def _run():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("X-Rewrite-URL") == "/admin" or request.headers.get("X-Original-URL") == "/admin":
                return httpx.Response(404, json={"error": "Route /admin not found via X-Rewrite-URL"})
            return httpx.Response(200, json={"status": "public_home"})

        fuzzer = HeaderTamperFuzzer()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            findings = await fuzzer.test_endpoint(client, "https://api.test", "/home", method="GET")
        assert findings == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Dual-User BOLA Public Endpoint Suppression
# ---------------------------------------------------------------------------

def _make_bola_prepared_case():
    class DummyCase:
        def __init__(self, endpoint):
            self.endpoint = endpoint

        def as_transport_kwargs(self, base_url):
            return {"method": "GET", "url": f"{base_url}{self.endpoint}"}

    payload = rest.Payload(
        endpoint="/items/1",
        method="GET",
        target_param="id",
        param_location="path",
        attack_type="BOLA",
        payload_value="1",
        expected_signal=[],
    )
    return rest.PreparedCase(
        "fp-bola-1", "test_app", "http://api.test",
        DummyCase("/items/1"), DummyCase("/items/1"), payload,
    )


def test_dual_user_bola_suppresses_public_read_endpoint(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        # Public endpoint: returns 200 even without Authorization
        return httpx.Response(200, json={"id": 1, "name": "Public Item"})

    async def _run():
        state = rest.RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, "fp-bola-1", [_make_bola_prepared_case()],
                {"Authorization": "Bearer user1"}, None, state, 0.0,
                user2_headers={"Authorization": "Bearer user2"},
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].confirmed is False
    assert "public-read or unprotected" in findings[0].evidence.response_signal[0]


def test_dual_user_bola_confirms_protected_cross_user_access(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization")
        if not auth:
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"id": 1, "owner": "user1"})

    async def _run():
        state = rest.RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, "fp-bola-1", [_make_bola_prepared_case()],
                {"Authorization": "Bearer user1"}, None, state, 0.0,
                user2_headers={"Authorization": "Bearer user2"},
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert findings[0].severity == "high"


def test_dependency_graph_skips_public_get_consumers():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Catalog", "version": "1.0.0"},
        "paths": {
            "/products": {
                "post": {
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/products/{id}": {
                "get": {
                    "security": [],
                    "responses": {"200": {"description": "Public product"}}
                }
            },
        },
    }
    graph = ApiDependencyGraph(spec)
    assert graph.consumers[0].is_public is True
    assert graph.synthesize_workflows() == []


# ---------------------------------------------------------------------------
# 4. Quality Gate SARIF Severity Evaluation
# ---------------------------------------------------------------------------

def test_quality_gate_does_not_miscount_medium_warnings_as_high(tmp_path: Path):
    import run_all
    from core import SecurityReporter

    reporter = SecurityReporter(results_dir=tmp_path)
    findings = [
        {
            "finding_id": f"m-{i}",
            "method": "GET",
            "endpoint": f"/items/{i}",
            "attack_type": "XSS",
            "owasp_category": "API8:2023",
            "severity": "medium",
            "confirmed": False,
            "evidence": "Unconfirmed candidate signal",
        }
        for i in range(4)
    ]
    sarif_path = reporter.generate_sarif_report(findings, output_file=tmp_path / "gate.sarif")

    # 4 medium (SARIF level='warning') unconfirmed findings must NOT fail --max-critical 0 --max-high 2
    rc = run_all.main(["gate", "--sarif", str(sarif_path), "--max-critical", "0", "--max-high", "2"])
    assert rc == 0


def test_quality_gate_blocks_actual_high_and_confirmed_findings(tmp_path: Path):
    import run_all
    from core import SecurityReporter

    reporter = SecurityReporter(results_dir=tmp_path)
    findings = [
        {
            "finding_id": f"h-{i}",
            "method": "GET",
            "endpoint": f"/admin/{i}",
            "attack_type": "BFLA",
            "owasp_category": "API5:2023",
            "severity": "high",
            "confirmed": False,
            "evidence": "High severity anomaly",
        }
        for i in range(3)
    ]
    sarif_path = reporter.generate_sarif_report(findings, output_file=tmp_path / "gate_high.sarif")

    # 3 actual high findings exceed --max-high 2 even with --allow-confirmed
    rc = run_all.main(["gate", "--sarif", str(sarif_path), "--max-critical", "0", "--max-high", "2", "--allow-confirmed"])
    assert rc == 1


def test_html_report_renders_and_infers_target_metadata(tmp_path: Path):
    from core import SecurityReporter

    run_dir = tmp_path / "rest-20261126-test"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "run_id": "rest-20261126-test",
            "target": "target_dummyjson_com=targets/schemas/dummyjson_spec.yaml",
            "metadata": {"tool": "schemathesis"},
        }),
        encoding="utf-8",
    )

    reporter = SecurityReporter(results_dir=tmp_path)
    findings = [{
        "finding_id": "f-html-1",
        "run_id": "rest-20261126-test",
        "target_app": "target_dummyjson_com",
        "endpoint": "/products/1",
        "method": "GET",
        "attack_type": "BOLA",
        "owasp_category": "API1:2023",
        "severity": "medium",
        "confirmed": False,
        "evidence": "Probe check",
        "curl_command": "curl -X GET 'https://dummyjson.com/products/1'",
    }]

    # Even without explicit target_info, report must display inferred target name, URL, app, run_id & schema
    html_path = reporter.generate_html_report(findings)
    content = html_path.read_text(encoding="utf-8")
    assert "target_dummyjson_com" in content
    assert "https://dummyjson.com" in content
    assert "rest-20261126-test" in content
    assert "targets/schemas/dummyjson_spec.yaml" in content
    assert "Target Base URL" in content


