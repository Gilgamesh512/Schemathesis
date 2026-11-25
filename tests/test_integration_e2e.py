"""End-to-end and regression tests for in-process orchestration, schema-driven audits, and P0 fixes."""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from core import (
    ConcurrencyFuzzer,
    Evidence,
    Finding,
    ResultManager,
    TargetManager,
    WorkflowDefinition,
    WorkflowRunner,
    WorkflowStep,
)
from modules.graphql import run_graphql_fuzz1 as graphql
from modules.rest import run_schemathesis1 as rest
from modules.security import run_security_tests


def test_finding_normalizes_severity_case():
    finding = Finding(
        finding_id="F-sev-1",
        run_id="run-1",
        timestamp="2026-11-25T00:00:00+00:00",
        target_app="api",
        endpoint="/items",
        method="GET",
        tool="schemathesis",
        attack_type="BOLA",
        evidence=Evidence(),
        severity="HIGH",
        confidence=0.9,
        fingerprint="fp-sev-1",
    )
    assert finding.severity == "high"


def test_concurrency_fuzzer_respects_verify_ssl_and_proxy():
    default_fuzzer = ConcurrencyFuzzer(burst_size=3)
    assert default_fuzzer.verify_ssl is True
    assert default_fuzzer.proxy is None

    insecure_fuzzer = ConcurrencyFuzzer(
        burst_size=3,
        verify_ssl=False,
        proxy="http://127.0.0.1:8080",
    )
    assert insecure_fuzzer.verify_ssl is False
    assert insecure_fuzzer.proxy == "http://127.0.0.1:8080"


def test_graphql_cli_runs_without_payloads_flag(tmp_path: Path):
    """GraphQL CLI must allow omitting --payloads and invoke built-in probe generation."""
    targets_dir = tmp_path / "targets"
    schemas_dir = targets_dir / "schemas"
    results_dir = tmp_path / "results"
    config_dir = tmp_path / "config"
    for d in (targets_dir, schemas_dir, results_dir, config_dir):
        d.mkdir(parents=True, exist_ok=True)

    (targets_dir / "registry.yaml").write_text(
        """profiles:
  - target_id: test_gql
    name: Test GraphQL
    base_url: http://127.0.0.1:5013
    settings:
      protocol: graphql
      endpoint: /graphql
""",
        encoding="utf-8",
    )
    (config_dir / "rules.json").write_text(
        json.dumps({"meta": {}, "static_error_signals": [], "owasp_categories": {}, "cve_signals": []}),
        encoding="utf-8",
    )

    tm = TargetManager(tmp_path)
    with patch.object(graphql, "TargetManager", return_value=tm), \
         patch.object(graphql, "run_all", return_value=[]) as mock_run_all:
        graphql.main([
            "--target-id", "test_gql",
            "--results-dir", str(results_dir),
            "--rules", str(config_dir / "rules.json"),
        ])

    mock_run_all.assert_called_once()
    generated_payloads = mock_run_all.call_args[0][0]
    assert len(generated_payloads) >= 4
    assert any(p.attack_type == "GRAPHQL_INTROSPECTION" for p in generated_payloads)


def test_mass_assignment_loopback_custom_field_no_unbound_local(tmp_path: Path):
    """Regression test: Mass Assignment loopback on non-role fields must not hit UnboundLocalError."""
    payload = rest.Payload(
        endpoint="/api/v1/account",
        method="PUT",
        target_param="balance",
        param_location="body",
        attack_type="MASS_ASSIGNMENT",
        payload_value=999999,
        owasp_category="API3:2023",
        target_app="bank_api",
    )

    mock_op = MagicMock()
    mock_op.path = "/api/v1/account"
    mock_op.method = "PUT"

    mock_case = MagicMock()
    mock_case.as_transport_kwargs.return_value = {
        "method": "PUT",
        "url": "http://127.0.0.1:8000/api/v1/account",
        "json": {"balance": 999999},
    }

    pc = rest.PreparedCase(
        fingerprint="fp-mass-balance",
        target_app="bank_api",
        base_url="http://127.0.0.1:8000",
        baseline_case=None,
        case=mock_case,
        payload=payload,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "balance": 999999})

    async def _run():
        transport = httpx.MockTransport(handler)
        state = rest.RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=transport) as client:
            with patch.object(
                rest,
                "verify_deep_state_persistence",
                return_value=(True, "Verified balance persisted"),
            ) as mock_verify:
                findings = await rest.process_fingerprint_group(
                    client,
                    scheduler,
                    "fp-mass-balance",
                    [pc],
                    {},
                    None,
                    state,
                    0.0,
                )
        return findings, mock_verify

    findings, mock_verify = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].confirmed is True
    assert findings[0].severity == "high"
    mock_verify.assert_called_once()
    assert mock_verify.call_args.kwargs["expected_field"] == "balance"
    assert mock_verify.call_args.kwargs["expected_value"] == 999999


def test_extract_audit_targets_from_schema_and_inprocess_wiring(tmp_path: Path):
    """Dynamic scans extract audit targets from OpenAPI and wire SessionKeeper & ProxyRotator in-process."""
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Shop API", "version": "1.0.0"},
        "paths": {
            "/api/v1/coupon/apply": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"webhook_url": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/api/v1/orders": {
                "get": {
                    "parameters": [{"name": "redirect_url", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    spec_file = tmp_path / "shop_openapi.json"
    spec_file.write_text(json.dumps(openapi_spec), encoding="utf-8")

    extracted = run_security_tests._extract_audit_targets_from_schema(str(spec_file))
    assert ("POST", "/api/v1/coupon/apply") in extracted["race_candidates"]
    assert ("POST", "/api/v1/coupon/apply", "webhook_url", "body") in extracted["callback_params"]
    assert ("GET", "/api/v1/orders", "redirect_url", "query") in extracted["callback_params"]

    captured = {}

    def fake_execute_rest_scan(**kwargs):
        captured.update(kwargs)
        return []

    tm = TargetManager(tmp_path)
    with patch("modules.rest.run_schemathesis1.execute_rest_scan", side_effect=fake_execute_rest_scan), \
         patch.object(run_security_tests, "run_concurrency_audit", return_value=[]) as mock_race:
        exit_code = run_security_tests.run_dynamic_target(
            url="http://127.0.0.1:9000",
            schema=str(spec_file),
            proxy_pool="http://127.0.0.1:8080,http://127.0.0.1:8081",
            auth_automation={
                "login_url": "/auth/login",
                "payload": {"user": "demo"},
            },
            auth_token="Bearer static_token_123",
            verify_concurrency=True,
            targets=tm,
        )

    assert exit_code == 0
    assert captured["session_keeper"] is not None
    assert captured["proxy_rotator"] is not None
    assert captured["proxy"] == "http://127.0.0.1:8080"
    assert captured["auth_manager"] is not None
    mock_race.assert_called_once()
    assert mock_race.call_args.kwargs["candidate_endpoints"] == [("POST", "/api/v1/coupon/apply")]
    assert mock_race.call_args.kwargs["proxy"] == "http://127.0.0.1:8080"


def test_result_manager_sanitizes_secrets_in_persisted_payload(tmp_path: Path):
    results_dir = tmp_path / "results"
    manager = ResultManager(root=tmp_path, results_dir=results_dir)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlF5m8b7zK1A"

    finding = Finding(
        finding_id="F-sec-1",
        run_id="run-sec-1",
        timestamp="2026-11-25T00:00:00+00:00",
        target_app="api",
        endpoint="/profile",
        method="GET",
        tool="pii_detector",
        attack_type="SENSITIVE_DATA_EXPOSURE",
        payload={"leaked_jwt": jwt},
        evidence=Evidence(endpoint="/profile", payload={"leaked_jwt": jwt}),
        severity="critical",
        confidence=0.95,
        confirmed=True,
        lifecycle="confirmed",
        fingerprint="fp-sec-1",
    )

    manager.append_findings([finding], source="pii_detector", fieldnames=list(Finding.model_fields.keys()))

    csv_text = (results_dir / "vulnerabilities.csv").read_text(encoding="utf-8")
    ndjson_text = (results_dir / "vulnerabilities.ndjson").read_text(encoding="utf-8")
    assert jwt not in csv_text
    assert jwt not in ndjson_text
    assert "REDACTED_JWT" in ndjson_text


def test_workflow_runner_detects_bola_on_201_and_204():
    async def _run():
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        wf = WorkflowDefinition(
            name="BOLA DELETE 204",
            base_url="http://api.test",
            steps=[
                WorkflowStep(
                    name="Delete victim item as attacker",
                    endpoint="/items/1",
                    method="DELETE",
                    auth_user="user2",
                    assert_denied=True,
                )
            ],
        )
        runner = WorkflowRunner(base_url="http://api.test", user_tokens={"user2": "Bearer tok2"})
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await runner.execute_step(client, wf.steps[0], {}, "http://api.test", "run-wf-204")
        return res

    res = asyncio.run(_run())
    assert res.success is False
    assert res.finding is not None
    assert res.finding.attack_type == "BOLA"
    assert res.finding.confirmed is True
