"""Tests for Dynamic Target Ingestion CLI, runner, and SecurityReporter."""

from pathlib import Path
from unittest.mock import patch
import pytest

from core import SecurityReporter, TargetManager
from modules.security import run_security_tests
import run_all
from cli import main as cli_main


def test_normalize_auth_header():
    assert run_security_tests.normalize_auth_header(None) is None
    assert run_security_tests.normalize_auth_header("") is None
    assert run_security_tests.normalize_auth_header("   ") is None
    assert run_security_tests.normalize_auth_header("jwt123") == "Authorization: Bearer jwt123"
    assert run_security_tests.normalize_auth_header("Bearer token_abc") == "Authorization: Bearer token_abc"
    assert run_security_tests.normalize_auth_header("Authorization: Bearer xyz") == "Authorization: Bearer xyz"
    assert run_security_tests.normalize_auth_header("X-API-Key: secret-key") == "X-API-Key: secret-key"


def test_auth_env_for_direct_header():
    tm = TargetManager()
    tm.add_target(
        "direct_auth_test",
        name="Direct Auth Test",
        base_url="http://127.0.0.1:8000",
        schema_source="targets/schemas/vampi/vampi_spec.yaml",
        auth={"header": "Bearer my_secret_token"},
        settings={"protocol": "rest"},
    )
    env = run_security_tests.auth_env_for("direct_auth_test", {}, targets=tm)
    assert env == {"FUZZ_AUTH_HEADER": "Authorization: Bearer my_secret_token"}


def test_run_dynamic_target_rest_dispatch(tmp_path: Path):
    dummy_schema = tmp_path / "schema.json"
    dummy_schema.write_text('{"openapi": "3.0.0"}', encoding="utf-8")

    custom_tm = TargetManager(tmp_path)
    captured = {}

    def mock_run_target(target_id, include_payload=True, tokens=None, targets=None):
        captured["target_id"] = target_id
        captured["include_payload"] = include_payload
        captured["target"] = targets.get_target(target_id)

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target):
        exit_code = run_security_tests.run_dynamic_target(
            url="https://api.example.com",
            schema=str(dummy_schema),
            auth_token="test_jwt_123",
            protocol="rest",
            target_id="my_custom_api",
            targets=custom_tm,
        )

    assert exit_code == 0
    assert captured["target_id"] == "my_custom_api"
    assert captured["include_payload"] is False
    target = captured["target"]
    assert target.base_url == "https://api.example.com"
    assert target.schema_source == str(dummy_schema)
    assert target.auth == {"header": "Authorization: Bearer test_jwt_123"}
    assert target.settings.get("protocol") == "rest"


def test_run_dynamic_target_remote_schema_sets_allow_remote(tmp_path: Path):
    custom_tm = TargetManager(tmp_path)
    captured = {}

    def mock_run_target(target_id, include_payload=True, tokens=None, targets=None):
        captured["target"] = targets.get_target(target_id)

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target):
        exit_code = run_security_tests.run_dynamic_target(
            url="http://127.0.0.1:9000",
            schema="http://127.0.0.1:9000/openapi.json",
            protocol="rest",
            targets=custom_tm,
        )

    assert exit_code == 0
    assert captured["target"].settings.get("allow_remote_schema") is True


def test_run_all_scan_command_dispatches_to_security_tests():
    with patch.object(run_all, "run_script") as mock_run_script:
        exit_code = run_all.main([
            "scan",
            "--url", "http://127.0.0.1:5000",
            "--schema", "targets/schemas/vampi/vampi_spec.yaml",
            "--token", "Bearer testtoken",
        ])
        assert exit_code == 0
        mock_run_script.assert_called_once()
        args = mock_run_script.call_args[0]
        assert args[0] == run_all.RUN_SECURITY_TESTS
        assert "--url" in args
        assert "http://127.0.0.1:5000" in args
        assert "--auth-token" in args
        assert "Bearer testtoken" in args


def test_cli_main_with_url_dispatches_directly():
    with patch.object(cli_main, "run_dynamic_target", return_value=0) as mock_dynamic:
        exit_code = cli_main.main([
            "--url", "https://petstore.swagger.io/v2",
            "--schema", "https://petstore.swagger.io/v2/swagger.json",
            "--auth-token", "my-api-key",
        ])
        assert exit_code == 0
        mock_dynamic.assert_called_once_with(
            url="https://petstore.swagger.io/v2",
            schema="https://petstore.swagger.io/v2/swagger.json",
            auth_token="my-api-key",
            protocol="rest",
            endpoint="/graphql",
            payloads=None,
            target_id=None,
            name=None,
        )


def test_security_reporter_html_and_terminal(tmp_path: Path):
    reporter = SecurityReporter(tmp_path)
    sample_findings = [
        {
            "finding_id": "f1",
            "run_id": "run-1",
            "timestamp": "2026-10-25T01:00:00Z",
            "target_app": "test_app",
            "endpoint": "/api/users",
            "method": "POST",
            "attack_type": "SQL_INJECTION",
            "owasp_category": "API8:2023",
            "payload": "' OR '1'='1",
            "status_code": 500,
            "response_time_ms": 45.2,
            "evidence": "Syntax error near OR",
            "severity": "high",
            "confirmed": True,
            "matched_cve": ["CVE-2024-9999"],
        },
        {
            "finding_id": "f2",
            "run_id": "run-1",
            "timestamp": "2026-10-25T01:00:01Z",
            "target_app": "test_app",
            "endpoint": "/api/profile",
            "method": "GET",
            "attack_type": "BOLA",
            "owasp_category": "API1:2023",
            "payload": "admin",
            "status_code": 200,
            "response_time_ms": 12.0,
            "evidence": "User data leaked",
            "severity": "critical",
            "confirmed": True,
            "matched_cve": [],
        },
    ]

    metrics = reporter.compute_metrics(sample_findings)
    assert metrics["total"] == 2
    assert metrics["confirmed"] == 2
    assert metrics["severity_counts"]["critical"] == 1
    assert metrics["severity_counts"]["high"] == 1

    # Render terminal dashboard
    reporter.render_terminal_dashboard(sample_findings, target_info={"name": "Test Target", "url": "http://test"})

    # Generate HTML report
    html_path = reporter.generate_html_report(sample_findings, target_info={"name": "Test Target", "url": "http://test"})
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "API Security Fuzzing Report" in content
    assert "/api/users" in content
    assert "SQL_INJECTION" in content
    assert "BOLA" in content
    assert "CONFIRMED VULNERABILITY" in content


def test_cli_dashboard_flag():
    with patch.object(cli_main.SecurityReporter, "render_terminal_dashboard") as mock_dash:
        exit_code = cli_main.main(["--dashboard"])
        assert exit_code == 0
        mock_dash.assert_called_once()
