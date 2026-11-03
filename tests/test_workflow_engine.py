"""Tests for Stateful Workflow Chaining Engine (core/workflow_engine.py)."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
import pytest

from core.workflow_engine import (
    StepExecutionResult,
    WorkflowDefinition,
    WorkflowExecutionReport,
    WorkflowRunner,
    WorkflowStep,
    interpolate_template,
    resolve_selector,
)


# -----------------------------------------------------------------------------
# 1. Selector and Template Interpolation Tests
# -----------------------------------------------------------------------------

def test_resolve_selector_nested_and_indexed():
    data = {
        "status": "success",
        "user": {
            "id": 12345,
            "profile": {
                "username": "tester",
                "emails": ["primary@test.com", "alt@test.com"],
            },
        },
        "headers": {
            "Set-Cookie": "session_id=abc; Path=/",
        },
    }

    assert resolve_selector(data, "user.id") == 12345
    assert resolve_selector(data, "user.profile.username") == "tester"
    assert resolve_selector(data, "user.profile.emails.0") == "primary@test.com"
    assert resolve_selector(data, "user.profile.emails.1") == "alt@test.com"
    assert resolve_selector(data, "headers.set-cookie") == "session_id=abc; Path=/"
    assert resolve_selector(data, "nonexistent.key") is None
    assert resolve_selector(data, "user.profile.emails.99") is None


def test_interpolate_template_preserves_types_and_replaces_strings():
    context = {
        "user_id": 999,
        "is_active": True,
        "tags": ["admin", "staff"],
        "token": "tok_xyz123",
    }

    # Exact token match preserves original non-string types
    assert interpolate_template("{{user_id}}", context) == 999
    assert interpolate_template("{{is_active}}", context) is True
    assert interpolate_template("{{tags}}", context) == ["admin", "staff"]

    # String composite interpolation
    assert (
        interpolate_template("/api/users/{{user_id}}/status?token={{token}}", context)
        == "/api/users/999/status?token=tok_xyz123"
    )

    # Dictionary and list recursive interpolation
    payload = {
        "id": "{{user_id}}",
        "nested": {"path": "/v1/{{user_id}}"},
        "query_items": ["{{user_id}}", "static"],
    }
    interpolated = interpolate_template(payload, context)
    assert interpolated["id"] == 999
    assert interpolated["nested"]["path"] == "/v1/999"
    assert interpolated["query_items"] == [999, "static"]


# -----------------------------------------------------------------------------
# 2. WorkflowDefinition YAML Parsing Tests
# -----------------------------------------------------------------------------

def test_workflow_definition_from_yaml(tmp_path: Path):
    yaml_content = """
name: "User Lifecycle Flow"
description: "Create user, get profile, and verify access"
base_url: "http://127.0.0.1:8000"
initial_context:
  default_role: "user"
steps:
  - name: "Create User"
    endpoint: "/api/v1/users"
    method: "POST"
    body:
      name: "Alice"
      role: "{{default_role}}"
    extract:
      created_id: "id"
    expected_status: [201]

  - name: "Fetch Profile"
    endpoint: "/api/v1/users/{{created_id}}"
    method: "GET"
    expected_status: [200]
"""
    yaml_file = tmp_path / "user_flow.yaml"
    yaml_file.write_text(yaml_content, encoding="utf-8")

    workflow = WorkflowDefinition.from_yaml(yaml_file)
    assert workflow.name == "User Lifecycle Flow"
    assert workflow.base_url == "http://127.0.0.1:8000"
    assert workflow.initial_context["default_role"] == "user"
    assert len(workflow.steps) == 2
    assert workflow.steps[0].method == "POST"
    assert workflow.steps[0].extract == {"created_id": "id"}
    assert workflow.steps[1].endpoint == "/api/v1/users/{{created_id}}"


# -----------------------------------------------------------------------------
# 3. WorkflowRunner Async Execution & Data Chaining Tests
# -----------------------------------------------------------------------------

def test_workflow_runner_chains_variables_across_steps():
    step1_response = Mock()
    step1_response.status_code = 201
    step1_response.json.return_value = {"id": 101, "status": "active"}
    step1_response.headers = {"content-type": "application/json"}
    step1_response.text = '{"id": 101, "status": "active"}'

    step2_response = Mock()
    step2_response.status_code = 200
    step2_response.json.return_value = {"id": 101, "name": "Created Resource"}
    step2_response.headers = {"content-type": "application/json"}
    step2_response.text = '{"id": 101, "name": "Created Resource"}'

    workflow = WorkflowDefinition(
        name="Chaining Test Workflow",
        base_url="http://127.0.0.1:5000",
        steps=[
            WorkflowStep(
                name="Step 1 Create",
                endpoint="/items",
                method="POST",
                body={"name": "test_item"},
                extract={"new_item_id": "id"},
                expected_status=[201],
            ),
            WorkflowStep(
                name="Step 2 Fetch",
                endpoint="/items/{{new_item_id}}",
                method="GET",
                expected_status=[200],
            ),
        ],
    )

    runner = WorkflowRunner()
    captured_requests = []

    mock_client = AsyncMock()

    async def mock_request(**kwargs):
        captured_requests.append(kwargs)
        if kwargs["url"].endswith("/items"):
            return step1_response
        return step2_response

    mock_client.request = mock_request

    async def run_test():
        with patch("httpx.AsyncClient") as mock_async_cls:
            mock_async_cls.return_value.__aenter__.return_value = mock_client
            return await runner.run(workflow)

    report = asyncio.run(run_test())

    assert report.success is True
    assert report.total_steps == 2
    assert report.passed_steps == 2
    assert report.failed_steps == 0
    assert report.final_context.get("new_item_id") == 101

    # Verify that Step 2 substituted the dynamic variable in URL
    assert len(captured_requests) == 2
    assert captured_requests[0]["url"] == "http://127.0.0.1:5000/items"
    assert captured_requests[1]["url"] == "http://127.0.0.1:5000/items/101"


def test_workflow_runner_detects_bola_when_assert_denied_returns_200():
    # When assert_denied=True, an HTTP 200 means authorization failed (BOLA vulnerability)
    vuln_response = Mock()
    vuln_response.status_code = 200
    vuln_response.json.return_value = {"secret": "user1_private_data"}
    vuln_response.headers = {"content-type": "application/json"}
    vuln_response.text = '{"secret": "user1_private_data"}'

    workflow = WorkflowDefinition(
        name="BOLA Cross-User Check",
        base_url="http://127.0.0.1:5000",
        steps=[
            WorkflowStep(
                name="Attacker Access Victim Resource",
                endpoint="/private/data/1001",
                method="GET",
                assert_denied=True,
                auth_user="user2",
            ),
        ],
    )

    runner = WorkflowRunner(
        user_tokens={"user2": "attacker_jwt_token_456"},
    )

    mock_client = AsyncMock()
    mock_client.request.return_value = vuln_response

    async def run_test():
        with patch("httpx.AsyncClient") as mock_async_cls:
            mock_async_cls.return_value.__aenter__.return_value = mock_client
            return await runner.run(workflow)

    report = asyncio.run(run_test())

    assert report.success is False
    assert report.failed_steps == 1
    assert len(report.findings) == 1

    finding = report.findings[0]
    assert finding.attack_type == "BOLA"
    assert finding.severity == "high"
    assert finding.confirmed is True
    assert finding.owasp_category == "API1:2023"


def test_workflow_runner_supports_proxy_and_insecure():
    workflow = WorkflowDefinition(
        name="Proxy Workflow",
        base_url="http://127.0.0.1:8000",
        steps=[
            WorkflowStep(
                name="Ping",
                endpoint="/ping",
                method="GET",
            ),
        ],
    )

    runner = WorkflowRunner(
        base_url="http://127.0.0.1:8000",
        proxy="http://127.0.0.1:8080",
        insecure=True,
    )

    mock_client_instance = AsyncMock()
    mock_client_instance.request.return_value = Mock(
        status_code=200, json=Mock(return_value={}), headers={}, text="{}"
    )

    async def run_test():
        with patch("httpx.AsyncClient") as mock_async_client_cls:
            mock_async_client_cls.return_value.__aenter__.return_value = mock_client_instance
            await runner.run(workflow)

            # Verify proxy and verify=False were passed to httpx
            mock_async_client_cls.assert_called_once_with(
                timeout=20.0,
                proxy="http://127.0.0.1:8080",
                verify=False,
            )

    asyncio.run(run_test())


# -----------------------------------------------------------------------------
# 4. CLI and Orchestration Integration Tests for Workflow
# -----------------------------------------------------------------------------

def test_run_workflow_orchestrator(tmp_path: Path):
    from modules.security import run_security_tests

    wf_file = tmp_path / "test_flow.yaml"
    wf_file.write_text("""
name: "Orchestrator Test Flow"
base_url: "http://127.0.0.1:8000"
steps:
  - name: "Step 1"
    endpoint: "/health"
    method: "GET"
    expected_status: [200]
""", encoding="utf-8")

    mock_resp = Mock(status_code=200, json=Mock(return_value={"status": "ok"}), headers={}, text="{}")

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client_cls.return_value.__aenter__.return_value.request = AsyncMock(return_value=mock_resp)
        exit_code = run_security_tests.run_workflow(wf_file)
        assert exit_code == 0


def test_run_all_workflow_command_parsing():
    import run_all
    parser = run_all._parser()
    args = parser.parse_args([
        "workflow",
        "targets/workflows/sample_workflow.yaml",
        "--url", "http://127.0.0.1:5002",
        "--proxy", "http://127.0.0.1:8080",
        "--insecure",
    ])
    assert args.command == "workflow"
    assert args.file == "targets/workflows/sample_workflow.yaml"
    assert args.url == "http://127.0.0.1:5002"
    assert args.proxy == "http://127.0.0.1:8080"
    assert args.insecure is True


def test_cli_main_dispatches_workflow():
    from cli import main as cli_main
    with patch.object(cli_main, "run_workflow", return_value=0) as mock_wf:
        exit_code = cli_main.main([
            "--workflow", "targets/workflows/sample_workflow.yaml",
            "--url", "http://127.0.0.1:5002",
            "--proxy", "http://127.0.0.1:8080",
            "--insecure",
        ])
        assert exit_code == 0
        mock_wf.assert_called_once_with(
            "targets/workflows/sample_workflow.yaml",
            base_url="http://127.0.0.1:5002",
            proxy="http://127.0.0.1:8080",
            insecure=True,
        )
