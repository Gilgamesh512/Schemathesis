"""Tests for orchestrator failure isolation, success tracking, error propagation,
idempotent CLI target selection, and custom TargetManager path resolution.
"""

import json
from pathlib import Path
import sys
from unittest.mock import patch
import pytest
import yaml

from core import TargetManager
from modules.security import run_security_tests
import run_all


def test_orchestrator_continues_on_target_failure_and_returns_nonzero(capsys):
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)
        if target_id == "crapi":
            raise RuntimeError("fuzzer process exited with code 1")

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py", "--target", "crapi", "--target", "vampi"]):
        exit_code = run_security_tests.main()

    # The second target must still execute despite the first target failing
    assert calls == ["crapi", "vampi"]
    # Overall pipeline must indicate failure
    assert exit_code == 1

    captured = capsys.readouterr().out
    assert "PARTIAL FAILURE" in captured
    assert "[X] Failed: crapi (fuzzer process exited with code 1)" in captured
    assert "[+] Succeeded: vampi" in captured


def test_orchestrator_success_path_records_all_targets(capsys):
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py", "--target", "crapi", "--target", "vampi"]):
        exit_code = run_security_tests.main()

    assert calls == ["crapi", "vampi"]
    assert exit_code == 0

    captured = capsys.readouterr().out
    assert "SECURITY TESTING COMPLETE" in captured
    assert "[+] Succeeded: crapi, vampi" in captured


def test_orchestrator_aborts_immediately_on_keyboard_interrupt():
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)
        raise KeyboardInterrupt()

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py", "--target", "crapi", "--target", "vampi"]):
        exit_code = run_security_tests.main()

    # Aborts immediately without executing remaining targets
    assert calls == ["crapi"]
    assert exit_code == 130


def test_run_all_propagates_orchestrator_failure():
    # Verify that run_all.py propagates orchestrator failure (exit code 1)
    with patch.object(run_all, "run_script") as mock_run_script, \
         patch.object(run_all, "validate_handoff", return_value=True):
        def side_effect(script, *args):
            if script == run_all.RUN_SECURITY_TESTS:
                raise RuntimeError("modules/security/run_security_tests.py failed with exit code 1")

        mock_run_script.side_effect = side_effect
        exit_code = run_all.main(["run"])
        assert exit_code == 1


# --------------------------------------------------------------------------
# Recommendation 1: Injected TargetManager path resolution
# --------------------------------------------------------------------------

def test_build_target_command_resolves_payload_using_injected_manager(tmp_path: Path):
    targets_dir = tmp_path / "targets"
    schemas_dir = targets_dir / "schemas"
    payloads_dir = tmp_path / "payloads"
    for d in (targets_dir, schemas_dir, payloads_dir):
        d.mkdir(parents=True, exist_ok=True)

    schema_file = schemas_dir / "custom_schema.json"
    schema_file.write_text('{"openapi": "3.0.0"}', encoding="utf-8")

    payload_file = payloads_dir / "custom_payload.json"
    payload_file.write_text("[]", encoding="utf-8")

    registry_file = targets_dir / "registry.yaml"
    registry_file.write_text(yaml.safe_dump({
        "profiles": [{
            "target_id": "isolated_target",
            "name": "Isolated Target",
            "base_url": "http://localhost:8888",
            "schema_source": "targets/schemas/custom_schema.json",
            "settings": {
                "protocol": "rest",
                "payload_source": "payloads/custom_payload.json",
            },
        }]
    }), encoding="utf-8")

    custom_tm = TargetManager(tmp_path)
    label, command = run_security_tests.build_target_command("isolated_target", targets=custom_tm)

    assert label == "Isolated Target"
    # Schema path must resolve to tmp_path
    schema_idx = command.index("--targets") + 1
    assert str(schema_file.resolve()) in command[schema_idx]

    # Payload path MUST resolve using custom_tm (under tmp_path), not repository TARGETS
    payload_idx = command.index("--payloads") + 1
    assert command[payload_idx] == str(payload_file.resolve())

    # Negative control: prove that if payload does NOT exist in custom root,
    # it raises FileNotFoundError pointing to custom root (does not fall back to repo root)
    payload_file.unlink()
    with pytest.raises(FileNotFoundError, match=r"custom_payload\.json"):
        run_security_tests.build_target_command("isolated_target", targets=custom_tm)


# --------------------------------------------------------------------------
# Recommendation 2: Idempotent target selection
# --------------------------------------------------------------------------

def test_target_selection_deduplicates_repeated_flags():
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py", "--target", "vampi", "--target", "vampi"]):
        exit_code = run_security_tests.main()

    # Repeated --target vampi flag must execute vampi only once
    assert calls == ["vampi"]
    assert exit_code == 0


def test_target_selection_distinct_targets_preserves_order():
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)

    # User specifies vampi then crapi
    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py", "--target", "vampi", "--target", "crapi", "--target", "vampi"]):
        exit_code = run_security_tests.main()

    # Preserves first occurrence order without duplicate
    assert calls == ["vampi", "crapi"]
    assert exit_code == 0


def test_target_selection_omitted_runs_all_configured_targets():
    calls = []

    def mock_run_target(target_id, tokens=None, targets=None):
        calls.append(target_id)

    # No --target flags provided
    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target), \
         patch.object(run_security_tests, "parse_tokens_env", return_value={}), \
         patch.object(sys, "argv", ["run_security_tests.py"]):
        exit_code = run_security_tests.main()

    # Omitted target runs all configured targets in sorted order
    assert calls == sorted(run_security_tests.TARGETS.targets)
    assert exit_code == 0


# --------------------------------------------------------------------------
# Recommendation 3: Configuration-driven extensibility
# --------------------------------------------------------------------------

def test_configuration_driven_target_dispatch_in_isolated_root(tmp_path: Path):
    targets_dir = tmp_path / "targets"
    schemas_dir = targets_dir / "schemas"
    payloads_dir = tmp_path / "payloads"
    for d in (targets_dir, schemas_dir, payloads_dir):
        d.mkdir(parents=True, exist_ok=True)

    # 1. New REST target configuration
    rest_schema = schemas_dir / "new_rest.json"
    rest_schema.write_text('{"openapi": "3.0.0"}', encoding="utf-8")
    rest_payload = payloads_dir / "new_rest.json"
    rest_payload.write_text("[]", encoding="utf-8")

    # 2. New GraphQL target configuration
    gql_payload = payloads_dir / "new_gql.json"
    gql_payload.write_text("[]", encoding="utf-8")

    registry_file = targets_dir / "registry.yaml"
    registry_file.write_text(yaml.safe_dump({
        "profiles": [
            {
                "target_id": "new_rest",
                "name": "New REST API",
                "base_url": "http://127.0.0.1:8000",
                "schema_source": "targets/schemas/new_rest.json",
                "settings": {
                    "protocol": "rest",
                    "payload_source": "payloads/new_rest.json",
                },
            },
            {
                "target_id": "new_gql",
                "name": "New GraphQL API",
                "base_url": "http://127.0.0.1:8001",
                "settings": {
                    "protocol": "graphql",
                    "endpoint": "/api/graphql",
                    "payload_source": "payloads/new_gql.json",
                },
            },
        ]
    }), encoding="utf-8")

    custom_tm = TargetManager(tmp_path)
    assert "new_rest" in custom_tm.targets
    assert "new_gql" in custom_tm.targets

    # Build REST command
    _, rest_cmd = run_security_tests.build_target_command("new_rest", targets=custom_tm)
    assert "--targets" in rest_cmd
    assert f"new_rest={rest_schema.resolve()}" in rest_cmd
    assert "--payloads" in rest_cmd
    assert str(rest_payload.resolve()) in rest_cmd

    # Build GraphQL command
    _, gql_cmd = run_security_tests.build_target_command("new_gql", targets=custom_tm)
    assert "--target-id" in gql_cmd
    assert "new_gql" in gql_cmd
    assert "--endpoint" in gql_cmd
    assert "/api/graphql" in gql_cmd
    assert "--payloads" in gql_cmd
    assert str(gql_payload.resolve()) in gql_cmd
