"""Focused regression tests for GraphQL endpoint normalization and target configuration."""

import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from modules.graphql import run_graphql_fuzz1 as graphql
from core import TargetConfig


def test_graphql_fingerprint_normalizes_trailing_and_leading_slashes():
    h_canonical = graphql.fingerprint_of("dvga", "/graphql", "query", "sqli", "{ users }")
    h_trailing = graphql.fingerprint_of("dvga", "/graphql/", "query", "sqli", "{ users }")
    h_no_slash = graphql.fingerprint_of("dvga", "graphql", "query", "sqli", "{ users }")
    h_both = graphql.fingerprint_of("dvga", "graphql/", "query", "sqli", "{ users }")

    # All equivalent representations of the endpoint must produce identical fingerprints
    assert h_trailing == h_canonical
    assert h_no_slash == h_canonical
    assert h_both == h_canonical


def test_graphql_fingerprint_nested_and_root_endpoints():
    h_nested = graphql.fingerprint_of("dvga", "/api/v1/graphql", "query", "sqli", "{ users }")
    h_nested_slash = graphql.fingerprint_of("dvga", "/api/v1/graphql/", "query", "sqli", "{ users }")
    assert h_nested == h_nested_slash

    # Root endpoint "/" must remain "/"
    h_root = graphql.fingerprint_of("dvga", "/", "query", "sqli", "{ users }")
    assert h_root


def test_graphql_cli_respects_dvga_base_url_fallback(monkeypatch):
    monkeypatch.setenv("DVGA_BASE_URL", "http://custom-dvga:5013")
    mock_target = TargetConfig(
        target_id="dvga",
        name="DVGA",
        base_url="http://default-dvga:5013",
        settings={"protocol": "graphql", "endpoint": "/graphql"},
    )

    with patch("modules.graphql.run_graphql_fuzz1.TargetManager") as mock_tm, \
         patch("modules.graphql.run_graphql_fuzz1.load_payloads", return_value=[]), \
         patch.object(sys, "argv", ["run_graphql_fuzz1.py", "--payloads", "dummy.json"]):
        mock_tm.return_value.get_target.return_value = mock_target
        # Parse arguments and verify base_url resolution
        ap = graphql.argparse.ArgumentParser()
        ap.add_argument("--target-id", default="dvga")
        ap.add_argument("--payloads", required=True)
        ap.add_argument("--base-url", default=None)
        args = ap.parse_args(["--payloads", "dummy.json"])

        base_url = (
            args.base_url
            or (os.environ.get("DVGA_BASE_URL") if args.target_id == "dvga" else None)
            or mock_target.base_url
        )
        assert base_url == "http://custom-dvga:5013"


def test_graphql_cli_non_dvga_ignores_dvga_base_url(monkeypatch):
    monkeypatch.setenv("DVGA_BASE_URL", "http://custom-dvga:5013")
    mock_target = TargetConfig(
        target_id="custom_gql",
        name="Custom GraphQL",
        base_url="http://custom-gql:9999",
        settings={"protocol": "graphql", "endpoint": "/graphql"},
    )

    ap = graphql.argparse.ArgumentParser()
    ap.add_argument("--target-id", default="dvga")
    ap.add_argument("--payloads", required=True)
    ap.add_argument("--base-url", default=None)
    args = ap.parse_args(["--target-id", "custom_gql", "--payloads", "dummy.json"])

    base_url = (
        args.base_url
        or (os.environ.get("DVGA_BASE_URL") if args.target_id == "dvga" else None)
        or mock_target.base_url
    )
    # DVGA_BASE_URL must NOT leak into non-dvga target
    assert base_url == "http://custom-gql:9999"

# --------------------------------------------------------------------------
# ISS-REL-1: GraphQL state and durable report consistency
# --------------------------------------------------------------------------

import asyncio
import csv
import json
from unittest.mock import AsyncMock

from core.evidence import Finding, Evidence
from modules.graphql.run_graphql_fuzz1 import GraphQLPayload, RunState, fingerprint_of


def make_mock_graphql_finding(fp: str, target_app: str = "dvga", confirmed: bool = True) -> Finding:
    evidence = Evidence(
        status_code=500,
        response_headers={},
        response_signal=["test evidence"],
        response_time_ms=10.0,
        payload_hash="phash",
        request_hash="rhash",
        endpoint="/graphql",
        payload={"query": "{ users }"},
        auth_context={},
        previous_observations=[],
    )
    return Finding(
        finding_id=f"F-{fp[:8]}",
        run_id="run-test",
        timestamp="2026-10-25T00:00:00Z",
        target_app=target_app,
        endpoint="/graphql",
        method="POST",
        tool="graphql",
        attack_type="sqli",
        payload={"query": "{ users }"},
        status_code=500,
        response_time_ms=10.0,
        evidence=evidence,
        severity="high",
        confidence=0.9,
        confirmed=confirmed,
        lifecycle="confirmed" if confirmed else "rejected",
        fingerprint=fp,
    )


def test_graphql_unreported_confirmed_finding_is_recovered_on_next_run(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    state_file = results_dir / "state_graphql.json"
    state = RunState(state_file)

    payload = GraphQLPayload(query="{ users }", attack_type="sqli", target_app="dvga")
    fp = fingerprint_of("dvga", "/graphql", None, "sqli", "{ users }", None)

    # Simulate interrupted run: confirmed recorded in state, but CSV was NEVER written
    state.record(fp, "confirmed")
    assert state.status(fp) == "confirmed"

    # Next run MUST NOT silently skip this finding because it is missing from report
    mock_finding = make_mock_graphql_finding(fp, confirmed=True)
    with patch("modules.graphql.run_graphql_fuzz1.process_payload", new_callable=AsyncMock) as mock_proc:
        mock_proc.return_value = mock_finding
        findings = asyncio.run(
            graphql.run_all(
                [payload], "http://localhost:5013", "/graphql", {}, None, state, 1, 0, target_id="dvga"
            )
        )

    assert len(findings) == 1
    assert findings[0].fingerprint == fp
    assert mock_proc.call_count == 1


def test_graphql_reported_finding_syncs_state_without_duplicate_run(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    state_file = results_dir / "state_graphql.json"
    state = RunState(state_file)

    payload = GraphQLPayload(query="{ users }", attack_type="sqli", target_app="dvga")
    fp = fingerprint_of("dvga", "/graphql", None, "sqli", "{ users }", None)

    # Report persistence succeeded: finding is confirmed in both CSV and NDJSON
    csv_path = results_dir / "vulnerabilities.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fingerprint", "confirmed"])
        w.writerow([fp, "True"])

    ndjson_path = results_dir / "vulnerabilities.ndjson"
    ndjson_path.write_text(json.dumps({"fingerprint": fp, "confirmed": True}) + "\n", encoding="utf-8")

    # But state was NOT yet updated (e.g. process was killed right after writing reports)
    assert state.status(fp) is None

    # Next run must recognize durable finding, sync state to confirmed, and skip execution
    with patch("modules.graphql.run_graphql_fuzz1.process_payload", new_callable=AsyncMock) as mock_proc:
        findings = asyncio.run(
            graphql.run_all(
                [payload], "http://localhost:5013", "/graphql", {}, None, state, 1, 0, target_id="dvga"
            )
        )

    assert len(findings) == 0
    assert mock_proc.call_count == 0
    # State must be synchronized
    assert state.status(fp) == "confirmed"


def test_graphql_existing_confirmed_finding_is_skipped(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    state_file = results_dir / "state_graphql.json"
    state = RunState(state_file)

    payload = GraphQLPayload(query="{ users }", attack_type="sqli", target_app="dvga")
    fp = fingerprint_of("dvga", "/graphql", None, "sqli", "{ users }", None)

    # Durably recorded in both state and report
    state.record(fp, "confirmed")
    csv_path = results_dir / "vulnerabilities.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fingerprint", "confirmed"])
        w.writerow([fp, "True"])
    ndjson_path = results_dir / "vulnerabilities.ndjson"
    ndjson_path.write_text(json.dumps({"fingerprint": fp, "confirmed": True}) + "\n", encoding="utf-8")

    with patch("modules.graphql.run_graphql_fuzz1.process_payload", new_callable=AsyncMock) as mock_proc:
        findings = asyncio.run(
            graphql.run_all(
                [payload], "http://localhost:5013", "/graphql", {}, None, state, 1, 0, target_id="dvga"
            )
        )

    assert len(findings) == 0
    assert mock_proc.call_count == 0


def test_graphql_retry_limit_behavior(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    state_file = results_dir / "state_graphql.json"
    state = RunState(state_file)

    payload = GraphQLPayload(query="{ users }", attack_type="sqli", target_app="dvga")
    fp = fingerprint_of("dvga", "/graphql", None, "sqli", "{ users }", None)

    # 1. Attempts < 3 retries
    state.data[fp] = {"attempts": 2, "status": "rejected"}
    state.save()

    with patch("modules.graphql.run_graphql_fuzz1.process_payload", new_callable=AsyncMock) as mock_proc:
        mock_proc.return_value = None
        findings = asyncio.run(
            graphql.run_all(
                [payload], "http://localhost:5013", "/graphql", {}, None, state, 1, 0, target_id="dvga"
            )
        )
    assert mock_proc.call_count == 1

    # 2. Attempts >= 3 skips
    state.data[fp] = {"attempts": 3, "status": "rejected"}
    state.save()

    with patch("modules.graphql.run_graphql_fuzz1.process_payload", new_callable=AsyncMock) as mock_proc2:
        findings2 = asyncio.run(
            graphql.run_all(
                [payload], "http://localhost:5013", "/graphql", {}, None, state, 1, 0, target_id="dvga"
            )
        )
    assert mock_proc2.call_count == 0


def test_graphql_write_results_failure_propagates_non_zero_exit(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    fp = "test-fp"
    finding = make_mock_graphql_finding(fp)

    with patch("core.result_manager.ResultManager.append_findings", side_effect=OSError("Disk write failed")):
        with pytest.raises(OSError, match="Disk write failed"):
            graphql.write_results([finding], results_dir, "run-1", "http://test/graphql", 1, 0)


def test_graphql_write_results_deduplicates_csv_and_syncs_ndjson(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)
    fp = "test-fp"
    finding = make_mock_graphql_finding(fp)

    # 1. First write persists to both CSV and NDJSON
    graphql.write_results([finding], results_dir, "run-1", "http://test/graphql", 1, 0)

    csv_path = results_dir / "vulnerabilities.csv"
    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        rows_initial = list(csv.DictReader(f))
    assert len(rows_initial) == 1

    # Remove NDJSON to simulate partial write recovery
    ndjson_path = results_dir / "vulnerabilities.ndjson"
    ndjson_path.unlink()

    # 2. Second write with same finding should NOT duplicate CSV, but SHOULD re-populate NDJSON
    graphql.write_results([finding], results_dir, "run-2", "http://test/graphql", 1, 0)

    with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
        rows_after = list(csv.DictReader(f))
    assert len(rows_after) == 1, "Must NOT duplicate row in vulnerabilities.csv!"

    assert ndjson_path.exists()
    with ndjson_path.open("r", encoding="utf-8") as f:
        ndjson_records = [json.loads(line) for line in f if line.strip()]
    assert len(ndjson_records) == 1
    assert ndjson_records[0]["fingerprint"] == fp
