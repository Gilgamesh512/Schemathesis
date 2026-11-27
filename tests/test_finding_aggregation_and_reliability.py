"""Tests for Finding/Observation aggregation, pipeline reliability, and multi-format reporting."""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from core import (
    CircuitBreakerTrippedError,
    ConfirmationEngine,
    Evidence,
    Finding,
    Observation,
    ResultManager,
    RunState,
    SecurityReporter,
    merge_findings,
    snapshot_response,
    summarize_lifecycle,
)
from modules.rest import run_schemathesis1 as rest


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


def _make_prepared_case(fp: str, payload_val, expected_signal=None, attack_type="SQL_INJECTION"):
    payload = rest.Payload(
        endpoint="/items",
        method="GET",
        target_param="q",
        param_location="query",
        attack_type=attack_type,
        payload_value=payload_val,
        expected_signal=expected_signal or [],
        owasp_category="API8:2023",
        target_app="test_api",
    )
    return rest.PreparedCase(
        fp,
        "test_api",
        "http://api.test",
        _DummyCase("/items", {"q": "normal"}),
        _DummyCase("/items", {"q": payload_val}),
        payload,
    )


def test_snapshot_response_and_confirmation_handle_none_and_timeout():
    assert snapshot_response(None, 15.0) is None

    async def _run():
        engine = ConfirmationEngine()

        async def ok_baseline():
            return httpx.Response(200, json={"ok": True})

        async def none_attack():
            return None

        async def timeout_attack():
            raise httpx.ReadTimeout("timed out")

        res_none = await engine.confirm(True, ok_baseline, none_attack, snapshot_response)
        res_timeout = await engine.confirm(True, ok_baseline, timeout_attack, snapshot_response)
        return res_none, res_timeout

    res_none, res_timeout = asyncio.run(_run())
    assert res_none.confirmed is False
    assert res_none.candidate is False
    assert res_none.attack is None
    assert res_none.error == "No HTTP response received"

    assert res_timeout.confirmed is False
    assert res_timeout.candidate is False
    assert res_timeout.attack is None
    assert "timed out" in (res_timeout.error or "")


def test_process_fingerprint_group_aggregates_observations_preserving_candidate_and_error(tmp_path: Path):
    fp = "fp-agg-1"
    group = [
        _make_prepared_case(fp, "' OR '1'='1", expected_signal=["sql syntax"]),
        _make_prepared_case(fp, "harmless", expected_signal=["sql syntax"]),
        _make_prepared_case(fp, "timeout-trigger", expected_signal=["sql syntax"]),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if "OR" in q:
            return httpx.Response(500, text="SQL syntax error near OR")
        if q == "timeout-trigger":
            raise httpx.ReadTimeout("probe timed out", request=request)
        return httpx.Response(200, json={"items": []})

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
    assert finding.lifecycle == "candidate"
    assert finding.confirmed is False
    assert finding.observation_count == 3
    assert finding.error_count == 1
    assert [o.outcome for o in finding.observations] == ["candidate", "rejected", "error"]
    assert finding.observations[2].error is not None
    assert state.status(fp) == "candidate"


def test_all_error_probes_produce_error_lifecycle_not_rejected(tmp_path: Path):
    fp = "fp-err-1"
    group = [
        _make_prepared_case(fp, "p1"),
        _make_prepared_case(fp, "p2"),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

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
    assert finding.lifecycle == "error"
    assert finding.confirmed is False
    assert finding.severity == "unknown"
    assert finding.observation_count == 2
    assert finding.error_count == 2
    assert state.status(fp) == "error"


def test_run_state_error_does_not_overwrite_rejected_or_candidate(tmp_path: Path):
    state = RunState(tmp_path / "state.json")
    state.record("fp-a", "error")
    assert state.status("fp-a") == "error"
    state.record("fp-a", "rejected")
    assert state.status("fp-a") == "rejected"
    state.record("fp-a", "error")
    assert state.status("fp-a") == "rejected"
    state.record("fp-a", "candidate")
    assert state.status("fp-a") == "candidate"
    state.record("fp-a", "error")
    assert state.status("fp-a") == "candidate"


def test_result_manager_merges_same_run_fingerprint_across_calls_and_preserves_conflicts(tmp_path: Path):
    results_dir = tmp_path / "results"
    manager = ResultManager(root=tmp_path, results_dir=results_dir)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature123"

    obs1 = Observation(
        observation_id="OBS-1",
        timestamp="2026-11-26T00:00:00+00:00",
        payload="probe-1",
        status_code=200,
        signals=["rejected signal"],
        outcome="rejected",
        severity="info",
        confidence=0.2,
        validation_result="rejected",
    )
    f1 = Finding(
        finding_id="F-1",
        run_id="run-same",
        timestamp="2026-11-26T00:00:00+00:00",
        target_app="api",
        endpoint="/items",
        method="GET",
        tool="schemathesis",
        attack_type="SQL_INJECTION",
        owasp_category="API8:2023",
        payload="probe-1",
        status_code=200,
        evidence=Evidence(endpoint="/items", payload="probe-1", response_signal=["rejected signal"]),
        severity="info",
        confidence=0.2,
        confirmed=False,
        lifecycle="rejected",
        fingerprint="fp-dup",
        observations=[obs1],
        observation_count=1,
        error_count=0,
    )

    obs2 = Observation(
        observation_id="OBS-2",
        timestamp="2026-11-26T00:01:00+00:00",
        payload={"token": jwt},
        status_code=500,
        signals=["SQL syntax error"],
        outcome="candidate",
        severity="high",
        confidence=0.55,
        validation_result="candidate",
    )
    f2 = Finding(
        finding_id="F-1",
        run_id="run-same",
        timestamp="2026-11-26T00:01:00+00:00",
        target_app="api",
        endpoint="/items",
        method="GET",
        tool="schemathesis",
        attack_type="SQL_INJECTION",
        owasp_category="API1:2023",  # intentional metadata conflict
        payload={"token": jwt},
        status_code=500,
        evidence=Evidence(endpoint="/items", payload={"token": jwt}, response_signal=["SQL syntax error"]),
        severity="high",
        confidence=0.55,
        confirmed=False,
        lifecycle="candidate",
        fingerprint="fp-dup",
        observations=[obs2],
        observation_count=1,
        error_count=0,
    )

    fields = list(Finding.model_fields.keys())
    manager.append_findings([f1], source="schemathesis", fieldnames=fields)
    manager.append_findings([f2], source="schemathesis", fieldnames=fields)

    ndjson_lines = [
        json.loads(line)
        for line in (results_dir / "vulnerabilities.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(ndjson_lines) == 1
    rec = ndjson_lines[0]
    assert rec["lifecycle"] == "candidate"
    assert rec["observation_count"] == 2
    assert len(rec["observations"]) == 2
    assert jwt not in json.dumps(rec)
    assert any(
        isinstance(p, dict) and p.get("role") == "metadata_conflict"
        for p in rec["evidence"]["previous_observations"]
    )

    with (results_dir / "vulnerabilities.csv").open("r", newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    assert len(csv_rows) == 1
    assert int(csv_rows[0]["observation_count"]) == 2
    assert len(json.loads(csv_rows[0]["observations"])) == 2
    assert jwt not in csv_rows[0]["observations"]


def test_run_all_does_not_swallow_programming_errors_or_cancellation(tmp_path: Path):
    pc = _make_prepared_case("fp-bug", "1")
    state = RunState(tmp_path / "state.json")

    async def _raise_type_error(*args, **kwargs):
        raise TypeError("unexpected bug in detector")

    async def _run_bug():
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(rest, "process_fingerprint_group", _raise_type_error)
            await rest.run_all([pc], {}, None, state, 1, 0)

    with pytest.raises(TypeError, match="unexpected bug"):
        asyncio.run(_run_bug())

    async def _raise_cancel(*args, **kwargs):
        raise asyncio.CancelledError()

    async def _run_cancel():
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(rest, "process_fingerprint_group", _raise_cancel)
            await rest.run_all([pc], {}, None, state, 1, 0)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_run_cancel())


def test_circuit_breaker_marks_manifest_status_not_completed(tmp_path: Path):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Test", "version": "1.0.0"},
        "servers": [{"url": "http://api.test"}],
        "paths": {
            "/items": {
                "get": {
                    "parameters": [{"name": "id", "in": "query", "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    schema = rest.schemathesis.openapi.from_dict(spec)
    results_dir = tmp_path / "results"

    async def _cb_request(*args, **kwargs):
        raise CircuitBreakerTrippedError("target halted after 15 5xx")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(rest.RequestScheduler, "request", _cb_request)
        findings = rest.execute_rest_scan(
            targets={"test_api": (schema, "http://api.test")},
            targets_desc="test_api=memory",
            results_dir=results_dir,
            concurrency=1,
            rate_limit_ms=0,
        )

    assert len(findings) >= 1
    assert all(f.lifecycle == "error" for f in findings)
    manifest_files = list(results_dir.glob("rest-*/manifest.json"))
    assert len(manifest_files) == 1
    manifest = json.loads(manifest_files[0].read_text(encoding="utf-8"))
    assert manifest["metadata"]["status"] == "aborted_circuit_breaker"
    assert len(manifest["metadata"]["execution_errors"]) >= 1


def test_reporter_and_sarif_support_legacy_and_aggregated_findings(tmp_path: Path):
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True)

    # Legacy finding without observations/lifecycle/observation_count + new finding with observations
    legacy = {
        "finding_id": "F-LEG",
        "run_id": "run-1",
        "timestamp": "2026-10-01T00:00:00+00:00",
        "target_app": "legacy_api",
        "endpoint": "/legacy",
        "method": "GET",
        "attack_type": "SQLI",
        "severity": "medium",
        "confirmed": False,
        "owasp_category": "API8:2023",
        "evidence": "legacy signal",
        "fingerprint": "fp-leg",
    }
    modern = Finding(
        finding_id="F-MOD",
        run_id="run-1",
        timestamp="2026-11-26T00:00:00+00:00",
        target_app="modern_api",
        endpoint="/modern",
        method="GET",
        tool="schemathesis",
        attack_type="BOLA",
        owasp_category="API1:2023",
        evidence=Evidence(endpoint="/modern", response_signal=["confirmed"]),
        severity="high",
        confidence=0.95,
        confirmed=True,
        lifecycle="confirmed",
        fingerprint="fp-mod",
        observations=[
            Observation(
                observation_id="OBS-M1",
                timestamp="2026-11-26T00:00:00+00:00",
                outcome="confirmed",
                severity="high",
                confidence=0.95,
                validation_result="confirmed",
            )
        ],
        observation_count=1,
        error_count=0,
    ).model_dump()

    (results_dir / "vulnerabilities.ndjson").write_text(
        json.dumps(legacy) + "\n" + json.dumps(modern) + "\n",
        encoding="utf-8",
    )

    reporter = SecurityReporter(results_dir)
    loaded = reporter.load_findings()
    assert len(loaded) == 2
    assert loaded[0]["observations"] == []
    assert loaded[0]["observation_count"] == 0
    assert loaded[1]["observation_count"] == 1
    assert loaded[1]["lifecycle"] == "confirmed"

    html_path = reporter.generate_html_report(loaded)
    sarif_path = results_dir / "vulnerabilities.sarif"
    assert html_path.exists()
    assert sarif_path.exists()
    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert len(sarif_doc["runs"][0]["results"]) == 2
    assert sarif_doc["runs"][0]["results"][1]["properties"]["observation_count"] == 1


def test_summarize_lifecycle_precedence():
    assert summarize_lifecycle(["error", "rejected"]) == "rejected"
    assert summarize_lifecycle(["candidate", "rejected", "error"]) == "candidate"
    assert summarize_lifecycle(["rejected", "inconclusive"]) == "inconclusive"
    assert summarize_lifecycle(["error", "error"]) == "error"
    assert summarize_lifecycle(["candidate", "confirmed", "rejected"]) == "confirmed"


def test_request_scheduler_retries_transient_errors_and_never_returns_none():
    async def _run():
        scheduler = rest.RequestScheduler(max_retries=1)
        attempts = 0

        async def flaky_op():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise httpx.ConnectError("transient failure")
            return httpx.Response(200, json={"ok": True})

        resp = await scheduler.request("api", flaky_op)
        assert resp is not None
        assert resp.status_code == 200
        assert attempts == 2

        async def deterministic_err():
            raise ValueError("invalid schema parameter")

        with pytest.raises(ValueError, match="invalid schema parameter"):
            await scheduler.request("api", deterministic_err)

    asyncio.run(_run())


def test_build_baseline_case_populates_missing_path_parameters():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Items", "version": "1.0.0"},
        "servers": [{"url": "http://api.test"}],
        "paths": {
            "/products/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
                "put": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"title": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "updated"}},
                },
            }
        },
    }
    schema = rest.schemathesis.openapi.from_dict(spec)
    op_get = rest.find_operation(schema, "/products/{id}", "get")
    case = rest.build_baseline_case(schema, op_get)
    kwargs = case.as_transport_kwargs(base_url="http://api.test")
    assert "/products/" in kwargs["url"]
    assert "{id}" not in kwargs["url"]

    # Also verify body-location attacks on path-parameterized endpoints preserve path_parameters
    op_put = rest.find_operation(schema, "/products/{id}", "put")
    baseline_put = rest.build_baseline_case(schema, op_put)
    mass_payload = rest.Payload(
        endpoint="/products/{id}",
        method="PUT",
        target_param="role",
        param_location="body",
        attack_type="MASS_ASSIGNMENT",
        payload_value="admin",
    )
    attack_case = rest.build_case(schema, op_put, mass_payload, baseline_case=baseline_put)
    put_kwargs = attack_case.as_transport_kwargs(base_url="http://api.test")
    assert "{id}" not in put_kwargs["url"]
    assert put_kwargs["json"]["role"] == "admin"


def test_fresh_scan_does_not_skip_past_max_attempts_unless_resume_enabled(tmp_path: Path):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Fixed Target", "version": "1.0.0"},
        "servers": [{"url": "http://api.test"}],
        "paths": {
            "/items": {
                "get": {
                    "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    schema = rest.schemathesis.openapi.from_dict(spec)
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Pre-populate state.json as if the same target already ran >= MAX_ATTEMPTS_PER_FINGERPRINT times
    payloads = rest.schema_payloads({"fixed_target": (schema, "http://api.test")})
    prepared = rest.prepare_cases(payloads, {"fixed_target": (schema, "http://api.test")})
    state = RunState(results_dir / "state.json")
    for pc in prepared:
        state.data[pc.fingerprint] = {"attempts": 5, "status": "confirmed"}
    state.save()

    def ok_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    # Verify fresh run_all (default skip_from_state=False) executes all groups
    async def _run_fresh():
        async with httpx.AsyncClient(transport=httpx.MockTransport(ok_transport)) as client:
            groups: dict[str, list] = {}
            for pc in prepared:
                groups.setdefault(pc.fingerprint, []).append(pc)
            scheduler = rest.RequestScheduler(max_retries=0)
            out = []
            for fp, grp in groups.items():
                out.extend(
                    await rest.process_fingerprint_group(
                        client, scheduler, fp, grp, {}, None, state, 0.0
                    )
                )
            return out, len(groups)

    findings_fresh, total_groups = asyncio.run(_run_fresh())
    assert len(findings_fresh) == total_groups
    assert total_groups >= 5

    # Verify opt-in skip_from_state=True skips when state has confirmed / max attempts
    async def _run_resumed():
        async with httpx.AsyncClient(transport=httpx.MockTransport(ok_transport)) as client:
            scheduler = rest.RequestScheduler(max_retries=0)
            pc0 = prepared[0]
            return await rest.process_fingerprint_group(
                client, scheduler, pc0.fingerprint, [pc0], {}, None, state, 0.0,
                skip_from_state=True,
            )

    assert asyncio.run(_run_resumed()) == []
