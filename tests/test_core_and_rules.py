from unittest.mock import Mock, patch

import asyncio
import json
from pathlib import Path

import httpx

from core import (ConfirmationEngine, Evidence, Finding, RequestScheduler,
                  ResponseObservation, compare_responses, confirmation_result,
                  redact_headers, snapshot_response, stable_finding_id)
from rules_engine import fetch_cves_for_keyword, match_cves_by_keyword


def test_finding_id_is_stable_and_payload_independent():
    first = stable_finding_id("VAmPI", "post", "/users/", "SQLi", "username")
    second = stable_finding_id("vampi", "POST", "/users", "sqli", "username")
    assert first == second


def test_auth_headers_are_redacted_but_correlatable():
    result = redact_headers({"Authorization": "Bearer secret", "Accept": "application/json"})
    assert result["Authorization"] == "<REDACTED>"
    assert result["Authorization_hash"]
    assert result["Accept"] == "application/json"


def test_nvd_fetch_paginates_until_total_results():
    def response(items, total):
        mocked = Mock()
        mocked.json.return_value = {
            "totalResults": total,
            "vulnerabilities": [{"cve": item} for item in items],
        }
        mocked.raise_for_status.return_value = None
        return mocked

    pages = [
        response([{"id": "CVE-1", "descriptions": []}], 2),
        response([{"id": "CVE-2", "descriptions": []}], 2),
    ]
    with patch("rules_engine.requests.get", side_effect=pages) as get:
        result = fetch_cves_for_keyword("SQL injection API", 30, None)

    assert [item["cve_id"] for item in result] == ["CVE-1", "CVE-2"]
    assert get.call_count == 2


def test_scheduler_retries_429_then_returns_success():
    class Response:
        def __init__(self, status_code, retry_after=None):
            self.status_code = status_code
            self.headers = {"Retry-After": str(retry_after)} if retry_after else {}

    async def run():
        scheduler = RequestScheduler(concurrency=1, max_retries=1)
        responses = iter((Response(429, 0), Response(200)))
        calls = 0

        async def operation():
            nonlocal calls
            calls += 1
            return next(responses)

        result = await scheduler.request("vampi", operation)
        return result.status_code, calls

    assert asyncio.run(run()) == (200, 2)


def test_confirmation_comparator_exposes_behavioral_difference():
    class Observation:
        status_code = 400
        body_hash = "same"
        headers_hash = "h1"
        response_time_ms = 20

    baseline = Observation()
    attack = Observation()
    attack.status_code = 500
    attack.body_hash = "different"
    attack.response_time_ms = 30
    assert set(compare_responses(baseline, attack)) == {
        "status_code", "body_hash", "response_time_ms"
    }


def test_confirmation_requires_attack_difference():
    baseline = ResponseObservation(200, "same", "headers", 20)
    attack = ResponseObservation(500, "different", "headers", 25)
    result = confirmation_result(baseline, attack, True)
    assert result.confirmed is True
    assert result.confidence == 0.9
    assert "status_code" in result.evidence


def test_body_only_difference_is_not_confirmation():
    baseline = ResponseObservation(200, "timestamp-a", "headers", 20)
    attack = ResponseObservation(200, "timestamp-b", "headers", 21)
    result = confirmation_result(baseline, attack, True)
    assert result.confirmed is False
    assert result.confidence == 0.55


def test_finding_requires_and_accepts_tool_field():
    finding = Finding(
        finding_id="F-test",
        run_id="run-test",
        timestamp="2026-09-05T00:00:00+00:00",
        target_app="vampi",
        endpoint="/users",
        method="POST",
        tool="schemathesis",
        attack_type="sqli",
        evidence=Evidence(),
        severity="high",
        confidence=0.9,
        fingerprint="fp-test",
    )
    assert finding.tool == "schemathesis"


def test_confirmation_engine_executes_baseline_then_attack():
    class Response:
        def __init__(self, status, body):
            self.status_code = status
            self.text = body
            self.headers = {}

    async def run():
        calls = []

        async def baseline():
            calls.append("baseline")
            return Response(200, '{"data":{"user":{}}}')

        async def attack():
            calls.append("attack")
            return Response(500, '{"errors":[{"message":"database error"}]}')

        return calls, await ConfirmationEngine().confirm(
            True, baseline, attack,
            lambda response, elapsed: snapshot_response(response, elapsed, graphql=True),
        )

    calls, result = asyncio.run(run())
    assert calls == ["baseline", "attack"]
    assert result.confirmed is True
    assert result.attack.graphql_errors == ("database error",)


def test_cve_technology_filter_requires_applicable_cpe():
    rules = {
        "cve_signals": [{
            "cve_id": "CVE-FLASK",
            "description": "server-side request forgery in Flask application",
            "cpe_uris": ["cpe:2.3:a:palletsproject:flask:2.0:*:*:*:*:*:*:*"],
        }, {
            "cve_id": "CVE-CISCO",
            "description": "server-side request forgery in Cisco router",
            "cpe_uris": ["cpe:2.3:h:cisco:router:1.0:*:*:*:*:*:*:*"],
        }],
    }
    result = match_cves_by_keyword(
        rules, "ssrf", technology={"framework": "flask"}
    )
    assert [item["cve_id"] for item in result] == ["CVE-FLASK"]


def test_graphql_process_uses_baseline_and_sets_tool(tmp_path: Path):
    from run_graphql_fuzz1 import GraphQLPayload, RunState, process_payload

    calls = []

    def handler(request):
        body = request.read().decode()
        calls.append(body)
        query = json.loads(body)["query"]
        if '"normal"' in query:
            return httpx.Response(200, json={"data": {"user": {"id": "1"}}})
        return httpx.Response(500, json={"errors": [{"message": "database error"}]})

    async def run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            payload = GraphQLPayload(
                query='query { user(id: "\' OR 1=1") { id } }',
                attack_type="sqli",
                payload_value="' OR 1=1",
            )
            state = RunState(tmp_path / "state.json")
            from core import RequestScheduler
            return await process_payload(
                client, RequestScheduler(max_retries=0), payload,
                "http://dvga", "/graphql", {}, None, state, 0,
            ), state, calls

    finding, state, requests = asyncio.run(run())
    assert len(requests) == 2
    assert 'normal' in json.loads(requests[0])["query"]
    assert finding.tool == "schemathesis"
    assert finding.lifecycle == "confirmed"
    assert state.status(finding.fingerprint) == "confirmed"
