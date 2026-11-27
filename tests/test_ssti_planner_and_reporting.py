"""Tests for SSTI differential validation, Test Planner applicability, and CVE/cURL reporting."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import schemathesis

import modules.rest.run_schemathesis1 as rest
from core.run_state import RunState
from core.semantic_mutator import SemanticMutationEngine
from core.ssti_validator import (
    PRIMARY_RESULT,
    SECONDARY_RESULT,
    SstiValidator,
    build_differential_ssti_probes,
)


class _DummyQueryCase:
    def __init__(self, path: str, query: dict):
        self.path = path
        self.query = query

    def as_transport_kwargs(self, base_url: str) -> dict:
        return {
            "method": "GET",
            "url": f"{base_url.rstrip('/')}{self.path}",
            "params": dict(self.query),
            "headers": {},
        }


# ======================================================================
# 1. SSTI High-Entropy Canary & Differential Validator
# ======================================================================


def test_semantic_mutator_uses_high_entropy_ssti_canaries():
    p_str = SemanticMutationEngine.inspect_param("name", "query", {"type": "string"})
    probes = SemanticMutationEngine.generate_probes(p_str)
    ssti_probes = [p for p in probes if p.attack_type == "SSTI"]

    assert len(ssti_probes) >= 3
    assert all("49" not in p.expected_signal for p in ssti_probes)
    assert all(PRIMARY_RESULT in p.expected_signal for p in ssti_probes)
    assert any("{{" in str(p.payload_value) for p in ssti_probes)
    assert any("${" in str(p.payload_value) for p in ssti_probes)
    assert any("<%=" in str(p.payload_value) for p in ssti_probes)


def test_build_differential_ssti_probes_preserves_delimiter_syntax():
    jinja = build_differential_ssti_probes("{{9187*8431}}")
    assert jinja is not None
    assert jinja.secondary_payload == "{{9199*8443}}"
    assert jinja.control_payload == "{{ssti_ctrl_canary_7x}}"
    assert jinja.secondary_expected == SECONDARY_RESULT

    el = build_differential_ssti_probes("${9187*8431}")
    assert el is not None
    assert el.secondary_payload == "${9199*8443}"
    assert el.control_payload == "${ssti_ctrl_canary_7x}"


def test_ssti_validator_confirms_differential_evaluation():
    verdict = SstiValidator.validate(
        attack_status=200,
        attack_body=f"Hello {PRIMARY_RESULT}",
        baseline_body="Hello world",
        initial_payload="{{9187*8431}}",
        initial_expected=PRIMARY_RESULT,
        secondary_status=200,
        secondary_body=f"Hello {SECONDARY_RESULT}",
        secondary_expected=SECONDARY_RESULT,
        control_status=200,
        control_body="Hello {{ssti_ctrl_canary_7x}}",
    )
    assert verdict is not None
    assert verdict.outcome == "confirmed"
    assert verdict.severity == "critical"
    assert verdict.confidence >= 0.90
    assert verdict.differential_verified is True


def test_ssti_validator_rejects_unevaluated_reflection_and_coincidental_match():
    unevaluated = SstiValidator.validate(
        attack_status=200,
        attack_body="Echo: {{9187*8431}}",
        baseline_body="Echo: normal",
        initial_payload="{{9187*8431}}",
        initial_expected=PRIMARY_RESULT,
    )
    assert unevaluated is not None
    assert unevaluated.outcome == "rejected"

    coincidental = SstiValidator.validate(
        attack_status=200,
        attack_body=f"Value: {PRIMARY_RESULT}",
        baseline_body="Value: 100",
        initial_payload="{{9187*8431}}",
        initial_expected=PRIMARY_RESULT,
        secondary_status=200,
        secondary_body="Value: literal {{9199*8443}}",
        secondary_expected=SECONDARY_RESULT,
        control_status=200,
        control_body="Value: {{ssti_ctrl_canary_7x}}",
    )
    assert coincidental is not None
    assert coincidental.outcome == "rejected"
    assert "differential_mismatch" in coincidental.evidence_refs


def test_e2e_process_fingerprint_group_confirms_reflected_ssti(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("tpl", "")
        if "{{9187*8431}}" in q:
            return httpx.Response(200, json={"rendered": f"hi {PRIMARY_RESULT}"})
        if "{{9199*8443}}" in q:
            return httpx.Response(200, json={"rendered": f"hi {SECONDARY_RESULT}"})
        return httpx.Response(200, json={"rendered": f"hi {q}"})

    pc = rest.PreparedCase(
        "fp-ssti-e2e",
        "test_api",
        "http://api.test",
        _DummyQueryCase("/render", {"tpl": "normal"}),
        _DummyQueryCase("/render", {"tpl": "{{9187*8431}}"}),
        rest.Payload(
            endpoint="/render",
            method="GET",
            target_param="tpl",
            param_location="query",
            attack_type="SSTI",
            payload_value="{{9187*8431}}",
            expected_signal=[PRIMARY_RESULT],
        ),
    )

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, "fp-ssti-e2e", [pc],
                {}, None, state, 0.0,
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "confirmed"
    assert findings[0].confirmed is True
    assert findings[0].severity == "critical"
    assert findings[0].curl_command is not None
    assert "http://api.test/render" in findings[0].curl_command


# ======================================================================
# 2. Test Planner Applicability (OpenAPI security & Mass Assignment)
# ======================================================================


def test_schema_payloads_skips_mass_assignment_on_auth_and_no_body_endpoints():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Planner API", "version": "1.0.0"},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/auth/login": {
                "post": {
                    "security": [],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/auth/logout": {
                "post": {
                    "responses": {"204": {"description": "Logged out"}},
                }
            },
            "/public/items/{id}": {
                "get": {
                    "security": [],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/users/{id}": {
                "put": {
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"email": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Updated"}},
                }
            },
        },
    }
    schema = schemathesis.openapi.from_dict(spec)
    payloads = rest.schema_payloads({"planner_api": (schema, "http://api.test")})

    login_ma = [p for p in payloads if p.endpoint == "/auth/login" and p.attack_type == "MASS_ASSIGNMENT"]
    logout_ma = [p for p in payloads if p.endpoint == "/auth/logout" and p.attack_type == "MASS_ASSIGNMENT"]
    users_ma = [p for p in payloads if p.endpoint == "/users/{id}" and p.attack_type == "MASS_ASSIGNMENT"]
    public_bola = [p for p in payloads if p.endpoint == "/public/items/{id}" and p.attack_type == "BOLA"]
    protected_bola = [p for p in payloads if p.endpoint == "/users/{id}" and p.attack_type == "BOLA"]

    assert login_ma == []
    assert logout_ma == []
    assert len(users_ma) == 2
    assert public_bola == []
    assert len(protected_bola) >= 1


# ======================================================================
# 3. Correlation (no guessed CVE) & Reproducibility (safe curl_command)
# ======================================================================


def test_cve_not_attached_without_technology_or_when_rejected(tmp_path: Path):
    rules = {
        "signals": {},
        "cve_signals": [
            {
                "cve_id": "CVE-2024-9999",
                "description": "Cross-site scripting (XSS) vulnerability in Express",
                "cpe_uris": ["cpe:2.3:a:expressjs:express:4.18:*:*:*:*:*:*:*"],
            }
        ],
    }

    # Case A: technology=None -> must not guess CVE even on candidate XSS
    payload_no_tech = rest.Payload(
        endpoint="/search",
        method="GET",
        target_param="q",
        param_location="query",
        attack_type="XSS",
        owasp_category="API8:2023",
        payload_value="<script>alert(1)</script>",
        expected_signal=["<script>alert(1)</script>"],
        technology=None,
    )
    det_no_tech, cves_no_tech = rest.detect_response(
        httpx.Response(
            200,
            text="<html><body><script>alert(1)</script></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        ),
        payload_no_tech,
        rules=rules,
    )
    assert det_no_tech.new_expected_signals == ["<script>alert(1)</script>"]
    assert cves_no_tech == []

    # Case B: technology set, but finding is rejected -> process_fingerprint_group must not attach CVE
    pc_rejected = rest.PreparedCase(
        "fp-cve-rej",
        "test_api",
        "http://api.test",
        _DummyQueryCase("/search", {"q": "normal"}),
        _DummyQueryCase("/search", {"q": "<script>alert(1)</script>"}),
        rest.Payload(
            endpoint="/search",
            method="GET",
            target_param="q",
            param_location="query",
            attack_type="XSS",
            owasp_category="API8:2023",
            payload_value="<script>alert(1)</script>",
            expected_signal=["<script>alert(1)</script>"],
            technology={"framework": "express"},
        ),
    )

    def clean_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": []})

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(clean_handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, "fp-cve-rej", [pc_rejected],
                {"Authorization": "Bearer super-secret-jwt-value"}, rules, state, 0.0,
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "rejected"
    assert findings[0].cve_matches == []
    assert findings[0].cve_confidence == 0.0
    assert findings[0].curl_command is not None
    assert "super-secret-jwt-value" not in findings[0].curl_command
    assert "Bearer <REDACTED>" in findings[0].curl_command
    assert "q=%3Cscript%3E" in findings[0].curl_command
