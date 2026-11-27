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


def test_schema_payloads_resolves_request_body_and_schema_refs_openapi3():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Ref Planner API", "version": "1.0.0"},
        "components": {
            "requestBodies": {
                "ChainedUserBody": {"$ref": "#/components/requestBodies/UserBody"},
                "UserBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UserInput"}
                        }
                    },
                },
                "LoginBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginCreds"}
                        }
                    },
                },
                "AdminLoginBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/AdminLoginCreds"}
                        }
                    },
                },
                "ArrayBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"type": "array", "items": {"type": "string"}}
                        }
                    },
                },
            },
            "schemas": {
                "BaseEntity": {
                    "type": "object",
                    "properties": {"display_name": {"type": "string"}},
                },
                "UserInput": {
                    "type": "object",
                    "properties": {"email": {"type": "string", "format": "email"}},
                },
                "ExtendedUser": {
                    "allOf": [
                        {"$ref": "#/components/schemas/BaseEntity"},
                        {"type": "object", "properties": {"bio": {"type": "string"}}},
                    ]
                },
                "NullableUser": {
                    "anyOf": [
                        {"$ref": "#/components/schemas/UserInput"},
                        {"type": "null"},
                    ]
                },
                "PrimitiveUnion": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "integer"},
                    ]
                },
                "LoginCreds": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                    },
                },
                "AdminLoginCreds": {
                    "allOf": [
                        {"$ref": "#/components/schemas/LoginCreds"},
                        {"type": "object", "properties": {"role": {"type": "string"}}},
                    ]
                },
            },
        },
        "paths": {
            "/users/schema-ref": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserInput"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}},
                }
            },
            "/users/reqbody-ref": {
                "put": {
                    "requestBody": {"$ref": "#/components/requestBodies/ChainedUserBody"},
                    "responses": {"200": {"description": "Updated"}},
                }
            },
            "/users/allof": {
                "patch": {
                    "requestBody": {
                        "content": {
                            "application/merge-patch+json": {
                                "schema": {"$ref": "#/components/schemas/ExtendedUser"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "Patched"}},
                }
            },
            "/users/nullable": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/NullableUser"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/users/array-ref": {
                "post": {
                    "requestBody": {"$ref": "#/components/requestBodies/ArrayBody"},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/users/primitive-union": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PrimitiveUnion"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/auth/login": {
                "post": {
                    "requestBody": {"$ref": "#/components/requestBodies/LoginBody"},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/v2/auth/login": {
                "post": {
                    "requestBody": {"$ref": "#/components/requestBodies/AdminLoginBody"},
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    payloads = rest.schema_payloads({"ref_api": (schema, "http://api.test")})

    def _ma(ep: str) -> list[rest.Payload]:
        return [p for p in payloads if p.endpoint == ep and p.attack_type == "MASS_ASSIGNMENT"]

    assert len(_ma("/users/schema-ref")) == 2
    assert len(_ma("/users/reqbody-ref")) == 2
    assert len(_ma("/users/allof")) == 2
    assert len(_ma("/users/nullable")) == 2
    assert _ma("/users/array-ref") == []
    assert _ma("/users/primitive-union") == []
    assert _ma("/auth/login") == []
    assert len(_ma("/v2/auth/login")) == 2


def test_schema_payloads_resolves_swagger2_body_param_refs():
    spec = {
        "swagger": "2.0",
        "info": {"title": "Swagger 2 Body API", "version": "1.0.0"},
        "host": "api.test",
        "basePath": "/",
        "definitions": {
            "ProfileUpdate": {
                "type": "object",
                "properties": {"email": {"type": "string", "format": "email"}},
            },
            "TagList": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "paths": {
            "/profiles": {
                "put": {
                    "consumes": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "required": True,
                            "schema": {"$ref": "#/definitions/ProfileUpdate"},
                        }
                    ],
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/tags": {
                "post": {
                    "consumes": ["application/json"],
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "required": True,
                            "schema": {"$ref": "#/definitions/TagList"},
                        }
                    ],
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    payloads = rest.schema_payloads({"sw2_api": (schema, "http://api.test")})

    profile_ma = [p for p in payloads if p.endpoint == "/profiles" and p.attack_type == "MASS_ASSIGNMENT"]
    tags_ma = [p for p in payloads if p.endpoint == "/tags" and p.attack_type == "MASS_ASSIGNMENT"]
    assert len(profile_ma) == 2
    assert tags_ma == []


def test_raw_ref_fallback_cycle_protection_and_pointer_unescaping():
    from unittest.mock import MagicMock

    spec_doc = {
        "components": {
            "requestBodies": {
                "User/Body~v1": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/CyclicA"}
                        }
                    }
                },
                "Escaped/Role~Body": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/EscapedObj"}
                        }
                    }
                },
            },
            "schemas": {
                "CyclicA": {"allOf": [{"$ref": "#/components/schemas/CyclicB"}]},
                "CyclicB": {"allOf": [{"$ref": "#/components/schemas/CyclicA"}]},
                "EscapedObj": {
                    "type": "object",
                    "properties": {"role": {"type": "string"}},
                },
            },
        }
    }

    mock_op_cycle = MagicMock()
    mock_op_cycle.method = "POST"
    mock_op_cycle.path = "/cycle"
    mock_op_cycle.schema.raw_schema = spec_doc
    op_raw_cycle = {
        "requestBody": {"$ref": "#/components/requestBodies/User~1Body~0v1"}
    }
    assert rest._is_mass_assignment_applicable(mock_op_cycle, op_raw_cycle) is False

    mock_op_escaped = MagicMock()
    mock_op_escaped.method = "POST"
    mock_op_escaped.path = "/auth/login"
    mock_op_escaped.schema.raw_schema = spec_doc
    op_raw_escaped = {
        "requestBody": {"$ref": "#/components/requestBodies/Escaped~1Role~0Body"}
    }
    assert rest._is_mass_assignment_applicable(mock_op_escaped, op_raw_escaped) is True


def test_schema_payloads_mass_assignment_media_type_applicability():
    obj_schema = {
        "type": "object",
        "properties": {"display_name": {"type": "string"}},
    }
    binary_obj_schema = {
        "type": "object",
        "properties": {"file": {"type": "string", "format": "binary"}},
    }

    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Media Type API", "version": "1.0.0"},
        "paths": {
            "/supported/json": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/supported/json-charset": {
                "post": {
                    "requestBody": {"content": {"application/json; charset=utf-8": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/supported/text-json": {
                "post": {
                    "requestBody": {"content": {"text/json": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/supported/vnd-json": {
                "patch": {
                    "requestBody": {"content": {"application/vnd.api+json": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/unsupported/text-plain-object": {
                "post": {
                    "requestBody": {"content": {"text/plain": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/unsupported/octet-stream-object": {
                "post": {
                    "requestBody": {"content": {"application/octet-stream": {"schema": binary_obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/unsupported/multipart-object": {
                "post": {
                    "requestBody": {"content": {"multipart/form-data": {"schema": binary_obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/unsupported/form-urlencoded": {
                "post": {
                    "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/unsupported/xml-object": {
                "post": {
                    "requestBody": {"content": {"application/xml": {"schema": obj_schema}}},
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/mixed/plain-object-json-array": {
                "post": {
                    "requestBody": {
                        "content": {
                            "text/plain": {"schema": obj_schema},
                            "application/json": {"schema": {"type": "array", "items": {"type": "string"}}},
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/mixed/plain-and-json-object": {
                "post": {
                    "requestBody": {
                        "content": {
                            "text/plain": {"schema": {"type": "string"}},
                            "application/json": {"schema": obj_schema},
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    payloads = rest.schema_payloads({"media_api": (schema, "http://api.test")})

    def _ma(ep: str) -> list[rest.Payload]:
        return [p for p in payloads if p.endpoint == ep and p.attack_type == "MASS_ASSIGNMENT"]

    assert len(_ma("/supported/json")) == 2
    assert len(_ma("/supported/json-charset")) == 2
    assert len(_ma("/supported/text-json")) == 2
    assert len(_ma("/supported/vnd-json")) == 2

    assert _ma("/unsupported/text-plain-object") == []
    assert _ma("/unsupported/octet-stream-object") == []
    assert _ma("/unsupported/multipart-object") == []
    assert _ma("/unsupported/form-urlencoded") == []
    assert _ma("/unsupported/xml-object") == []
    assert _ma("/mixed/plain-object-json-array") == []
    assert len(_ma("/mixed/plain-and-json-object")) == 2

    # Swagger 2.0 text/plain consumes with object schema must also be rejected
    sw2_plain = schemathesis.openapi.from_dict({
        "swagger": "2.0",
        "info": {"title": "SW2 Plain", "version": "1.0.0"},
        "host": "api.test",
        "basePath": "/",
        "definitions": {"Obj": obj_schema},
        "paths": {
            "/sw2-plain": {
                "post": {
                    "consumes": ["text/plain"],
                    "parameters": [{"in": "body", "name": "body", "schema": {"$ref": "#/definitions/Obj"}}],
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    })
    sw2_payloads = rest.schema_payloads({"sw2_plain": (sw2_plain, "http://api.test")})
    assert [p for p in sw2_payloads if p.attack_type == "MASS_ASSIGNMENT"] == []


def test_x_bundled_ref_resolution_and_fail_safe():
    from types import SimpleNamespace

    # 1. Real Schemathesis OpenApiBody x-bundled structure from schemathesis.openapi.from_dict
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Bundled Ref API", "version": "1.0.0"},
        "components": {
            "schemas": {
                "Profile": {
                    "type": "object",
                    "properties": {"bio": {"type": "string"}},
                },
                "User": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "profile": {"$ref": "#/components/schemas/Profile"},
                    },
                },
                "UserAlias": {"$ref": "#/components/schemas/User"},
                "AllOfUser": {
                    "allOf": [
                        {"$ref": "#/components/schemas/User"},
                        {"type": "object", "properties": {"role": {"type": "string"}}},
                    ]
                },
            }
        },
        "paths": {
            "/users/alias": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserAlias"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/auth/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserAlias"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/v2/auth/login": {
                "patch": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AllOfUser"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    op_alias = rest.find_operation(schema, "/users/alias", "POST")
    assert op_alias is not None
    alias_bodies = list(op_alias.body)
    assert len(alias_bodies) == 1
    assert isinstance(alias_bodies[0].raw_schema, dict)
    assert str(alias_bodies[0].raw_schema.get("$ref", "")).startswith("#/x-bundled/")
    assert isinstance(alias_bodies[0].raw_schema.get("x-bundled"), dict)

    payloads = rest.schema_payloads({"bundled_api": (schema, "http://api.test")})
    assert len([p for p in payloads if p.endpoint == "/users/alias" and p.attack_type == "MASS_ASSIGNMENT"]) == 2
    assert [p for p in payloads if p.endpoint == "/auth/login" and p.attack_type == "MASS_ASSIGNMENT"] == []
    assert len([p for p in payloads if p.endpoint == "/v2/auth/login" and p.attack_type == "MASS_ASSIGNMENT"]) == 2

    # 2. Fail-safe behavior for unresolved, non-dict, missing-container, and cyclic x-bundled refs
    unresolved_bundled = {
        "$ref": "#/x-bundled/missing_schema",
        "x-bundled": {"schema1": {"type": "object", "properties": {"a": {"type": "string"}}}},
    }
    non_dict_bundled = {
        "$ref": "#/x-bundled/bad_schema",
        "x-bundled": {"bad_schema": "not-a-dict"},
    }
    missing_container = {
        "$ref": "#/x-bundled/schema1",
    }
    cyclic_bundled = {
        "$ref": "#/x-bundled/schema1",
        "x-bundled": {
            "schema1": {"$ref": "#/x-bundled/schema2"},
            "schema2": {"$ref": "#/x-bundled/schema1"},
        },
    }

    for bad_schema in (unresolved_bundled, non_dict_bundled, missing_container, cyclic_bundled):
        assert rest._extract_object_body_info(bad_schema, None) == (False, {})
        fake_op = SimpleNamespace(
            method="POST",
            path="/bundled-bad",
            schema=SimpleNamespace(raw_schema={}),
            body=[SimpleNamespace(media_type="application/json", raw_schema=bad_schema)],
        )
        assert rest._is_mass_assignment_applicable(fake_op, {"requestBody": {"content": {}}}) is False
