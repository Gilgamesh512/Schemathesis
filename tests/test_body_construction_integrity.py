"""Regression tests for AUD-02B-I: REST Request Body Construction & Baseline Integrity."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import schemathesis

from modules.rest import run_schemathesis1 as rest


def _make_ma_payload(endpoint: str, method: str = "PUT", target_param: str = "role", payload_value="admin") -> rest.Payload:
    return rest.Payload(
        endpoint=endpoint,
        method=method,
        target_param=target_param,
        param_location="body",
        attack_type="MASS_ASSIGNMENT",
        payload_value=payload_value,
        owasp_category="API3:2023",
        context="schema_conformant",
    )


def test_strategy_failure_synthesizes_required_body_and_preserves_siblings_and_nested_objects():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Profile API", "version": "1.0.0"},
        "paths": {
            "/users/{id}/profile": {
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
                                    "required": ["display_name", "age", "prefs"],
                                    "properties": {
                                        "display_name": {"type": "string", "minLength": 3},
                                        "age": {"type": "integer", "minimum": 18, "maximum": 120},
                                        "prefs": {
                                            "type": "object",
                                            "required": ["theme"],
                                            "properties": {
                                                "theme": {"type": "string", "enum": ["light", "dark"]},
                                            },
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    op = rest.find_operation(schema, "/users/{id}/profile", "PUT")
    assert op is not None

    with patch.object(op, "as_strategy", side_effect=RuntimeError("strategy failed")):
        baseline = rest.build_baseline_case(schema, op)

    assert isinstance(baseline.body, dict)
    assert baseline.media_type == "application/json"
    assert isinstance(baseline.body["display_name"], str)
    assert len(baseline.body["display_name"]) >= 3
    assert isinstance(baseline.body["age"], int)
    assert 18 <= baseline.body["age"] <= 120
    assert baseline.body["prefs"] == {"theme": "light"}

    snapshot_before = {
        "display_name": baseline.body["display_name"],
        "age": baseline.body["age"],
        "prefs": dict(baseline.body["prefs"]),
    }

    attack_role = rest.build_case(
        schema, op, _make_ma_payload("/users/{id}/profile", "PUT", "role", "admin"), baseline_case=baseline
    )
    attack_admin = rest.build_case(
        schema, op, _make_ma_payload("/users/{id}/profile", "PUT", "is_admin", True), baseline_case=baseline
    )

    # Sibling and nested required fields survive attack construction
    assert attack_role.body["display_name"] == snapshot_before["display_name"]
    assert attack_role.body["age"] == snapshot_before["age"]
    assert attack_role.body["prefs"] == {"theme": "light"}
    assert attack_role.body["role"] == "admin"
    assert "is_admin" not in attack_role.body

    assert attack_admin.body["display_name"] == snapshot_before["display_name"]
    assert attack_admin.body["prefs"] == {"theme": "light"}
    assert attack_admin.body["is_admin"] is True
    assert "role" not in attack_admin.body

    # Mutating nested dict in attack case does not contaminate baseline
    attack_role.body["prefs"]["theme"] = "mutated"
    assert baseline.body == snapshot_before
    assert "role" not in baseline.body
    assert "is_admin" not in baseline.body


def test_baseline_privilege_safety_blocks_unsafe_defaults_examples_and_enums():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Privilege Safety API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": [
                                        "username",
                                        "is_admin",
                                        "role",
                                        "tier_role",
                                        "permissions",
                                    ],
                                    "properties": {
                                        "username": {"type": "string"},
                                        "is_admin": {"type": "boolean", "default": True, "example": True},
                                        "role": {"type": "string", "enum": ["admin", "superuser", "member"]},
                                        "tier_role": {"type": "string", "default": "administrator", "example": "root"},
                                        "permissions": {
                                            "type": "array",
                                            "default": ["manage_users"],
                                            "items": {"type": "string"},
                                        },
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "Created"}},
                }
            },
            "/impossible-priv": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["role"],
                                    "properties": {
                                        "role": {"type": "string", "enum": ["admin", "superuser"]},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "Created"}},
                }
            },
            "/impossible-bool": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["is_admin"],
                                    "properties": {
                                        "is_admin": {"type": "boolean", "enum": [True]},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "Created"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)

    op_users = rest.find_operation(schema, "/users", "POST")
    assert op_users is not None
    baseline = rest.build_baseline_case(schema, op_users)
    assert baseline.body["is_admin"] is False
    assert baseline.body["role"] == "member"
    assert baseline.body["tier_role"] == "user"
    assert baseline.body["permissions"] == []

    # Even if strategy().example() succeeds and emits privileged values, baseline sanitizes them
    priv_strategy_case = schema.make_case(
        operation=op_users,
        method="POST",
        path="/users",
        body={
            "username": "alice",
            "is_admin": True,
            "role": "admin",
            "tier_role": "administrator",
            "permissions": ["manage_users"],
        },
        media_type="application/json",
    )
    mock_strategy = MagicMock()
    mock_strategy.return_value.example.return_value = priv_strategy_case
    with patch.object(op_users, "as_strategy", mock_strategy):
        sanitized_baseline = rest.build_baseline_case(schema, op_users)
    assert sanitized_baseline.body["username"] == "alice"
    assert sanitized_baseline.body["is_admin"] is False
    assert sanitized_baseline.body["role"] == "member"
    assert sanitized_baseline.body["tier_role"] == "user"
    assert sanitized_baseline.body["permissions"] == []

    # Required privilege fields with NO safe value must fail baseline construction cleanly
    for ep in ("/impossible-priv", "/impossible-bool"):
        op_bad = rest.find_operation(schema, ep, "POST")
        assert op_bad is not None
        with pytest.raises(ValueError):
            rest.build_baseline_case(schema, op_bad)


def test_ref_x_bundled_allof_oneof_anyof_and_cycle_failure():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Composition API", "version": "1.0.0"},
        "components": {
            "schemas": {
                "Base": {
                    "type": "object",
                    "required": ["account_name"],
                    "properties": {"account_name": {"type": "string"}},
                },
                "Address": {
                    "type": "object",
                    "required": ["city"],
                    "properties": {"city": {"type": "string"}},
                },
                "AllOfPayload": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Base"},
                        {
                            "type": "object",
                            "required": ["address"],
                            "properties": {"address": {"$ref": "#/components/schemas/Address"}},
                        },
                    ]
                },
                "UnionPayload": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["email"],
                            "properties": {"email": {"type": "string", "format": "email"}},
                        },
                        {
                            "type": "object",
                            "required": ["phone"],
                            "properties": {"phone": {"type": "string"}},
                        },
                    ]
                },
                "NullableAnyOf": {
                    "anyOf": [
                        {"type": "null"},
                        {"$ref": "#/components/schemas/Address"},
                    ]
                },
            }
        },
        "paths": {
            "/allof": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AllOfPayload"}}},
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/oneof": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UnionPayload"}}},
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/anyof": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/NullableAnyOf"}}},
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)

    # allOf + x-bundled nested $ref
    op_allof = rest.find_operation(schema, "/allof", "POST")
    assert op_allof is not None
    b_allof = rest.build_baseline_case(schema, op_allof)
    assert b_allof.body["account_name"] == "sample_text"
    assert b_allof.body["address"] == {"city": "sample_text"}

    # oneOf selects a single deterministic branch without merging branches
    op_oneof = rest.find_operation(schema, "/oneof", "POST")
    assert op_oneof is not None
    b_oneof = rest.build_baseline_case(schema, op_oneof)
    assert set(b_oneof.body.keys()) == {"email"}
    assert "phone" not in b_oneof.body

    # anyOf skips null and builds Address object
    op_anyof = rest.find_operation(schema, "/anyof", "POST")
    assert op_anyof is not None
    b_anyof = rest.build_baseline_case(schema, op_anyof)
    assert b_anyof.body == {"city": "sample_text"}

    # Cycle, depth overflow, and unresolved $ref must return None (never silently {})
    cyclic_bundled = {
        "$ref": "#/x-bundled/s1",
        "x-bundled": {
            "s1": {"$ref": "#/x-bundled/s2"},
            "s2": {"$ref": "#/x-bundled/s1"},
        },
    }
    unresolved_ref = {"$ref": "#/components/schemas/DoesNotExist"}
    deep_chain = {
        "type": "object",
        "required": ["a"],
        "properties": {
            "a": {
                "type": "object",
                "required": ["b"],
                "properties": {
                    "b": {
                        "type": "object",
                        "required": ["c"],
                        "properties": {
                            "c": {
                                "type": "object",
                                "required": ["d"],
                                "properties": {
                                    "d": {
                                        "type": "object",
                                        "required": ["e"],
                                        "properties": {
                                            "e": {"type": "object", "required": ["f"], "properties": {"f": {"type": "string"}}}
                                        },
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
    }
    assert rest._build_safe_json_body_sample(cyclic_bundled, {}) is None
    assert rest._build_safe_json_body_sample(unresolved_ref, {}) is None
    assert rest._build_safe_json_body_sample(deep_chain, {}) is None

    # Required broken schema refuses to emit incomplete attack body even when baseline_case=None
    broken_spec = {
        "openapi": "3.0.3",
        "info": {"title": "Broken", "version": "1.0.0"},
        "paths": {
            "/broken": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["role"],
                                    "properties": {"role": {"type": "string", "enum": ["admin"]}},
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    broken_schema = schemathesis.openapi.from_dict(broken_spec)
    broken_op = rest.find_operation(broken_schema, "/broken", "POST")
    assert broken_op is not None
    with pytest.raises(ValueError):
        rest.build_case(broken_schema, broken_op, _make_ma_payload("/broken", "POST"), baseline_case=None)


def test_media_type_consistency_and_never_forcing_undeclared_application_json():
    body_obj = {
        "type": "object",
        "required": ["title"],
        "properties": {"title": {"type": "string"}},
    }
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Media Consistency", "version": "1.0.0"},
        "paths": {
            "/prefer-json": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/merge-patch+json": {"schema": body_obj},
                            "application/json": {"schema": body_obj},
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/xml-and-merge-patch": {
                "patch": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/xml": {"schema": body_obj},
                            "application/merge-patch+json": {"schema": body_obj},
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/text-json-only": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/json": {"schema": body_obj},
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/text-plain-only": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "text/plain": {"schema": body_obj},
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }
    schema = schemathesis.openapi.from_dict(spec)

    # 1. Prefers application/json over other JSON subtypes
    op_pref = rest.find_operation(schema, "/prefer-json", "POST")
    b_pref = rest.build_baseline_case(schema, op_pref)
    a_pref = rest.build_case(schema, op_pref, _make_ma_payload("/prefer-json", "POST"), baseline_case=b_pref)
    assert b_pref.media_type == "application/json"
    assert a_pref.media_type == "application/json"
    assert b_pref.as_transport_kwargs(base_url="http://api.test")["headers"]["Content-Type"] == "application/json"
    assert a_pref.as_transport_kwargs(base_url="http://api.test")["headers"]["Content-Type"] == "application/json"

    # 2. Multi-media-type (xml + merge-patch+json) selects merge-patch+json and NEVER forces application/json
    op_mp = rest.find_operation(schema, "/xml-and-merge-patch", "PATCH")
    b_mp = rest.build_baseline_case(schema, op_mp)
    a_mp = rest.build_case(schema, op_mp, _make_ma_payload("/xml-and-merge-patch", "PATCH"), baseline_case=b_mp)
    assert b_mp.media_type == "application/merge-patch+json"
    assert a_mp.media_type == "application/merge-patch+json"
    assert b_mp.as_transport_kwargs(base_url="http://api.test")["headers"]["Content-Type"] == "application/merge-patch+json"
    assert a_mp.as_transport_kwargs(base_url="http://api.test")["headers"]["Content-Type"] == "application/merge-patch+json"

    # 3. text/json only
    op_tj = rest.find_operation(schema, "/text-json-only", "POST")
    b_tj = rest.build_baseline_case(schema, op_tj)
    a_tj = rest.build_case(schema, op_tj, _make_ma_payload("/text-json-only", "POST"), baseline_case=b_tj)
    assert b_tj.media_type == "text/json"
    assert a_tj.media_type == "text/json"

    # 4. Unsupported media type only (text/plain) refuses MA body construction
    op_tp = rest.find_operation(schema, "/text-plain-only", "POST")
    with pytest.raises(ValueError):
        rest.build_case(schema, op_tp, _make_ma_payload("/text-plain-only", "POST"), baseline_case=None)


def test_required_non_auth_query_header_params_and_auth_untouched():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Params & Auth API", "version": "1.0.0"},
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                "apiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "apiKeyQuery": {"type": "apiKey", "in": "query", "name": "api_key"},
            }
        },
        "security": [{"bearerAuth": []}, {"apiKeyHeader": []}, {"apiKeyQuery": []}],
        "paths": {
            "/orders": {
                "post": {
                    "parameters": [
                        {"name": "dry_run", "in": "query", "required": True, "schema": {"type": "boolean"}},
                        {"name": "optional_tag", "in": "query", "required": False, "schema": {"type": "string"}},
                        {"name": "X-Tenant-Id", "in": "header", "required": True, "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["item"],
                                    "properties": {"item": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {"201": {"description": "Created"}},
                }
            },
            "/no-body-ping": {
                "get": {
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    op_orders = rest.find_operation(schema, "/orders", "POST")
    baseline = rest.build_baseline_case(schema, op_orders)
    attack = rest.build_case(schema, op_orders, _make_ma_payload("/orders", "POST"), baseline_case=baseline)

    b_kw = baseline.as_transport_kwargs(base_url="http://api.test")
    a_kw = attack.as_transport_kwargs(base_url="http://api.test")

    # Required non-auth query and header populated; optional query omitted
    assert b_kw["params"]["dry_run"] is False
    assert a_kw["params"]["dry_run"] is False
    assert "optional_tag" not in b_kw["params"]
    assert b_kw["headers"]["X-Tenant-Id"] == "sample_text"
    assert a_kw["headers"]["X-Tenant-Id"] == "sample_text"

    # Auth headers/query parameters must NOT be fabricated
    for hdr_map in (b_kw["headers"], a_kw["headers"]):
        lower_hdrs = {k.lower() for k in hdr_map}
        assert "authorization" not in lower_hdrs
        assert "x-api-key" not in lower_hdrs
    assert "api_key" not in b_kw["params"]
    assert "api_key" not in a_kw["params"]

    # Existing no-body operation retains compatible behavior
    op_ping = rest.find_operation(schema, "/no-body-ping", "GET")
    b_ping = rest.build_baseline_case(schema, op_ping)
    assert type(b_ping.body).__name__ == "NotSet"


def test_build_case_minimal_mock_without_baseline_remains_compatible():
    mock_op = MagicMock()
    mock_op.path = "/mock/items"
    mock_op.method = "POST"
    mock_op.definition.raw = None

    mock_schema = MagicMock()
    mock_schema.make_case.side_effect = lambda **kw: SimpleNamespace(**kw)

    case = rest.build_case(mock_schema, mock_op, _make_ma_payload("/mock/items", "POST"), baseline_case=None)
    assert case.body == {"role": "admin"}


def test_recursive_strategy_sanitization_nested_arrays_enums_and_immutability():
    import copy

    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Recursive Sanitize API", "version": "1.0.0"},
        "components": {
            "schemas": {
                "MemberItem": {
                    "type": "object",
                    "required": ["username", "role", "is_admin"],
                    "properties": {
                        "username": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "member", "user"]},
                        "is_admin": {"type": "boolean"},
                    },
                },
                "GroupEntry": {
                    "allOf": [
                        {
                            "type": "object",
                            "required": ["members"],
                            "properties": {
                                "members": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/MemberItem"},
                                }
                            },
                        }
                    ]
                },
                "UsersBatch": {
                    "type": "object",
                    "required": ["users"],
                    "properties": {
                        "users": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/MemberItem"},
                        },
                        "groups": {
                            "type": "array",
                            "items": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/GroupEntry"},
                            },
                        },
                    },
                },
            }
        },
        "paths": {
            "/batch": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UsersBatch"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/req-unsafe-array": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["users"],
                                    "properties": {
                                        "users": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "required": ["username", "role"],
                                                "properties": {
                                                    "username": {"type": "string"},
                                                    "role": {"type": "string", "enum": ["admin", "superuser"]},
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/opt-unsafe-array": {
                "post": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["users"],
                                    "properties": {
                                        "users": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "required": ["username"],
                                                "properties": {
                                                    "username": {"type": "string"},
                                                    "role": {"type": "string", "enum": ["admin", "superuser"]},
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)

    # 1-4 & 8. Nested array of objects (role=admin, is_admin=True), multi-level nested arrays,
    # safe enum selection, and original strategy body immutability
    op_batch = rest.find_operation(schema, "/batch", "POST")
    assert op_batch is not None
    raw_strategy_body = {
        "users": [
            {"username": "alice", "role": "admin", "is_admin": False},
            {"username": "bob", "role": "member", "is_admin": True},
        ],
        "groups": [
            [
                {
                    "members": [
                        {"username": "carol", "role": "superuser", "is_admin": True}
                    ]
                }
            ]
        ],
    }
    original_snapshot = copy.deepcopy(raw_strategy_body)

    strategy_case = schema.make_case(
        operation=op_batch,
        method="POST",
        path="/batch",
        body=raw_strategy_body,
        media_type="application/json",
    )
    mock_strategy = MagicMock()
    mock_strategy.return_value.example.return_value = strategy_case
    with patch.object(op_batch, "as_strategy", mock_strategy):
        baseline = rest.build_baseline_case(schema, op_batch)

    assert baseline.body["users"][0]["role"] in ("user", "member")
    assert baseline.body["users"][0]["is_admin"] is False
    assert baseline.body["users"][1]["role"] in ("user", "member")
    assert baseline.body["users"][1]["is_admin"] is False
    assert baseline.body["groups"][0][0]["members"][0]["role"] in ("user", "member")
    assert baseline.body["groups"][0][0]["members"][0]["is_admin"] is False
    # Original input body must not be mutated in-place
    assert raw_strategy_body == original_snapshot

    # 5. Unsafe enum on required sensitive field inside nested array must fail baseline construction
    op_req_unsafe = rest.find_operation(schema, "/req-unsafe-array", "POST")
    assert op_req_unsafe is not None
    unsafe_req_body = {"users": [{"username": "alice", "role": "admin"}]}
    unsafe_req_snapshot = copy.deepcopy(unsafe_req_body)
    req_strategy_case = schema.make_case(
        operation=op_req_unsafe,
        method="POST",
        path="/req-unsafe-array",
        body=unsafe_req_body,
        media_type="application/json",
    )
    mock_req_strategy = MagicMock()
    mock_req_strategy.return_value.example.return_value = req_strategy_case
    with patch.object(op_req_unsafe, "as_strategy", mock_req_strategy):
        with pytest.raises(ValueError):
            rest.build_baseline_case(schema, op_req_unsafe)
    assert unsafe_req_body == unsafe_req_snapshot

    # 6. Unsafe enum on optional sensitive field inside nested array is safely omitted
    op_opt_unsafe = rest.find_operation(schema, "/opt-unsafe-array", "POST")
    assert op_opt_unsafe is not None
    opt_strategy_case = schema.make_case(
        operation=op_opt_unsafe,
        method="POST",
        path="/opt-unsafe-array",
        body={"users": [{"username": "alice", "role": "admin"}]},
        media_type="application/json",
    )
    mock_opt_strategy = MagicMock()
    mock_opt_strategy.return_value.example.return_value = opt_strategy_case
    with patch.object(op_opt_unsafe, "as_strategy", mock_opt_strategy):
        opt_baseline = rest.build_baseline_case(schema, op_opt_unsafe)
    assert opt_baseline.body == {"users": [{"username": "alice"}]}

    # 7. Recursion/depth guard fails closed (returns None) without partially sanitized output
    deep_body = {"a": [{"b": [{"role": "admin"}]}]}
    assert rest._sanitize_strategy_body(deep_body, None, None, max_depth=2) is None
    assert deep_body == {"a": [{"b": [{"role": "admin"}]}]}

    # Also verify x-bundled array-item schema resolution directly
    bundled_schema = {
        "$ref": "#/x-bundled/root",
        "x-bundled": {
            "item": {
                "type": "object",
                "required": ["username", "role"],
                "properties": {
                    "username": {"type": "string"},
                    "role": {"type": "string", "enum": ["admin", "superuser"]},
                },
            },
            "root": {
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": {"type": "array", "items": {"$ref": "#/x-bundled/item"}}
                },
            },
        },
    }
    assert rest._sanitize_strategy_body({"items": [{"username": "u", "role": "admin"}]}, bundled_schema, None) is None


def test_recursive_ref_preserves_schema_context_and_enum_constraints():
    from unittest.mock import MagicMock, patch
    import pytest

    safe_spec = {
        "openapi": "3.0.3",
        "info": {"title": "RecursiveRefSafe", "version": "1.0.0"},
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "required": ["name", "role"],
                    "properties": {
                        "name": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "member"]},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Node"},
                        },
                    },
                }
            }
        },
        "paths": {
            "/nodes": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Node"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }

    schema = schemathesis.openapi.from_dict(safe_spec)
    op = rest.find_operation(schema, "/nodes", "PUT")
    assert op is not None

    dirty_tree = {
        "name": "root",
        "role": "admin",
        "children": [
            {
                "name": "child-1",
                "role": "admin",
                "children": [
                    {
                        "name": "grandchild-1",
                        "role": "admin",
                    }
                ],
            }
        ],
    }

    # Direct recursive $ref sanitization across 3 levels preserves enum constraints
    # at root, child, and grandchild (does not degrade to heuristic "user").
    sanitized_direct = rest._sanitize_strategy_body(
        dirty_tree,
        {"$ref": "#/components/schemas/Node"},
        safe_spec,
    )
    assert sanitized_direct == {
        "name": "root",
        "role": "member",
        "children": [
            {
                "name": "child-1",
                "role": "member",
                "children": [
                    {
                        "name": "grandchild-1",
                        "role": "member",
                    }
                ],
            }
        ],
    }

    # Schemathesis unrolls one level of recursion in op.definition.raw for /nodes,
    # so root and child-1 preserve the Node enum through build_baseline_case().
    strategy_mock = MagicMock()
    strategy_mock.example.return_value = schema.make_case(
        operation=op,
        body={
            "name": "root",
            "role": "admin",
            "children": [{"name": "child-1", "role": "admin"}],
        },
        media_type="application/json",
    )
    with patch.object(op, "as_strategy", return_value=strategy_mock):
        baseline_case = rest.build_baseline_case(schema, op)

    assert baseline_case.body == {
        "name": "root",
        "role": "member",
        "children": [
            {
                "name": "child-1",
                "role": "member",
            }
        ],
    }

    # Recursive descendant with an unsafe-only required enum must fail closed rather than
    # falling back to heuristic values because the same $ref already appeared in an ancestor.
    unsafe_descendant_spec = {
        "openapi": "3.0.3",
        "info": {"title": "RecursiveRefUnsafeDescendant", "version": "1.0.0"},
        "components": {
            "schemas": {
                "ChildNode": {
                    "type": "object",
                    "required": ["name", "role"],
                    "properties": {
                        "name": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "superuser"]},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ChildNode"},
                        },
                    },
                },
                "Wrapper": {
                    "type": "object",
                    "required": ["title", "nodes"],
                    "properties": {
                        "title": {"type": "string"},
                        "nodes": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ChildNode"},
                        },
                    },
                },
            }
        },
        "paths": {
            "/tree": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Wrapper"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }

    unsafe_schema = schemathesis.openapi.from_dict(unsafe_descendant_spec)
    unsafe_op = rest.find_operation(unsafe_schema, "/tree", "PUT")
    assert unsafe_op is not None

    # Direct recursive check at depth 2: Root ChildNode (sanitizable if not unsafe) vs unsafe ChildNode
    assert (
        rest._sanitize_strategy_body(
            {
                "title": "org",
                "nodes": [
                    {
                        "name": "n1",
                        "role": "admin",
                        "children": [{"name": "n2", "role": "superuser"}],
                    }
                ],
            },
            {"$ref": "#/components/schemas/Wrapper"},
            unsafe_descendant_spec,
        )
        is None
    )

    # Also prove build_baseline_case fails closed when strategy returns recursive unsafe descendant
    # on a schema where Wrapper allows building only after strategy fallback isn't allowed.
    strategy_mock_unsafe = MagicMock()
    strategy_mock_unsafe.example.return_value = unsafe_schema.make_case(
        operation=unsafe_op,
        body={
            "title": "org",
            "nodes": [
                {
                    "name": "n1",
                    "role": "admin",
                    "children": [{"name": "n2", "role": "admin"}],
                }
            ],
        },
        media_type="application/json",
    )
    with patch.object(unsafe_op, "as_strategy", return_value=strategy_mock_unsafe):
        with pytest.raises(ValueError, match="Cannot build safe non-privileged baseline body"):
            rest.build_baseline_case(unsafe_schema, unsafe_op)


def test_sensitive_numeric_fields_without_schema_fail_closed():
    from unittest.mock import MagicMock, patch
    import pytest

    # Non-sensitive numeric fields without schema are preserved; sensitive numeric fields fail closed.
    assert rest._sanitize_strategy_body({"username": "alice", "age": 42}, None, None) == {
        "username": "alice",
        "age": 42,
    }
    assert rest._sanitize_strategy_body(
        {"username": "alice", "access_level": 99, "age": 42},
        None,
        None,
    ) is None
    assert rest._sanitize_strategy_body(
        {"users": [{"username": "alice", "access_level": 99}]},
        None,
        None,
    ) is None

    # With a schema where obj_props is known: undeclared optional sensitive numeric is omitted,
    # whereas declared required sensitive numeric without prop_schema fails closed.
    schema_with_extra = {
        "type": "object",
        "required": ["username"],
        "properties": {"username": {"type": "string"}},
    }
    assert rest._sanitize_strategy_body(
        {"username": "alice", "access_level": 99},
        schema_with_extra,
        None,
    ) == {"username": "alice"}

    schema_req_missing_prop = {
        "type": "object",
        "required": ["username", "access_level"],
        "properties": {"username": {"type": "string"}},
    }
    assert rest._sanitize_strategy_body(
        {"username": "alice", "access_level": 99},
        schema_req_missing_prop,
        None,
    ) is None

    # Through build_baseline_case with an unconstrained object schema (no properties defined):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "FreeformObj", "version": "1.0.0"},
        "paths": {
            "/freeform": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            }
        },
    }
    schema = schemathesis.openapi.from_dict(spec)
    op = rest.find_operation(schema, "/freeform", "PUT")
    assert op is not None
    strategy_mock = MagicMock()
    strategy_mock.example.return_value = schema.make_case(
        operation=op,
        body={"username": "alice", "access_level": 99},
        media_type="application/json",
    )
    with patch.object(op, "as_strategy", return_value=strategy_mock):
        with pytest.raises(ValueError, match="Cannot build safe non-privileged baseline body"):
            rest.build_baseline_case(schema, op)


def test_ambiguous_oneof_anyof_branches_fail_closed_or_omit_safely():
    ambiguous_schema = {
        "oneOf": [
            {
                "type": "object",
                "required": ["username", "email"],
                "properties": {
                    "username": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string", "enum": ["user", "admin"]},
                },
            },
            {
                "type": "object",
                "required": ["username", "phone", "role"],
                "properties": {
                    "username": {"type": "string"},
                    "phone": {"type": "string"},
                    "role": {"type": "string", "enum": ["admin", "superuser"]},
                },
            },
        ]
    }

    # Partial overlap ("username" only, missing both "email" and "phone") is ambiguous.
    # Because "role" is required in a candidate branch, sanitizer must fail closed rather than
    # selecting Branch 1 from partial key overlap.
    assert (
        rest._sanitize_strategy_body(
            {"username": "alice", "role": "admin"},
            ambiguous_schema,
            None,
        )
        is None
    )

    # Unambiguous full structural match with Branch 1 selects Branch 1 and sanitizes role -> "user".
    assert rest._sanitize_strategy_body(
        {"username": "alice", "email": "alice@example.com", "role": "admin"},
        ambiguous_schema,
        None,
    ) == {"username": "alice", "email": "alice@example.com", "role": "user"}

    # Two compatible branches both match body keys where sensitive fields are optional:
    # ambiguous resolution must omit sensitive fields rather than retaining privileged values.
    overlapping_optional_schema = {
        "anyOf": [
            {
                "type": "object",
                "required": ["username"],
                "properties": {
                    "username": {"type": "string"},
                    "role": {"type": "string", "enum": ["user", "admin"]},
                    "is_admin": {"type": "boolean"},
                },
            },
            {
                "type": "object",
                "required": ["username"],
                "properties": {
                    "username": {"type": "string"},
                    "role": {"type": "string", "enum": ["member", "admin"]},
                    "is_admin": {"type": "boolean"},
                },
            },
        ]
    }
    assert rest._sanitize_strategy_body(
        {"username": "alice", "role": "admin", "is_admin": True},
        overlapping_optional_schema,
        None,
    ) == {"username": "alice"}


def test_build_baseline_safe_parent_fails_closed_on_unsafe_descendant():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "SafeParentUnsafeChild", "version": "1.0.0"},
        "components": {
            "schemas": {
                "SafeParent": {
                    "type": "object",
                    "required": ["name", "role"],
                    "properties": {
                        "name": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "member"]},
                    },
                },
                "UnsafeChild": {
                    "type": "object",
                    "required": ["name", "role"],
                    "properties": {
                        "name": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "superuser"]},
                    },
                },
                "ParentWithChildren": {
                    "type": "object",
                    "required": ["name", "role", "children"],
                    "properties": {
                        "name": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "member"]},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/UnsafeChild"},
                        },
                    },
                },
            }
        },
        "paths": {
            "/parent-only": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SafeParent"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/parent-with-child": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ParentWithChildren"}
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    op_parent = rest.find_operation(schema, "/parent-only", "PUT")
    op_parent_child = rest.find_operation(schema, "/parent-with-child", "PUT")
    assert op_parent is not None
    assert op_parent_child is not None

    # 1. Parent alone produces a valid safe baseline ("role" -> "member") via both strategy and fallback.
    strat_parent = MagicMock()
    strat_parent.example.return_value = schema.make_case(
        operation=op_parent,
        body={"name": "parent", "role": "admin"},
        media_type="application/json",
    )
    with patch.object(op_parent, "as_strategy", return_value=strat_parent):
        parent_baseline = rest.build_baseline_case(schema, op_parent)
    assert parent_baseline.body == {"name": "parent", "role": "member"}

    with patch.object(op_parent, "as_strategy", side_effect=RuntimeError("strategy failed")):
        fallback_parent_baseline = rest.build_baseline_case(schema, op_parent)
    assert fallback_parent_baseline.body["role"] == "member"

    # 2. On the parent-child operation itself, empty children succeeds (parent schema is safe),
    # whereas an UnsafeChild descendant fails closed with ValueError.
    strat_no_child = MagicMock()
    strat_no_child.example.return_value = schema.make_case(
        operation=op_parent_child,
        body={"name": "parent", "role": "admin", "children": []},
        media_type="application/json",
    )
    with patch.object(op_parent_child, "as_strategy", return_value=strat_no_child):
        empty_child_baseline = rest.build_baseline_case(schema, op_parent_child)
    assert empty_child_baseline.body == {"name": "parent", "role": "member", "children": []}

    strat_with_unsafe_child = MagicMock()
    strat_with_unsafe_child.example.return_value = schema.make_case(
        operation=op_parent_child,
        body={
            "name": "parent",
            "role": "admin",
            "children": [{"name": "child-1", "role": "admin"}],
        },
        media_type="application/json",
    )
    with patch.object(op_parent_child, "as_strategy", return_value=strat_with_unsafe_child):
        with pytest.raises(ValueError, match="Cannot build safe non-privileged baseline body"):
            rest.build_baseline_case(schema, op_parent_child)


def test_build_baseline_case_handles_ambiguous_oneof_anyof_variants():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "AmbiguousCombinersAPI", "version": "1.0.0"},
        "paths": {
            "/oneof-required-ambiguous": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "required": ["username", "email"],
                                            "properties": {
                                                "username": {"type": "string"},
                                                "email": {"type": "string"},
                                                "role": {"type": "string", "enum": ["user", "admin"]},
                                            },
                                        },
                                        {
                                            "type": "object",
                                            "required": ["username", "phone", "role"],
                                            "properties": {
                                                "username": {"type": "string"},
                                                "phone": {"type": "string"},
                                                "role": {"type": "string", "enum": ["admin", "superuser"]},
                                            },
                                        },
                                    ]
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
            "/anyof-optional-ambiguous": {
                "put": {
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "anyOf": [
                                        {
                                            "type": "object",
                                            "required": ["username"],
                                            "properties": {
                                                "username": {"type": "string"},
                                                "role": {"type": "string", "enum": ["user", "admin"]},
                                                "is_admin": {"type": "boolean"},
                                            },
                                        },
                                        {
                                            "type": "object",
                                            "required": ["username"],
                                            "properties": {
                                                "username": {"type": "string"},
                                                "role": {"type": "string", "enum": ["member", "admin"]},
                                                "is_admin": {"type": "boolean"},
                                            },
                                        },
                                    ]
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "OK"}},
                }
            },
        },
    }

    schema = schemathesis.openapi.from_dict(spec)
    op_req = rest.find_operation(schema, "/oneof-required-ambiguous", "PUT")
    op_opt = rest.find_operation(schema, "/anyof-optional-ambiguous", "PUT")
    assert op_req is not None
    assert op_opt is not None

    # 1. Ambiguous required sensitive field fails closed through build_baseline_case()
    strat_req = MagicMock()
    strat_req.example.return_value = schema.make_case(
        operation=op_req,
        body={"username": "alice", "role": "admin"},
        media_type="application/json",
    )
    with patch.object(op_req, "as_strategy", return_value=strat_req):
        with pytest.raises(ValueError, match="Cannot build safe non-privileged baseline body"):
            rest.build_baseline_case(schema, op_req)

    # 2. Ambiguous optional sensitive fields are safely omitted through build_baseline_case()
    strat_opt = MagicMock()
    strat_opt.example.return_value = schema.make_case(
        operation=op_opt,
        body={"username": "alice", "role": "admin", "is_admin": True},
        media_type="application/json",
    )
    with patch.object(op_opt, "as_strategy", return_value=strat_opt):
        baseline_opt = rest.build_baseline_case(schema, op_opt)
    assert baseline_opt.body == {"username": "alice"}


