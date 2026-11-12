"""Unit tests for Schema-Conforming Semantic Mutation Engine."""

import pytest
from core.semantic_mutator import ParamSchema, SemanticMutationEngine, SemanticProbe


def test_inspect_param_uuid():
    schema = SemanticMutationEngine.inspect_param(
        "user_id", "path", {"type": "string", "format": "uuid", "required": True}
    )
    assert schema.name == "user_id"
    assert schema.format == "uuid"
    assert schema.required is True

    probes = SemanticMutationEngine.generate_probes(schema)
    assert any(p.attack_type == "BOLA" and "00000000" in str(p.payload_value) for p in probes)
    assert any(p.attack_type == "SQL_INJECTION" for p in probes)


def test_inspect_param_email():
    schema = SemanticMutationEngine.inspect_param(
        "contact_email", "query", {"type": "string", "format": "email"}
    )
    assert schema.format == "email"

    probes = SemanticMutationEngine.generate_probes(schema)
    # Must generate schema-conforming email payloads
    assert any("@" in str(p.payload_value) and p.attack_type == "SQL_INJECTION" for p in probes)
    assert any("@" in str(p.payload_value) and p.attack_type == "SSTI" for p in probes)
    assert any("@" in str(p.payload_value) and p.attack_type == "XSS" for p in probes)
    assert any("@" in str(p.payload_value) and p.attack_type == "BOLA" for p in probes)


def test_inspect_param_integer_boundary():
    schema = SemanticMutationEngine.inspect_param(
        "page_limit", "query", {"type": "integer", "minimum": 1, "maximum": 100}
    )
    assert schema.type == "integer"

    probes = SemanticMutationEngine.generate_probes(schema)
    # Integer probes must be integers, not string 'admin'
    assert any(p.attack_type == "BOLA" and p.payload_value == 1 for p in probes)
    assert any(p.attack_type == "INTEGER_OVERFLOW" and p.payload_value == 2147483647 for p in probes)
    assert any(p.attack_type == "INTEGER_OVERFLOW" and p.payload_value == -1 for p in probes)


def test_inspect_param_enum():
    schema = SemanticMutationEngine.inspect_param(
        "role", "body", {"type": "string", "enum": ["user", "moderator", "admin"]}
    )
    assert len(schema.enum) == 3

    probes = SemanticMutationEngine.generate_probes(schema)
    assert any(p.attack_type == "BFLA" and p.payload_value == "admin" for p in probes)


def test_generate_schema_valid_sample():
    obj_schema = {
        "type": "object",
        "required": ["id", "email"],
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "email": {"type": "string", "format": "email"},
            "age": {"type": "integer"},
        },
    }
    sample = SemanticMutationEngine.generate_schema_valid_sample(obj_schema)
    assert isinstance(sample, dict)
    assert "id" in sample
    assert "email" in sample
    assert "@" in sample["email"]
