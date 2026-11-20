"""Unit tests for Pure-Python Schema Validator Fallback & Environment Resilience."""

from __future__ import annotations

import sys
from core.schema_validator import PurePythonSchemaValidator, install_jsonschema_rs_shim_if_needed


def test_pure_python_schema_validator():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer", "minimum": 0},
            "email": {"type": "string"},
        },
        "required": ["name", "email"],
    }

    validator = PurePythonSchemaValidator(schema)

    # Valid payload
    valid_payload = {"name": "Alice", "email": "alice@example.com", "age": 30}
    is_ok, errors = validator.validate(valid_payload)
    assert is_ok is True
    assert errors == []
    assert validator.is_valid(valid_payload) is True

    # Invalid payload (missing email, invalid age type)
    invalid_payload = {"name": "Bob", "age": -5}
    is_ok, errors = validator.validate(invalid_payload)
    assert is_ok is False
    assert len(errors) > 0
    assert validator.is_valid(invalid_payload) is False


def test_jsonschema_rs_shim_installation_and_attributes():
    # Verify the shim is in sys.modules and provides all required attributes
    install_jsonschema_rs_shim_if_needed()
    shim = sys.modules["jsonschema_rs"]

    # Check key classes and attributes expected by Schemathesis
    assert hasattr(shim, "ValidationError")
    assert hasattr(shim, "ValidationErrorKind")
    assert hasattr(shim, "Registry")
    assert hasattr(shim, "Resolver")
    assert hasattr(shim, "Validator")
    assert hasattr(shim, "Draft4Validator")
    assert hasattr(shim, "Draft202012Validator")
    assert hasattr(shim, "Draft4")
    assert hasattr(shim, "Draft202012")
    assert hasattr(shim, "canonical")
    assert hasattr(shim.canonical, "schema")
    assert hasattr(shim.canonical, "json")

    # Check canonical JSON clone and serialization
    test_dict = {"a": 1, "b": [2, 3]}
    cloned = shim.canonical.schema.clone(test_dict)
    assert cloned == test_dict
    assert cloned is not test_dict

    serialized = shim.canonical.json.to_string(test_dict)
    assert '"a": 1' in serialized

    # Check registry resolver
    reg = shim.Registry([("urn:test", {})])
    res = reg.resolver("urn:test")
    assert hasattr(res, "lookup")
    assert res.base_uri == "urn:test"
