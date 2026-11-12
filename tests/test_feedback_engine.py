"""Unit tests for Adaptive Feedback Engine and validation analysis."""

import json
import pytest
from core.feedback_engine import FeedbackAnalyzer, FeedbackAnalysisResult


def test_fastapi_pydantic_validation_error():
    err_body = json.dumps({
        "detail": [
            {
                "loc": ["body", "email"],
                "msg": "value is not a valid email address",
                "type": "value_error.email",
            },
            {
                "loc": ["body", "user_id"],
                "msg": "value is not a valid uuid",
                "type": "type_error.uuid",
            },
        ]
    })
    res = FeedbackAnalyzer.analyze_response(422, err_body)
    assert res.is_validation_error is True
    assert res.framework_hint == "pydantic_fastapi"
    assert len(res.failed_fields) == 2

    # Verify adaptive payload repair
    original = {"email": "invalid_email_string", "user_id": "invalid_uuid"}
    adapted = FeedbackAnalyzer.adapt_payload(original, res)
    assert "@" in adapted["email"]
    assert "00000000" in adapted["user_id"]


def test_nestjs_class_validator_error():
    err_body = json.dumps({
        "statusCode": 400,
        "message": ["email must be an email", "id must be a UUID"],
        "error": "Bad Request",
    })
    res = FeedbackAnalyzer.analyze_response(400, err_body)
    assert res.is_validation_error is True
    assert res.framework_hint == "nestjs_class_validator"
    assert len(res.failed_fields) == 2


def test_spring_boot_validation_error():
    err_body = json.dumps({
        "timestamp": "2026-11-12T12:00:00Z",
        "status": 400,
        "errors": [
            {"field": "email", "defaultMessage": "must be a well-formed email address"}
        ]
    })
    res = FeedbackAnalyzer.analyze_response(400, err_body)
    assert res.is_validation_error is True
    assert res.framework_hint == "spring_boot"
    assert res.failed_fields[0].field_name == "email"


def test_non_validation_status():
    res = FeedbackAnalyzer.analyze_response(200, "OK")
    assert res.is_validation_error is False
    assert len(res.failed_fields) == 0
