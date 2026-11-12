"""Adaptive Feedback Engine for Schema Validation Error Analysis.

Parses HTTP 400 (Bad Request) and HTTP 422 (Unprocessable Entity) responses from
modern API frameworks (FastAPI/Pydantic, NestJS class-validator, Spring Boot,
Express validator, RFC 7807 Problem Details). Extracts specific field validation
failures, expected formats, and generates adaptive mutation advice to automatically
repair and bypass validation barriers on retry attempts.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional
from pydantic import BaseModel, Field


class FieldValidationFailure(BaseModel):
    """Specific field-level validation failure extracted from response."""
    field_name: str
    location: str = "body"  # "body" | "query" | "path" | "header"
    error_type: str = ""    # "type_error", "value_error", "missing", "regex_mismatch"
    message: str = ""
    expected_format: Optional[str] = None  # "uuid", "email", "integer", "datetime"...


class FeedbackAnalysisResult(BaseModel):
    """Structured breakdown of server-side validation feedback."""
    status_code: int
    is_validation_error: bool = False
    framework_hint: str = "generic"
    failed_fields: list[FieldValidationFailure] = Field(default_factory=list)
    raw_message: str = ""
    adaptive_recommendations: list[str] = Field(default_factory=list)


class FeedbackAnalyzer:
    """Analyzes validation responses and provides adaptive repair hints."""

    @classmethod
    def analyze_response(cls, status_code: int, response_text: str, headers: Optional[dict[str, Any]] = None) -> FeedbackAnalysisResult:
        """Parse status code and response body to identify validation constraints."""
        if status_code not in (400, 422):
            return FeedbackAnalysisResult(
                status_code=status_code,
                is_validation_error=False,
                raw_message=(response_text or "")[:200],
            )

        parsed_json: Any = None
        try:
            parsed_json = json.loads(response_text)
        except Exception:
            parsed_json = None

        failures: list[FieldValidationFailure] = []
        framework = "generic"
        recs: list[str] = []

        if isinstance(parsed_json, dict):
            # 1. FastAPI / Pydantic style: {"detail": [{"loc": ["body", "email"], "msg": "...", "type": "..."}]}
            if "detail" in parsed_json and isinstance(parsed_json["detail"], list):
                framework = "pydantic_fastapi"
                for item in parsed_json["detail"]:
                    if isinstance(item, dict):
                        loc = item.get("loc", [])
                        field_name = str(loc[-1]) if loc else "unknown"
                        loc_type = str(loc[0]) if len(loc) > 1 else "body"
                        msg = str(item.get("msg", ""))
                        err_type = str(item.get("type", ""))
                        fmt = cls._infer_expected_format(msg, err_type)
                        failures.append(FieldValidationFailure(
                            field_name=field_name,
                            location=loc_type,
                            error_type=err_type,
                            message=msg,
                            expected_format=fmt,
                        ))
                        recs.append(f"Field '{field_name}' rejected: {msg}. Expected format: {fmt or 'conformant value'}")

            # 2. NestJS / class-validator style: {"statusCode": 400, "message": ["email must be an email"], "error": "Bad Request"}
            elif "message" in parsed_json and isinstance(parsed_json["message"], list):
                framework = "nestjs_class_validator"
                for msg in parsed_json["message"]:
                    msg_str = str(msg)
                    parts = msg_str.split()
                    field_name = parts[0] if parts else "unknown"
                    fmt = cls._infer_expected_format(msg_str, "")
                    failures.append(FieldValidationFailure(
                        field_name=field_name,
                        message=msg_str,
                        expected_format=fmt,
                    ))
                    recs.append(f"NestJS constraint on '{field_name}': {msg_str}")

            # 3. Spring Boot style: {"errors": [{"field": "email", "defaultMessage": "..."}]}
            elif "errors" in parsed_json and isinstance(parsed_json["errors"], list):
                framework = "spring_boot"
                for err in parsed_json["errors"]:
                    if isinstance(err, dict):
                        field_name = str(err.get("field", "unknown"))
                        msg = str(err.get("defaultMessage", ""))
                        fmt = cls._infer_expected_format(msg, "")
                        failures.append(FieldValidationFailure(
                            field_name=field_name,
                            message=msg,
                            expected_format=fmt,
                        ))
                        recs.append(f"Spring validation on '{field_name}': {msg}")

            # 4. RFC 7807 Problem Details: {"type": "...", "invalid-params": [{"name": "email", "reason": "..."}]}
            elif "invalid-params" in parsed_json and isinstance(parsed_json["invalid-params"], list):
                framework = "rfc7807"
                for item in parsed_json["invalid-params"]:
                    if isinstance(item, dict):
                        field_name = str(item.get("name", "unknown"))
                        reason = str(item.get("reason", ""))
                        fmt = cls._infer_expected_format(reason, "")
                        failures.append(FieldValidationFailure(
                            field_name=field_name,
                            message=reason,
                            expected_format=fmt,
                        ))
                        recs.append(f"RFC7807 parameter error '{field_name}': {reason}")

            # 5. Generic single message dict: {"error": "Invalid UUID format"}
            elif "error" in parsed_json or "message" in parsed_json:
                msg = str(parsed_json.get("error") or parsed_json.get("message"))
                fmt = cls._infer_expected_format(msg, "")
                failures.append(FieldValidationFailure(
                    field_name="general",
                    message=msg,
                    expected_format=fmt,
                ))
                recs.append(f"Generic error: {msg}")

        # Plain text fallback
        elif response_text:
            fmt = cls._infer_expected_format(response_text, "")
            if fmt:
                failures.append(FieldValidationFailure(
                    field_name="general",
                    message=response_text[:150],
                    expected_format=fmt,
                ))
                recs.append(f"Plain text constraint detected: {fmt}")

        return FeedbackAnalysisResult(
            status_code=status_code,
            is_validation_error=bool(failures or status_code in (400, 422)),
            framework_hint=framework,
            failed_fields=failures,
            raw_message=(response_text or "")[:200],
            adaptive_recommendations=recs,
        )

    @classmethod
    def _infer_expected_format(cls, message: str, error_type: str) -> Optional[str]:
        """Deduce required format from error message string or error type identifier."""
        text = (message + " " + error_type).lower()
        if "uuid" in text:
            return "uuid"
        if "email" in text or "mail" in text:
            return "email"
        if "integer" in text or "int" in text or "number" in text:
            return "integer"
        if "date-time" in text or "datetime" in text or "timestamp" in text:
            return "date-time"
        if "date" in text:
            return "date"
        if "url" in text or "uri" in text:
            return "uri"
        if "boolean" in text or "bool" in text:
            return "boolean"
        if "missing" in text or "required" in text:
            return "required_missing"
        return None

    @classmethod
    def adapt_payload(cls, original_payload: Any, feedback: FeedbackAnalysisResult) -> Any:
        """Adjust payload to satisfy reported validation format constraints."""
        if not feedback.is_validation_error or not feedback.failed_fields:
            return original_payload

        # If payload is a dictionary (JSON body or query params)
        if isinstance(original_payload, dict):
            adapted = dict(original_payload)
            for failure in feedback.failed_fields:
                fname = failure.field_name
                fmt = failure.expected_format
                if not fmt:
                    continue

                if fmt == "uuid":
                    # Adapt to valid UUID with canary tag
                    adapted[fname] = "00000000-0000-0000-0000-000000000001"
                elif fmt == "email":
                    adapted[fname] = "probe.sqli'OR'1'='1@canary.local"
                elif fmt == "integer":
                    adapted[fname] = 1
                elif fmt == "uri":
                    adapted[fname] = "http://127.0.0.1:80/canary"
                elif fmt == "date-time":
                    adapted[fname] = "2026-01-01T00:00:00Z"
                elif fmt == "date":
                    adapted[fname] = "2026-01-01"
                elif fmt == "boolean":
                    adapted[fname] = True
            return adapted

        # If payload is a primitive string
        if isinstance(original_payload, str):
            primary_fmt = feedback.failed_fields[0].expected_format if feedback.failed_fields else None
            if primary_fmt == "uuid":
                return "00000000-0000-0000-0000-000000000001"
            if primary_fmt == "email":
                return "probe.sqli'OR'1'='1@canary.local"
            if primary_fmt == "integer":
                return 1
            if primary_fmt == "uri":
                return "http://127.0.0.1:80/canary"

        return original_payload
