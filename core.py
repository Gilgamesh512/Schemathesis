"""Shared security evidence, finding identity, and redaction helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional

from pydantic import BaseModel, Field


def stable_finding_id(
    target: str, method: str, endpoint: str, attack_type: str, parameter: str = ""
) -> str:
    normalized_endpoint = re.sub(r"//+", "/", endpoint.strip().lower()).rstrip("/") or "/"
    raw = "|".join((target.lower(), method.upper(), normalized_endpoint,
                     attack_type.lower().replace(" ", ""), parameter.lower()))
    return "F-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def content_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def redact_headers(headers: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not headers:
        return {}
    secret_names = {"authorization", "cookie", "set-cookie", "x-api-key"}
    redacted: dict[str, Any] = {}
    for key, value in headers.items():
        if key.lower() in secret_names:
            redacted[key] = "<REDACTED>"
            redacted[f"{key}_hash"] = content_hash(str(value))
        else:
            redacted[key] = value
    return redacted


class Evidence(BaseModel):
    status_code: Optional[int] = None
    response_headers: dict[str, Any] = Field(default_factory=dict)
    response_signal: list[str] = Field(default_factory=list)
    response_time_ms: Optional[float] = None
    payload_hash: str = ""
    request_hash: str = ""
    endpoint: str = ""
    payload: Any = None
    auth_context: dict[str, Any] = Field(default_factory=dict)
    previous_observations: list[dict[str, Any]] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    run_id: str
    timestamp: str
    target_app: str
    endpoint: str
    method: str
    tool: str
    attack_type: str
    owasp_category: Optional[str] = None
    payload: Any = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    evidence: Evidence
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    confirmed: bool = False
    lifecycle: str = "new"
    fingerprint: str
    cve_matches: list[str] = Field(default_factory=list)
