"""Unit tests for Framework-Specific Remediation Snippet Engine."""

from __future__ import annotations

from core.remediation_engine import RemediationEngine, RemediationSnippet
from core.reporter import SecurityReporter


def test_detect_framework():
    # FastAPI detection from Server / hint
    assert RemediationEngine.detect_framework(headers={"server": "uvicorn"}) == "fastapi"
    assert RemediationEngine.detect_framework(framework_hint="pydantic_fastapi") == "fastapi"

    # Spring Boot detection
    assert RemediationEngine.detect_framework(headers={"server": "Apache-Coyote/1.1"}) == "spring_boot"
    assert RemediationEngine.detect_framework(body="<html>Whitelabel Error Page</html>") == "spring_boot"

    # Express / NestJS detection
    assert RemediationEngine.detect_framework(headers={"x-powered-by": "Express"}) == "express"
    assert RemediationEngine.detect_framework(framework_hint="nestjs_class_validator") == "nestjs"


def test_get_snippet_by_category():
    # API1:2023 - BOLA
    snip_fastapi = RemediationEngine.get_snippet("API1:2023", framework="fastapi")
    assert snip_fastapi is not None
    assert snip_fastapi.framework == "FastAPI"
    assert "current_user" in snip_fastapi.secure_example
    assert "VULNERABLE" in snip_fastapi.vulnerable_example

    snip_spring = RemediationEngine.get_snippet("API1:2023", framework="spring_boot")
    assert snip_spring is not None
    assert "@PreAuthorize" in snip_spring.secure_example

    # API2:2023 - Broken Authentication
    snip_jwt = RemediationEngine.get_snippet("API2:2023", framework="fastapi")
    assert snip_jwt is not None
    assert "algorithms=['HS256']" in snip_jwt.secure_example

    # API3:2023 - BOPLA / Mass Assignment
    snip_bopla = RemediationEngine.get_snippet("API3:2023", framework="fastapi")
    assert snip_bopla is not None
    assert "extra='forbid'" in snip_bopla.secure_example

    # API7:2023 - SSRF
    snip_ssrf = RemediationEngine.get_snippet("API7:2023", framework="fastapi")
    assert snip_ssrf is not None
    assert "ip.is_private" in snip_ssrf.secure_example


def test_reporter_html_and_sarif_includes_snippets(tmp_path):
    reporter = SecurityReporter(tmp_path)
    dummy_findings = [
        {
            "finding_id": "F-TEST-1",
            "endpoint": "/api/v1/orders/{id}",
            "method": "GET",
            "attack_type": "BOLA",
            "owasp_category": "API1:2023",
            "severity": "HIGH",
            "status_code": 200,
            "response_time_ms": 45.0,
            "evidence": "BOLA user 2 accessed user 1 order",
            "confirmed": True,
            "lifecycle": "confirmed",
        }
    ]

    # HTML Report should embed idiomatic fix pattern
    html_path = reporter.generate_html_report(dummy_findings)
    assert html_path.exists()
    html_content = html_path.read_text(encoding="utf-8")
    assert "Idiomatic Fix Pattern (FastAPI)" in html_content
    assert "current_user" in html_content

    # SARIF Export should embed markdown remediation
    sarif_path = reporter.generate_sarif_report(dummy_findings)
    assert sarif_path.exists()
    sarif_content = sarif_path.read_text(encoding="utf-8")
    assert "Recommended Fix (FastAPI)" in sarif_content
