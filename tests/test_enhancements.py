"""Unit tests for newly added framework enhancements:
1. SARIF v2.1.0 report generation
2. Built-in dynamic GraphQL payload generator
3. Built-in REST security mutation engine
4. Dual-user BOLA/IDOR cross-user verification
5. Google OSV API fallback
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from core import SecurityReporter
from modules.graphql import run_graphql_fuzz1 as graphql
from modules.rest import run_schemathesis1 as rest
from modules.security import rules_engine


def test_sarif_report_generation(tmp_path: Path):
    reporter = SecurityReporter(tmp_path)
    mock_findings = [
        {
            "finding_id": "F-TEST-1",
            "endpoint": "/users/v1/1",
            "method": "GET",
            "attack_type": "BOLA",
            "severity": "high",
            "confirmed": True,
            "owasp_category": "API1:2023",
            "evidence": "BOLA verified via cross-user token swap",
            "target_app": "vampi",
            "matched_cve": ["CVE-2023-1234"],
        },
        {
            "finding_id": "F-TEST-2",
            "endpoint": "/graphql",
            "method": "POST",
            "attack_type": "GRAPHQL_INTROSPECTION",
            "severity": "medium",
            "confirmed": False,
            "owasp_category": "API8:2023",
            "evidence": "Introspection enabled",
            "target_app": "dvga",
            "matched_cve": [],
        },
    ]

    out_file = tmp_path / "custom.sarif"
    result_path = reporter.generate_sarif_report(mock_findings, output_file=out_file)
    assert result_path.exists()

    sarif_doc = json.loads(result_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"]) == 1
    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Schemathesis API Security Fuzzer"

    # Rules map must include API1:2023 and API8:2023
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "API1:2023" in rule_ids
    assert "API8:2023" in rule_ids

    # Results check
    results = run["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "API1:2023"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/users/v1/1"


def test_builtin_graphql_payload_generator():
    dvga_schema = Path("targets/schemas/dvga/dvga_schema.json")
    payloads = graphql.generate_builtin_graphql_payloads("dvga", dvga_schema)
    assert len(payloads) >= 2

    attack_types = {p.attack_type for p in payloads}
    assert "GRAPHQL_INTROSPECTION" in attack_types
    assert "GRAPHQL_BATCHING_DOS" in attack_types

    # Schema-driven queries check
    if dvga_schema.exists():
        assert any(p.attack_type in ("SQL_INJECTION", "COMMAND_INJECTION", "INFORMATION_DISCLOSURE") for p in payloads)


def test_builtin_rest_mutation_engine():
    # Verify schema_payloads generates BOLA and SQLi when path parameter exists
    mock_op = Mock()
    mock_op.path = "/api/v1/resources/{resource_id}"
    mock_op.method = "GET"

    mock_schema = Mock()
    mock_result = Mock()
    mock_result.ok.return_value = mock_op
    mock_schema.get_all_operations.return_value = [mock_result]

    targets = {"test_api": (mock_schema, "http://127.0.0.1:8000")}
    payloads = rest.schema_payloads(targets)

    assert len(payloads) >= 3  # baseline + BOLA + SQLi
    attack_types = {p.attack_type for p in payloads}
    assert "schema-generated" in attack_types
    assert "BOLA" in attack_types
    assert "SQL_INJECTION" in attack_types

    bola_payload = next(p for p in payloads if p.attack_type == "BOLA")
    assert bola_payload.target_param == "resource_id"
    assert bola_payload.param_location == "path"


def test_osv_api_fallback():
    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy",
                "aliases": ["CVE-2024-9999"],
                "summary": "Flask Security Issue",
                "published": "2024-01-01T00:00:00Z",
            }
        ]
    }

    with patch("modules.security.rules_engine.requests.post", return_value=mock_resp):
        cves = rules_engine.fetch_cves_from_osv("flask", "PyPI")
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "CVE-2024-9999"
        assert "flask" in cves[0]["keyword"]
