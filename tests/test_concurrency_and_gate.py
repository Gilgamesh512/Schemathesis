from __future__ import annotations

import json
from pathlib import Path
import pytest
import httpx

from core.concurrency_fuzzer import ConcurrencyBurstResult, ConcurrencyFuzzer
from core.evidence import Finding


def test_concurrency_candidate_detection():
    # Should identify sensitive endpoints
    assert ConcurrencyFuzzer.is_candidate_endpoint("/api/v1/coupon/apply", "POST")
    assert ConcurrencyFuzzer.is_candidate_endpoint("/checkout/pay", "POST")
    assert ConcurrencyFuzzer.is_candidate_endpoint("/orders", "POST")
    assert ConcurrencyFuzzer.is_candidate_endpoint("/auth/reset-password", "POST")
    
    # Should ignore safe read-only or non-sensitive endpoints
    assert not ConcurrencyFuzzer.is_candidate_endpoint("/products", "GET")
    assert not ConcurrencyFuzzer.is_candidate_endpoint("/users/profile", "GET")


def test_concurrency_burst_result_evaluation():
    fuzzer = ConcurrencyFuzzer(burst_size=5)
    
    # Simulate single-use coupon vulnerability (3 out of 5 succeeded)
    burst_res = ConcurrencyBurstResult(
        endpoint="/api/v1/coupon/apply",
        method="POST",
        burst_size=5,
        success_count=3,
        client_error_count=2,
        server_error_count=0,
        status_codes=[200, 200, 200, 400, 400],
        latencies_ms=[12.0, 12.5, 13.0, 15.0, 15.5],
        is_vulnerable=True,
        vulnerability_reason="Single-use action allowed multiple successful executions (3/5 HTTP 200).",
        evidence_details={"burst_size": 5},
    )
    
    finding = fuzzer.convert_to_finding(burst_res, target_app="test_app", run_id="run_123")
    assert finding is not None
    assert finding.attack_type == "RACE_CONDITION"
    assert finding.owasp_category == "API4:2023"
    assert finding.severity == "HIGH"
    assert finding.confirmed is True


def test_sarif_quality_gate_logic(tmp_path: Path):
    sarif_file = tmp_path / "test_report.sarif"
    sarif_content = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Schemathesis"}},
            "results": [
                {"ruleId": "API1:2023", "level": "warning", "message": {"text": "CONFIRMED BOLA vulnerability"}},
                {"ruleId": "API4:2023", "level": "error", "message": {"text": "Race condition detected"}},
            ]
        }]
    }
    sarif_file.write_text(json.dumps(sarif_content), encoding="utf-8")
    
    # Read and evaluate gate rules
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    critical_count = sum(1 for r in results if r.get("level") == "error")
    high_count = sum(1 for r in results if r.get("level") == "warning")
    confirmed_count = sum(1 for r in results if "CONFIRMED" in r.get("message", {}).get("text", ""))
    
    assert critical_count == 1
    assert high_count == 1
    assert confirmed_count == 1
