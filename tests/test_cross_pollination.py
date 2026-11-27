"""Test suite for features ported from LLM-Assisted API Fuzzing:
- curl_builder (1-Click cURL generation)
- har_parser (SeedCorpus and HAR ingestion)
- safety_cleanup (CleanupTracker & Audit Headers)
- verify_deep_state_persistence (Loopback check)
"""

import json
from pathlib import Path
import pytest

from core.curl_builder import build_curl_command, build_curl_from_finding
from core.har_parser import HARSeed, SeedCorpus, parse_har_file
from core.safety_cleanup import CleanupTracker, get_audit_headers
from core.evidence import Finding, Evidence, verify_deep_state_persistence


def test_build_curl_command():
    cmd = build_curl_command(
        method="POST",
        url="https://api.example.com/v1/users",
        headers={"Authorization": "Bearer test123", "X-Custom": "val"},
        params={"active": "true"},
        json_data={"username": "admin", "role": "superadmin"},
        insecure=True,
    )
    assert "curl -i -s -k -X POST" in cmd
    assert 'https://api.example.com/v1/users?active=true' in cmd
    assert '-H "Authorization: Bearer test123"' in cmd
    assert '-H "X-Custom: val"' in cmd
    assert '-H "Content-Type: application/json"' in cmd
    assert '{"username": "admin", "role": "superadmin"}' in cmd


def test_build_curl_from_finding():
    finding = Finding(
        finding_id="F-test123",
        run_id="run-1",
        timestamp="2026-11-20T00:00:00Z",
        target_app="TestApp",
        endpoint="/api/v1/orders/99",
        method="PUT",
        tool="schemathesis",
        attack_type="Mass Assignment",
        severity="high",
        confidence=0.9,
        fingerprint="fp123",
        evidence=Evidence(auth_context={"header": "X-API-Key", "token": "secret-key-1"}),
        payload={"is_admin": True},
    )
    cmd = build_curl_from_finding(finding, base_url="http://localhost:8000")
    assert 'curl -i -s -X PUT "http://localhost:8000/api/v1/orders/99"' in cmd
    assert '-H "X-API-Key: secret-key-1"' in cmd
    assert '{"is_admin": true}' in cmd


def test_har_parser_seed_corpus(tmp_path):
    har_content = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://api.local/api/transfer",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token-abc"},
                            {"name": "X-Tenant-Id", "value": "tenant-999"},
                        ],
                        "queryString": [{"name": "dry_run", "value": "false"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"source_account": "ACC-1234", "amount": 500}),
                        },
                    },
                    "response": {"status": 200},
                }
            ]
        }
    }
    har_file = tmp_path / "sample.har"
    har_file.write_text(json.dumps(har_content), encoding="utf-8")

    corpus = parse_har_file(har_file)
    assert corpus.suggest_auth_token() == "Bearer token-abc"
    assert corpus.get_seed_for_param("source_account") == "ACC-1234"
    assert corpus.get_seed_for_param("X-Tenant-Id") == "tenant-999"
    assert corpus.get_seed_for_param("dry_run") == "false"
    body_seed = corpus.get_body_seed("POST", "/api/transfer")
    assert body_seed == {"source_account": "ACC-1234", "amount": 500}


def test_safety_cleanup_and_audit(tmp_path):
    headers = get_audit_headers("test-run-uuid")
    assert headers["X-Fuzzer-Audit"] == "true"
    assert headers["X-Fuzzer-Run-Id"] == "test-run-uuid"

    tracker = CleanupTracker("test-run-uuid", out_dir=tmp_path)
    tracker.record_mutation(
        method="POST",
        target_url="http://api.local",
        endpoint="/api/items",
        status_code=201,
        response_data={"id": "item-999", "name": "Test"},
    )
    manifest = tracker.write_manifest()
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["total_created_resources"] == 1
    assert data["resources"][0]["created_id"] == "item-999"
    assert data["resources"][0]["rollback_url"] == "/api/items/item-999"


def test_safety_cleanup_safe_skip_when_no_id(tmp_path):
    tracker = CleanupTracker("test-run-uuid", out_dir=tmp_path)
    tracker.record_mutation(
        method="POST",
        target_url="http://api.local",
        endpoint="/api/items",
        status_code=200,
        response_data="OK",  # No ID in response
    )
    assert len(tracker.created_resources) == 1
    assert tracker.created_resources[0].rollback_url == ""
    # Should safely skip auto-cleanup without executing dangerous DELETE on collection
    res = tracker.execute_auto_cleanup("http://api.local")
    assert res["skipped"] == 1
    assert res["deleted"] == 0


def test_build_curl_from_dict_finding():
    finding_dict = {
        "endpoint": "/api/v2/products",
        "method": "POST",
        "payload": {"sku": "PROD-1", "price": 99.9},
        "evidence": {"auth_context": {"Authorization": "Bearer token-xyz", "X-Custom": "val"}},
    }
    cmd = build_curl_from_finding(finding_dict, base_url="https://api.shop.com")
    assert 'curl -i -s -X POST "https://api.shop.com/api/v2/products"' in cmd
    assert '-H "Authorization: Bearer token-xyz"' in cmd
    assert '-H "X-Custom: val"' in cmd
    assert '"sku": "PROD-1"' in cmd


def test_har_parser_handles_null_and_malformed_entries(tmp_path):
    har_content = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://api.local/ping",
                        "queryString": None,
                        "headers": None,
                        "cookies": None,
                        "postData": None,
                    },
                    "response": None,
                },
                "invalid_entry_not_a_dict",
            ]
        }
    }
    har_file = tmp_path / "nulls.har"
    har_file.write_text(json.dumps(har_content), encoding="utf-8")
    corpus = parse_har_file(har_file)
    assert len(corpus.request_seeds) == 1
    assert ("GET", "/ping") in corpus.request_seeds


def test_verify_deep_state_persistence(monkeypatch):
    class MockResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data

        def json(self):
            if isinstance(self._json, Exception):
                raise self._json
            return self._json

    import requests

    # 1. Successful persistence match
    monkeypatch.setattr(requests, "get", lambda *a, **kw: MockResponse(200, {"user": {"role": "admin", "is_admin": True}}))
    persisted, msg = verify_deep_state_persistence("http://api.local/users/1", "role", "admin")
    assert persisted is True
    assert "actively persisted" in msg

    # 2. Field not found in response
    persisted, msg = verify_deep_state_persistence("http://api.local/users/1", "nonexistent", "val")
    assert persisted is False
    assert "was NOT found" in msg

    # 3. HTTP error response
    monkeypatch.setattr(requests, "get", lambda *a, **kw: MockResponse(404, {}))
    persisted, msg = verify_deep_state_persistence("http://api.local/users/1", "role", "admin")
    assert persisted is False
    assert "returned HTTP 404" in msg

    # 4. Type-aware boolean persistence matching
    monkeypatch.setattr(requests, "get", lambda *a, **kw: MockResponse(200, {"user": {"is_admin": True}}))
    persisted, _ = verify_deep_state_persistence("http://api.local/users/1", "is_admin", True)
    assert persisted is True

    for non_bool_payload in (
        {"user": {"is_admin": False}},
        {"user": {"is_admin": "true"}},
        {"user": {"is_admin": 1}},
        {"user": {"display_name": "alice"}},
    ):
        monkeypatch.setattr(requests, "get", lambda *a, _p=non_bool_payload, **kw: MockResponse(200, _p))
        persisted, _ = verify_deep_state_persistence("http://api.local/users/1", "is_admin", True)
        assert persisted is False


def test_semantic_mutator_with_live_seed_corpus():
    from core.semantic_mutator import SemanticMutationEngine, ParamSchema
    from core.har_parser import SeedCorpus

    # 1. Integer live seed mutation (Neighbor ID BOLA)
    corpus = SeedCorpus()
    corpus.add_param_seed("order_id", 1005)
    schema = ParamSchema(name="order_id", location="path", type="integer")
    probes = SemanticMutationEngine.generate_probes(schema, seed_corpus=corpus)
    
    # Must have live seed successor and predecessor BOLA probes
    probe_vals = [p.payload_value for p in probes]
    assert 1006 in probe_vals
    assert 1004 in probe_vals
    descriptions = " ".join(p.description for p in probes)
    assert "Live seed successor BOLA probe" in descriptions

    # 2. String live seed mutation & live seed SQL canary
    corpus_str = SeedCorpus()
    corpus_str.add_param_seed("account_number", "VN998877")
    schema_str = ParamSchema(name="account_number", location="query", type="string")
    probes_str = SemanticMutationEngine.generate_probes(schema_str, seed_corpus=corpus_str)
    
    str_vals = [p.payload_value for p in probes_str]
    assert "VN998877' OR '1'='1" in str_vals
    assert any("VN998878" in str(v) for v in str_vals)


def test_curl_builder_cross_platform_cmd_and_dual():
    from core.curl_builder import build_curl_command, build_curl_dual, build_curl_dual_from_finding

    # 1. shell='cmd' uses escaped double quotes for cmd.exe
    cmd_win = build_curl_command(
        method="POST",
        url="https://api.corp.com/v1/auth",
        headers={"Content-Type": "application/json"},
        json_data={"user": "admin", "token": "abc"},
        shell="cmd",
    )
    assert '-d "{\\"user\\": \\"admin\\", \\"token\\": \\"abc\\"}"' in cmd_win

    # 2. shell='bash' uses single quotes
    cmd_bash = build_curl_command(
        method="POST",
        url="https://api.corp.com/v1/auth",
        headers={"Content-Type": "application/json"},
        json_data={"user": "admin", "token": "abc"},
        shell="bash",
    )
    assert "-d '{\"user\": \"admin\", \"token\": \"abc\"}'" in cmd_bash

    # 3. Dual builder provides both
    dual = build_curl_dual(
        method="POST",
        url="https://api.corp.com/v1/auth",
        json_data={"action": "test"},
    )
    assert "bash" in dual and "cmd" in dual
    assert "curl -i -s -X POST" in dual["bash"]
    assert "curl -i -s -X POST" in dual["cmd"]


def test_reporter_renders_cross_platform_curl_buttons(tmp_path):
    from core.reporter import SecurityReporter

    reporter = SecurityReporter(results_dir=tmp_path)
    sample_finding = {
        "finding_id": "F-TEST-DUAL",
        "run_id": "run-test",
        "timestamp": "2026-11-20T00:00:00Z",
        "target_app": "ShopAPI",
        "endpoint": "/api/items",
        "method": "POST",
        "tool": "schemathesis",
        "attack_type": "MASS_ASSIGNMENT",
        "severity": "high",
        "confidence": 0.95,
        "confirmed": True,
        "fingerprint": "fp_test",
        "payload": {"role": "admin"},
        "owasp_category": "API3:2023",
        "evidence": "State persisted",
    }
    report_file = tmp_path / "test_report.html"
    res_path = reporter.generate_html_report([sample_finding], output_file=report_file)
    content = Path(res_path).read_text(encoding="utf-8")
    assert "📋 Bash / PowerShell" in content
    assert "📋 Windows CMD" in content
    assert "data-curl" in content
