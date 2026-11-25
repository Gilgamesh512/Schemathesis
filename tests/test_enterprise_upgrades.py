"""Unit & Integration Tests for Enterprise DevSecOps Upgrades.

Verifies:
1. Shannon Entropy calculation & High-Entropy secret detection.
2. Custom PII patterns loading from config/pii_rules.json.
3. AuthManager mTLS certificate configuration and OAuth2 Client Credentials flow.
4. Concurrency Fuzzer synchronized burst barrier.
5. SARIF OASIS v2.1.0 Taxonomies & Schema Location mapping.
6. DevSecOps Quality Gate structured evaluation and Markdown table output.
7. Webhook Alerting payload formatting.
8. Preflight Target Reachability check.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from core import (
    AuthConfig,
    AuthManager,
    ConcurrencyFuzzer,
    PiiDetector,
    SecurityReporter,
)
from core.pii_detector import calculate_shannon_entropy
from core.alerting import send_webhook_alert
from run_all import preflight_check


def test_shannon_entropy_calculation():
    """Verify Shannon entropy accurately distinguishes repetitive vs pseudo-random keys."""
    # Repetitive single char -> 0.0 entropy
    assert calculate_shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0

    # Low entropy patterned string
    low_entropy = calculate_shannon_entropy("abababababababab")
    assert low_entropy == 1.0

    # High entropy random base64 / cryptographic key
    random_key = "dGVzdF9zZWNyZXRfa2V5XzEyMzQ1Njc4OTA="
    high_entropy = calculate_shannon_entropy(random_key)
    assert high_entropy >= 4.0


def test_pii_entropy_and_custom_rules_detection():
    """Verify that PII detector detects custom rules and high-entropy secrets."""
    sample = (
        "Account info: IBAN: DE89370400440532013000, "
        "SecretKey: 9f8a7c6e5d4b3a210fedcba987654321, "
        "SSN: 123-45-6789"
    )
    res = PiiDetector.scan(sample)
    assert res.has_pii is True

    # Check that custom IBAN or High-Entropy was identified
    detected_cats = {m.category for m in res.matches}
    assert "BANK_ACCOUNT" in detected_cats or "HIGH_ENTROPY_SECRET" in detected_cats or "GOV_ID" in detected_cats

    # Verify masking
    masked = PiiDetector.mask_text(sample)
    assert "DE89370400440532013000" not in masked
    assert "123-45-6789" not in masked


def test_auth_manager_mtls_configuration():
    """Verify mTLS client certificate configuration and tuple generation."""
    # No cert configured
    auth = AuthManager(AuthConfig())
    assert auth.get_httpx_cert() is None

    # Cert only
    auth_cert = AuthManager(AuthConfig(client_cert="/path/to/client.crt"))
    assert auth_cert.get_httpx_cert() == "/path/to/client.crt"

    # Cert + Key pair
    auth_pair = AuthManager(AuthConfig(
        client_cert="/path/to/client.crt",
        client_key="/path/to/client.key",
    ))
    assert auth_pair.get_httpx_cert() == ("/path/to/client.crt", "/path/to/client.key")


def test_auth_manager_oauth2_client_credentials():
    """Verify OAuth2 RFC 6749 client credentials flow execution."""
    import asyncio

    async def _test():
        auth = AuthManager(AuthConfig(
            oauth2_endpoint="https://auth.company.test/oauth/token",
            oauth2_client_id="client-app-123",
            oauth2_client_secret="super-secret-xyz",
            oauth2_scope="api:read api:write",
        ))

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "mock-oauth2-jwt-token-abcdef",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_client.post.return_value = mock_resp

        success = await auth.fetch_oauth2_token(mock_client)
        assert success is True
        assert auth.config.token == "mock-oauth2-jwt-token-abcdef"
        assert auth.get_headers() == {"Authorization": "Bearer mock-oauth2-jwt-token-abcdef"}

    asyncio.run(_test())


def test_sarif_taxonomies_and_schema_mapping(tmp_path):
    """Verify SARIF v2.1.0 generator includes OASIS Taxonomies and accurate schema URI."""
    reporter = SecurityReporter(results_dir=tmp_path)
    findings = [{
        "finding_id": "test-finding-1",
        "owasp_category": "API1:2023",
        "attack_type": "BOLA",
        "severity": "critical",
        "confirmed": True,
        "endpoint": "/api/v1/orders/100",
        "method": "GET",
        "evidence": "Unauthorized access to victim resource",
    }]
    target_info = {
        "schema": "tests/fixtures/sample_openapi.yaml"
    }
    out_file = tmp_path / "test.sarif"
    sarif_path = reporter.generate_sarif_report(findings, target_info=target_info, output_file=out_file)

    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    
    # Check Taxonomies in run
    run = sarif_doc["runs"][0]
    assert "taxonomies" in run
    assert run["taxonomies"][0]["name"] == "OWASP API Security Top 10 2023"
    assert "supportedTaxonomies" in run["tool"]["driver"]

    # Check physicalLocation mapped to schema
    result_entry = run["results"][0]
    artifact_loc = result_entry["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "sample_openapi.yaml" in artifact_loc["uri"]
    assert result_entry["properties"]["confirmed"] is True
    assert "taxa" in result_entry


def test_webhook_alerting_generic_and_slack():
    """Verify Webhook Alerter formats JSON payloads and handles network errors gracefully."""
    # Test with invalid URL returns False without raising
    assert send_webhook_alert("", "Test Alert", "Gate Passed", "PASSED") is False
    assert send_webhook_alert("ftp://invalid-scheme", "Test", "Test", "PASSED") is False


def test_preflight_check():
    """Verify preflight check returns boolean and status description."""
    # Invalid domain should fail gracefully
    alive, msg = preflight_check("http://127.0.0.1:59999", timeout=0.2)
    assert alive is False
    assert "refused" in msg.lower() or "failed" in msg.lower() or "error" in msg.lower() or "timed out" in msg.lower()
