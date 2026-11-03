"""Enterprise-Grade Features Test Suite.

Verifies:
1. Token Verifier Authentication Challenge & False Positive Suppression.
2. Blind SSRF External OOB Callback Polling.
3. Enterprise AuthManager Dynamic Token Refresh on HTTP 401.
4. Time-based Blind Injection Latency Detection.
5. Extended Built-in Security Mutation Probes (Path Traversal, SSTI, Mass Assignment).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from core.auth_manager import AuthConfig, AuthManager
from core.callback_verifier import CallbackVerifier, LocalCallbackListener
from core.token_verifier import TokenVerifier, b64url_encode
from core.evidence import compare_responses, ResponseObservation
from modules.rest import run_schemathesis1 as rest


# =========================================================================
# 1. Token Verifier: Challenge & False-Positive Suppression
# =========================================================================

def _dummy_jwt() -> str:
    h = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
    p = b64url_encode(b'{"sub":"123","user":"bob","exp":9999999999}')
    s = b64url_encode(b'signature123')
    return f"{h}.{p}.{s}"


def test_token_verifier_skips_public_endpoint_when_challenged():
    """Verify that unauthenticated endpoints returning 200 do NOT trigger false-positive findings."""
    async def run_test():
        verifier = TokenVerifier()
        token = _dummy_jwt()

        # Mock client where unauthenticated request returns 200 (public route)
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_client.request.return_value = mock_resp

        findings = await verifier.verify_endpoint(
            client=mock_client,
            endpoint="/public/catalog",
            method="GET",
            valid_auth_header=token,
            base_url="http://api.test",
            run_id="run-fp-test",
            require_auth_challenge=True,
        )

        # Must suppress false positives and return zero findings
        assert len(findings) == 0

    asyncio.run(run_test())


def test_token_verifier_detects_broken_auth_when_challenged():
    """Verify that when unauthenticated request gets 401, but probe gets 200, finding is reported."""
    async def run_test():
        verifier = TokenVerifier()
        token = _dummy_jwt()

        # Side effect: first request (unauth challenge) returns 401; probe requests return 200 (vulnerable)
        responses = [
            MagicMock(status_code=401, headers={}),  # Challenge: requires auth!
            MagicMock(status_code=200, headers={}),  # Probe 1 accepted!
            MagicMock(status_code=200, headers={}),  # Probe 2 accepted!
            MagicMock(status_code=200, headers={}),  # Probe 3 accepted!
        ]

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=responses)

        findings = await verifier.verify_endpoint(
            client=mock_client,
            endpoint="/api/v1/secure-data",
            method="GET",
            valid_auth_header=token,
            base_url="http://api.test",
            run_id="run-vuln-test",
            require_auth_challenge=True,
        )

        assert len(findings) == 3
        for f in findings:
            assert f.attack_type == "BROKEN_AUTHENTICATION"
            assert f.confirmed is True

    asyncio.run(run_test())


# =========================================================================
# 2. Blind SSRF External OOB Callback Polling
# =========================================================================

def test_callback_verifier_external_poll_hit():
    """Verify that CallbackVerifier polls external canary API and records confirmed SSRF."""
    async def run_test():
        verifier = CallbackVerifier(
            external_callback_url="https://webhook.site/abc-123",
            poll_url="https://webhook.site/token/abc-123/requests?query={token}",
        )

        # Mock API requests:
        # 1. Target API request (200 OK)
        # 2. Poller query returning hit JSON
        async def fake_request(*args, **kwargs):
            url = kwargs.get("url") or (args[1] if len(args) > 1 else (args[0] if args else ""))
            if "webhook.site" in str(url):
                mock_poll = MagicMock()
                mock_poll.status_code = 200
                mock_poll.json.return_value = {
                    "data": [{
                        "created_at": "2026-11-03T12:00:00Z",
                        "ip": "198.51.100.25",
                        "url": "/ssrf_canary_hit",
                        "method": "POST",
                        "headers": {"user-agent": "Target-Internal-Curl"},
                    }]
                }
                return mock_poll

            mock_api = MagicMock()
            mock_api.status_code = 200
            mock_api.headers = {"Content-Type": "application/json"}
            return mock_api

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=fake_request)
        mock_client.get = AsyncMock(side_effect=fake_request)

        finding = await verifier.verify_endpoint_url_parameter(
            client=mock_client,
            endpoint="/api/v1/webhook",
            method="POST",
            param_name="dest_url",
            param_location="body",
            base_url="http://api.test",
            run_id="run-ssrf-external",
            timeout=0.1,
        )

        assert finding is not None
        assert finding.attack_type == "SSRF"
        assert finding.confirmed is True
        assert "198.51.100.25" in finding.evidence.response_signal[0]

    asyncio.run(run_test())


# =========================================================================
# 3. Enterprise AuthManager Dynamic Token Refresh
# =========================================================================

def test_auth_manager_initialization_and_header_generation():
    # Test Bearer header parsing
    mgr1 = AuthManager.from_header_string("Bearer eyJhbGciOi...")
    assert mgr1.get_headers() == {"Authorization": "Bearer eyJhbGciOi..."}

    # Test Custom API-Key parsing
    mgr2 = AuthManager.from_header_string("X-API-Key: secret_key_999")
    assert mgr2.get_headers() == {"X-API-Key": "secret_key_999"}


def test_auth_manager_dynamic_refresh_on_401():
    async def run_test():
        config = AuthConfig(
            auth_type="bearer",
            token="expired_token_111",
            refresh_url="http://auth.test/oauth/token",
            refresh_payload={"grant_type": "client_credentials", "client_id": "sec_ops"},
            token_response_path="access_token",
        )
        mgr = AuthManager(config)

        # Mock refresh response from auth server
        mock_client = AsyncMock()
        mock_refresh_resp = MagicMock()
        mock_refresh_resp.status_code = 200
        mock_refresh_resp.json.return_value = {
            "access_token": "fresh_token_222",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_client.post.return_value = mock_refresh_resp

        start_time = 100.0
        refreshed = await mgr.handle_unauthorized(mock_client, trigger_time=start_time)

        assert refreshed is True
        assert mgr.config.token == "fresh_token_222"
        assert mgr.get_headers() == {"Authorization": "Bearer fresh_token_222"}

    asyncio.run(run_test())


# =========================================================================
# 4. Time-based Blind Injection Latency Detection
# =========================================================================

def test_time_based_latency_delta_evaluation():
    # Test compare_responses delta detection
    obs_base = ResponseObservation(status_code=200, body_hash="h1", headers_hash="hdr", response_time_ms=50.0)
    obs_attack = ResponseObservation(status_code=200, body_hash="h1", headers_hash="hdr", response_time_ms=4100.0)

    diff = compare_responses(obs_base, obs_attack)
    assert "response_time_ms" in diff
    assert diff["response_time_ms"].get("significant_delay") is True
    assert diff["response_time_ms"].get("delta_ms") == 4050.0

    # Test evaluate_response detection
    payload = rest.Payload(
        endpoint="/items",
        method="GET",
        target_param="id",
        param_location="query",
        attack_type="TIME_BASED_SQLI",
        payload_value="1' AND SLEEP(4)--",
        expected_signal=[],
    )

    resp_mock = MagicMock()
    resp_mock.status_code = 200
    resp_mock.text = "OK"
    resp_mock.elapsed_ms = 4150.0

    sev, cand, ev, cves = rest.evaluate_response(resp_mock, payload)
    assert cand is True
    assert sev == "high"
    assert "significant time delay observed" in ev


# =========================================================================
# 5. Extended Built-in Security Mutation Probes
# =========================================================================

def test_extended_mutation_payloads():
    mock_op = MagicMock()
    mock_op.path = "/api/v1/files/{filename}"
    mock_op.method = "POST"

    mock_schema = MagicMock()
    mock_result = MagicMock()
    mock_result.ok.return_value = mock_op
    mock_schema.get_all_operations.return_value = [mock_result]

    targets = {"test_target": (mock_schema, "http://api.test")}
    payloads = rest.schema_payloads(targets)

    attack_types = {p.attack_type for p in payloads}
    assert "PATH_TRAVERSAL" in attack_types
    assert "SSTI" in attack_types
    assert "MASS_ASSIGNMENT" in attack_types
    assert "BOLA" in attack_types
    assert "SQL_INJECTION" in attack_types
