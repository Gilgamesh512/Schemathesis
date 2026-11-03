"""Unit tests for RFC 7519 Token Authentication and Callback Whitelist Verifiers (Phase 2)."""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from core.callback_verifier import (
    CallbackEvent,
    CallbackVerifier,
    LocalCallbackListener,
)
from core.token_verifier import (
    TokenInspection,
    TokenVerifier,
    b64url_decode,
    b64url_encode,
)


def _create_sample_jwt(alg: str = "HS256", exp_offset: int = 3600) -> str:
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "12345", "user": "alice", "exp": int(time.time()) + exp_offset}
    h_str = b64url_encode(json.dumps(header).encode("utf-8"))
    p_str = b64url_encode(json.dumps(payload).encode("utf-8"))
    sig_str = b64url_encode(b"dummy_signature_bytes_12345")
    return f"{h_str}.{p_str}.{sig_str}"


# =========================================================================
# Token Verifier Tests
# =========================================================================

def test_token_inspection_valid():
    token = _create_sample_jwt(alg="HS256", exp_offset=3600)
    inspection = TokenVerifier.inspect_token(token)

    assert inspection is not None
    assert inspection.algorithm == "HS256"
    assert inspection.header.get("typ") == "JWT"
    assert inspection.payload.get("user") == "alice"
    assert inspection.has_exp is True
    assert inspection.is_expired is False


def test_token_inspection_bearer_prefix():
    token = _create_sample_jwt(alg="RS256")
    inspection = TokenVerifier.inspect_token(f"Bearer {token}")

    assert inspection is not None
    assert inspection.algorithm == "RS256"
    assert inspection.raw_token == token


def test_token_inspection_expired():
    token = _create_sample_jwt(exp_offset=-3600)
    inspection = TokenVerifier.inspect_token(token)

    assert inspection is not None
    assert inspection.is_expired is True


def test_token_inspection_invalid_formats():
    assert TokenVerifier.inspect_token("not-a-jwt") is None
    assert TokenVerifier.inspect_token("part1.part2") is None
    assert TokenVerifier.inspect_token("invalid_b64.invalid_b64.invalid_b64") is None


def test_generate_verification_probes():
    token = _create_sample_jwt(alg="HS256", exp_offset=3600)
    probes = TokenVerifier.generate_verification_probes(token)

    assert "alg_none" in probes
    assert "stripped_signature" in probes
    assert "expired_claim" in probes

    # Verify alg_none probe structure
    p_none = probes["alg_none"]
    parts_none = p_none.split(".")
    assert len(parts_none) == 3
    assert parts_none[2] == ""  # Empty signature
    h_none = json.loads(b64url_decode(parts_none[0]).decode("utf-8"))
    assert h_none["alg"] == "none"

    # Verify stripped signature probe structure
    p_stripped = probes["stripped_signature"]
    parts_stripped = p_stripped.split(".")
    assert parts_stripped[2] == ""

    # Verify expired claim probe structure
    p_exp = probes["expired_claim"]
    parts_exp = p_exp.split(".")
    payload_exp = json.loads(b64url_decode(parts_exp[1]).decode("utf-8"))
    assert payload_exp["exp"] < int(time.time())


def test_verify_endpoint_broken_auth_detected():
    async def run_test():
        verifier = TokenVerifier()
        token = _create_sample_jwt()

        # Mock client returning 200 OK (vulnerable - accepted insecure token)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_resp

        findings = await verifier.verify_endpoint(
            client=mock_client,
            endpoint="/api/v1/profile",
            method="GET",
            valid_auth_header=token,
            base_url="http://api.test",
            run_id="run-test-1",
        )

        assert len(findings) == 3
        for finding in findings:
            assert finding.attack_type == "BROKEN_AUTHENTICATION"
            assert finding.owasp_category == "API2:2023"
            assert finding.severity == "high"
            assert finding.confirmed is True

    asyncio.run(run_test())


def test_verify_endpoint_properly_secured():
    async def run_test():
        verifier = TokenVerifier()
        token = _create_sample_jwt()

        # Mock client returning 401 Unauthorized (properly secured endpoint)
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_resp

        findings = await verifier.verify_endpoint(
            client=mock_client,
            endpoint="/api/v1/profile",
            method="GET",
            valid_auth_header=token,
            base_url="http://api.test",
            run_id="run-test-2",
        )

        assert len(findings) == 0

    asyncio.run(run_test())


# =========================================================================
# Callback Whitelist & SSRF Verifier Tests
# =========================================================================

def test_is_callback_parameter():
    assert CallbackVerifier.is_callback_parameter("webhook") is True
    assert CallbackVerifier.is_callback_parameter("callback_url") is True
    assert CallbackVerifier.is_callback_parameter("redirect") is True
    assert CallbackVerifier.is_callback_parameter("dest") is True
    assert CallbackVerifier.is_callback_parameter("target_url") is True

    assert CallbackVerifier.is_callback_parameter("username") is False
    assert CallbackVerifier.is_callback_parameter("password") is False
    assert CallbackVerifier.is_callback_parameter("item_id") is False


def test_local_callback_listener_loopback():
    async def run_test():
        listener = LocalCallbackListener()
        listener_url = await listener.start()

        try:
            assert listener_url.startswith("http://127.0.0.1:")
            token = "canary_token_xyz_99"

            # Simulate an outbound request from target server to the canary listener
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{listener_url}/{token}", timeout=2.0)
                assert resp.status_code == 200
                assert resp.text == "OK"

            # Verify hit was recorded
            hit = listener.check_hit(token)
            assert hit is not None
            assert hit.path == f"/{token}"
            assert hit.method == "GET"
            assert hit.client_ip in {"127.0.0.1", "::1", "unknown"} or hit.client_ip.startswith("127.")
        finally:
            await listener.stop()

    asyncio.run(run_test())


def test_callback_verifier_outbound_hit():
    async def run_test():
        verifier = CallbackVerifier()

        # Mock client: when requesting endpoint, trigger callback on listener
        async def fake_request(*args, **kwargs):
            # Extract canary_url from query params
            params = kwargs.get("params", {})
            canary = params.get("webhook")
            if canary:
                # Trigger HTTP call to canary url
                async with httpx.AsyncClient() as c:
                    await c.get(canary, timeout=2.0)

            mock_r = MagicMock()
            mock_r.status_code = 200
            mock_r.headers = {"Content-Type": "application/json"}
            return mock_r

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=fake_request)

        finding = await verifier.verify_endpoint_url_parameter(
            client=mock_client,
            endpoint="/api/v1/subscribe",
            method="POST",
            param_name="webhook",
            param_location="query",
            base_url="http://api.test",
            run_id="run-ssrf-1",
            timeout=1.0,
        )

        assert finding is not None
        assert finding.attack_type == "SSRF"
        assert finding.owasp_category == "API7:2023"
        assert finding.severity == "high"
        assert finding.confirmed is True
        assert "Server made outbound loopback request" in finding.evidence.response_signal[0]

    asyncio.run(run_test())


# =========================================================================
# Audit Functions & CLI Integration Tests
# =========================================================================

def test_run_token_audit_non_jwt_skips():
    from modules.security.run_security_tests import run_token_audit

    findings = run_token_audit(
        base_url="http://127.0.0.1:8000",
        auth_token="simple-static-api-key",
    )
    assert findings == []


def test_run_token_audit_with_jwt():
    from modules.security.run_security_tests import run_token_audit

    token = _create_sample_jwt()
    with patch("httpx.AsyncClient.request") as mock_req:
        mock_r = MagicMock()
        mock_r.status_code = 401
        mock_r.headers = {}
        mock_req.return_value = mock_r

        findings = run_token_audit(
            base_url="http://127.0.0.1:8000",
            auth_token=token,
            endpoints=[("GET", "/api/v1/profile")],
        )
        assert findings == []


def test_run_callback_audit_execution():
    from modules.security.run_security_tests import run_callback_audit

    with patch.object(CallbackVerifier, "verify_endpoint_url_parameter", new_callable=AsyncMock) as mock_verify:
        mock_verify.return_value = None
        findings = run_callback_audit(
            base_url="http://127.0.0.1:8000",
            candidate_params=[("POST", "/webhook", "url", "body")],
        )
        assert findings == []
        mock_verify.assert_called_once()


def test_run_all_scan_passes_phase2_flags():
    import run_all

    with patch.object(run_all, "run_script") as mock_run:
        exit_code = run_all.main([
            "scan",
            "--url", "http://127.0.0.1:8000",
            "--schema", "targets/schemas/vampi/vampi_spec.yaml",
            "--verify-tokens",
            "--verify-callbacks",
            "--callback-url", "https://canary.example.com/hit",
        ])
        assert exit_code == 0
        mock_run.assert_called_once()
        args = mock_run.call_args[0]
        assert "--verify-tokens" in args
        assert "--verify-callbacks" in args
        assert "--callback-url" in args
        assert "https://canary.example.com/hit" in args

