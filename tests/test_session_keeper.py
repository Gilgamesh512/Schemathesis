"""Unit tests for Generic Auto-Token Refresh Hook & Multi-Role Session Keeper."""

from __future__ import annotations

import base64
import json
import time
import pytest
import httpx

from core.session_keeper import (
    AuthAutomationConfig,
    SessionKeeper,
    decode_jwt_unverified,
    is_jwt_expired_or_expiring,
)


def _make_dummy_jwt(claims: dict, header: dict | None = None) -> str:
    hdr = header or {"alg": "HS256", "typ": "JWT"}
    b64_hdr = base64.urlsafe_b64encode(json.dumps(hdr).encode()).decode().rstrip("=")
    b64_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{b64_hdr}.{b64_payload}.fakesig"


def test_decode_jwt_unverified():
    jwt_str = _make_dummy_jwt({"sub": "user123", "role": "admin", "exp": 1893456000})
    claims = decode_jwt_unverified(jwt_str)
    assert claims["sub"] == "user123"
    assert claims["role"] == "admin"
    assert claims["exp"] == 1893456000

    # With Bearer prefix
    claims_bearer = decode_jwt_unverified(f"Bearer {jwt_str}")
    assert claims_bearer["sub"] == "user123"

    # Malformed token returns empty dict without crashing
    assert decode_jwt_unverified("invalid-token") == {}


def test_is_jwt_expired_or_expiring():
    now = time.time()
    # Expired 100 seconds ago
    expired_jwt = _make_dummy_jwt({"exp": now - 100})
    assert is_jwt_expired_or_expiring(expired_jwt, threshold_seconds=30) is True

    # Expiring in 10 seconds (within 30s threshold)
    expiring_soon_jwt = _make_dummy_jwt({"exp": now + 10})
    assert is_jwt_expired_or_expiring(expiring_soon_jwt, threshold_seconds=30) is True

    # Valid for 1000 seconds
    valid_jwt = _make_dummy_jwt({"exp": now + 1000})
    assert is_jwt_expired_or_expiring(valid_jwt, threshold_seconds=30) is False

    # No exp claim
    assert is_jwt_expired_or_expiring(_make_dummy_jwt({"sub": "no-exp"})) is False


def test_session_keeper_registration_and_headers():
    cfg_admin = AuthAutomationConfig(
        role="admin",
        login_url="http://127.0.0.1:8000/auth/login",
        header_format="Bearer {token}",
    )
    cfg_user = AuthAutomationConfig(
        role="user",
        login_url="http://127.0.0.1:8000/auth/login",
        header_format="Token {token}",
    )

    keeper = SessionKeeper([cfg_admin, cfg_user])
    keeper.set_token("admin", "admin-jwt-token")
    keeper.set_token("user", "user-token-123")

    assert keeper.get_token("admin") == "admin-jwt-token"
    assert keeper.get_auth_header("admin") == "Bearer admin-jwt-token"

    assert keeper.get_token("user") == "user-token-123"
    assert keeper.get_auth_header("user") == "Token user-token-123"


def test_extract_token_from_response():
    keeper = SessionKeeper()

    # 1. JSON path extraction
    req = httpx.Request("POST", "http://test.local/login")
    resp_json = httpx.Response(200, request=req, json={"data": {"auth": {"token": "extracted-abc"}}})
    val = keeper._extract_token_from_response(resp_json, "json:data.auth.token")
    assert val == "extracted-abc"

    # 2. Header extraction
    resp_hdr = httpx.Response(200, request=req, headers={"X-Access-Token": "hdr-token-xyz"})
    val_hdr = keeper._extract_token_from_response(resp_hdr, "header:x-access-token")
    assert val_hdr == "hdr-token-xyz"

    # 3. Regex extraction
    resp_txt = httpx.Response(200, request=req, text='Authorization callback code: secret_code_9999 for user')
    val_regex = keeper._extract_token_from_response(resp_txt, r"regex:code:\s*([A-Za-z0-9_]+)")
    assert val_regex == "secret_code_9999"


@pytest.mark.anyio
async def test_session_keeper_reactive_handle_response():
    called = []

    class MockKeeper(SessionKeeper):
        async def refresh_token(self, role="default", proxy=None, insecure=False):
            called.append(role)
            self.set_token(role, f"refreshed-token-for-{role}")
            return f"refreshed-token-for-{role}"

    cfg = AuthAutomationConfig(
        role="editor",
        login_url="http://127.0.0.1:8000/login",
        auto_refresh_on_statuses=[401, 403],
    )
    keeper = MockKeeper(cfg)
    keeper.set_token("editor", "old-token")

    # Status 200 should NOT refresh
    refreshed, hdr = await keeper.handle_response(200, role="editor")
    assert refreshed is False
    assert hdr is None
    assert len(called) == 0

    # Status 401 SHOULD trigger reactive refresh
    refreshed, hdr = await keeper.handle_response(401, role="editor")
    assert refreshed is True
    assert hdr == "Bearer refreshed-token-for-editor"
    assert called == ["editor"]
