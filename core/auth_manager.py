"""Enterprise Authentication Manager with Dynamic Token Refresh.

Supports RFC 6749 OAuth2 Token Refresh, API Keys, Custom Headers, and
automated re-authentication when receiving HTTP 401 Unauthorized during scans.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


@dataclass
class AuthConfig:
    """Enterprise authentication configuration."""
    auth_type: str = "bearer"  # "bearer" | "apikey" | "basic" | "custom" | "oauth2"
    token: Optional[str] = None
    header_name: str = "Authorization"
    header_prefix: str = "Bearer "
    api_key_name: Optional[str] = None
    api_key_location: str = "header"  # "header" | "query"
    refresh_url: Optional[str] = None
    refresh_payload: dict[str, Any] = field(default_factory=dict)
    refresh_headers: dict[str, str] = field(default_factory=dict)
    token_response_path: str = "access_token"  # or "token"


class AuthManager:
    """Thread-safe / Coroutine-safe authentication manager with automatic refresh."""

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self._lock = asyncio.Lock()
        self._last_refresh_time: float = 0.0

    @classmethod
    def from_header_string(cls, raw_header: str) -> "AuthManager":
        """Construct from raw 'Header: Value' or 'Bearer <TOKEN>' string."""
        raw = raw_header.strip()
        if not raw:
            return cls(AuthConfig())

        if ":" in raw:
            h_name, _, h_val = raw.partition(":")
            h_name = h_name.strip()
            h_val = h_val.strip()
            if h_val.lower().startswith("bearer "):
                return cls(AuthConfig(
                    auth_type="bearer",
                    token=h_val[7:].strip(),
                    header_name=h_name,
                    header_prefix="Bearer ",
                ))
            return cls(AuthConfig(
                auth_type="custom",
                token=h_val,
                header_name=h_name,
                header_prefix="",
            ))

        if raw.lower().startswith("bearer "):
            token = raw[7:].strip()
        else:
            token = raw

        return cls(AuthConfig(
            auth_type="bearer",
            token=token,
            header_name="Authorization",
            header_prefix="Bearer ",
        ))

    def get_headers(self) -> dict[str, str]:
        """Produce request headers for current authentication state."""
        if not self.config.token:
            return {}

        if self.config.auth_type == "bearer":
            return {self.config.header_name: f"{self.config.header_prefix}{self.config.token}".strip()}
        elif self.config.auth_type in ("apikey", "custom"):
            return {self.config.header_name: f"{self.config.header_prefix}{self.config.token}".strip()}

        return {self.config.header_name: str(self.config.token)}

    def get_query_params(self) -> dict[str, str]:
        """Produce query params if API key is query-based."""
        if (
            self.config.auth_type == "apikey"
            and self.config.api_key_location == "query"
            and self.config.api_key_name
            and self.config.token
        ):
            return {self.config.api_key_name: self.config.token}
        return {}

    async def handle_unauthorized(
        self,
        client: httpx.AsyncClient,
        trigger_time: float,
    ) -> bool:
        """Attempt to refresh token when encountering HTTP 401.

        Returns True if token was successfully refreshed, False otherwise.
        """
        if not self.config.refresh_url:
            return False

        async with self._lock:
            # If another coroutine already refreshed token after trigger_time, skip duplicate refresh
            if self._last_refresh_time > trigger_time:
                return True

            try:
                headers = dict(self.config.refresh_headers)
                if "content-type" not in {k.lower() for k in headers}:
                    headers["Content-Type"] = "application/json"

                resp = await client.post(
                    self.config.refresh_url,
                    json=self.config.refresh_payload,
                    headers=headers,
                    timeout=10.0,
                )

                if resp.status_code in (200, 201):
                    data = resp.json()
                    new_token = None
                    # Resolve token from response path (e.g. "access_token" or "data.token")
                    target_field = self.config.token_response_path
                    if "." in target_field:
                        cur = data
                        for part in target_field.split("."):
                            cur = cur.get(part, {}) if isinstance(cur, dict) else None
                        new_token = cur if isinstance(cur, str) else None
                    else:
                        new_token = data.get(target_field) or data.get("token") or data.get("access_token")

                    if new_token and isinstance(new_token, str):
                        self.config.token = new_token
                        self._last_refresh_time = time.monotonic()
                        return True
            except Exception:
                pass

        return False


__all__ = ["AuthConfig", "AuthManager"]
