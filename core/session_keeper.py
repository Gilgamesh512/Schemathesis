"""Generic Auto-Token Refresh Hook & Multi-Role Session Keeper (OWASP API2:2023 Resilience).

Provides automated, generic session maintenance and proactive/reactive token refreshing
for ANY REST or GraphQL API target without hardcoding. Supports multi-role RBAC matrices
(e.g., admin, manager, member, anonymous) for authorization testing.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from typing import Any, Optional
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Extract and parse JWT claims payload without signature verification."""
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()
    parts = clean.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # Add base64 padding if needed
    rem = len(payload_b64) % 4
    if rem:
        payload_b64 += "=" * (4 - rem)
    try:
        decoded = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        return json.loads(decoded.decode("utf-8", errors="replace"))
    except Exception:
        return {}


def is_jwt_expired_or_expiring(token: str, threshold_seconds: float = 30.0) -> bool:
    """Return True if token contains an 'exp' claim that expires within threshold_seconds."""
    claims = decode_jwt_unverified(token)
    exp = claims.get("exp")
    if exp is None:
        return False
    try:
        exp_ts = float(exp)
        return (exp_ts - time.time()) <= threshold_seconds
    except (ValueError, TypeError):
        return False


class AuthAutomationConfig(BaseModel):
    """Declarative specification for automated authentication on any target."""
    role: str = "default"
    enabled: bool = True
    login_url: str
    refresh_url: Optional[str] = None
    method: str = "POST"
    payload: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    token_extraction: str = "json:access_token"  # "json:<path>", "header:<name>", "regex:<pat>"
    header_format: str = "Bearer {token}"
    auth_header_name: str = "Authorization"
    refresh_threshold_seconds: float = 30.0
    auto_refresh_on_statuses: list[int] = Field(default_factory=lambda: [401, 403])


class SessionKeeper:
    """Universal Session Keeper maintaining live tokens for single or multi-role targets."""

    def __init__(
        self,
        configs: Optional[list[AuthAutomationConfig] | dict[str, Any] | AuthAutomationConfig] = None,
        base_url: str = "",
    ):
        self.base_url = base_url.rstrip("/")
        self.configs: dict[str, AuthAutomationConfig] = {}
        self._tokens: dict[str, str] = {}
        self._locks: dict[str, asyncio.Lock] = {}

        if configs:
            self.register_config(configs)

    def register_config(
        self,
        config: list[AuthAutomationConfig] | dict[str, Any] | AuthAutomationConfig,
    ) -> None:
        """Register one or more role automation configurations."""
        if isinstance(config, list):
            for item in config:
                self.register_config(item)
        elif isinstance(config, AuthAutomationConfig):
            self.configs[config.role] = config
            if config.role not in self._locks:
                self._locks[config.role] = asyncio.Lock()
        elif isinstance(config, dict):
            # Check if dict represents multiple roles or a single config
            if "login_url" in config:
                cfg = AuthAutomationConfig(**config)
                self.register_config(cfg)
            else:
                for role_name, sub_cfg in config.items():
                    if isinstance(sub_cfg, dict):
                        sub_cfg_dict = dict(sub_cfg)
                        sub_cfg_dict.setdefault("role", role_name)
                        self.register_config(AuthAutomationConfig(**sub_cfg_dict))

    def _get_lock(self, role: str) -> asyncio.Lock:
        if role not in self._locks:
            self._locks[role] = asyncio.Lock()
        return self._locks[role]

    def set_token(self, role: str, token_value: str) -> None:
        """Manually seed or override the current token for a role."""
        clean = token_value.strip()
        self._tokens[role] = clean

    def get_token(self, role: str = "default") -> Optional[str]:
        """Return the current cached token for a role."""
        return self._tokens.get(role)

    def get_auth_header(self, role: str = "default") -> Optional[str]:
        """Return formatted header value (e.g. 'Bearer eyJ...') for a role."""
        raw_token = self.get_token(role)
        if not raw_token:
            return None
        cfg = self.configs.get(role)
        fmt = cfg.header_format if cfg else "Bearer {token}"
        if "{token}" in fmt:
            return fmt.format(token=raw_token)
        return raw_token

    def _extract_token_from_response(self, response: httpx.Response, rule: str) -> str:
        """Extract token value from HTTP response based on rule."""
        rule = rule.strip()
        if rule.startswith("json:"):
            json_path = rule[5:].strip()
            data = response.json()
            # Traverse dot-separated paths: e.g. "data.auth.token"
            parts = json_path.split(".")
            curr: Any = data
            for part in parts:
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                else:
                    raise KeyError(f"Key '{part}' not found in response JSON")
            return str(curr)

        if rule.startswith("header:"):
            header_name = rule[7:].strip()
            val = response.headers.get(header_name)
            if not val:
                raise KeyError(f"Header '{header_name}' not found in response headers")
            return val

        if rule.startswith("regex:"):
            pattern = rule[6:].strip()
            match = re.search(pattern, response.text)
            if match and match.groups():
                return match.group(1)
            raise ValueError(f"Regex pattern '{pattern}' matched nothing in response body")

        # Fallback to direct field lookup in JSON
        data = response.json()
        if isinstance(data, dict):
            for cand in ("access_token", "token", "jwt", "id_token", "authToken", "accessToken"):
                if cand in data:
                    return str(data[cand])
        raise ValueError(f"Could not extract token using rule '{rule}'")

    async def refresh_token(
        self,
        role: str = "default",
        proxy: Optional[str] = None,
        insecure: bool = False,
    ) -> str:
        """Execute automated login/refresh flow and update cached token."""
        cfg = self.configs.get(role)
        if not cfg or not cfg.enabled:
            raise ValueError(f"No active auth automation configuration for role '{role}'")

        lock = self._get_lock(role)
        async with lock:
            target_url = cfg.login_url
            if not target_url.startswith(("http://", "https://")) and self.base_url:
                target_url = f"{self.base_url}/{target_url.lstrip('/')}"

            transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
            async with httpx.AsyncClient(transport=transport, timeout=12.0) as client:
                req_kwargs: dict[str, Any] = {"headers": dict(cfg.headers)}
                if cfg.method.upper() in ("POST", "PUT", "PATCH"):
                    req_kwargs["json"] = cfg.payload
                else:
                    req_kwargs["params"] = cfg.payload

                resp = await client.request(cfg.method.upper(), target_url, **req_kwargs)
                if resp.status_code >= 400:
                    raise RuntimeError(
                        f"Auth automation failed for role '{role}': HTTP {resp.status_code} - {resp.text[:200]}"
                    )

                extracted = self._extract_token_from_response(resp, cfg.token_extraction)
                self._tokens[role] = extracted
                logger.info("Successfully refreshed session token for role '%s'", role)
                return extracted

    async def ensure_valid_token(
        self,
        role: str = "default",
        proxy: Optional[str] = None,
        insecure: bool = False,
    ) -> str:
        """Proactively verify and refresh token if missing or close to expiration."""
        cfg = self.configs.get(role)
        current = self.get_token(role)
        if not current:
            return await self.refresh_token(role, proxy=proxy, insecure=insecure)

        threshold = cfg.refresh_threshold_seconds if cfg else 30.0
        if is_jwt_expired_or_expiring(current, threshold_seconds=threshold):
            logger.info("Token for role '%s' is expired or close to expiry. Refreshing proactively...", role)
            return await self.refresh_token(role, proxy=proxy, insecure=insecure)

        return current

    async def handle_response(
        self,
        status_code: int,
        role: str = "default",
        proxy: Optional[str] = None,
        insecure: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """Reactive refresh on 401/403. Returns (was_refreshed, new_header_value)."""
        cfg = self.configs.get(role)
        if not cfg or not cfg.enabled:
            return False, None

        if status_code in cfg.auto_refresh_on_statuses:
            logger.warning(
                "Encountered HTTP %d for role '%s'. Performing reactive session refresh...",
                status_code, role,
            )
            try:
                new_token = await self.refresh_token(role, proxy=proxy, insecure=insecure)
                header_val = self.get_auth_header(role)
                return True, header_val
            except Exception as exc:
                logger.error("Failed to reactive-refresh session for role '%s': %s", role, exc)
                return False, None

        return False, None
