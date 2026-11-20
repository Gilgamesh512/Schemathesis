"""Smart Proxy Pool & Rate-Limit / WAF Evasion Rotator.

Manages dynamic proxy pools (HTTP, HTTPS, SOCKS5) to evade IP-level rate-limiting
(HTTP 429) and WAF blocks (HTTP 403 Cloudflare/Akamai/Imperva) during high-throughput
security testing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from pathlib import Path
import time
from typing import Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class ProxyState:
    url: str
    cooldown_until: float = 0.0
    failure_count: int = 0
    success_count: int = 0

    @property
    def is_cooling_down(self) -> bool:
        return time.monotonic() < self.cooldown_until


class ProxyRotator:
    """Thread-safe and async-safe Round-Robin Proxy Rotator with automated cooldown."""

    def __init__(
        self,
        proxies: Optional[Sequence[str]] = None,
        default_cooldown_seconds: float = 45.0,
    ):
        self.default_cooldown = default_cooldown_seconds
        self._states: list[ProxyState] = []
        self._index: int = 0
        self._lock = asyncio.Lock()

        if proxies:
            self.set_proxies(proxies)

    @classmethod
    def from_source(cls, source: str | Path | Sequence[str], default_cooldown: float = 45.0) -> "ProxyRotator":
        """Initialize from list, comma-separated string, or file path."""
        if isinstance(source, (list, tuple)):
            return cls(source, default_cooldown_seconds=default_cooldown)

        source_str = str(source).strip()
        path = Path(source_str)
        if path.is_file():
            lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
            return cls(lines, default_cooldown_seconds=default_cooldown)

        # Comma-separated string
        proxies = [p.strip() for p in source_str.split(",") if p.strip()]
        return cls(proxies, default_cooldown_seconds=default_cooldown)

    def set_proxies(self, proxies: Sequence[str]) -> None:
        """Replace active proxy pool."""
        clean = [p.strip() for p in proxies if p and p.strip()]
        self._states = [ProxyState(url=p) for p in clean]
        self._index = 0

    @property
    def count(self) -> int:
        return len(self._states)

    @property
    def has_proxies(self) -> bool:
        return len(self._states) > 0

    async def get_next_proxy(self, force_rotate: bool = False) -> Optional[str]:
        """Obtain the next healthy proxy in the pool."""
        if not self._states:
            return None

        async with self._lock:
            n = len(self._states)
            # Find first non-cooling-down proxy starting from current index
            for offset in range(n):
                idx = (self._index + offset + (1 if force_rotate else 0)) % n
                cand = self._states[idx]
                if not cand.is_cooling_down:
                    self._index = (idx + 1) % n
                    return cand.url

            # If all are cooling down, select the one whose cooldown expires earliest
            earliest = min(self._states, key=lambda p: p.cooldown_until)
            self._index = (self._states.index(earliest) + 1) % n
            return earliest.url

    async def report_response(self, proxy_url: Optional[str], status_code: int) -> None:
        """Evaluate response status code to trigger adaptive proxy rotation and cooldown."""
        if not proxy_url or not self._states:
            return

        async with self._lock:
            state = next((s for s in self._states if s.url == proxy_url), None)
            if not state:
                return

            # Check for Rate Limit or WAF Block
            if status_code in (429, 403, 503):
                state.failure_count += 1
                state.cooldown_until = time.monotonic() + self.default_cooldown
                logger.warning(
                    "Proxy %s triggered HTTP %d (Throttled/Blocked). Entering %.1fs cooldown.",
                    proxy_url, status_code, self.default_cooldown,
                )
            else:
                state.success_count += 1
