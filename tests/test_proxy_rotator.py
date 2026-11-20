"""Unit tests for Smart Proxy Pool & Rate-Limit / WAF Evasion Rotator."""

from __future__ import annotations

import time
import pytest
from core.proxy_rotator import ProxyRotator, ProxyState


def test_proxy_rotator_initialization_from_sources(tmp_path):
    # 1. From list
    rot_list = ProxyRotator.from_source(["http://p1:8080", "http://p2:8080"])
    assert rot_list.count == 2
    assert rot_list.has_proxies is True

    # 2. From comma-separated string
    rot_str = ProxyRotator.from_source("http://p1:8080, http://p2:8080, http://p3:8080")
    assert rot_str.count == 3

    # 3. From file
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("# Proxy List\nhttp://proxy-file-1:8080\nhttp://proxy-file-2:8080\n", encoding="utf-8")
    rot_file = ProxyRotator.from_source(proxy_file)
    assert rot_file.count == 2


@pytest.mark.anyio
async def test_proxy_rotator_round_robin():
    proxies = ["http://p1:8080", "http://p2:8080", "http://p3:8080"]
    rotator = ProxyRotator(proxies)

    p1 = await rotator.get_next_proxy()
    p2 = await rotator.get_next_proxy()
    p3 = await rotator.get_next_proxy()
    p4 = await rotator.get_next_proxy()

    assert p1 == "http://p1:8080"
    assert p2 == "http://p2:8080"
    assert p3 == "http://p3:8080"
    assert p4 == "http://p1:8080"  # Wrapped around


@pytest.mark.anyio
async def test_proxy_rotator_cooldown_on_rate_limit():
    proxies = ["http://p1:8080", "http://p2:8080"]
    rotator = ProxyRotator(proxies, default_cooldown_seconds=10.0)

    # First returns p1
    p = await rotator.get_next_proxy()
    assert p == "http://p1:8080"

    # Report 429 on p1 -> triggers 10s cooldown
    await rotator.report_response("http://p1:8080", 429)

    # Next call should skip p1 and return p2
    next_p = await rotator.get_next_proxy()
    assert next_p == "http://p2:8080"

    # Report 403 (WAF block) on p2 -> triggers cooldown
    await rotator.report_response("http://p2:8080", 403)

    # Both are cooling down: returns the one with earliest cooldown expiry
    earliest_p = await rotator.get_next_proxy()
    assert earliest_p in proxies
