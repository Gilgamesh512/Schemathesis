"""URL Destination & Callback Whitelist Verifier (API7:2023 Server-Side Request Forgery).

Detects URL-receiving parameters and verifies whether the server restricts
outgoing requests against loopback, local network, and unvalidated destinations.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import re
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


CALLBACK_PARAM_NAMES = {
    "url", "redirect", "redirect_url", "dest", "destination",
    "callback", "callback_url", "webhook", "webhook_url",
    "feed", "uri", "target", "return_url", "next", "link",
}


class CallbackEvent(BaseModel):
    """Record of an incoming callback hit on the listener."""

    received_at: str
    client_ip: str
    path: str
    method: str
    headers: dict[str, str] = Field(default_factory=dict)


class LocalCallbackListener:
    """Lightweight in-memory loopback HTTP listener for verifying local SSRF callbacks."""

    def __init__(self, host: str = "0.0.0.0", advertised_host: Optional[str] = None):
        self.bind_host = host
        self.advertised_host = advertised_host
        self.port: int = 0
        self.server: Optional[asyncio.Server] = None
        self.hits: dict[str, CallbackEvent] = {}
        self._running = False

    async def start(self) -> str:
        """Start listener on an available OS-assigned dynamic port."""
        loop = asyncio.get_running_loop()
        self.server = await asyncio.start_server(
            self._handle_client,
            self.bind_host,
            0,  # OS dynamically selects free available port
        )
        sockets = self.server.sockets
        if sockets:
            self.port = sockets[0].getsockname()[1]
        self._running = True

        reported_host = self.advertised_host
        if not reported_host:
            # Attempt auto-detection for container network gateways
            for candidate in ("host.docker.internal", "host.containers.internal"):
                try:
                    socket.gethostbyname(candidate)
                    reported_host = candidate
                    break
                except Exception:
                    pass
            if not reported_host:
                reported_host = "127.0.0.1"

        return f"http://{reported_host}:{self.port}"

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            if not line:
                writer.close()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split()
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Read headers
            headers: dict[str, str] = {}
            while True:
                h_line = await asyncio.wait_for(reader.readline(), timeout=1.0)
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                decoded_h = h_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded_h:
                    k, _, v = decoded_h.partition(":")
                    headers[k.strip().lower()] = v.strip()

            client_peer = writer.get_extra_info("peername")
            client_ip = client_peer[0] if client_peer else "unknown"

            event = CallbackEvent(
                received_at=datetime.now(timezone.utc).isoformat(),
                client_ip=client_ip,
                path=path,
                method=method,
                headers=headers,
            )
            # Store hit by path token
            token = path.strip("/").split("/")[-1]
            self.hits[token] = event

            # Send minimal HTTP 200 OK response
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n\r\n"
                b"OK"
            )
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def check_hit(self, token: str) -> Optional[CallbackEvent]:
        """Check if a specific canary token was hit."""
        return self.hits.get(token)

    async def stop(self) -> None:
        """Stop listener server and close open sockets."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self._running = False


class CallbackVerifier:
    """Verifies whether API endpoints properly restrict URL parameters against SSRF."""

    def __init__(
        self,
        external_callback_url: Optional[str] = None,
        poll_url: Optional[str] = None,
        advertised_host: Optional[str] = None,
    ):
        self.external_url = external_callback_url.rstrip("/") if external_callback_url else None
        self.poll_url = poll_url
        self.advertised_host = advertised_host

        # Auto-configure polling endpoint for Webhook.site
        if self.external_url and not self.poll_url and "webhook.site" in self.external_url:
            parts = self.external_url.strip("/").split("/")
            if len(parts) >= 4 and parts[-2] == "webhook.site":
                webhook_uuid = parts[-1]
                self.poll_url = f"https://webhook.site/token/{webhook_uuid}/requests?query={{token}}&sorting=newest"

    @staticmethod
    def is_callback_parameter(param_name: str) -> bool:
        """Check if parameter name indicates a URL/webhook destination."""
        norm = param_name.strip().lower()
        return norm in CALLBACK_PARAM_NAMES or any(
            k in norm for k in ("callback", "webhook", "redirect", "url", "uri", "target", "dest")
        )

    async def poll_external_hit(self, client: httpx.AsyncClient, token: str) -> Optional[CallbackEvent]:
        """Poll external canary listener (e.g. Webhook.site or custom OOB API) for incoming hits."""
        if not self.poll_url:
            return None
        try:
            target_poll = self.poll_url.replace("{token}", token)
            resp = await client.get(target_poll, timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                # Webhook.site response structure: {"data": [...]}
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                    req_entry = data["data"][0]
                    return CallbackEvent(
                        received_at=req_entry.get("created_at") or datetime.now(timezone.utc).isoformat(),
                        client_ip=req_entry.get("ip") or "canary_remote",
                        path=req_entry.get("url") or f"/{token}",
                        method=req_entry.get("method") or "GET",
                        headers=req_entry.get("headers") or {},
                    )
                # Generic list response
                elif isinstance(data, list) and len(data) > 0:
                    first = data[0] if isinstance(data[0], dict) else {}
                    return CallbackEvent(
                        received_at=datetime.now(timezone.utc).isoformat(),
                        client_ip=first.get("client_ip") or first.get("ip") or "canary_remote",
                        path=first.get("path") or f"/{token}",
                        method=first.get("method") or "GET",
                        headers=first.get("headers") or {},
                    )
        except Exception:
            pass
        return None

    async def verify_endpoint_url_parameter(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str,
        param_name: str,
        param_location: str,
        base_url: str,
        run_id: str,
        headers: Optional[dict[str, str]] = None,
        timeout: float = 3.0,
    ) -> Optional[Finding]:
        """Test parameter with a unique canary loopback/external URL and check for SSRF callback."""
        listener = LocalCallbackListener(advertised_host=self.advertised_host)
        token = f"ssrf_{int(time.time())}_{abs(hash((endpoint, param_name))) % 10000}"

        if self.external_url:
            canary_url = f"{self.external_url}/{token}"
            listener_url = None
        else:
            listener_url = await listener.start()
            canary_url = f"{listener_url}/{token}"

        clean_ep = "/" + endpoint.lstrip("/")
        full_url = f"{base_url.rstrip('/')}{clean_ep}"

        req_kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": full_url,
            "headers": headers or {},
        }

        if param_location == "query":
            req_kwargs["params"] = {param_name: canary_url}
        elif param_location == "body":
            req_kwargs["json"] = {param_name: canary_url}
        else:
            req_kwargs["params"] = {param_name: canary_url}

        started = time.perf_counter()
        finding = None

        try:
            resp = await client.request(**req_kwargs)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

            # Wait briefly for server-side asynchronous callback
            await asyncio.sleep(min(timeout, 1.5))

            if not self.external_url:
                hit = listener.check_hit(token)
            else:
                hit = await self.poll_external_hit(client, token)

            if hit:
                src_desc = "loopback " if not self.external_url else "external "
                evidence_text = (
                    f"Server made outbound {src_desc}request to canary listener at {hit.path} "
                    f"(Client IP: {hit.client_ip}, Method: {hit.method})"
                )
                finding = Finding(
                    finding_id=stable_finding_id(
                        "callback_verifier", method, clean_ep, "SSRF", param_name,
                    ),
                    run_id=run_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tool="callback_verifier",
                    target_app="callback_verifier",
                    endpoint=clean_ep,
                    method=method.upper(),
                    attack_type="SSRF",
                    owasp_category="API7:2023",
                    payload={param_name: canary_url},
                    status_code=resp.status_code,
                    response_time_ms=elapsed_ms,
                    evidence=Evidence(
                        status_code=resp.status_code,
                        response_headers=redact_headers(dict(resp.headers)),
                        response_signal=[evidence_text],
                        response_time_ms=elapsed_ms,
                        payload_hash=content_hash(canary_url),
                        request_hash=content_hash(full_url),
                        endpoint=clean_ep,
                        payload={param_name: canary_url},
                    ),
                    severity="high",
                    confidence=0.95,
                    confirmed=True,
                    lifecycle="confirmed",
                    fingerprint=content_hash(f"{method}|{clean_ep}|SSRF|{param_name}"),
                )
        except Exception:
            pass
        finally:
            if not self.external_url:
                await listener.stop()

        return finding
