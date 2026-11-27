"""Deterministic local TCP HTTP lab server for P1.6 DAST Ground Truth benchmarking.

Uses Python standard library ``http.server.ThreadingHTTPServer`` bound strictly to
``127.0.0.1`` on an ephemeral port (``port=0``) so both async ``httpx`` requests
and synchronous ``requests.get()`` loopback persistence checks work without Docker
or external network access.
"""

from __future__ import annotations

import base64
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

BENCHMARK_LAB_DIR = Path(__file__).resolve().parent
OPENAPI_SPEC_PATH = BENCHMARK_LAB_DIR / "openapi.yaml"
GROUND_TRUTH_PATH = BENCHMARK_LAB_DIR / "ground_truth.json"

ALICE_ID = "user-1"
ALICE_EMAIL = "alice@lab.local"
BOB_ID = "user-2"
BOB_EMAIL = "bob@lab.local"

# Matches strictly simple integer multiplication inside {{...}}, ${...}, or <%= ... %>.
_ARITH_PATTERNS = (
    re.compile(r"\{\{\s*(\d{1,6})\s*\*\s*(\d{1,6})\s*\}\}"),
    re.compile(r"\$\{\s*(\d{1,6})\s*\*\s*(\d{1,6})\s*\}"),
    re.compile(r"<%=\s*(\d{1,6})\s*\*\s*(\d{1,6})\s*%>"),
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_lab_jwt(sub: str, email: str) -> str:
    """Create a deterministic JWT token compatible with ``decode_jwt_unverified``."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _b64url(json.dumps({"sub": sub, "email": email}, separators=(",", ":")).encode("utf-8"))
    sig = _b64url(f"lab-sig-{sub}".encode("utf-8"))
    return f"{header}.{payload}.{sig}"


def build_lab_auth_headers() -> tuple[dict[str, str], dict[str, str]]:
    """Return ``(user1_headers, user2_headers)`` for Alice and Bob."""
    alice_token = make_lab_jwt(ALICE_ID, ALICE_EMAIL)
    bob_token = make_lab_jwt(BOB_ID, BOB_EMAIL)
    return (
        {"Authorization": f"Bearer {alice_token}"},
        {"Authorization": f"Bearer {bob_token}"},
    )


def _extract_subject_from_headers(headers: Any) -> Optional[str]:
    """Decode Bearer JWT subject claim without external dependencies."""
    auth_val = headers.get("Authorization") or headers.get("authorization")
    if not auth_val or not isinstance(auth_val, str):
        return None
    token = auth_val.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    rem = len(payload_b64) % 4
    if rem:
        payload_b64 += "=" * (4 - rem)
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        claims = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if isinstance(claims, dict):
        sub = claims.get("sub")
        return str(sub) if sub is not None else None
    return None


def safe_eval_mul_template(text: str) -> str:
    """Evaluate strictly bounded ``int * int`` template expressions without ``eval()``."""
    result = text
    for pattern in _ARITH_PATTERNS:
        result = pattern.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), result)
    return result


class _LabState:
    """Thread-safe deterministic in-memory datastore for the benchmark lab."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.request_count = 0
        self.requests_by_path: dict[str, int] = {}
        self.catalog_products = [{"id": i, "name": f"Product {i}", "price": 10 + i} for i in range(1, 151)]
        self.orders: dict[int, dict[str, Any]] = {}
        self.accounts: dict[str, dict[str, Any]] = {}
        self.adjustment_stock: int = 100
        self.vuln_profile: dict[str, Any] = {}
        self.secure_profile: dict[str, Any] = {}
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.request_count = 0
            self.requests_by_path = {}
            self.orders = {
                1: {
                    "id": 1,
                    "owner_id": ALICE_ID,
                    "email": ALICE_EMAIL,
                    "item": "Workstation Laptop",
                    "total": 1200,
                },
                2: {
                    "id": 2,
                    "owner_id": BOB_ID,
                    "email": BOB_EMAIL,
                    "item": "USB-C Dock",
                    "total": 180,
                },
            }
            self.accounts = {
                "admin": {
                    "account_id": "admin",
                    "owner_id": ALICE_ID,
                    "email": ALICE_EMAIL,
                    "role": "administrator",
                },
                "00000000-0000-0000-0000-000000000001": {
                    "account_id": "00000000-0000-0000-0000-000000000001",
                    "owner_id": ALICE_ID,
                    "email": ALICE_EMAIL,
                    "role": "administrator",
                },
                ALICE_ID: {
                    "account_id": ALICE_ID,
                    "owner_id": ALICE_ID,
                    "email": ALICE_EMAIL,
                    "role": "member",
                },
                BOB_ID: {
                    "account_id": BOB_ID,
                    "owner_id": BOB_ID,
                    "email": BOB_EMAIL,
                    "role": "member",
                },
            }
            self.adjustment_stock = 100
            self.vuln_profile = {
                "id": 1,
                "owner_id": ALICE_ID,
                "display_name": "Alice",
                "role": "user",
                "is_admin": False,
            }
            self.secure_profile = {
                "id": 1,
                "owner_id": ALICE_ID,
                "display_name": "Alice",
                "role": "user",
                "is_admin": False,
            }

    def record_request(self, path: str) -> None:
        with self._lock:
            self.request_count += 1
            self.requests_by_path[path] = self.requests_by_path.get(path, 0) + 1


def _make_handler(state: _LabState):
    class _BenchmarkRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            # Suppress noisy HTTP server stderr logging during pytest/CLI runs.
            return

        def _send_json(self, status: int, body: Any) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> tuple[Optional[dict[str, Any]], bool]:
            length_raw = self.headers.get("Content-Length")
            if not length_raw:
                return {}, True
            try:
                length = int(length_raw)
            except ValueError:
                return None, False
            raw = self.rfile.read(max(0, length))
            if not raw:
                return {}, True
            try:
                parsed = json.loads(raw.decode("utf-8"))
                return (parsed if isinstance(parsed, dict) else None), isinstance(parsed, dict)
            except Exception:
                return None, False

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query, keep_blank_values=True)
            state.record_request(path)
            sub = _extract_subject_from_headers(self.headers)

            # ---- A. BOLA endpoints ----
            if method == "GET" and path.startswith("/api/bola/vuln/orders/"):
                if sub is None:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                id_raw = path.rsplit("/", 1)[-1]
                try:
                    oid = int(id_raw)
                except ValueError:
                    self._send_json(404, {"error": "Order not found"})
                    return
                with state._lock:
                    order = state.orders.get(oid)
                if order is None:
                    self._send_json(404, {"error": "Order not found"})
                    return
                self._send_json(200, order)
                return

            if method == "GET" and path.startswith("/api/bola/vuln/accounts/"):
                if sub is None:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                account_id = path.rsplit("/", 1)[-1]
                with state._lock:
                    acct = state.accounts.get(account_id)
                if acct is None:
                    self._send_json(404, {"error": "Account not found"})
                    return
                self._send_json(200, acct)
                return

            if method == "GET" and path.startswith("/api/bola/secure/orders/"):
                if sub is None:
                    self._send_json(401, {"error": "Authentication required"})
                    return
                id_raw = path.rsplit("/", 1)[-1]
                try:
                    oid = int(id_raw)
                except ValueError:
                    self._send_json(404, {"error": "Order not found"})
                    return
                with state._lock:
                    order = state.orders.get(oid)
                if order is None:
                    self._send_json(404, {"error": "Order not found"})
                    return
                if order["owner_id"] != sub:
                    self._send_json(403, {"error": "Forbidden: resource belongs to another user"})
                    return
                self._send_json(200, order)
                return

            if method == "GET" and path.startswith("/api/bola/secure/public-items/"):
                id_raw = path.rsplit("/", 1)[-1]
                try:
                    item_id = int(id_raw)
                except ValueError:
                    self._send_json(404, {"error": "Item not found"})
                    return
                self._send_json(200, {"id": item_id, "title": f"Public Item {item_id}", "public": True})
                return

            if method == "GET" and path.startswith("/api/bola/secure/open-catalog/"):
                id_raw = path.rsplit("/", 1)[-1]
                try:
                    item_id = int(id_raw)
                except ValueError:
                    self._send_json(404, {"error": "Catalog item not found"})
                    return
                self._send_json(200, {"id": item_id, "catalog": "open", "public": True})
                return

            # ---- B. BOUNDARY endpoints ----
            if method == "GET" and path == "/api/boundary/vuln/wraparound":
                raw_amt = (query.get("amount") or ["10"])[0]
                try:
                    amt = int(raw_amt)
                except ValueError:
                    self._send_json(422, {"detail": [{"loc": ["query", "amount"], "msg": "Input should be a valid integer", "type": "int_parsing"}]})
                    return
                if amt >= 2147483647:
                    wrapped = ((amt + 1 + 2147483648) % 4294967296) - 2147483648
                    self._send_json(200, {"amount": wrapped, "total": -100})
                    return
                if amt < 0:
                    wrapped_u32 = amt % 4294967296
                    self._send_json(200, {"amount": wrapped_u32, "total": wrapped_u32})
                    return
                self._send_json(200, {"amount": amt, "total": amt * 10})
                return

            if method == "GET" and path == "/api/boundary/vuln/products":
                raw_lim = (query.get("limit") or ["1"])[0]
                try:
                    lim = int(raw_lim)
                except ValueError:
                    self._send_json(422, {"detail": [{"loc": ["query", "limit"], "msg": "Input should be a valid integer", "type": "int_parsing"}]})
                    return
                if lim == -1:
                    items = state.catalog_products
                elif lim <= 0:
                    items = []
                else:
                    items = state.catalog_products[:lim]
                self._send_json(200, {"products": items, "limit": lim, "total": len(state.catalog_products)})
                return

            if method == "POST" and path == "/api/boundary/vuln/adjust":
                raw_qty = (query.get("quantity") or ["1"])[0]
                try:
                    qty = int(raw_qty)
                except ValueError:
                    self._send_json(422, {"detail": [{"loc": ["query", "quantity"], "msg": "Input should be a valid integer", "type": "int_parsing"}]})
                    return
                with state._lock:
                    state.adjustment_stock += qty
                    stock_after = state.adjustment_stock
                self._send_json(201, {
                    "quantity": qty,
                    "applied_delta": qty,
                    "stock_after": stock_after,
                    "status": "applied",
                })
                return

            if method == "GET" and path == "/api/boundary/secure/products":
                raw_lim = (query.get("limit") or ["1"])[0]
                try:
                    lim = int(raw_lim)
                except ValueError:
                    self._send_json(422, {"detail": [{"loc": ["query", "limit"], "msg": "Input should be a valid integer", "type": "int_parsing"}]})
                    return
                effective_limit = 10 if lim <= 0 else min(lim, 30)
                items = state.catalog_products[:effective_limit]
                self._send_json(200, {
                    "products": items,
                    "limit": effective_limit,
                    "effective_limit": effective_limit,
                    "total": len(state.catalog_products),
                })
                return

            if method == "GET" and path == "/api/boundary/secure/strict":
                raw_amt = (query.get("amount") or ["10"])[0]
                try:
                    amt = int(raw_amt)
                except ValueError:
                    self._send_json(422, {"detail": [{"loc": ["query", "amount"], "msg": "Input should be a valid integer", "type": "int_parsing"}]})
                    return
                if amt < 1 or amt > 1000:
                    self._send_json(422, {"detail": [{"loc": ["query", "amount"], "msg": "Input should be between 1 and 1000", "type": "value_error"}]})
                    return
                self._send_json(200, {"amount": amt, "valid": True})
                return

            # ---- C. SSTI endpoints ----
            if method == "GET" and path == "/api/ssti/vuln/render":
                tpl = (query.get("tpl") or ["hello"])[0]
                rendered = safe_eval_mul_template(tpl)
                self._send_json(200, {"rendered": rendered})
                return

            if method == "GET" and path == "/api/ssti/vuln/invite":
                email = (query.get("email") or ["user@example.com"])[0]
                invited = safe_eval_mul_template(email)
                self._send_json(200, {"invited": invited})
                return

            if method == "GET" and path == "/api/ssti/secure/echo":
                tpl = (query.get("tpl") or ["hello"])[0]
                self._send_json(200, {"rendered": f"Echo: {tpl}"})
                return

            if method == "GET" and path == "/api/ssti/secure/static-report":
                self._send_json(200, {"report_id": 49, "checksum": "77455597", "query": "static"})
                return

            # ---- D. MASS ASSIGNMENT endpoints ----
            if path == "/api/mass/vuln/profile":
                if method == "GET":
                    with state._lock:
                        snap = dict(state.vuln_profile)
                    self._send_json(200, snap)
                    return
                if method == "PUT":
                    body, ok = self._read_json_body()
                    if not ok or body is None:
                        self._send_json(400, {"error": "Invalid JSON body"})
                        return
                    with state._lock:
                        for k, v in body.items():
                            state.vuln_profile[k] = v
                        snap = dict(state.vuln_profile)
                    self._send_json(200, snap)
                    return

            if path == "/api/mass/secure/profile":
                if method == "GET":
                    with state._lock:
                        snap = dict(state.secure_profile)
                    self._send_json(200, snap)
                    return
                if method == "PUT":
                    body, ok = self._read_json_body()
                    if not ok or body is None:
                        self._send_json(400, {"error": "Invalid JSON body"})
                        return
                    with state._lock:
                        if "display_name" in body and isinstance(body["display_name"], str):
                            state.secure_profile["display_name"] = body["display_name"]
                        # DTO echo includes extra keys in response without persisting them in store.
                        dto = dict(state.secure_profile)
                        for k, v in body.items():
                            if k in ("role", "is_admin"):
                                dto[k] = v
                    self._send_json(200, dto)
                    return

            # ---- E. NOISE CONTROL endpoint ----
            if method == "GET" and path == "/api/noise/secure/status":
                self._send_json(200, {
                    "id": 49,
                    "user": "guest",
                    "admin": False,
                    "invalid": False,
                    "status": "ok",
                    "message": "status ok",
                })
                return

            self._send_json(404, {"error": f"No route for {method} {path}"})

    return _BenchmarkRequestHandler


class BenchmarkLabServer:
    """Context-managed local deterministic HTTP server bound on ``127.0.0.1:0``."""

    def __init__(self) -> None:
        self.state = _LabState()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("BenchmarkLabServer is not running")
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def request_count(self) -> int:
        with self.state._lock:
            return self.state.request_count

    @property
    def requests_by_path(self) -> dict[str, int]:
        with self.state._lock:
            return dict(self.state.requests_by_path)

    def reset(self) -> None:
        self.state.reset()

    def start(self) -> "BenchmarkLabServer":
        if self._server is not None:
            return self
        handler_cls = _make_handler(self.state)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="p16-benchmark-lab",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            finally:
                self._server.server_close()
                self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def __enter__(self) -> "BenchmarkLabServer":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
