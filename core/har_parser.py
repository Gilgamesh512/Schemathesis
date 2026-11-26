"""core/har_parser.py — Traffic-Driven HAR Ingestion & Live Seed Corpus Harvester.

Addresses static spec-only blindness and strict DTO validation barriers:
- Ingests .har (HTTP Archive) captures from Chrome DevTools, Burp Suite, Charles Proxy, Postman, or API Gateways.
- Extracts live parameter values (real IDs, tokens, custom x-* headers, valid DTO bodies).
- Supplies a live SeedCorpus to SemanticMutationEngine to pass HTTP 400/422 validation layers.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

BROWSER_IGNORE_HEADERS = {
    "host",
    "connection",
    "accept-encoding",
    "accept-language",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "user-agent",
    "priority",
}


@dataclass
class HARSeed:
    method: str
    url: str
    path: str
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Any = None
    body_json: dict[str, Any] | None = None
    status_code: int | None = None


class SeedCorpus:
    """Repository of live seed values extracted from captured HTTP traffic."""

    def __init__(self) -> None:
        self.param_seeds: dict[str, list[Any]] = {}
        self.request_seeds: dict[tuple[str, str], list[HARSeed]] = {}
        self.auth_headers: dict[str, str] = {}
        self.common_headers: dict[str, str] = {}
        self.discovered_hosts: set[str] = set()

    def add_param_seed(self, param_name: str, value: Any) -> None:
        clean_name = str(param_name).strip()
        if not clean_name or value is None:
            return
        if clean_name not in self.param_seeds:
            self.param_seeds[clean_name] = []
        if value not in self.param_seeds[clean_name]:
            self.param_seeds[clean_name].append(value)

    def get_seed_for_param(self, param_name: str) -> Any | None:
        """Return a live seed value for a parameter (exact or case-insensitive match)."""
        if param_name in self.param_seeds and self.param_seeds[param_name]:
            return self.param_seeds[param_name][0]
        p_lower = param_name.lower()
        for k, vals in self.param_seeds.items():
            if k.lower() == p_lower and vals:
                return vals[0]
        return None

    def get_body_seed(self, method: str, path: str) -> dict[str, Any] | None:
        """Return a recorded JSON request body for the given HTTP method and path."""
        key = (method.upper(), path)
        if key in self.request_seeds:
            for seed in self.request_seeds[key]:
                if seed.body_json:
                    return dict(seed.body_json)
        # Match equivalent paths ignoring trailing slashes
        for (m, p), seeds in self.request_seeds.items():
            if m == method.upper() and (p.rstrip("/") == path.rstrip("/") or path.startswith(p)):
                for seed in seeds:
                    if seed.body_json:
                        return dict(seed.body_json)
        return None

    def get_template_for_endpoint(self, method: str, path: str) -> HARSeed | None:
        key = (method.upper(), path)
        seeds = self.request_seeds.get(key)
        return seeds[0] if seeds else None

    def suggest_auth_token(self) -> str | None:
        """Suggest an authentication token discovered in HAR traffic."""
        for name, val in self.auth_headers.items():
            if name.lower() == "authorization":
                return val
        for name, val in self.common_headers.items():
            if any(k in name.lower() for k in ("token", "jwt", "api-key", "apikey", "session")):
                return val
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "total_endpoints": len(self.request_seeds),
            "total_param_seeds": len(self.param_seeds),
            "discovered_hosts": list(self.discovered_hosts),
            "auth_headers_found": list(self.auth_headers.keys()),
            "custom_headers_found": list(self.common_headers.keys()),
        }


def _extract_params_from_object(obj: Any, corpus: SeedCorpus, prefix: str = "") -> None:
    """Recursively extract field names and values from nested JSON objects."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            corpus.add_param_seed(k, v)
            if prefix:
                corpus.add_param_seed(full_key, v)
            if isinstance(v, (dict, list)):
                _extract_params_from_object(v, corpus, full_key)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _extract_params_from_object(item, corpus, prefix)


def parse_har_file(har_path: str | Path, target_host: str | None = None) -> SeedCorpus:
    """Parse an HTTP Archive (.har) file and return a populated SeedCorpus."""
    p = Path(har_path)
    if not p.is_file():
        raise FileNotFoundError(f"HAR file not found: {har_path}")

    with p.open("r", encoding="utf-8", errors="replace") as f:
        har_data = json.load(f)

    log = har_data.get("log", {})
    entries = log.get("entries", [])

    corpus = SeedCorpus()

    target_host_clean = target_host.lower().strip() if target_host else None
    if target_host_clean:
        target_host_clean = re.sub(r"^https?://", "", target_host_clean).split("/")[0]

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url", "")
        if not url:
            continue

        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc.lower()
        if host:
            corpus.discovered_hosts.add(host)

        # Filter by target host when specified
        if target_host_clean:
            if host != target_host_clean and not host.startswith(target_host_clean.split(":")[0]):
                continue

        method = (req.get("method") or "GET").upper()
        path = parsed_url.path or "/"

        # 1. Extract query parameters
        query_params: dict[str, Any] = {}
        for qp in (req.get("queryString") or []):
            if not isinstance(qp, dict):
                continue
            name = qp.get("name", "")
            val = qp.get("value", "")
            if name:
                query_params[name] = val
                corpus.add_param_seed(name, val)

        if parsed_url.query:
            raw_qs = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            for k, vs in raw_qs.items():
                if vs:
                    corpus.add_param_seed(k, vs[0])
                    if k not in query_params:
                        query_params[k] = vs[0]

        # 2. Extract headers
        headers: dict[str, str] = {}
        for h in (req.get("headers") or []):
            if not isinstance(h, dict):
                continue
            h_name = h.get("name", "")
            h_val = h.get("value", "")
            if not h_name:
                continue
            h_name_lower = h_name.lower()
            if h_name_lower in BROWSER_IGNORE_HEADERS:
                continue

            headers[h_name] = h_val
            corpus.add_param_seed(h_name, h_val)

            if h_name_lower in ("authorization", "proxy-authorization", "x-auth-token"):
                corpus.auth_headers[h_name] = h_val
            elif h_name_lower.startswith("x-") or any(
                k in h_name_lower for k in ("token", "key", "tenant", "client", "signature", "session")
            ):
                corpus.common_headers[h_name] = h_val

        # 3. Extract cookies
        cookies: dict[str, str] = {}
        for c in (req.get("cookies") or []):
            if not isinstance(c, dict):
                continue
            c_name = c.get("name", "")
            c_val = c.get("value", "")
            if c_name:
                cookies[c_name] = c_val
                corpus.add_param_seed(c_name, c_val)

        # 4. Extract request body / form parameters
        body_raw = None
        body_json = None
        post_data = req.get("postData") or {}
        mime_type = (post_data.get("mimeType") or "").lower()
        text_content = post_data.get("text", "")

        if text_content:
            body_raw = text_content
            if "application/json" in mime_type or text_content.strip().startswith(("{", "[")):
                try:
                    parsed_json = json.loads(text_content)
                    body_json = parsed_json
                    _extract_params_from_object(parsed_json, corpus)
                except Exception as exc:
                    logger.debug("Skipping non-JSON HAR body on %s %s: %s", method, path, exc)
            elif "application/x-www-form-urlencoded" in mime_type:
                try:
                    form_dict = urllib.parse.parse_qs(text_content, keep_blank_values=True)
                    for fk, fvs in form_dict.items():
                        if fvs:
                            corpus.add_param_seed(fk, fvs[0])
                except Exception as exc:
                    logger.debug("Skipping malformed form-urlencoded HAR body on %s %s: %s", method, path, exc)

        # 5. Record request seed
        seed_obj = HARSeed(
            method=method,
            url=url,
            path=path,
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body=body_raw,
            body_json=body_json,
            status_code=resp.get("status"),
        )
        key = (method, path)
        if key not in corpus.request_seeds:
            corpus.request_seeds[key] = []
        corpus.request_seeds[key].append(seed_obj)

    return corpus
