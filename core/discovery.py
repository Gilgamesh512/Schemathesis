from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml


@dataclass
class DiscoveryResult:
    url: str
    protocol: str  # "rest" | "graphql"
    schema_url: str | None = None
    endpoint: str | None = None
    title: str | None = None
    version: str | None = None
    spec_data: dict[str, Any] | None = field(default=None, repr=False)
    source_type: str = "openapi"  # "openapi", "swagger", "graphql_introspection"

    @property
    def is_discovered(self) -> bool:
        return bool(self.schema_url or (self.protocol == "graphql" and self.endpoint))


# Common paths where OpenAPI / Swagger specs are typically exposed
COMMON_REST_SCHEMA_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/openapi.json",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
]

# Common documentation UI pages that might link to the spec
COMMON_DOCS_UI_PATHS = [
    "/docs",
    "/docs/",
    "/swagger",
    "/swagger/",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/index.html",
    "/api-docs",
]

# Common GraphQL endpoints
COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
]

GRAPHQL_INTROSPECTION_QUERY = {
    "query": "query IntrospectionCheck { __schema { queryType { name } } }"
}


class ApiDiscoveryEngine:
    """Probes target base URLs to automatically locate OpenAPI specs or GraphQL endpoints."""

    def __init__(
        self,
        timeout: float = 6.0,
        proxy: str | None = None,
        insecure: bool = False,
        headers: dict[str, str] | None = None,
    ):
        self.timeout = timeout
        self.proxy = proxy
        self.insecure = insecure
        self.headers = headers or {}

    def _client(self) -> httpx.Client:
        return httpx.Client(
            proxy=self.proxy,
            verify=not self.insecure,
            timeout=self.timeout,
            follow_redirects=True,
            headers={
                "User-Agent": "Schemathesis-AutoDiscovery/2.0",
                "Accept": "application/json, application/yaml, text/yaml, */*",
                **self.headers,
            },
        )

    def discover(self, base_url: str) -> DiscoveryResult:
        """Attempt to discover API schema from a base URL."""
        clean_url = base_url.rstrip("/")
        parsed = urlparse(clean_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid URL: {base_url}")

        with self._client() as client:
            # 1. Direct check: maybe the provided URL itself is already a schema!
            direct = self._check_is_schema(client, clean_url)
            if direct:
                return direct

            # 2. Check common OpenAPI/Swagger paths
            for path in COMMON_REST_SCHEMA_PATHS:
                target_url = urljoin(clean_url + "/", path.lstrip("/"))
                res = self._check_is_schema(client, target_url)
                if res:
                    return res

            # 3. Check GraphQL endpoints
            for path in COMMON_GRAPHQL_PATHS:
                target_url = urljoin(clean_url + "/", path.lstrip("/"))
                res = self._check_graphql_endpoint(client, target_url, path)
                if res:
                    return res

            # 4. Check documentation UI for embedded schema links (e.g. FastAPI /docs)
            for path in COMMON_DOCS_UI_PATHS:
                target_url = urljoin(clean_url + "/", path.lstrip("/"))
                res = self._inspect_docs_html(client, target_url, clean_url)
                if res:
                    return res

        return DiscoveryResult(url=clean_url, protocol="rest", schema_url=None)

    def _check_is_schema(self, client: httpx.Client, url: str) -> DiscoveryResult | None:
        try:
            resp = client.get(url)
            if resp.status_code != 200 or len(resp.content) < 10:
                return None

            content_type = resp.headers.get("content-type", "").lower()
            text = resp.text.strip()

            # Attempt JSON parse
            data = None
            if "json" in content_type or text.startswith("{"):
                try:
                    data = resp.json()
                except Exception:
                    data = None

            # Attempt YAML parse if JSON failed
            if data is None and ("yaml" in content_type or "openapi" in text or "swagger" in text):
                try:
                    data = yaml.safe_load(text)
                except Exception:
                    data = None

            if isinstance(data, dict):
                # Verify if this has OpenAPI / Swagger signatures
                if "openapi" in data or "swagger" in data:
                    title = ""
                    version = ""
                    info = data.get("info")
                    if isinstance(info, dict):
                        title = str(info.get("title", ""))
                        version = str(info.get("version", ""))
                    spec_type = "openapi" if "openapi" in data else "swagger"
                    return DiscoveryResult(
                        url=url,
                        protocol="rest",
                        schema_url=url,
                        title=title,
                        version=version,
                        spec_data=data,
                        source_type=spec_type,
                    )
        except Exception:
            return None
        return None

    def _check_graphql_endpoint(
        self, client: httpx.Client, url: str, path: str
    ) -> DiscoveryResult | None:
        try:
            resp = client.post(
                url,
                json=GRAPHQL_INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and "data" in data and "__schema" in data["data"]:
                    return DiscoveryResult(
                        url=url,
                        protocol="graphql",
                        endpoint=path,
                        schema_url=url,
                        title="GraphQL API",
                        source_type="graphql_introspection",
                    )
        except Exception:
            return None
        return None

    def _inspect_docs_html(
        self, client: httpx.Client, docs_url: str, base_url: str
    ) -> DiscoveryResult | None:
        try:
            resp = client.get(docs_url)
            if resp.status_code != 200 or "html" not in resp.headers.get("content-type", "").lower():
                return None

            html = resp.text
            # Look for common schema references in HTML / JS config (e.g. Swagger UI or Redoc)
            # e.g.: url: '/openapi.json', "url": "/v3/api-docs", swaggerDocUrl
            import re
            patterns = [
                r"""(?:url|spec-url|spec)\s*[:=]\s*["']([^"']+\.(?:json|yaml|yml))["']""",
                r"""(?:url|spec-url|spec)\s*[:=]\s*["'](/v[23]/api-docs[^"']*)["']""",
                r"""["'](/openapi\.(?:json|yaml|yml))["']""",
                r"""["'](/swagger\.(?:json|yaml|yml))["']""",
            ]
            for pat in patterns:
                matches = re.findall(pat, html, re.IGNORECASE)
                for rel_spec in matches:
                    candidate = urljoin(docs_url, rel_spec)
                    res = self._check_is_schema(client, candidate)
                    if res:
                        return res
        except Exception:
            return None
        return None


def discover_api(
    base_url: str,
    *,
    proxy: str | None = None,
    insecure: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float = 6.0,
) -> DiscoveryResult:
    """Convenience helper to auto-discover API specs from any URL."""
    engine = ApiDiscoveryEngine(
        timeout=timeout,
        proxy=proxy,
        insecure=insecure,
        headers=headers,
    )
    return engine.discover(base_url)
