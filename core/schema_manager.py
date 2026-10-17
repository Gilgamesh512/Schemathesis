from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from .path_manager import ProjectPaths


class SchemaManager:
    MAX_SCHEMA_BYTES = 10 * 1024 * 1024

    def __init__(self, root: str | Path | None = None):
        self.paths = ProjectPaths.from_root(root)

    def resolve_local_schema(self, value: str | Path) -> Path:
        resolved = self.paths.resolve(value)
        if not resolved.exists():
            raise FileNotFoundError(f"Schema file not found: {resolved}")
        if not resolved.is_file():
            raise ValueError(f"Schema path is not a file: {resolved}")
        return resolved

    def load(
        self,
        schema_source: str | Path,
        *,
        allow_remote: bool = False,
    ) -> dict[str, Any]:
        if isinstance(schema_source, Path):
            return self.load_local(schema_source)
        scheme = urlparse(str(schema_source)).scheme
        if scheme in {"http", "https"}:
            if not allow_remote:
                raise ValueError("Remote schema loading is disabled")
            return self.load_remote(str(schema_source))
        if "://" in str(schema_source):
            raise ValueError(f"Unsupported schema URL scheme: {scheme}")
        return self.load_local(str(schema_source))

    def load_local(self, schema_path: str | Path) -> dict[str, Any]:
        path = self.resolve_local_schema(schema_path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            payload = yaml.safe_load(text)
        elif path.suffix.lower() == ".json":
            payload = json.loads(text)
        else:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = yaml.safe_load(text)
        if not isinstance(payload, dict):
            raise ValueError(f"Schema file must contain a mapping: {path}")
        return payload

    def load_remote(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid remote schema URL: {url}")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in a schema URL")
        with httpx.Client(
            timeout=20,
            follow_redirects=False,
            headers={"Accept": "application/json, application/yaml, text/yaml"},
        ) as client:
            response = client.get(url)
            response.raise_for_status()
            if len(response.content) > self.MAX_SCHEMA_BYTES:
                raise ValueError(
                    f"Schema response exceeds {self.MAX_SCHEMA_BYTES} bytes: {url}"
                )
            try:
                payload = response.json()
            except ValueError:
                payload = yaml.safe_load(response.text)
        if not isinstance(payload, dict):
            raise ValueError(f"Schema response from {url} was not a mapping")
        return payload


def load_schema(
    schema_source: str | Path,
    *,
    root: str | Path | None = None,
    allow_remote: bool = False,
) -> dict[str, Any]:
    return SchemaManager(root=root).load(schema_source, allow_remote=allow_remote)


__all__ = ["SchemaManager", "load_schema"]
