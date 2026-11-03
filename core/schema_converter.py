"""Postman Collection v2.0/v2.1 and HAR (HTTP Archive) to OpenAPI 3.0 Converter."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qs, urlparse


STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".webp",
)

STATIC_MIME_PREFIXES = (
    "image/", "font/", "text/css", "application/javascript",
    "application/x-javascript", "text/javascript",
)


def _infer_json_schema(value: Any) -> dict[str, Any]:
    """Infer minimal OpenAPI JSON schema from an arbitrary JSON value."""
    if value is None:
        return {"type": "string", "nullable": True}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        if value:
            return {"type": "array", "items": _infer_json_schema(value[0])}
        return {"type": "array", "items": {"type": "string"}}
    if isinstance(value, dict):
        properties = {}
        for k, v in value.items():
            properties[str(k)] = _infer_json_schema(v)
        return {"type": "object", "properties": properties}
    return {"type": "string"}


def _normalize_path(raw_path: str) -> tuple[str, list[str]]:
    """Normalize path: convert :param and {{param}} to {param}, extract param names."""
    # Convert Postman :param to {param}
    normalized = re.sub(r":([a-zA-Z0-9_]+)", r"{\1}", raw_path)
    # Convert Postman {{param}} to {param}
    normalized = re.sub(r"\{\{([a-zA-Z0-9_]+)\}\}", r"{\1}", normalized)
    # Ensure leading slash
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    # Clean double slashes
    normalized = re.sub(r"//+", "/", normalized)
    # Extract path parameters
    params = re.findall(r"\{([a-zA-Z0-9_]+)\}", normalized)
    return normalized, params


class PostmanConverter:
    """Converts Postman Collection (v2.0 / v2.1) JSON to OpenAPI 3.0 specification."""

    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.title = (
            self.data.get("info", {}).get("name")
            or "Converted Postman Collection"
        )
        self.version = "1.0.0"

    def convert(self) -> dict[str, Any]:
        paths: dict[str, dict[str, Any]] = {}
        items = self.data.get("item", [])
        self._process_items(items, paths)

        return {
            "openapi": "3.0.0",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Auto-converted from Postman Collection to OpenAPI 3.0",
            },
            "paths": paths,
        }

    def _process_items(self, items: list[dict[str, Any]], paths: dict[str, dict[str, Any]]) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            # If item is a folder containing sub-items
            sub_items = item.get("item")
            if isinstance(sub_items, list):
                self._process_items(sub_items, paths)
                continue

            request = item.get("request")
            if not isinstance(request, dict):
                continue

            self._process_request(item.get("name", ""), request, paths)

    def _process_request(
        self,
        name: str,
        request: dict[str, Any],
        paths: dict[str, dict[str, Any]],
    ) -> None:
        method = str(request.get("method") or "GET").lower()
        url_obj = request.get("url")

        raw_path = ""
        query_params: list[dict[str, Any]] = []

        if isinstance(url_obj, str):
            parsed = urlparse(url_obj)
            raw_path = parsed.path or "/"
            if parsed.query:
                parsed_qs = parse_qs(parsed.query, keep_blank_values=True)
                for q_key, q_vals in parsed_qs.items():
                    query_params.append({
                        "name": q_key,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "example": q_vals[0] if q_vals else "",
                    })
        elif isinstance(url_obj, dict):
            path_parts = url_obj.get("path", [])
            if isinstance(path_parts, list):
                raw_path = "/" + "/".join(str(p).strip("/") for p in path_parts if str(p).strip("/"))
            elif isinstance(path_parts, str):
                raw_path = path_parts
            elif url_obj.get("raw"):
                parsed = urlparse(str(url_obj["raw"]))
                raw_path = parsed.path or "/"

            for q in url_obj.get("query", []):
                if isinstance(q, dict) and q.get("key"):
                    query_params.append({
                        "name": str(q["key"]),
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "example": str(q.get("value") or ""),
                    })
                elif isinstance(q, str) and q:
                    query_params.append({
                        "name": q,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                    })

        if not raw_path:
            raw_path = "/"

        normalized_path, path_param_names = _normalize_path(raw_path)

        parameters: list[dict[str, Any]] = []
        for p_name in path_param_names:
            parameters.append({
                "name": p_name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
            })
        parameters.extend(query_params)

        operation: dict[str, Any] = {
            "summary": name or f"{method.upper()} {normalized_path}",
            "parameters": parameters,
            "responses": {
                "200": {"description": "Successful response"},
            },
        }

        # Parse Request Body
        body_obj = request.get("body")
        if isinstance(body_obj, dict) and method in {"post", "put", "patch"}:
            mode = body_obj.get("mode")
            if mode == "raw":
                raw_body = body_obj.get("raw", "")
                if raw_body and isinstance(raw_body, str):
                    try:
                        parsed_json = json.loads(raw_body)
                        schema = _infer_json_schema(parsed_json)
                        operation["requestBody"] = {
                            "content": {
                                "application/json": {
                                    "schema": schema,
                                    "example": parsed_json,
                                }
                            }
                        }
                    except json.JSONDecodeError:
                        operation["requestBody"] = {
                            "content": {
                                "text/plain": {
                                    "schema": {"type": "string"},
                                }
                            }
                        }
            elif mode == "urlencoded":
                form_props = {}
                for field in body_obj.get("urlencoded", []):
                    if isinstance(field, dict) and field.get("key"):
                        form_props[str(field["key"])] = {"type": "string"}
                if form_props:
                    operation["requestBody"] = {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": form_props,
                                }
                            }
                        }
                    }

        if normalized_path not in paths:
            paths[normalized_path] = {}
        paths[normalized_path][method] = operation


class HarConverter:
    """Converts HTTP Archive (HAR v1.2) JSON to OpenAPI 3.0 specification."""

    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.title = "Converted HAR Log API Spec"
        self.version = "1.0.0"

    def convert(self) -> dict[str, Any]:
        paths: dict[str, dict[str, Any]] = {}
        entries = self.data.get("log", {}).get("entries", [])

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            request = entry.get("request")
            if not isinstance(request, dict):
                continue

            url_str = str(request.get("url") or "")
            parsed = urlparse(url_str)
            raw_path = parsed.path or "/"

            # Filter static assets
            if any(raw_path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
                continue

            mime_type = request.get("postData", {}).get("mimeType", "").lower()
            if any(mime_type.startswith(pref) for pref in STATIC_MIME_PREFIXES):
                continue

            method = str(request.get("method") or "GET").lower()
            normalized_path, path_params = _normalize_path(raw_path)

            parameters: list[dict[str, Any]] = []
            for p_name in path_params:
                parameters.append({
                    "name": p_name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                })

            for q in request.get("queryString", []):
                if isinstance(q, dict) and q.get("name"):
                    parameters.append({
                        "name": str(q["name"]),
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                        "example": str(q.get("value") or ""),
                    })

            operation: dict[str, Any] = {
                "summary": f"{method.upper()} {normalized_path}",
                "parameters": parameters,
                "responses": {
                    "200": {"description": "Successful response"},
                },
            }

            # Process postData
            post_data = request.get("postData")
            if isinstance(post_data, dict) and method in {"post", "put", "patch"}:
                text = post_data.get("text")
                if text and isinstance(text, str):
                    try:
                        parsed_json = json.loads(text)
                        schema = _infer_json_schema(parsed_json)
                        operation["requestBody"] = {
                            "content": {
                                "application/json": {
                                    "schema": schema,
                                    "example": parsed_json,
                                }
                            }
                        }
                    except json.JSONDecodeError:
                        pass

            if normalized_path not in paths:
                paths[normalized_path] = {}
            paths[normalized_path][method] = operation

        return {
            "openapi": "3.0.0",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": "Auto-converted from HAR log to OpenAPI 3.0",
            },
            "paths": paths,
        }


def detect_schema_format(data: dict[str, Any]) -> str:
    """Detect whether dictionary is OpenAPI, Postman Collection, or HAR."""
    if not isinstance(data, dict):
        return "unknown"
    if "openapi" in data or "swagger" in data:
        return "openapi"
    if "info" in data and ("schema" in data["info"] or "item" in data):
        info_schema = str(data["info"].get("schema") or "").lower()
        if "postman" in info_schema or "item" in data:
            return "postman"
    if "log" in data and "entries" in data.get("log", {}):
        return "har"
    return "unknown"


def postman_to_openapi(data: dict[str, Any]) -> dict[str, Any]:
    """Convert Postman collection mapping to OpenAPI 3.0."""
    return PostmanConverter(data).convert()


def har_to_openapi(data: dict[str, Any]) -> dict[str, Any]:
    """Convert HAR mapping to OpenAPI 3.0."""
    return HarConverter(data).convert()


def convert_any_to_openapi(data: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Convert mapping to OpenAPI 3.0 if it's Postman or HAR, or return as-is if OpenAPI."""
    fmt = detect_schema_format(data)
    if fmt == "openapi":
        return data, "openapi"
    if fmt == "postman":
        return postman_to_openapi(data), "postman"
    if fmt == "har":
        return har_to_openapi(data), "har"
    return data, "unknown"


def convert_file_to_openapi(file_path: str | Path) -> tuple[dict[str, Any], str]:
    """Read a JSON/YAML file and return (openapi_dict, original_format)."""
    path = Path(file_path).resolve()
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    return convert_any_to_openapi(data)
