"""Comprehensive tests for Phase 1 enhancements:
1. Postman Collection v2.0/v2.1 to OpenAPI 3.0 converter
2. HAR (HTTP Archive) to OpenAPI 3.0 converter
3. SchemaManager auto-detection & conversion
4. Upstream Proxy (--proxy) & Insecure SSL (--insecure) support in runners & CLI
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch
import pytest

from core.schema_converter import (
    convert_any_to_openapi,
    detect_schema_format,
    har_to_openapi,
    postman_to_openapi,
)
from core.schema_manager import SchemaManager
from modules.rest import run_schemathesis1 as rest
from modules.graphql import run_graphql_fuzz1 as graphql
from modules.security import run_security_tests
import run_all
from cli import main as cli_main


# -----------------------------------------------------------------------------
# 1. Postman Collection to OpenAPI Converter Tests
# -----------------------------------------------------------------------------

def test_postman_converter_endpoints_and_params():
    postman_data = {
        "info": {
            "name": "E-Commerce API",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": [
            {
                "name": "Users Folder",
                "item": [
                    {
                        "name": "Get User Profile",
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "https://api.shop.com/api/v1/users/:userId?verbose=true",
                                "path": ["api", "v1", "users", ":userId"],
                                "query": [{"key": "verbose", "value": "true"}],
                            },
                        },
                    },
                    {
                        "name": "Create User",
                        "request": {
                            "method": "POST",
                            "url": "https://api.shop.com/api/v1/users",
                            "body": {
                                "mode": "raw",
                                "raw": json.dumps({"username": "john", "age": 30, "admin": False}),
                            },
                        },
                    },
                ],
            },
            {
                "name": "Delete Item",
                "request": {
                    "method": "DELETE",
                    "url": {
                        "raw": "https://api.shop.com/items/{{itemId}}",
                        "path": ["items", "{{itemId}}"],
                    },
                },
            },
        ],
    }

    assert detect_schema_format(postman_data) == "postman"
    openapi = postman_to_openapi(postman_data)

    assert openapi["openapi"] == "3.0.0"
    assert openapi["info"]["title"] == "E-Commerce API"

    paths = openapi["paths"]
    assert "/api/v1/users/{userId}" in paths
    assert "/api/v1/users" in paths
    assert "/items/{itemId}" in paths

    # Check GET /api/v1/users/{userId}
    get_op = paths["api/v1/users/{userId}" if "api/v1/users/{userId}" in paths else "/api/v1/users/{userId}"]["get"]
    param_names = {p["name"] for p in get_op["parameters"]}
    assert "userId" in param_names
    assert "verbose" in param_names

    # Check POST /api/v1/users requestBody schema
    post_op = paths["/api/v1/users"]["post"]
    req_body = post_op["requestBody"]["content"]["application/json"]["schema"]
    assert req_body["type"] == "object"
    assert req_body["properties"]["username"]["type"] == "string"
    assert req_body["properties"]["age"]["type"] == "integer"
    assert req_body["properties"]["admin"]["type"] == "boolean"


# -----------------------------------------------------------------------------
# 2. HAR to OpenAPI Converter Tests
# -----------------------------------------------------------------------------

def test_har_converter_filters_static_assets_and_extracts_apis():
    har_data = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://myapi.com/static/style.css",
                        "queryString": [],
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://myapi.com/static/bundle.js",
                        "queryString": [],
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://myapi.com/images/logo.png",
                        "queryString": [],
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://myapi.com/api/v2/orders?status=active",
                        "queryString": [{"name": "status", "value": "active"}],
                    },
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://myapi.com/api/v2/orders",
                        "queryString": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"order_id": "ORD-123", "amount": 99.5}),
                        },
                    },
                },
            ],
        },
    }

    assert detect_schema_format(har_data) == "har"
    openapi = har_to_openapi(har_data)

    paths = openapi["paths"]
    # Static assets must be filtered out
    assert not any("style.css" in p or "bundle.js" in p or "logo.png" in p for p in paths)

    # API endpoints must be present
    assert "/api/v2/orders" in paths
    assert "get" in paths["/api/v2/orders"]
    assert "post" in paths["/api/v2/orders"]

    # Parameter and postData check
    get_params = paths["/api/v2/orders"]["get"]["parameters"]
    assert any(p["name"] == "status" for p in get_params)

    post_body = paths["/api/v2/orders"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert post_body["type"] == "object"
    assert post_body["properties"]["order_id"]["type"] == "string"
    assert post_body["properties"]["amount"]["type"] == "number"


# -----------------------------------------------------------------------------
# 3. SchemaManager Auto-Detection & Schemathesis Integration Tests
# -----------------------------------------------------------------------------

def test_schema_manager_loads_and_converts_postman_file(tmp_path: Path):
    postman_file = tmp_path / "postman_collection.json"
    postman_data = {
        "info": {"name": "Test Postman API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {
                "name": "Get Info",
                "request": {
                    "method": "GET",
                    "url": "http://127.0.0.1:8000/info",
                },
            }
        ],
    }
    postman_file.write_text(json.dumps(postman_data), encoding="utf-8")

    sm = SchemaManager(tmp_path)
    loaded_schema = sm.load(postman_file)

    assert loaded_schema["openapi"] == "3.0.0"
    assert "/info" in loaded_schema["paths"]

    # Must be parseable by Schemathesis
    import schemathesis
    st_schema = schemathesis.openapi.from_dict(loaded_schema)
    ops = list(st_schema.get_all_operations())
    assert len(ops) == 1
    assert ops[0].ok().path == "/info"


# -----------------------------------------------------------------------------
# 4. Upstream Proxy & Insecure Option Tests
# -----------------------------------------------------------------------------

def test_build_target_command_with_proxy_and_insecure():
    name, cmd = run_security_tests.build_target_command(
        "vampi",
        proxy="http://127.0.0.1:8080",
        insecure=True,
    )
    assert "--proxy" in cmd
    assert "http://127.0.0.1:8080" in cmd
    assert "--insecure" in cmd


def test_run_target_sets_proxy_environment(monkeypatch):
    captured_env = {}

    def mock_run_command(label, command, extra_env=None):
        captured_env.update(extra_env or {})

    monkeypatch.setattr(run_security_tests, "run_command", mock_run_command)
    run_security_tests.run_target(
        "vampi",
        proxy="http://127.0.0.1:8080",
        insecure=True,
    )

    assert captured_env.get("HTTP_PROXY") == "http://127.0.0.1:8080"
    assert captured_env.get("HTTPS_PROXY") == "http://127.0.0.1:8080"
    assert captured_env.get("PYTHONHTTPSVERIFY") == "0"


def test_dynamic_target_with_proxy_and_postman(tmp_path: Path):
    dummy_postman = tmp_path / "collection.json"
    dummy_postman.write_text(json.dumps({
        "info": {"name": "Postman Test", "schema": "https://schema.postman.com"},
        "item": [],
    }), encoding="utf-8")

    captured_target = {}

    def mock_run_target(target_id, include_payload=True, tokens=None, targets=None, **kwargs):
        captured_target["target"] = targets.get_target(target_id)
        captured_target["kwargs"] = kwargs

    with patch.object(run_security_tests, "run_target", side_effect=mock_run_target):
        exit_code = run_security_tests.run_dynamic_target(
            url="https://api.example.com",
            postman=str(dummy_postman),
            proxy="http://127.0.0.1:8080",
            insecure=True,
            targets=run_security_tests.TargetManager(tmp_path),
        )

    assert exit_code == 0
    target = captured_target["target"]
    assert target.schema_source == str(dummy_postman)
    assert target.settings.get("proxy") == "http://127.0.0.1:8080"
    assert target.settings.get("insecure") is True
    assert captured_target["kwargs"].get("proxy") == "http://127.0.0.1:8080"
    assert captured_target["kwargs"].get("insecure") is True


def test_cli_main_supports_proxy_and_postman():
    with patch.object(cli_main, "run_dynamic_target", return_value=0) as mock_dynamic:
        exit_code = cli_main.main([
            "--url", "https://api.example.com",
            "--postman", "./my_collection.json",
            "--proxy", "http://127.0.0.1:8080",
            "--insecure",
        ])
        assert exit_code == 0
        mock_dynamic.assert_called_once_with(
            url="https://api.example.com",
            schema=None,
            auth_token=None,
            protocol="rest",
            endpoint="/graphql",
            payloads=None,
            target_id=None,
            name=None,
            postman="./my_collection.json",
            proxy="http://127.0.0.1:8080",
            insecure=True,
        )


def test_run_all_script_scan_with_proxy_and_har():
    parser = run_all._parser()
    args = parser.parse_args([
        "scan",
        "--url", "http://127.0.0.1:8000",
        "--har", "./traffic.har",
        "--proxy", "http://127.0.0.1:8080",
        "--insecure",
    ])
    assert args.command == "scan"
    assert args.url == "http://127.0.0.1:8000"
    assert args.har == "./traffic.har"
    assert args.proxy == "http://127.0.0.1:8080"
    assert args.insecure is True
