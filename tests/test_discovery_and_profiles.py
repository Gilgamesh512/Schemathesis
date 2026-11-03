from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from core import (
    ApiDiscoveryEngine,
    DiscoveryResult,
    TargetConfig,
    TargetManager,
    discover_api,
)


def test_discovery_result_properties():
    res_none = DiscoveryResult(url="https://api.example.com", protocol="rest")
    assert not res_none.is_discovered

    res_rest = DiscoveryResult(
        url="https://api.example.com",
        protocol="rest",
        schema_url="https://api.example.com/openapi.json",
    )
    assert res_rest.is_discovered

    res_gql = DiscoveryResult(
        url="https://api.example.com",
        protocol="graphql",
        endpoint="/graphql",
    )
    assert res_gql.is_discovered


def test_api_discovery_direct_openapi_schema():
    dummy_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test Production API", "version": "1.2.3"},
        "paths": {},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"openapi": "3.0.0"}'
    mock_resp.headers = {"content-type": "application/json"}
    mock_resp.text = '{"openapi": "3.0.0"}'
    mock_resp.json.return_value = dummy_spec

    with patch("httpx.Client.get", return_value=mock_resp):
        res = discover_api("https://api.example.com/openapi.json")
        assert res.is_discovered
        assert res.protocol == "rest"
        assert res.title == "Test Production API"
        assert res.version == "1.2.3"
        assert res.schema_url == "https://api.example.com/openapi.json"


def test_api_discovery_common_path():
    dummy_spec = {
        "swagger": "2.0",
        "info": {"title": "Swagger Legacy API", "version": "2.0"},
        "paths": {},
    }

    def mock_get(url, **kwargs):
        resp = MagicMock()
        if url.endswith("/openapi.json"):
            resp.status_code = 200
            resp.content = b'{"swagger": "2.0"}'
            resp.headers = {"content-type": "application/json"}
            resp.text = '{"swagger": "2.0"}'
            resp.json.return_value = dummy_spec
            return resp
        resp.status_code = 404
        resp.content = b""
        return resp

    with patch("httpx.Client.get", side_effect=mock_get):
        res = discover_api("https://api.example.com")
        assert res.is_discovered
        assert res.title == "Swagger Legacy API"
        assert res.schema_url == "https://api.example.com/openapi.json"


def test_api_discovery_graphql_introspection():
    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 404
        resp.content = b""
        return resp

    def mock_post(url, **kwargs):
        resp = MagicMock()
        if url.endswith("/graphql"):
            resp.status_code = 200
            resp.json.return_value = {
                "data": {"__schema": {"queryType": {"name": "Query"}}}
            }
            return resp
        resp.status_code = 404
        return resp

    with patch("httpx.Client.get", side_effect=mock_get), patch(
        "httpx.Client.post", side_effect=mock_post
    ):
        res = discover_api("https://api.example.com")
        assert res.is_discovered
        assert res.protocol == "graphql"
        assert res.endpoint == "/graphql"


def test_target_manager_profile_persistence(tmp_path: Path):
    tm = TargetManager(tmp_path)
    # Add a custom target
    tm.add_target(
        "customer_crm",
        name="Customer CRM Production",
        base_url="https://crm.company.internal",
        schema_source="https://crm.company.internal/swagger.json",
        auth={"header": "Bearer jwt_super_secret"},
        settings={"protocol": "rest", "allow_remote_schema": True},
    )

    # Save profile to disk
    saved_path = tm.save_profile("customer_crm")
    assert saved_path.exists()
    assert saved_path.name == "customer_crm.yaml"

    # Refresh manager to test loading from disk
    tm2 = TargetManager(tmp_path)
    assert "customer_crm" in tm2.targets
    loaded = tm2.get_target("customer_crm")
    assert loaded.name == "Customer CRM Production"
    assert loaded.base_url == "https://crm.company.internal"
    assert loaded.auth["header"] == "Bearer jwt_super_secret"

    # Custom vs Lab listing
    customs = tm2.list_custom_profiles()
    assert len(customs) == 1
    assert customs[0].target_id == "customer_crm"

    # Test delete
    assert tm2.delete_profile("customer_crm") is True
    assert not saved_path.exists()
    assert "customer_crm" not in tm2.targets
