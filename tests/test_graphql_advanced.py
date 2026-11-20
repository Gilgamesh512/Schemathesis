"""Unit tests for GraphQL Advanced Security Auditor (Query Batching & Alias DoS)."""

from __future__ import annotations

import pytest
import httpx

from core.graphql_advanced_auditor import GraphQLAdvancedAuditor, GraphQLAuditResult


@pytest.mark.anyio
async def test_graphql_batching_detection(monkeypatch):
    auditor = GraphQLAdvancedAuditor()

    async def mock_post(self, url, json=None, headers=None, **kwargs):
        # Simulate server accepting batch of queries
        if isinstance(json, list):
            res_list = [{"data": {"__typename": "Query"}} for _ in json]
            return httpx.Response(200, json=res_list, request=httpx.Request("POST", url))
        return httpx.Response(200, json={"data": {}}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    result = await auditor.audit_endpoint(
        base_url="http://test.local",
        endpoint="/graphql",
        batch_size=10,
        alias_count=20,
    )

    assert result.batching_enabled is True
    assert result.batch_size_accepted == 10
    batch_finding = next((f for f in result.findings if f.attack_type == "GraphQL Query Batching"), None)
    assert batch_finding is not None
    assert batch_finding.severity.lower() == "high"
    assert batch_finding.owasp_category == "API4:2023"
    assert "batched" in batch_finding.evidence.response_signal[0].lower()


@pytest.mark.anyio
async def test_graphql_alias_overload_detection(monkeypatch):
    auditor = GraphQLAdvancedAuditor()

    async def mock_post(self, url, json=None, headers=None, **kwargs):
        query = (json or {}).get("query", "")
        if "AliasOverloadProbe" in query:
            # Simulate server resolving 50 aliases
            resolved_dict = {f"alias_{i}": "Query" for i in range(50)}
            return httpx.Response(200, json={"data": resolved_dict}, request=httpx.Request("POST", url))
        # Refuse batching
        if isinstance(json, list):
            return httpx.Response(400, text="Batching not allowed", request=httpx.Request("POST", url))
        return httpx.Response(200, json={"data": {}}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    result = await auditor.audit_endpoint(
        base_url="http://test.local",
        endpoint="/graphql",
        batch_size=10,
        alias_count=50,
    )

    assert result.batching_enabled is False
    assert result.alias_overload_vulnerable is True
    assert result.aliases_accepted == 50
    alias_finding = next((f for f in result.findings if f.attack_type == "GraphQL Alias Overload DoS"), None)
    assert alias_finding is not None
    assert alias_finding.severity.lower() == "medium"
    assert "alias" in alias_finding.evidence.response_signal[0].lower()


@pytest.mark.anyio
async def test_graphql_introspection_detection(monkeypatch):
    auditor = GraphQLAdvancedAuditor()

    async def mock_post(self, url, json=None, headers=None, **kwargs):
        query = (json or {}).get("query", "")
        if "IntrospectionProbe" in query:
            return httpx.Response(
                200,
                json={"data": {"__schema": {"types": [{"name": "User"}, {"name": "Query"}]}}},
                request=httpx.Request("POST", url),
            )
        return httpx.Response(400, text="Refused", request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    result = await auditor.audit_endpoint(
        base_url="http://test.local",
        endpoint="/graphql",
    )

    assert result.introspection_enabled is True
    intro_finding = next((f for f in result.findings if f.attack_type == "GraphQL Introspection Enabled"), None)
    assert intro_finding is not None
    assert intro_finding.owasp_category == "API8:2023"
