"""GraphQL Advanced Security Auditor: Query Batching & Alias Overload DoS (OWASP API4:2023).

Audits GraphQL endpoints for:
1. HTTP Query Batching Attack: Array-based query execution bypassing Rate Limiting & WAF (API4:2023 / API2:2023).
2. Field Alias Overload: Amplification attacks that exhaust CPU/memory via unconstrained alias multipliers (API4:2023).
3. Public Schema Introspection Exposure: Information disclosure exposing full API surface (API8:2023).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
import uuid
from typing import Any, Optional
import httpx
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, stable_finding_id
from .curl_builder import build_curl_command

logger = logging.getLogger(__name__)


class GraphQLAuditResult(BaseModel):
    batching_enabled: bool = False
    batch_size_accepted: int = 0
    alias_overload_vulnerable: bool = False
    aliases_accepted: int = 0
    introspection_enabled: bool = False
    response_time_ms: float = 0.0
    findings: list[Finding] = Field(default_factory=list)


class GraphQLAdvancedAuditor:
    """Specialized auditor for modern GraphQL-specific architecture vulnerabilities."""

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    async def audit_endpoint(
        self,
        base_url: str,
        endpoint: str = "/graphql",
        headers: Optional[dict[str, str]] = None,
        proxy: Optional[str] = None,
        insecure: bool = False,
        run_id: str = "",
        batch_size: int = 20,
        alias_count: int = 100,
    ) -> GraphQLAuditResult:
        """Run comprehensive GraphQL security audits against target endpoint."""
        target_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        rid = run_id or f"gql-adv-{uuid.uuid4().hex[:8]}"
        req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        result = GraphQLAuditResult()

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout) as client:
            # 1. Audit HTTP Query Batching
            await self._audit_batching(
                client=client,
                target_url=target_url,
                endpoint=endpoint,
                base_url=base_url,
                headers=req_headers,
                run_id=rid,
                batch_size=batch_size,
                result=result,
            )

            # 2. Audit Field Alias Overload DoS
            await self._audit_alias_overload(
                client=client,
                target_url=target_url,
                endpoint=endpoint,
                base_url=base_url,
                headers=req_headers,
                run_id=rid,
                alias_count=alias_count,
                result=result,
            )

            # 3. Audit Public Schema Introspection
            await self._audit_introspection(
                client=client,
                target_url=target_url,
                endpoint=endpoint,
                base_url=base_url,
                headers=req_headers,
                run_id=rid,
                result=result,
            )

        return result

    async def _audit_batching(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        endpoint: str,
        base_url: str,
        headers: dict[str, str],
        run_id: str,
        batch_size: int,
        result: GraphQLAuditResult,
    ) -> None:
        """Probe for array-based query batching."""
        batched_payload = [{"query": "query BatchProbe { __typename }"} for _ in range(batch_size)]
        try:
            t0 = time.perf_counter()
            resp = await client.post(target_url, json=batched_payload, headers=headers)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        successful_items = [
                            item for item in data
                            if isinstance(item, dict)
                            and isinstance(item.get("data"), dict)
                            and bool(item["data"])
                        ]
                        if len(successful_items) >= max(2, batch_size // 2):
                            result.batching_enabled = True
                            result.batch_size_accepted = len(successful_items)

                            finding_id = stable_finding_id(
                                target=base_url,
                                method="POST",
                                endpoint=endpoint,
                                attack_type="graphql_query_batching",
                                parameter="batch_array",
                            )
                            curl_cmd = build_curl_command(
                                method="POST",
                                url=target_url,
                                headers=headers,
                                json_data=batched_payload[:3],  # Sample for cURL
                            )
                            now_iso = datetime.now(timezone.utc).isoformat()
                            fp = f"gql_batching_{base_url}_{endpoint}"

                            finding = Finding(
                                finding_id=finding_id,
                                run_id=run_id,
                                timestamp=now_iso,
                                target_app="graphql_target",
                                endpoint=endpoint,
                                method="POST",
                                tool="graphql_advanced_auditor",
                                attack_type="GraphQL Query Batching",
                                owasp_category="API4:2023",
                                severity="high",
                                status_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                confirmed=True,
                                confidence=0.95,
                                fingerprint=fp,
                                curl_command=curl_cmd,
                                evidence=Evidence(
                                    status_code=resp.status_code,
                                    response_time_ms=elapsed_ms,
                                    response_signal=[
                                        f"Server executed {len(successful_items)}/{len(data)} batched GraphQL queries with valid data payloads in a single HTTP request",
                                        "Rate limiting bypass / Brute-force amplification possible",
                                    ],
                                    endpoint=endpoint,
                                    payload=batched_payload[:2],
                                ),
                            )
                            result.findings.append(finding)
                except Exception as exc:
                    logger.debug("GraphQL batching JSON parse error: %s", exc)
        except Exception as exc:
            logger.debug("GraphQL batching probe error: %s", exc)

    async def _audit_alias_overload(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        endpoint: str,
        base_url: str,
        headers: dict[str, str],
        run_id: str,
        alias_count: int,
        result: GraphQLAuditResult,
    ) -> None:
        """Probe for lack of Query Cost Analysis / Field Alias Overload."""
        aliases = " ".join(f"alias_{i}: __typename" for i in range(alias_count))
        query_str = f"query AliasOverloadProbe {{ {aliases} }}"
        payload = {"query": query_str}

        try:
            t0 = time.perf_counter()
            resp = await client.post(target_url, json=payload, headers=headers)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    res_dict = data.get("data") if isinstance(data, dict) else None
                    if isinstance(res_dict, dict) and len(res_dict) >= alias_count // 2:
                        result.alias_overload_vulnerable = True
                        result.aliases_accepted = len(res_dict)

                        finding_id = stable_finding_id(
                            target=base_url,
                            method="POST",
                            endpoint=endpoint,
                            attack_type="graphql_alias_overload",
                            parameter="alias_amplification",
                        )
                        curl_cmd = build_curl_command(
                            method="POST",
                            url=target_url,
                            headers=headers,
                            json_data={"query": f"query {{ {' '.join(f'a_{i}: __typename' for i in range(10))} }}"},
                        )
                        now_iso = datetime.now(timezone.utc).isoformat()
                        fp = f"gql_alias_{base_url}_{endpoint}"

                        finding = Finding(
                            finding_id=finding_id,
                            run_id=run_id,
                            timestamp=now_iso,
                            target_app="graphql_target",
                            endpoint=endpoint,
                            method="POST",
                            tool="graphql_advanced_auditor",
                            attack_type="GraphQL Alias Overload DoS",
                            owasp_category="API4:2023",
                            severity="medium",
                            status_code=resp.status_code,
                            response_time_ms=elapsed_ms,
                            confirmed=True,
                            confidence=0.90,
                            fingerprint=fp,
                            curl_command=curl_cmd,
                            evidence=Evidence(
                                status_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                response_signal=[
                                    f"GraphQL engine evaluated {len(res_dict)} field aliases without complexity limits",
                                    "Vulnerable to computational amplification DoS",
                                ],
                                endpoint=endpoint,
                                payload={"alias_count": alias_count},
                            ),
                        )
                        result.findings.append(finding)
                except Exception as exc:
                    logger.debug("GraphQL alias overload JSON parse error: %s", exc)
        except Exception as exc:
            logger.debug("GraphQL alias overload probe error: %s", exc)

    async def _audit_introspection(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        endpoint: str,
        base_url: str,
        headers: dict[str, str],
        run_id: str,
        result: GraphQLAuditResult,
    ) -> None:
        """Probe for public schema introspection exposure."""
        payload = {"query": "query IntrospectionProbe { __schema { types { name } } }"}
        try:
            t0 = time.perf_counter()
            resp = await client.post(target_url, json=payload, headers=headers)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    schema_data = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
                    if schema_data and "types" in schema_data:
                        result.introspection_enabled = True

                        finding_id = stable_finding_id(
                            target=base_url,
                            method="POST",
                            endpoint=endpoint,
                            attack_type="graphql_introspection_enabled",
                            parameter="__schema",
                        )
                        curl_cmd = build_curl_command(
                            method="POST",
                            url=target_url,
                            headers=headers,
                            json_data=payload,
                        )
                        now_iso = datetime.now(timezone.utc).isoformat()
                        fp = f"gql_intro_{base_url}_{endpoint}"

                        finding = Finding(
                            finding_id=finding_id,
                            run_id=run_id,
                            timestamp=now_iso,
                            target_app="graphql_target",
                            endpoint=endpoint,
                            method="POST",
                            tool="graphql_advanced_auditor",
                            attack_type="GraphQL Introspection Enabled",
                            owasp_category="API8:2023",
                            severity="low",
                            status_code=resp.status_code,
                            response_time_ms=elapsed_ms,
                            confirmed=True,
                            confidence=1.0,
                            fingerprint=fp,
                            curl_command=curl_cmd,
                            evidence=Evidence(
                                status_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                response_signal=[
                                    "Public GraphQL Schema Introspection is enabled in production",
                                    "Exposes complete internal data structures, queries, and mutations",
                                ],
                                endpoint=endpoint,
                                payload=payload,
                            ),
                        )
                        result.findings.append(finding)
                except Exception as exc:
                    logger.debug("GraphQL introspection JSON parse error: %s", exc)
        except Exception as exc:
            logger.debug("GraphQL introspection probe error: %s", exc)
