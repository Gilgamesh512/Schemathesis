#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import (
    ApiDependencyGraph,
    AuthConfig,
    AuthManager,
    CallbackVerifier,
    Finding,
    ProjectPaths,
    ResultManager,
    SchemaManager,
    SecurityReporter,
    TargetManager,
    TokenVerifier,
    WorkflowDefinition,
    WorkflowRunner,
    discover_api,
    normalize_auth_header,
    parse_tokens_env as _core_parse_tokens_env,
    parse_har_file,
    PiiDetector,
    HeaderTamperFuzzer,
    ResourceExhaustionFuzzer,
    get_audit_headers,
    CleanupTracker,
    GraphQLAdvancedAuditor,
    GraphQLAuditResult,
    ProxyRotator,
    SessionKeeper,
    AuthAutomationConfig,
)

try:
    from core.concurrency_fuzzer import ConcurrencyBurstResult, ConcurrencyFuzzer
except Exception:
    try:
        from core import ConcurrencyBurstResult, ConcurrencyFuzzer  # type: ignore
    except Exception:
        ConcurrencyBurstResult = None  # type: ignore
        ConcurrencyFuzzer = None  # type: ignore


PROJECT_PATHS = ProjectPaths.from_root(PROJECT_ROOT)
TARGETS = TargetManager(PROJECT_ROOT)
RESULTS = ResultManager(PROJECT_ROOT)
PYTHON = sys.executable
REST_FUZZER = PROJECT_ROOT / "modules" / "rest" / "run_schemathesis1.py"
GRAPHQL_FUZZER = PROJECT_ROOT / "modules" / "graphql" / "run_graphql_fuzz1.py"
RULES = PROJECT_PATHS.config / "rules.json"
TOKENS_FILE = PROJECT_ROOT / "tokens.env"


def banner(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def parse_tokens_env(path: Path = TOKENS_FILE) -> dict[str, str]:
    return _core_parse_tokens_env(path, auth_headers_only=False, warn_missing=True)


def auth_env_for(
    target_id: str,
    tokens: dict[str, str],
    *,
    targets: TargetManager = TARGETS,
) -> dict[str, str] | None:
    target = targets.get_target(target_id)

    # 1. Direct header / token configured in target auth dictionary
    direct = (
        target.auth.get("header")
        or target.auth.get("token")
        or target.auth.get("auth_header")
    )
    if direct:
        normalized = normalize_auth_header(str(direct))
        return {"FUZZ_AUTH_HEADER": normalized} if normalized else None

    # 2. Key from tokens dictionary (e.g. from tokens.env or CLI)
    token_env = target.auth.get("token_env")
    value = None
    if isinstance(token_env, str):
        value = tokens.get(token_env) or os.environ.get(token_env)
    elif "FUZZ_AUTH_HEADER" in tokens:
        value = tokens["FUZZ_AUTH_HEADER"]
    elif "AUTH_TOKEN" in tokens:
        value = normalize_auth_header(tokens["AUTH_TOKEN"])

    env_res: dict[str, str] = {}
    if value:
        env_res["FUZZ_AUTH_HEADER"] = value

    # Check for custom multi-headers
    headers_dict = target.auth.get("headers")
    if isinstance(headers_dict, dict) and headers_dict:
        env_res["FUZZ_EXTRA_HEADERS_JSON"] = json.dumps(headers_dict)

    # Check for User 2 token (Dual-user auth for BOLA / IDOR cross-account testing)
    if isinstance(token_env, str):
        user2_key = f"{token_env}_USER2"
        user2_val = tokens.get(user2_key) or os.environ.get(user2_key)
        if user2_val:
            env_res["FUZZ_AUTH_HEADER_USER2"] = user2_val

    return env_res if env_res else None


def build_target_command(
    target_id: str,
    *,
    include_payload: bool = True,
    targets: TargetManager = TARGETS,
    proxy: str | None = None,
    insecure: bool = False,
) -> tuple[str, list[str]]:
    target = targets.get_target(target_id)
    protocol = target.settings.get("protocol")
    schema_source = target.schema_source

    command = [PYTHON]
    if protocol == "rest":
        if not schema_source:
            raise ValueError(f"Target '{target_id}' has no schema_source configured")
        remote_schema = schema_source.startswith(("http://", "https://"))
        schema_path = schema_source if remote_schema else targets.resolve_source(schema_source)
        if not remote_schema and not schema_path.is_file():
            raise FileNotFoundError(
                f"Schema for target '{target_id}' not found: {schema_path}"
            )
        command.extend([
            str(REST_FUZZER),
            "--targets", f"{target_id}={schema_path}",
            "--base-urls", f"{target_id}={target.base_url}",
        ])
        if target.settings.get("allow_remote_schema", False) or remote_schema:
            command.append("--allow-remote-schema")
    elif protocol == "graphql":
        command.extend([
            str(GRAPHQL_FUZZER),
            "--target-id", target_id,
            "--base-url", target.base_url,
            "--endpoint", str(target.settings.get("endpoint", "/graphql")),
        ])
    else:
        raise ValueError(
            f"Target '{target_id}' has unsupported protocol '{protocol}'"
        )

    payload_source = target.settings.get("payload_source")
    payload_path = (
        targets.resolve_source(payload_source)
        if isinstance(payload_source, str) and payload_source
        else None
    )
    if include_payload and payload_path is not None:
        if not payload_path.is_file():
            raise FileNotFoundError(
                f"Payload file for target '{target_id}' not found: {payload_path}"
            )
        command.extend(["--payloads", str(payload_path)])
    elif protocol == "graphql":
        # Built-in GraphQL mutation engine activates automatically when no custom payload file is supplied
        pass

    results_dir = RESULTS.ensure_results_dir()
    command.extend([
        "--rules", str(RULES),
        "--results-dir", str(results_dir),
        "--concurrency", "3",
    ])

    proxy_val = proxy or target.settings.get("proxy")
    if proxy_val:
        command.extend(["--proxy", str(proxy_val)])
    if insecure or target.settings.get("insecure"):
        command.append("--insecure")

    return target.name, command


def run_command(label: str, command: list[str],
                extra_env: dict[str, str] | None = None) -> None:
    print()
    print(f"[+] RUNNING: {label}")
    print("[CMD]")
    print(" ".join(command))
    print()

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(PROJECT_ROOT), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    if extra_env:
        env.update(extra_env)
        print("[INFO] Auth header passed via process environment.")
    else:
        env.pop("FUZZ_AUTH_HEADER", None)

    result = subprocess.run(command, cwd=PROJECT_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    print(f"[+] {label}: OK")


_DEFAULT_RUN_COMMAND = run_command


def _extract_audit_targets_from_schema(
    schema_source: str | None,
    *,
    allow_remote: bool = False,
) -> dict[str, list]:
    """Derive endpoints, callback params, race candidates, and resource params from an OpenAPI spec."""
    extracted: dict[str, list] = {
        "endpoints": [],
        "callback_params": [],
        "race_candidates": [],
        "resource_candidates": [],
    }
    if not schema_source:
        return extracted
    try:
        spec = SchemaManager(PROJECT_ROOT).load(
            schema_source,
            allow_remote=allow_remote,
            allow_outside=True,
        )
    except Exception:
        return extracted

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return extracted

    seen_eps: set[tuple[str, str]] = set()
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_level_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method_key, op in path_item.items():
            method = method_key.upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or not isinstance(op, dict):
                continue
            ep_pair = (method, path)
            if ep_pair not in seen_eps:
                seen_eps.add(ep_pair)
                extracted["endpoints"].append(ep_pair)

            if ConcurrencyFuzzer is not None and ConcurrencyFuzzer.is_candidate_endpoint(path, method):
                extracted["race_candidates"].append(ep_pair)

            op_params = op.get("parameters") if isinstance(op.get("parameters"), list) else []
            for p in [*path_level_params, *op_params]:
                if not isinstance(p, dict):
                    continue
                p_name = str(p.get("name") or "").strip()
                p_loc = str(p.get("in") or "query").strip().lower()
                if not p_name:
                    continue
                if CallbackVerifier.is_callback_parameter(p_name):
                    extracted["callback_params"].append((method, path, p_name, p_loc))
                if method == "GET" and p_loc == "query":
                    extracted["resource_candidates"].append((method, path, p_name))

            req_body = op.get("requestBody")
            if isinstance(req_body, dict):
                content = req_body.get("content", {})
                json_schema = content.get("application/json", {}).get("schema", {}) if isinstance(content, dict) else {}
                props = json_schema.get("properties", {}) if isinstance(json_schema, dict) else {}
                for prop_name in props:
                    if CallbackVerifier.is_callback_parameter(prop_name):
                        extracted["callback_params"].append((method, path, prop_name, "body"))
                    if method in {"POST", "PUT", "PATCH"}:
                        extracted["resource_candidates"].append((method, path, prop_name))

    return extracted


def run_target(
    target_id: str,
    *,
    include_payload: bool = True,
    tokens: dict[str, str] | None = None,
    targets: TargetManager = TARGETS,
    proxy: str | None = None,
    insecure: bool = False,
    session_keeper: SessionKeeper | None = None,
    proxy_rotator: ProxyRotator | None = None,
    auth_manager: AuthManager | None = None,
    seed_corpus: Any = None,
) -> None:
    label, command = build_target_command(
        target_id,
        include_payload=include_payload,
        targets=targets,
        proxy=proxy,
        insecure=insecure,
    )
    extra_env = auth_env_for(target_id, tokens or {}, targets=targets) or {}
    target = targets.get_target(target_id)
    proxy_val = proxy or target.settings.get("proxy")
    if proxy_val:
        extra_env["HTTP_PROXY"] = str(proxy_val)
        extra_env["HTTPS_PROXY"] = str(proxy_val)
    if insecure or target.settings.get("insecure"):
        extra_env["PYTHONHTTPSVERIFY"] = "0"

    schema_source = target.schema_source
    if schema_source and str(schema_source).lower().endswith(".har"):
        extra_env["SCHEMATHESIS_SEED_CORPUS"] = str(schema_source)

    # Preserve compatibility when unit tests monkeypatch run_command
    if run_command is not _DEFAULT_RUN_COMMAND:
        run_command(
            f"FUZZING - {label}",
            command,
            extra_env if extra_env else None,
        )
        return

    protocol = target.settings.get("protocol")
    effective_insecure = bool(insecure or target.settings.get("insecure"))
    headers: dict[str, str] = {}
    if extra_env.get("FUZZ_AUTH_HEADER"):
        hk, _, hv = extra_env["FUZZ_AUTH_HEADER"].partition(":")
        if hk.strip():
            headers[hk.strip()] = hv.strip()
    if extra_env.get("FUZZ_EXTRA_HEADERS_JSON"):
        try:
            for hk, hv in json.loads(extra_env["FUZZ_EXTRA_HEADERS_JSON"]).items():
                headers[str(hk).strip()] = str(hv).strip()
        except Exception:
            pass

    user2_headers: dict[str, str] = {}
    if extra_env.get("FUZZ_AUTH_HEADER_USER2"):
        hk2, _, hv2 = extra_env["FUZZ_AUTH_HEADER_USER2"].partition(":")
        if hk2.strip():
            user2_headers[hk2.strip()] = hv2.strip()

    payload_source = target.settings.get("payload_source")
    payload_path = (
        str(targets.resolve_source(payload_source))
        if include_payload and isinstance(payload_source, str) and payload_source
        else None
    )

    if protocol == "rest":
        from modules.rest import run_schemathesis1 as rest_runner

        remote_schema = bool(schema_source and str(schema_source).startswith(("http://", "https://")))
        resolved_schema = str(schema_source) if remote_schema else str(targets.resolve_source(schema_source or ""))
        schema, base_url = rest_runner.load_schema(
            resolved_schema,
            target.base_url,
            allow_remote=bool(target.settings.get("allow_remote_schema", False) or remote_schema),
        )
        rest_runner.execute_rest_scan(
            targets={target_id: (schema, base_url)},
            targets_desc=f"{target_id}={resolved_schema}",
            headers=headers,
            user2_headers=user2_headers or None,
            payloads_path=payload_path,
            rules_path=RULES,
            results_dir=RESULTS.ensure_results_dir(),
            concurrency=3,
            proxy=str(proxy_val) if proxy_val else None,
            insecure=effective_insecure,
            session_keeper=session_keeper,
            proxy_rotator=proxy_rotator,
            auth_manager=auth_manager,
            seed_corpus=seed_corpus,
        )
    elif protocol == "graphql":
        from modules.graphql import run_graphql_fuzz1 as gql_runner

        gql_runner.execute_graphql_scan(
            target_id=target_id,
            base_url=target.base_url,
            endpoint=str(target.settings.get("endpoint", "/graphql")),
            payloads_path=payload_path,
            rules_path=RULES,
            results_dir=RESULTS.ensure_results_dir(),
            concurrency=3,
            headers=headers,
            proxy=str(proxy_val) if proxy_val else None,
            insecure=effective_insecure,
            targets=targets,
            session_keeper=session_keeper,
            proxy_rotator=proxy_rotator,
            auth_manager=auth_manager,
        )
    else:
        raise ValueError(f"Target '{target_id}' has unsupported protocol '{protocol}'")


def run_token_audit(
    base_url: str,
    auth_token: str,
    endpoints: list[tuple[str, str]] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    require_auth_challenge: bool = True,
) -> list[Finding]:
    """Audit protected endpoints for RFC 7519 compliance (Broken Authentication)."""
    verifier = TokenVerifier()
    clean_token = auth_token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    inspection = verifier.inspect_token(clean_token)
    if not inspection:
        print("[i] Token does not appear to be an RFC 7519 JWT, skipping token compliance probes.")
        return []

    banner("RFC 7519 TOKEN AUTHENTICATION COMPLIANCE AUDIT")
    print(f"[i] Algorithm: {inspection.algorithm}")
    print(f"[i] Expiration Claim: {'Present' if inspection.has_exp else 'Missing'}")
    if inspection.is_expired:
        print("[!] Warning: Provided token is already expired.")

    target_eps = endpoints or [("GET", "/")]

    all_findings: list[Finding] = []
    run_id = f"token-audit-{uuid.uuid4().hex[:8]}"

    async def _run():
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            for method, ep in target_eps:
                findings = await verifier.verify_endpoint(
                    client=client,
                    endpoint=ep,
                    method=method,
                    valid_auth_header=clean_token,
                    base_url=base_url,
                    run_id=run_id,
                    require_auth_challenge=require_auth_challenge,
                )
                all_findings.extend(findings)

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] Token verification probe failed: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} token verification anomalies!")
    else:
        print("[+] Token verification completed: No broken authentication signatures accepted.")
    return all_findings


def run_callback_audit(
    base_url: str,
    candidate_params: list[tuple[str, str, str, str]] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    external_url: str | None = None,
    poll_url: str | None = None,
    advertised_host: str | None = None,
) -> list[Finding]:
    """Audit potential URL-accepting parameters for SSRF & destination whitelisting."""
    verifier = CallbackVerifier(
        external_callback_url=external_url,
        poll_url=poll_url,
        advertised_host=advertised_host,
    )
    banner("DESTINATION WHITELIST & CALLBACK AUDIT (SSRF)")
    if external_url:
        print(f"[i] External Canary Callback URL: {external_url}")
        if verifier.poll_url:
            print(f"[i] Canary Polling Endpoint:      {verifier.poll_url}")
    else:
        reported = advertised_host or "127.0.0.1"
        print(f"[i] Using dynamic in-memory loopback callback listener ({reported})")

    if not candidate_params:
        print("[i] No URL/callback parameters detected in schema; skipping callback audit.")
        return []

    candidates = candidate_params

    all_findings: list[Finding] = []
    run_id = f"callback-audit-{uuid.uuid4().hex[:8]}"

    async def _run():
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            for method, ep, param, loc in candidates:
                finding = await verifier.verify_endpoint_url_parameter(
                    client=client,
                    endpoint=ep,
                    method=method,
                    param_name=param,
                    param_location=loc,
                    base_url=base_url,
                    run_id=run_id,
                )
                if finding:
                    all_findings.append(finding)

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] Callback audit error: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} callback destination whitelist issues!")
    else:
        print("[+] Callback destination audit completed: No loopback callbacks received.")
    return all_findings


def run_concurrency_audit(
    base_url: str,
    candidate_endpoints: list[tuple[str, str]] | None = None,
    auth_token: str | None = None,
    burst_size: int = 5,
    proxy: str | None = None,
    insecure: bool = False,
) -> list[Finding]:
    """Audit state-changing endpoints for Race Conditions & Concurrency Flaws (OWASP API4:2023)."""
    banner("CONCURRENCY & RACE CONDITION AUDIT (OWASP API4:2023)")
    if ConcurrencyFuzzer is None:
        print("[!] ConcurrencyFuzzer module is unavailable in this environment, skipping.")
        return []
    fuzzer = ConcurrencyFuzzer(
        burst_size=burst_size,
        verify_ssl=not insecure,
        proxy=proxy,
    )
    print(f"[i] Testing state-changing actions with synchronized burst size: {burst_size} req/burst")

    if not candidate_endpoints:
        print("[i] No state-changing race-condition candidates found in schema; skipping concurrency audit.")
        return []

    candidates = candidate_endpoints

    all_findings: list[Finding] = []
    run_id = f"race-audit-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": auth_token} if auth_token else {}

    async def _run():
        for method, ep in candidates:
            sample_body = {"coupon_code": "PROMO2026", "code": "DISCOUNT50"}
            res = await fuzzer.execute_burst(
                base_url=base_url,
                endpoint=ep,
                method=method,
                headers=headers,
                json_data=sample_body,
            )
            finding = fuzzer.convert_to_finding(res, target_app="dynamic_target", run_id=run_id)
            if finding:
                all_findings.append(finding)
                print(f"[!] CONFIRMED RACE CONDITION on {method} {ep}: {res.vulnerability_reason}")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] Concurrency audit error: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} confirmed Concurrency / Race Condition vulnerabilities!")
    else:
        print("[+] Concurrency audit completed: No race conditions or duplicate execution detected.")
    return all_findings


def run_pii_audit(
    base_url: str,
    endpoints: list[tuple[str, str]] | None = None,
    auth_token: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
) -> list[Finding]:
    """Audit response bodies across target endpoints for PII and cryptographic secret leakage (API3:2023)."""
    banner("PII & SENSITIVE DATA EXPOSURE AUDIT (OWASP API3:2023)")
    target_eps = endpoints or [("GET", "/")]
    all_findings: list[Finding] = []
    run_id = f"pii-audit-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": auth_token} if auth_token else {}

    async def _run():
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            for method, ep in target_eps:
                full_url = f"{base_url.rstrip('/')}/{ep.lstrip('/')}"
                try:
                    t0 = time.perf_counter()
                    resp = await client.request(method=method, url=full_url, headers=headers)
                    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                    finding = PiiDetector.audit_response(
                        status_code=resp.status_code,
                        response_text=resp.text or "",
                        endpoint=ep,
                        method=method,
                        run_id=run_id,
                        target_app="dynamic_target",
                        elapsed_ms=elapsed_ms,
                    )
                    if finding:
                        all_findings.append(finding)
                        print(f"[!] CONFIRMED PII/SECRET LEAK on {method} {ep}: {finding.evidence.response_signal[0]}")
                except Exception:
                    continue

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] PII audit error: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} confirmed PII/Secret Data Exposure vulnerabilities!")
    else:
        print("[+] PII audit completed: No sensitive credentials or PII patterns leaked in response bodies.")
    return all_findings


def run_header_tamper_audit(
    base_url: str,
    endpoints: list[tuple[str, str]] | None = None,
    auth_token: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
) -> list[Finding]:
    """Audit endpoints for Reverse Proxy, Routing Integrity, and Cache Poisoning (API8:2023)."""
    banner("REVERSE PROXY & HEADER TAMPERING AUDIT (OWASP API8:2023)")
    fuzzer = HeaderTamperFuzzer()
    target_eps = endpoints or [("GET", "/")]
    all_findings: list[Finding] = []
    run_id = f"header-tamper-audit-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": auth_token} if auth_token else {}

    async def _run():
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            for method, ep in target_eps:
                findings = await fuzzer.test_endpoint(
                    client=client,
                    base_url=base_url,
                    endpoint=ep,
                    method=method,
                    base_headers=headers,
                    run_id=run_id,
                    target_app="dynamic_target",
                )
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        print(f"[!] CONFIRMED HEADER TAMPERING on {method} {ep}: {f.evidence.response_signal[0]}")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] Header tampering audit error: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} confirmed Routing Integrity / Header Tampering issues!")
    else:
        print("[+] Header tampering audit completed: No unvalidated host reflections or route overrides.")
    return all_findings


def run_resource_exhaustion_audit(
    base_url: str,
    candidate_endpoints: list[tuple[str, str, str]] | None = None,
    auth_token: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
) -> list[Finding]:
    """Audit endpoints for ReDoS and Unrestricted Resource Consumption (API4:2023)."""
    banner("RESOURCE EXHAUSTION & REDOS AUDIT (OWASP API4:2023)")
    fuzzer = ResourceExhaustionFuzzer()
    if not candidate_endpoints:
        print("[i] No parameterized endpoints found in schema; skipping resource exhaustion audit.")
        return []

    candidates = candidate_endpoints
    all_findings: list[Finding] = []
    run_id = f"resource-audit-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": auth_token} if auth_token else {}

    async def _run():
        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=not insecure)
        async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
            for method, ep, param in candidates:
                findings = await fuzzer.test_redos(
                    client=client,
                    base_url=base_url,
                    endpoint=ep,
                    param_name=param,
                    param_location="query" if method == "GET" else "body",
                    method=method,
                    headers=headers,
                    run_id=run_id,
                    target_app="dynamic_target",
                )
                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        print(f"[!] CONFIRMED REDOS on {method} {ep}: {f.evidence.response_signal[0]}")

            for method, ep, _ in candidates:
                if method.upper() in ("POST", "PUT"):
                    finding = await fuzzer.test_body_inflation(
                        client=client,
                        base_url=base_url,
                        endpoint=ep,
                        method=method,
                        headers=headers,
                        run_id=run_id,
                        target_app="dynamic_target",
                    )
                    if finding:
                        all_findings.append(finding)
                        print(f"[!] CONFIRMED JSON BOMB RESOURCE EXHAUSTION on {method} {ep}: {finding.evidence.response_signal[0]}")

    try:
        asyncio.run(_run())
    except Exception as exc:
        print(f"[!] Resource exhaustion audit error: {exc}")

    if all_findings:
        print(f"[!] Detected {len(all_findings)} confirmed Resource Consumption / DoS vulnerabilities!")
    else:
        print("[+] Resource exhaustion audit completed: Target properly limits regex execution and body sizes.")
    return all_findings


def run_graphql_advanced_audit(
    base_url: str,
    endpoint: str = "/graphql",
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    batch_size: int = 20,
    alias_count: int = 100,
) -> list[Finding]:
    """Audit GraphQL endpoint for Query Batching, Alias Overload DoS, and Introspection Exposure (OWASP API4:2023)."""
    banner("GRAPHQL ADVANCED SECURITY AUDIT (QUERY BATCHING & ALIAS DoS)")
    auditor = GraphQLAdvancedAuditor()
    print(f"[i] Testing endpoint: {endpoint} on {base_url}")
    print(f"[i] Probing Query Batching ({batch_size} queries) & Alias Overload ({alias_count} aliases)...")

    run_id = f"gql-adv-audit-{uuid.uuid4().hex[:8]}"
    try:
        res = asyncio.run(
            auditor.audit_endpoint(
                base_url=base_url,
                endpoint=endpoint,
                headers=headers,
                proxy=proxy,
                insecure=insecure,
                run_id=run_id,
                batch_size=batch_size,
                alias_count=alias_count,
            )
        )
        for f in res.findings:
            sig = f.evidence.response_signal[0] if f.evidence.response_signal else "Vulnerability detected"
            print(f"[!] CONFIRMED GRAPHQL VULNERABILITY: {f.attack_type} -> {sig}")
        if not res.findings:
            print("[+] GraphQL advanced audit completed: Query batching is disabled or restricted, and complexity limits are enforced.")
        return res.findings
    except Exception as exc:
        print(f"[!] GraphQL advanced audit error: {exc}")
        return []


def run_dynamic_target(
    *,
    url: str,
    schema: str | None = None,
    postman: str | None = None,
    har: str | None = None,
    auth_token: str | None = None,
    custom_headers: dict[str, str] | None = None,
    protocol: str = "rest",
    endpoint: str = "/graphql",
    payloads: str | None = None,
    target_id: str | None = None,
    name: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    verify_tokens: bool = False,
    verify_callbacks: bool = False,
    verify_concurrency: bool = False,
    verify_pii: bool = False,
    verify_headers: bool = False,
    verify_resources: bool = False,
    verify_graphql_advanced: bool = False,
    proxy_pool: str | None = None,
    auth_automation: dict[str, Any] | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    concurrency_burst: int = 5,
    callback_url: str | None = None,
    callback_poll_url: str | None = None,
    advertised_host: str | None = None,
    targets: TargetManager | None = None,
    save_profile: bool = False,
    safe_staging: bool = False,
) -> int:
    """Dynamically register and run security fuzzing on an ad-hoc target URL."""
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError(f"Invalid base URL: {url} (must include http:// or https:// and host)")

    protocol = protocol.lower().strip()
    if protocol not in {"rest", "graphql"}:
        raise ValueError(f"Protocol must be 'rest' or 'graphql', got '{protocol}'")

    effective_schema = schema or postman or har
    if protocol == "rest" and not effective_schema:
        print(f"\n[i] No schema specified. Starting Auto-Discovery on {url} ...")
        discovery = discover_api(url, proxy=proxy, insecure=insecure, headers=custom_headers)
        if discovery.is_discovered:
            if discovery.protocol == "graphql":
                protocol = "graphql"
                endpoint = discovery.endpoint or "/graphql"
                print(f"[+] AUTO-DISCOVERY: Found GraphQL endpoint: {endpoint}")
            elif discovery.schema_url:
                effective_schema = discovery.schema_url
                if discovery.title and not name:
                    name = f"{discovery.title} ({url})"
                print(f"[+] AUTO-DISCOVERY: Found OpenAPI/Swagger schema: {discovery.schema_url}")
                if discovery.title:
                    print(f"    API Title: {discovery.title} (v{discovery.version or 'unknown'})")
        else:
            raise ValueError(
                f"Auto-Discovery could not find an OpenAPI or GraphQL specification at {url}.\n"
                "Please provide a schema source explicitly using --schema, --postman, or --har."
            )

    if not target_id:
        host = parsed_url.netloc.split(":")[0]
        cleaned = re.sub(r"[^a-z0-9_-]", "_", host.lower()).strip("_")
        target_id = f"target_{cleaned}" if cleaned else "dynamic_target"
    else:
        target_id = re.sub(r"[^a-z0-9_-]", "_", target_id.lower()).strip("_")
        if not target_id:
            target_id = "dynamic_target"

    target_name = name or f"Dynamic target ({url})"

    settings: dict[str, Any] = {"protocol": protocol}
    if proxy:
        settings["proxy"] = proxy
    if insecure:
        settings["insecure"] = True

    resolved_schema = effective_schema
    if protocol == "rest":
        if effective_schema and effective_schema.startswith(("http://", "https://")):
            settings["allow_remote_schema"] = True
        elif effective_schema:
            schema_file = Path(effective_schema)
            candidates = [
                schema_file,
                schema_file.resolve(),
                (PROJECT_ROOT / effective_schema).resolve(),
                (PROJECT_ROOT / "targets" / "schemas" / Path(effective_schema).name).resolve(),
                (PROJECT_ROOT / "targets" / "schemas" / "realworld" / Path(effective_schema).name).resolve(),
            ]
            found_path = None
            for cand in candidates:
                if cand.is_file():
                    found_path = cand
                    break

            if not found_path:
                raise FileNotFoundError(f"Schema file not found: {effective_schema}")
            resolved_schema = str(found_path)
    elif protocol == "graphql":
        ep = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        settings["endpoint"] = ep

    resolved_payloads = payloads
    if payloads:
        cand_payloads = [
            Path(payloads),
            Path(payloads).resolve(),
            (PROJECT_ROOT / payloads).resolve(),
        ]
        found_payload = None
        for cand in cand_payloads:
            if cand.is_file():
                found_payload = cand
                break
        if not found_payload:
            raise FileNotFoundError(f"Payload file not found: {payloads}")
        resolved_payloads = str(found_payload)
        settings["payload_source"] = resolved_payloads

    auth: dict[str, Any] = {}
    if auth_token:
        auth["header"] = normalize_auth_header(auth_token)
    if custom_headers:
        auth["headers"] = dict(custom_headers)
    if safe_staging:
        if "headers" not in auth:
            auth["headers"] = {}
        auth["headers"].update(get_audit_headers())

    session_keeper: SessionKeeper | None = None
    if auth_automation:
        session_keeper = SessionKeeper(auth_automation, base_url=url)
        if not auth_token:
            try:
                tok = asyncio.run(session_keeper.ensure_valid_token(proxy=proxy, insecure=insecure))
                hdr = session_keeper.get_auth_header()
                if hdr:
                    auth_token = hdr
                    auth["header"] = normalize_auth_header(hdr)
                    print("[+] Auth Automation: Successfully initialized session token.")
            except Exception as exc:
                print(f"[!] Auth Automation initial login warning: {exc}")

    rotator: ProxyRotator | None = None
    effective_proxy = proxy
    if proxy_pool:
        rotator = ProxyRotator.from_source(proxy_pool)
        first_proxy = asyncio.run(rotator.get_next_proxy())
        if first_proxy:
            effective_proxy = first_proxy
        print(f"[+] Smart Proxy Pool activated ({rotator.count} proxies). Active: {effective_proxy}")

    auth_manager: AuthManager | None = None
    if client_cert or auth_token:
        auth_cfg = AuthConfig(
            token=auth_token.replace("Bearer ", "").strip() if auth_token and ":" not in auth_token else None,
            client_cert=client_cert,
            client_key=client_key,
        )
        if auth_token:
            auth_manager = AuthManager.from_header_string(auth_token)
            auth_manager.config.client_cert = client_cert
            auth_manager.config.client_key = client_key
        else:
            auth_manager = AuthManager(auth_cfg)

    seed_corpus = None
    if har and Path(har).is_file():
        try:
            seed_corpus = parse_har_file(har)
        except Exception:
            seed_corpus = None

    mgr = targets or TargetManager(PROJECT_ROOT)
    # If target_id collides in manager, give it a unique suffix
    if target_id in mgr.targets:
        target_id = f"{target_id}_{uuid.uuid4().hex[:6]}"

    mgr.add_target(
        target_id,
        name=target_name,
        base_url=url,
        schema_source=resolved_schema,
        auth=auth,
        settings=settings,
    )
    if save_profile:
        saved_path = mgr.save_profile(target_id, overwrite=True)
        print(f"[+] Saved target profile: {saved_path}")

    banner(f"DYNAMIC TARGET FUZZING: {target_name}")
    print(f"[i] Base URL: {url}")
    print(f"[i] Protocol: {protocol}")
    if protocol == "rest":
        print(f"[i] Schema: {resolved_schema}")
    else:
        print(f"[i] GraphQL Endpoint: {settings.get('endpoint')}")
    if auth.get("header"):
        print("[i] Auth: Configured via CLI")
    if client_cert:
        print(f"[i] mTLS Client Cert: {client_cert}")
    if effective_proxy:
        print(f"[i] Upstream Proxy: {effective_proxy}")
    if insecure:
        print("[i] SSL Verify: Disabled (--insecure)")
    if resolved_payloads:
        print(f"[i] Payloads: {resolved_payloads}")
    else:
        print("[i] Payloads: None (Generating cases directly from OpenAPI schema)")
    print(f"[i] Results dir: {RESULTS.results_dir}")

    audit_targets = (
        _extract_audit_targets_from_schema(
            resolved_schema,
            allow_remote=bool(settings.get("allow_remote_schema", False)),
        )
        if protocol == "rest"
        else {"endpoints": [], "callback_params": [], "race_candidates": [], "resource_candidates": []}
    )

    try:
        kwargs: dict[str, Any] = {
            "include_payload": bool(resolved_payloads),
            "targets": mgr,
        }
        if effective_proxy:
            kwargs["proxy"] = effective_proxy
        if insecure:
            kwargs["insecure"] = insecure
        if session_keeper is not None:
            kwargs["session_keeper"] = session_keeper
        if rotator is not None:
            kwargs["proxy_rotator"] = rotator
        if auth_manager is not None and (client_cert or auth_automation):
            kwargs["auth_manager"] = auth_manager
        if seed_corpus is not None:
            kwargs["seed_corpus"] = seed_corpus
        run_target(target_id, **kwargs)

        if verify_tokens and auth_token:
            token_findings = run_token_audit(
                base_url=url,
                auth_token=auth_token,
                endpoints=audit_targets["endpoints"] or None,
                proxy=effective_proxy,
                insecure=insecure,
            )
            if token_findings:
                RESULTS.append_findings(
                    token_findings,
                    source="token_verifier",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_callbacks:
            callback_findings = run_callback_audit(
                base_url=url,
                candidate_params=audit_targets["callback_params"] or None,
                proxy=effective_proxy,
                insecure=insecure,
                external_url=callback_url,
                poll_url=callback_poll_url,
                advertised_host=advertised_host,
            )
            if callback_findings:
                RESULTS.append_findings(
                    callback_findings,
                    source="callback_verifier",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_concurrency:
            race_findings = run_concurrency_audit(
                base_url=url,
                candidate_endpoints=audit_targets["race_candidates"] or None,
                auth_token=auth_token,
                burst_size=concurrency_burst,
                proxy=effective_proxy,
                insecure=insecure,
            )
            if race_findings:
                RESULTS.append_findings(
                    race_findings,
                    source="concurrency_fuzzer",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_pii:
            get_eps = [ep for ep in audit_targets["endpoints"] if ep[0] == "GET"]
            pii_findings = run_pii_audit(
                base_url=url,
                endpoints=get_eps or audit_targets["endpoints"] or None,
                auth_token=auth_token,
                proxy=effective_proxy,
                insecure=insecure,
            )
            if pii_findings:
                RESULTS.append_findings(
                    pii_findings,
                    source="pii_detector",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_headers:
            header_findings = run_header_tamper_audit(
                base_url=url,
                endpoints=audit_targets["endpoints"][:10] or None,
                auth_token=auth_token,
                proxy=effective_proxy,
                insecure=insecure,
            )
            if header_findings:
                RESULTS.append_findings(
                    header_findings,
                    source="header_tamper_fuzzer",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_resources:
            res_findings = run_resource_exhaustion_audit(
                base_url=url,
                candidate_endpoints=audit_targets["resource_candidates"][:10] or None,
                auth_token=auth_token,
                proxy=effective_proxy,
                insecure=insecure,
            )
            if res_findings:
                RESULTS.append_findings(
                    res_findings,
                    source="resource_exhaustion_fuzzer",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        if verify_graphql_advanced or (protocol == "graphql"):
            gql_findings = run_graphql_advanced_audit(
                base_url=url,
                endpoint=settings.get("endpoint", "/graphql"),
                headers={"Authorization": auth_token} if auth_token else {},
                proxy=effective_proxy,
                insecure=insecure,
            )
            if gql_findings:
                RESULTS.append_findings(
                    gql_findings,
                    source="graphql_advanced_auditor",
                    fieldnames=list(Finding.model_fields.keys()),
                )

        banner("FUZZING COMPLETE")

        # Render terminal dashboard and generate HTML report
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_latest_findings()
        reporter.render_terminal_dashboard(findings, target_info={"name": target_name, "url": url})
        html_report = reporter.generate_html_report(findings, target_info={"name": target_name, "url": url})
        print(f"[+] Standalone HTML Report: {html_report}")
        print(f"[+] Latest Report Link:     {RESULTS.results_dir / 'latest_report.html'}")

        manifest_file = RESULTS.results_dir / "cleanup_manifest.json"
        if manifest_file.exists():
            try:
                import json
                m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                tot = m_data.get("total_created_resources", 0)
                if tot > 0:
                    print(f"[🛡️] Staging Safety: Tracked {tot} created resources in {manifest_file.name}")
            except Exception:
                pass
        return 0
    except (FileNotFoundError, KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"\n[X] Dynamic scan failed: {exc}", file=sys.stderr)
        return 1


def run_workflow(
    workflow_source: str | Path | WorkflowDefinition,
    *,
    base_url: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    tokens: dict[str, str] | None = None,
) -> int:
    if isinstance(workflow_source, WorkflowDefinition):
        workflow = workflow_source
        path_label = workflow.name
    else:
        path = Path(workflow_source).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Workflow file not found: {workflow_source}")
        workflow = WorkflowDefinition.from_yaml(path)
        path_label = str(path)

    banner(f"STATEFUL WORKFLOW EXECUTION: {workflow.name}")
    print(f"[i] Workflow Source: {path_label}")
    if base_url:
        print(f"[i] Base URL Override: {base_url}")
    if proxy:
        print(f"[i] Upstream Proxy: {proxy}")
    if insecure:
        print("[i] SSL Verify: Disabled (--insecure)")
    print(f"[i] Total Defined Steps: {len(workflow.steps)}")

    token_dict = tokens if tokens is not None else parse_tokens_env()
    user_tokens = {
        "user1": token_dict.get("FUZZ_AUTH_HEADER") or token_dict.get("AUTH_TOKEN") or "",
        "user2": token_dict.get("FUZZ_AUTH_HEADER_USER2") or token_dict.get("AUTH_TOKEN_USER2") or "",
    }
    for k, v in token_dict.items():
        if k.endswith("_AUTH_HEADER"):
            app = k.replace("_AUTH_HEADER", "").lower()
            user_tokens[app] = v
        elif k.endswith("_AUTH_HEADER_USER2"):
            app = k.replace("_AUTH_HEADER_USER2", "").lower() + "_user2"
            user_tokens[app] = v

    runner = WorkflowRunner(
        base_url=base_url or workflow.base_url,
        proxy=proxy,
        insecure=insecure,
        user_tokens=user_tokens,
    )

    report = asyncio.run(runner.run(workflow))

    print(f"\n[+] Workflow execution completed in {report.duration_ms} ms")
    print(f"    Passed: {report.passed_steps}/{report.total_steps} steps")
    print(f"    Failed: {report.failed_steps}/{report.total_steps} steps")

    for idx, res in enumerate(report.results, start=1):
        status_label = f"HTTP {res.status_code}" if res.status_code else "ERROR"
        mark = "✓" if res.success else "✗"
        print(f"    [{mark}] Step {idx}: {res.step_name} [{res.method} {res.url}] -> {status_label} ({res.elapsed_ms}ms)")
        if res.extracted:
            print(f"        Extracted Context: {res.extracted}")
        if res.error_message:
            print(f"        Failure Reason: {res.error_message}")

    # Record findings if any
    if report.findings:
        banner("WORKFLOW SECURITY FINDINGS DETECTED")
        RESULTS.append_findings(
            report.findings,
            source="workflow_engine",
            fieldnames=list(Finding.model_fields.keys()),
        )
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_latest_findings()
        reporter.render_terminal_dashboard(findings, target_info={"name": workflow.name, "url": str(path)})
        html_report = reporter.generate_html_report(findings, target_info={"name": workflow.name, "url": str(path)})
        print(f"[+] Standalone HTML Report: {html_report}")
        print(f"[+] Latest Report Link:     {RESULTS.results_dir / 'latest_report.html'}")

        manifest_file = RESULTS.results_dir / "cleanup_manifest.json"
        if manifest_file.exists():
            try:
                import json
                m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                tot = m_data.get("total_created_resources", 0)
                if tot > 0:
                    print(f"[🛡️] Staging Safety: Tracked {tot} created resources in {manifest_file.name}")
            except Exception:
                pass

    return 0 if report.success else 1


def run_auto_workflow(
    schema_path: str | Path,
    *,
    base_url: str | None = None,
    proxy: str | None = None,
    insecure: bool = False,
    tokens: dict[str, str] | None = None,
    max_workflows: int = 5,
) -> int:
    """Infer CRUD dependencies from OpenAPI schema, synthesize workflows, and execute BOLA assertions."""
    path = Path(schema_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Schema file for auto-workflow not found: {schema_path}")

    banner("AUTONOMOUS API DEPENDENCY GRAPH & WORKFLOW SYNTHESIS")
    print(f"[i] Analyzing OpenAPI Schema: {path}")
    graph = ApiDependencyGraph.from_file(path)
    print(f"[i] Discovered Resource Producers: {len(graph.producers)}")
    print(f"[i] Discovered Resource Consumers: {len(graph.consumers)}")

    workflows = graph.synthesize_workflows(max_workflows=max_workflows)
    if not workflows:
        print("[!] No matching producer-consumer entity pairings could be inferred automatically.")
        return 0

    print(f"[+] Synthesized {len(workflows)} stateful end-to-end BOLA workflows!")

    all_passed = True
    for idx, wf in enumerate(workflows, start=1):
        print(f"\n--- [Executing Flow {idx}/{len(workflows)}: {wf.name}] ---")
        if base_url:
            wf.base_url = base_url
        exit_code = run_workflow(
            wf,
            base_url=base_url or wf.base_url,
            proxy=proxy,
            insecure=insecure,
            tokens=tokens,
        )
        if exit_code != 0:
            all_passed = False

    return 0 if all_passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run configured or dynamic API security targets")
    parser.add_argument(
        "--target",
        action="append",
        choices=sorted(TARGETS.targets),
        help="Target to run; repeat for multiple targets (default: all configured)",
    )
    # Dynamic target ingestion options
    parser.add_argument("--url", default=None, help="Dynamic target base URL (e.g. https://api.example.com)")
    parser.add_argument("--schema", default=None, help="OpenAPI schema path or URL (required for REST)")
    parser.add_argument("--postman", default=None, help="Path to Postman collection v2.1/v2.0 JSON file")
    parser.add_argument("--har", default=None, help="Path to HTTP Archive (.har) log file")
    parser.add_argument("--workflow", default=None, help="Path to stateful workflow YAML file")
    parser.add_argument("--auto-workflow", default=None, help="OpenAPI schema path to auto-infer and execute stateful workflows")
    parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (default: /graphql)")
    parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    parser.add_argument("--target-id", default=None, help="Identifier for dynamic target")
    parser.add_argument("--name", default=None, help="Display name for dynamic target")
    parser.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--verify-tokens", action="store_true", help="Audit protected endpoints for RFC 7519 Broken Authentication")
    parser.add_argument("--verify-callbacks", action="store_true", help="Audit endpoints for loopback/SSRF callback vulnerabilities")
    parser.add_argument("--verify-concurrency", action="store_true", help="Audit state-changing endpoints for Race Condition (OWASP API4:2023)")
    parser.add_argument("--verify-pii", action="store_true", help="Audit response bodies for PII, tokens, and secret leakage (OWASP API3:2023)")
    parser.add_argument("--verify-headers", action="store_true", help="Audit reverse proxy routing integrity and cache poisoning (OWASP API8:2023)")
    parser.add_argument("--verify-resources", action="store_true", help="Audit endpoints for ReDoS and payload size inflation (OWASP API4:2023)")
    parser.add_argument("--verify-graphql-advanced", action="store_true", help="Audit GraphQL for Query Batching and Field Alias Overload DoS (OWASP API4:2023)")
    parser.add_argument("--proxy-pool", default=None, help="Path to proxy list file or comma-separated proxy URLs")
    parser.add_argument("--login-url", default=None, help="Automated login URL for generic token refreshing")
    parser.add_argument("--login-body", default=None, help="JSON body for automated login request")
    parser.add_argument("--token-extract", default="json:access_token", help="Extraction rule for session token")
    parser.add_argument("--client-cert", default=None, help="Path to mTLS client certificate file")
    parser.add_argument("--client-key", default=None, help="Path to mTLS client private key file")
    parser.add_argument("--concurrency-burst", type=int, default=5, help="Number of synchronized burst requests (default: 5)")
    parser.add_argument("--callback-url", default=None, help="External canary callback URL for OOB SSRF detection")
    parser.add_argument("--poll-url", default=None, help="External Canary API polling endpoint URL (use {token} placeholder)")
    parser.add_argument("--advertised-host", default=None, help="Host/IP advertised to targets for loopback callback (e.g. host.docker.internal)")

    args, unknown = parser.parse_known_args(argv)

    if args.workflow:
        return run_workflow(
            args.workflow,
            base_url=args.url,
            proxy=args.proxy,
            insecure=args.insecure,
        )

    if args.auto_workflow:
        return run_auto_workflow(
            args.auto_workflow,
            base_url=args.url,
            proxy=args.proxy,
            insecure=args.insecure,
        )

    # Dynamic target scan mode:
    if args.url:
        auth_auto_dict = None
        if args.login_url:
            payload_data: dict[str, Any] = {}
            if args.login_body:
                try:
                    payload_data = json.loads(args.login_body)
                except Exception:
                    payload_data = {"data": args.login_body}
            auth_auto_dict = {
                "login_url": args.login_url,
                "payload": payload_data,
                "token_extraction": args.token_extract or "json:access_token",
            }

        return run_dynamic_target(
            url=args.url,
            schema=args.schema,
            postman=args.postman,
            har=args.har,
            auth_token=args.auth_token,
            protocol=args.protocol,
            endpoint=args.endpoint,
            payloads=args.payloads,
            target_id=args.target_id,
            name=args.name,
            proxy=args.proxy,
            insecure=args.insecure,
            verify_tokens=args.verify_tokens,
            verify_callbacks=args.verify_callbacks,
            verify_concurrency=args.verify_concurrency,
            verify_pii=args.verify_pii,
            verify_headers=args.verify_headers,
            verify_resources=args.verify_resources,
            verify_graphql_advanced=args.verify_graphql_advanced,
            proxy_pool=args.proxy_pool,
            auth_automation=auth_auto_dict,
            client_cert=args.client_cert,
            client_key=args.client_key,
            concurrency_burst=args.concurrency_burst,
            callback_url=args.callback_url,
            callback_poll_url=args.poll_url,
            advertised_host=args.advertised_host,
        )

    selected = list(dict.fromkeys(args.target)) if args.target else sorted(TARGETS.targets)
    if not selected:
        print("[i] No saved target profiles found. Run with --url <TARGET_URL> to scan any API dynamically.")
        return 0

    banner("API SECURITY TESTING")
    print(f"[i] Results: {RESULTS.results_dir}")
    if args.proxy:
        print(f"[i] Proxy: {args.proxy}")
    if args.insecure:
        print("[i] SSL Verify: Disabled (--insecure)")
    tokens = parse_tokens_env()
    successful: list[str] = []
    failures: list[tuple[str, str]] = []
    try:
        for target_id in selected:
            try:
                target_kwargs: dict[str, Any] = {"tokens": tokens}
                if args.proxy:
                    target_kwargs["proxy"] = args.proxy
                if args.insecure:
                    target_kwargs["insecure"] = args.insecure
                run_target(target_id, **target_kwargs)
                successful.append(target_id)
            except (FileNotFoundError, KeyError, OSError, RuntimeError, ValueError) as exc:
                print(f"\n[X] Target '{target_id}' failed: {exc}")
                failures.append((target_id, str(exc)))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130

    if failures:
        banner("SECURITY TESTING PARTIAL FAILURE")
        for target_id, reason in failures:
            print(f"[X] Failed: {target_id} ({reason})")
        if successful:
            print(f"[+] Succeeded: {', '.join(successful)}")
        print(f"[+] Findings (if any): {RESULTS.results_dir / 'vulnerabilities.csv'}")
        return 1

    banner("SECURITY TESTING COMPLETE")
    if successful:
        print(f"[+] Succeeded: {', '.join(successful)}")
    print(f"[+] Findings: {RESULTS.results_dir / 'vulnerabilities.csv'}")

    # Render terminal dashboard and generate HTML report for all findings
    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_latest_findings()
    if findings:
        reporter.render_terminal_dashboard(
            findings,
            target_info={"name": "API Security Target Suite", "url": ", ".join(selected)},
        )
        html_report = reporter.generate_html_report(
            findings,
            target_info={"name": "API Security Target Suite", "url": ", ".join(selected)},
        )
        print(f"[+] Standalone HTML Report: {html_report}")
        print(f"[+] Latest Report Link:     {RESULTS.results_dir / 'latest_report.html'}")

        manifest_file = RESULTS.results_dir / "cleanup_manifest.json"
        if manifest_file.exists():
            try:
                import json
                m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                tot = m_data.get("total_created_resources", 0)
                if tot > 0:
                    print(f"[🛡️] Staging Safety: Tracked {tot} created resources in {manifest_file.name}")
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
