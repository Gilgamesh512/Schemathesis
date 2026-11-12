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
    CallbackVerifier,
    Finding,
    ProjectPaths,
    ResultManager,
    SecurityReporter,
    TargetManager,
    TokenVerifier,
    WorkflowDefinition,
    WorkflowRunner,
    discover_api,
)


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


def normalize_auth_header(token_or_header: str | None) -> str | None:
    """Normalize raw token or header string into 'Header: Value' format.

    Examples:
        - 'eyJhbGciOi...' -> 'Authorization: Bearer eyJhbGciOi...'
        - 'Bearer eyJhbGci...' -> 'Authorization: Bearer eyJhbGci...'
        - 'Authorization: Bearer ...' -> 'Authorization: Bearer ...'
        - 'X-API-Key: secret' -> 'X-API-Key: secret'
    """
    if not token_or_header:
        return None
    val = token_or_header.strip()
    if not val:
        return None
    if ":" in val:
        return val
    if val.lower().startswith("bearer "):
        return f"Authorization: {val}"
    return f"Authorization: Bearer {val}"


def parse_tokens_env(path: Path = TOKENS_FILE) -> dict[str, str]:
    if not path.exists():
        print(f"[CANH BAO] Khong thay {path} - fuzzing se chay KHONG co auth header.")
        return {}

    tokens: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        tokens[key] = value
    return tokens


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
        print("[INFO] Auth header được truyền qua môi trường của tiến trình.")
    else:
        env.pop("FUZZ_AUTH_HEADER", None)

    result = subprocess.run(command, cwd=PROJECT_ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    print(f"[+] {label}: OK")


def run_target(
    target_id: str,
    *,
    include_payload: bool = True,
    tokens: dict[str, str] | None = None,
    targets: TargetManager = TARGETS,
    proxy: str | None = None,
    insecure: bool = False,
) -> None:
    label, command = build_target_command(
        target_id,
        include_payload=include_payload,
        targets=targets,
        proxy=proxy,
        insecure=insecure,
    )
    extra_env = auth_env_for(target_id, tokens or {}, targets=targets) or {}
    proxy_val = proxy or targets.get_target(target_id).settings.get("proxy")
    if proxy_val:
        extra_env["HTTP_PROXY"] = str(proxy_val)
        extra_env["HTTPS_PROXY"] = str(proxy_val)
    if insecure or targets.get_target(target_id).settings.get("insecure"):
        extra_env["PYTHONHTTPSVERIFY"] = "0"

    run_command(
        f"FUZZING - {label}",
        command,
        extra_env if extra_env else None,
    )


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

    target_eps = endpoints or [
        ("GET", "/"),
        ("GET", "/api/v1/user"),
        ("GET", "/api/v1/profile"),
        ("GET", "/users/v1/_me"),
    ]

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

    candidates = candidate_params or [
        ("POST", "/webhook", "url", "body"),
        ("POST", "/api/v1/subscribe", "callback", "json"),
        ("GET", "/redirect", "url", "query"),
    ]

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
    callback_url: str | None = None,
    callback_poll_url: str | None = None,
    advertised_host: str | None = None,
    targets: TargetManager | None = None,
    save_profile: bool = False,
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
            schema_file = Path(effective_schema).resolve()
            if not schema_file.is_file():
                raise FileNotFoundError(f"Schema file not found: {effective_schema}")
            resolved_schema = str(schema_file)
    elif protocol == "graphql":
        ep = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        settings["endpoint"] = ep

    resolved_payloads = payloads
    if payloads:
        payload_file = Path(payloads).resolve()
        if not payload_file.is_file():
            raise FileNotFoundError(f"Payload file not found: {payloads}")
        resolved_payloads = str(payload_file)
        settings["payload_source"] = resolved_payloads

    auth: dict[str, Any] = {}
    if auth_token:
        auth["header"] = normalize_auth_header(auth_token)
    if custom_headers:
        auth["headers"] = custom_headers

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
    if proxy:
        print(f"[i] Upstream Proxy: {proxy}")
    if insecure:
        print("[i] SSL Verify: Disabled (--insecure)")
    if resolved_payloads:
        print(f"[i] Payloads: {resolved_payloads}")
    else:
        print("[i] Payloads: None (Generating cases directly from OpenAPI schema)")
    print(f"[i] Results dir: {RESULTS.results_dir}")

    try:
        kwargs: dict[str, Any] = {
            "include_payload": bool(resolved_payloads),
            "targets": mgr,
        }
        if proxy:
            kwargs["proxy"] = proxy
        if insecure:
            kwargs["insecure"] = insecure
        run_target(target_id, **kwargs)

        if verify_tokens and auth_token:
            token_findings = run_token_audit(
                base_url=url,
                auth_token=auth_token,
                proxy=proxy,
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
                proxy=proxy,
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

        banner("FUZZING COMPLETE")

        # Render terminal dashboard and generate HTML report
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_latest_findings()
        reporter.render_terminal_dashboard(findings, target_info={"name": target_name, "url": url})
        html_report = reporter.generate_html_report(findings, target_info={"name": target_name, "url": url})
        print(f"[+] Standalone HTML Report: {html_report}")
        print(f"[+] Latest Report Link:     {RESULTS.results_dir / 'latest_report.html'}")
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
    parser.add_argument("--callback-url", default=None, help="External canary callback URL for OOB SSRF detection")
    parser.add_argument("--poll-url", default=None, help="External Canary API polling endpoint URL (use {token} placeholder)")
    parser.add_argument("--advertised-host", default=None, help="Host/IP advertised to targets for loopback callback (e.g. host.docker.internal)")

    args = parser.parse_args(argv)

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
            callback_url=args.callback_url,
            callback_poll_url=args.poll_url,
            advertised_host=args.advertised_host,
        )

    selected = list(dict.fromkeys(args.target)) if args.target else sorted(TARGETS.targets)

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
            target_info={"name": "API Security Lab Suite", "url": ", ".join(selected)},
        )
        html_report = reporter.generate_html_report(
            findings,
            target_info={"name": "API Security Lab Suite", "url": ", ".join(selected)},
        )
        print(f"[+] Standalone HTML Report: {html_report}")
        print(f"[+] Latest Report Link:     {RESULTS.results_dir / 'latest_report.html'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
