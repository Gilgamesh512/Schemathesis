#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import ProjectPaths, ResultManager, SecurityReporter, TargetManager


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

    return {"FUZZ_AUTH_HEADER": value} if value else None


def build_target_command(
    target_id: str,
    *,
    include_payload: bool = True,
    targets: TargetManager = TARGETS,
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
        raise FileNotFoundError(
            f"GraphQL target '{target_id}' requires a payload file; "
            f"configured source: {payload_path or '<not configured>'}"
        )

    results_dir = RESULTS.ensure_results_dir()
    command.extend([
        "--rules", str(RULES),
        "--results-dir", str(results_dir),
        "--concurrency", "3",
    ])
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
) -> None:
    label, command = build_target_command(
        target_id,
        include_payload=include_payload,
        targets=targets,
    )
    run_command(
        f"FUZZING - {label}",
        command,
        auth_env_for(target_id, tokens or {}, targets=targets),
    )


def run_dynamic_target(
    *,
    url: str,
    schema: str | None = None,
    auth_token: str | None = None,
    protocol: str = "rest",
    endpoint: str = "/graphql",
    payloads: str | None = None,
    target_id: str | None = None,
    name: str | None = None,
    targets: TargetManager | None = None,
) -> int:
    """Dynamically register and run security fuzzing on an ad-hoc target URL."""
    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError(f"Invalid base URL: {url} (must include http:// or https:// and host)")

    protocol = protocol.lower().strip()
    if protocol not in {"rest", "graphql"}:
        raise ValueError(f"Protocol must be 'rest' or 'graphql', got '{protocol}'")

    if protocol == "rest" and not schema:
        raise ValueError("REST target requires an OpenAPI schema (--schema <URL or file path>)")

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
    resolved_schema = schema
    if protocol == "rest":
        if schema and schema.startswith(("http://", "https://")):
            settings["allow_remote_schema"] = True
        elif schema:
            schema_file = Path(schema).resolve()
            if not schema_file.is_file():
                raise FileNotFoundError(f"OpenAPI schema file not found: {schema}")
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

    banner(f"DYNAMIC TARGET FUZZING: {target_name}")
    print(f"[i] Base URL: {url}")
    print(f"[i] Protocol: {protocol}")
    if protocol == "rest":
        print(f"[i] Schema: {resolved_schema}")
    else:
        print(f"[i] GraphQL Endpoint: {settings.get('endpoint')}")
    if auth.get("header"):
        print("[i] Auth: Configured via CLI")
    if resolved_payloads:
        print(f"[i] Payloads: {resolved_payloads}")
    else:
        print("[i] Payloads: None (Generating cases directly from OpenAPI schema)")
    print(f"[i] Results dir: {RESULTS.results_dir}")

    try:
        run_target(target_id, include_payload=bool(resolved_payloads), targets=mgr)
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
    parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (default: /graphql)")
    parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    parser.add_argument("--target-id", default=None, help="Identifier for dynamic target")
    parser.add_argument("--name", default=None, help="Display name for dynamic target")

    args = parser.parse_args(argv)

    # Dynamic target scan mode:
    if args.url:
        return run_dynamic_target(
            url=args.url,
            schema=args.schema,
            auth_token=args.auth_token,
            protocol=args.protocol,
            endpoint=args.endpoint,
            payloads=args.payloads,
            target_id=args.target_id,
            name=args.name,
        )

    selected = list(dict.fromkeys(args.target)) if args.target else sorted(TARGETS.targets)

    banner("API SECURITY TESTING")
    print(f"[i] Results: {RESULTS.results_dir}")
    tokens = parse_tokens_env()
    successful: list[str] = []
    failures: list[tuple[str, str]] = []
    try:
        for target_id in selected:
            try:
                run_target(target_id, tokens=tokens)
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
