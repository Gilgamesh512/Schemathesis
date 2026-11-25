#!/usr/bin/env python3
"""Explicit CLI for lab operations, dynamic target scanning, and universal API security fuzzing."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from typing import Sequence
import urllib.error
import urllib.request

try:
    from core import parse_tokens_env as _core_parse_tokens_env
    from core.alerting import send_webhook_alert
except ImportError:
    _core_parse_tokens_env = None  # type: ignore
    send_webhook_alert = None  # type: ignore


ROOT = Path(__file__).resolve().parent


def _get_python_command() -> list[str]:
    try:
        import schemathesis  # noqa: F401
        return [sys.executable]
    except ImportError:
        pass

    venv_py = ROOT / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return [str(venv_py)]

    if sys.platform == "win32":
        try:
            res = subprocess.run(["py", "-3.12", "-c", "import schemathesis"], capture_output=True, check=False)
            if res.returncode == 0:
                return ["py", "-3.12"]
        except Exception:
            pass

    return [sys.executable]


PYTHON_CMD = _get_python_command()
LAB_SCRIPT = ROOT / "lab" / "start_lab.py"
RUN_AUTH = ROOT / "auth" / "run_auth.py"
RUN_DVGA = ROOT / "auth" / "run_dvga.py"
RUN_SECURITY_TESTS = ROOT / "modules" / "security" / "run_security_tests.py"
TOKENS_FILE = ROOT / "tokens.env"
DVGA_SCHEMA = ROOT / "targets" / "schemas" / "dvga" / "dvga_schema.json"


def preflight_check(url: str, proxy: str | None = None, insecure: bool = False, timeout: float = 6.0) -> tuple[bool, str]:
    """Perform a non-invasive pre-flight reachability probe on the target API."""
    try:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        handlers = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)

        req = urllib.request.Request(url, headers={"User-Agent": "Schemathesis-Preflight/2.0"}, method="GET")
        with opener.open(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        # Target answered with HTTP error code (e.g. 401, 403, 404) -> Target is alive and reachable!
        return True, f"HTTP {exc.code} (Reachable)"
    except Exception as exc:
        return False, str(exc)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the local API lab or scan targets dynamically with auto-discovery."
    )
    commands = parser.add_subparsers(dest="command")
    for command, description in (
        ("setup", "Fetch pinned vulnerable applications and create local configuration"),
        ("start", "Start the lab and wait for HTTP health checks"),
        ("check", "Check lab endpoints without starting or modifying services"),
        ("stop", "Stop lab containers without deleting containers or volumes"),
        ("run", "Authenticate, refresh DVGA schema, then run all fuzzers"),
    ):
        commands.add_parser(command, help=description, description=description)

    scan_parser = commands.add_parser(
        "scan",
        help="Scan a remote or local target API dynamically without local Docker setup",
        description="Scan any API target dynamically by specifying --url and optional schema/auth options.",
    )
    scan_parser.add_argument("--url", required=True, help="Base URL of the target API (e.g. http://localhost:8000)")
    scan_parser.add_argument("--schema", default=None, help="OpenAPI schema file path or URL (auto-discovered if omitted)")
    scan_parser.add_argument("--postman", default=None, help="Postman collection JSON file path")
    scan_parser.add_argument("--har", default=None, help="HTTP Archive (.har) log file path")
    scan_parser.add_argument("--workflow", default=None, help="Stateful workflow YAML file path")
    scan_parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    scan_parser.add_argument("--auth-token-file", default=None, help="Path to file containing auth token securely (prevents CLI leaking)")
    scan_parser.add_argument("--auth-token-stdin", action="store_true", help="Read auth token securely from standard input (stdin)")
    scan_parser.add_argument("--client-cert", default=None, help="Path to client certificate file for mTLS")
    scan_parser.add_argument("--client-key", default=None, help="Path to client private key file for mTLS")
    scan_parser.add_argument("--webhook-url", default=None, help="Alert webhook URL (Slack, MS Teams, Discord, or Generic Webhook)")
    scan_parser.add_argument("--no-preflight", action="store_true", help="Skip pre-flight connectivity reachability check")
    scan_parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    scan_parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (if protocol=graphql)")
    scan_parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    scan_parser.add_argument("--target-id", default=None, help="Identifier for this target")
    scan_parser.add_argument("--name", default=None, help="Display name for this target")
    scan_parser.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    scan_parser.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")
    scan_parser.add_argument("--save-profile", action="store_true", help="Save target profile to targets/profiles/ for future one-click scans")
    scan_parser.add_argument("--verify-tokens", action="store_true", help="Audit protected endpoints for RFC 7519 Broken Authentication")
    scan_parser.add_argument("--verify-callbacks", action="store_true", help="Audit endpoints for loopback/SSRF callback vulnerabilities")
    scan_parser.add_argument("--verify-concurrency", action="store_true", help="Audit state-changing endpoints for Race Condition (OWASP API4:2023)")
    scan_parser.add_argument("--verify-pii", action="store_true", help="Audit response bodies for PII and cryptographic secret leakage (OWASP API3:2023)")
    scan_parser.add_argument("--verify-headers", action="store_true", help="Audit reverse proxy routing integrity and cache poisoning (OWASP API8:2023)")
    scan_parser.add_argument("--verify-resources", action="store_true", help="Audit endpoints for ReDoS and payload size inflation (OWASP API4:2023)")
    scan_parser.add_argument("--verify-graphql-advanced", action="store_true", help="Audit GraphQL for Query Batching Attack and Field Alias Overload DoS (OWASP API4:2023)")
    scan_parser.add_argument("--proxy-pool", default=None, help="Path to proxy list file or comma-separated proxies for smart rotation")
    scan_parser.add_argument("--login-url", default=None, help="Automated login URL to fetch and refresh session token dynamically")
    scan_parser.add_argument("--login-body", default=None, help="JSON body for automated login request (e.g. '{\"user\":\"...\",\"pass\":\"...\"}')")
    scan_parser.add_argument("--token-extract", default="json:access_token", help="Extraction rule for session token (default: json:access_token)")
    scan_parser.add_argument("--concurrency-burst", type=int, default=5, help="Number of synchronized burst requests (default: 5)")
    scan_parser.add_argument("--callback-url", default=None, help="External canary callback URL for OOB SSRF detection")
    scan_parser.add_argument("--poll-url", default=None, help="External canary polling API endpoint (use {token} placeholder)")
    scan_parser.add_argument("--advertised-host", default=None, help="Advertised host/IP for container callbacks (e.g. host.docker.internal)")

    wf_parser = commands.add_parser(
        "workflow",
        help="Execute a stateful multi-step API workflow YAML",
        description="Run chained API workflow steps with sequential variable extraction and BOLA verification.",
    )
    wf_parser.add_argument("file", help="Path to workflow YAML file")
    wf_parser.add_argument("--url", default=None, help="Base URL override")
    wf_parser.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL")
    wf_parser.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")

    auto_wf_parser = commands.add_parser(
        "auto-workflow",
        help="Auto-infer and synthesize stateful multi-step BOLA workflows directly from OpenAPI schema",
        description="Automatically inspect OpenAPI spec, pair Producers and Consumers, and execute synthesized workflows.",
    )
    auto_wf_parser.add_argument("schema", nargs="?", default="targets/schemas/vampi/vampi_spec.yaml", help="Path to OpenAPI schema file (JSON/YAML) [default: targets/schemas/vampi/vampi_spec.yaml]")
    auto_wf_parser.add_argument("--url", default="http://127.0.0.1:5002", help="Base URL override [default: http://127.0.0.1:5002]")
    auto_wf_parser.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL")
    auto_wf_parser.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")

    gate_parser = commands.add_parser(
        "gate",
        help="DevSecOps Quality Gate: evaluate SARIF/results and enforce CI/CD policy",
        description="Inspects latest SARIF/vulnerabilities findings and enforces CI/CD quality gate rules.",
    )
    gate_parser.add_argument("--sarif", default=None, help="Path to SARIF report file (default: results/vulnerabilities.sarif)")
    gate_parser.add_argument("--max-critical", type=int, default=0, help="Maximum allowed Critical findings (default: 0)")
    gate_parser.add_argument("--max-high", type=int, default=0, help="Maximum allowed High findings (default: 0)")
    gate_parser.add_argument("--allow-confirmed", action="store_true", help="Do not fail on confirmed exploit findings (default: fails on confirmed)")
    gate_parser.add_argument("--summary-markdown", default=None, help="Output Markdown table summary path (e.g. for $GITHUB_STEP_SUMMARY)")
    gate_parser.add_argument("--webhook-url", default=None, help="Alert webhook URL for Quality Gate status")

    return parser


def parse_tokens_env(path: Path = TOKENS_FILE) -> dict[str, str]:
    if _core_parse_tokens_env is not None:
        return _core_parse_tokens_env(path, auth_headers_only=True, warn_missing=False)
    if not path.exists():
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
        if key.endswith("_AUTH_HEADER"):
            tokens[key] = value
    return tokens


def validate_handoff() -> bool:
    required_tokens = (
        "VAMPI_AUTH_HEADER",
        "CRAPI_AUTH_HEADER",
        "DVGA_AUTH_HEADER",
    )
    tokens = parse_tokens_env()
    valid = True
    for key in required_tokens:
        if tokens.get(key):
            print(f"[+] {key}: READY")
        else:
            print(f"[X] {key}: MISSING")
            valid = False

    try:
        data = json.loads(DVGA_SCHEMA.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[X] DVGA schema is missing: {DVGA_SCHEMA}")
        return False
    except json.JSONDecodeError as exc:
        print(f"[X] Cannot parse DVGA schema {DVGA_SCHEMA}: {exc}")
        return False

    if data.get("target") != "dvga" or data.get("protocol") != "graphql":
        print("[X] DVGA schema metadata is invalid.")
        valid = False
    else:
        print("[+] DVGA schema: READY")
    return valid


def run_script(script: Path, *arguments: str) -> None:
    if not script.is_file():
        raise FileNotFoundError(f"Missing required script: {script}")
    if script == RUN_SECURITY_TESTS:
        from modules.security import run_security_tests as sec_runner

        exit_code = sec_runner.main(list(arguments))
        if exit_code:
            raise RuntimeError(
                f"{script.relative_to(ROOT)} failed with exit code {exit_code}"
            )
        return
    print(f"\n[+] RUNNING: {script.relative_to(ROOT)} {' '.join(arguments)}".rstrip())
    cmd = list(PYTHON_CMD) + [str(script), *arguments]
    result = subprocess.run(cmd, cwd=ROOT, check=False)
    if result.returncode:
        raise RuntimeError(
            f"{script.relative_to(ROOT)} failed with exit code {result.returncode}"
        )


def run_pipeline() -> int:
    print("[i] This explicit command runs authentication, schema discovery, and fuzzing.")
    run_script(LAB_SCRIPT, "start")
    run_script(RUN_AUTH)
    run_script(RUN_DVGA)
    print("\n[+] Validating authentication and schema handoff")
    if not validate_handoff():
        return 1
    run_script(RUN_SECURITY_TESTS)
    print("\n[+] Fuzzing complete. Results are in results/.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2

    if args.command in {"setup", "start", "check", "stop"}:
        try:
            run_script(LAB_SCRIPT, args.command)
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            print(f"[X] Lab command failed: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.command == "workflow":
        wf_args = ["--workflow", args.file]
        if args.url:
            wf_args.extend(["--url", args.url])
        if args.proxy:
            wf_args.extend(["--proxy", args.proxy])
        if args.insecure:
            wf_args.append("--insecure")
        try:
            run_script(RUN_SECURITY_TESTS, *wf_args)
            return 0
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            print(f"[X] Workflow failed: {exc}", file=sys.stderr)
            return 1

    if args.command == "auto-workflow":
        schema_target = args.schema or "targets/schemas/vampi/vampi_spec.yaml"
        url_target = args.url or "http://127.0.0.1:5002"
        auto_args = ["--auto-workflow", schema_target, "--url", url_target]
        if args.proxy:
            auto_args.extend(["--proxy", args.proxy])
        if args.insecure:
            auto_args.append("--insecure")
        try:
            run_script(RUN_SECURITY_TESTS, *auto_args)
            return 0
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            print(f"[X] Auto-workflow synthesis failed: {exc}", file=sys.stderr)
            return 1

    if args.command == "scan":
        # Resolve auth token securely if provided via file or stdin
        effective_token = args.auth_token
        if not effective_token and args.auth_token_file:
            token_p = Path(args.auth_token_file)
            if token_p.is_file():
                effective_token = token_p.read_text(encoding="utf-8").strip()
                print(f"[i] Secure Auth: Loaded token from {token_p}")
            else:
                print(f"[X] Auth token file not found: {token_p}", file=sys.stderr)
                return 1
        elif not effective_token and args.auth_token_stdin:
            print("[i] Secure Auth: Reading auth token from standard input (stdin)...")
            effective_token = sys.stdin.read().strip()

        # Non-invasive pre-flight reachability check
        if not args.no_preflight:
            print(f"[i] Pre-flight: Probing target reachability at {args.url} ...")
            is_alive, msg = preflight_check(args.url, proxy=args.proxy, insecure=args.insecure)
            if is_alive:
                print(f"[+] Pre-flight PASS: Target is reachable ({msg})")
            else:
                print(f"[WARNING] Target pre-flight check failed: {msg}")
                print("[i] If testing an offline/local container, verify it is running or pass --no-preflight.")

        scan_args = [
            "--url", args.url,
            "--protocol", args.protocol,
        ]
        if args.schema:
            scan_args.extend(["--schema", args.schema])
        if args.postman:
            scan_args.extend(["--postman", args.postman])
        if args.har:
            scan_args.extend(["--har", args.har])
        if args.workflow:
            scan_args.extend(["--workflow", args.workflow])
        if effective_token:
            scan_args.extend(["--auth-token", effective_token])
        if args.protocol == "graphql" and args.endpoint:
            scan_args.extend(["--endpoint", args.endpoint])
        if args.payloads:
            scan_args.extend(["--payloads", args.payloads])
        if args.target_id:
            scan_args.extend(["--target-id", args.target_id])
        if args.name:
            scan_args.extend(["--name", args.name])
        if args.proxy:
            scan_args.extend(["--proxy", args.proxy])
        if args.insecure:
            scan_args.append("--insecure")
        if args.save_profile:
            scan_args.append("--save-profile")
        if args.verify_tokens:
            scan_args.append("--verify-tokens")
        if args.verify_callbacks:
            scan_args.append("--verify-callbacks")
        if args.verify_concurrency:
            scan_args.append("--verify-concurrency")
        if args.verify_pii:
            scan_args.append("--verify-pii")
        if args.verify_headers:
            scan_args.append("--verify-headers")
        if args.verify_resources:
            scan_args.append("--verify-resources")
        if args.verify_graphql_advanced:
            scan_args.append("--verify-graphql-advanced")
        if args.proxy_pool:
            scan_args.extend(["--proxy-pool", args.proxy_pool])
        if args.login_url:
            scan_args.extend(["--login-url", args.login_url])
        if args.login_body:
            scan_args.extend(["--login-body", args.login_body])
        if args.token_extract:
            scan_args.extend(["--token-extract", args.token_extract])
        if args.client_cert:
            scan_args.extend(["--client-cert", args.client_cert])
        if args.client_key:
            scan_args.extend(["--client-key", args.client_key])
        if args.concurrency_burst:
            scan_args.extend(["--concurrency-burst", str(args.concurrency_burst)])
        if args.callback_url:
            scan_args.extend(["--callback-url", args.callback_url])
        if args.poll_url:
            scan_args.extend(["--poll-url", args.poll_url])
        if args.advertised_host:
            scan_args.extend(["--advertised-host", args.advertised_host])

        try:
            run_script(RUN_SECURITY_TESTS, *scan_args)
            return 0
        except (FileNotFoundError, OSError, RuntimeError) as exc:
            print(f"[X] Scan failed: {exc}", file=sys.stderr)
            return 1

    if args.command == "gate":
        sarif_file = Path(args.sarif) if args.sarif else (ROOT / "results" / "vulnerabilities.sarif")
        print("\n" + "=" * 70)
        print("  🛡️  DEVSECOPS SECURITY QUALITY GATE EVALUATION  🛡️".center(68))
        print("=" * 70)
        if not sarif_file.exists():
            print(f"[X] SARIF report not found at: {sarif_file}", file=sys.stderr)
            return 1
        try:
            sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
            runs = sarif_data.get("runs", [])
            results = runs[0].get("results", []) if runs else []
        except Exception as exc:
            print(f"[X] Failed to parse SARIF file: {exc}", file=sys.stderr)
            return 1

        crit_count = 0
        high_count = 0
        confirmed_count = 0
        for r in results:
            lvl = r.get("level", "note").lower()
            props = r.get("properties") or {}
            
            # Precise structured verification: use boolean confirmed property
            is_confirmed = bool(props.get("confirmed", False))
            if not is_confirmed:
                msg = r.get("message", {}).get("text", "")
                if "Confirmed: True" in msg or "CONFIRMED: TRUE" in msg:
                    is_confirmed = True

            if is_confirmed:
                confirmed_count += 1
            if lvl == "error":
                crit_count += 1
            elif lvl == "warning":
                high_count += 1

        print(f"[i] Evaluated SARIF Findings: {len(results)} total findings")
        print(f"    - Critical / Errors: {crit_count} (Limit: {args.max_critical})")
        print(f"    - High / Warnings:   {high_count} (Limit: {args.max_high})")
        print(f"    - Confirmed Exploits: {confirmed_count} (Policy: {'Allow' if args.allow_confirmed else 'Reject any'})")

        gate_failed = False
        reasons = []
        if crit_count > args.max_critical:
            reasons.append(f"Critical findings ({crit_count}) exceed threshold ({args.max_critical})")
            gate_failed = True
        if high_count > args.max_high:
            reasons.append(f"High findings ({high_count}) exceed threshold ({args.max_high})")
            gate_failed = True
        if not args.allow_confirmed and confirmed_count > 0:
            reasons.append(f"Confirmed exploit vulnerability detected ({confirmed_count})")
            gate_failed = True

        status_str = "FAILED" if gate_failed else "PASSED"

        # Generate Markdown Summary table
        md_summary = [
            "### 🛡️ DevSecOps Security Quality Gate Summary",
            "",
            f"**Evaluation Status**: {'🚨 **BLOCKED / FAILED**' if gate_failed else '✅ **PASSED / APPROVED**'}",
            "",
            "| Security Metric | Count | Allowed Limit | Gate Policy Result |",
            "| :--- | :---: | :---: | :---: |",
            f"| 🔴 Critical Severity / Errors | **{crit_count}** | Max {args.max_critical} | {'❌ VIOLATION' if crit_count > args.max_critical else '✅ PASSED'} |",
            f"| 🟠 High Severity / Warnings | **{high_count}** | Max {args.max_high} | {'❌ VIOLATION' if high_count > args.max_high else '✅ PASSED'} |",
            f"| 🎯 Confirmed Active Exploits | **{confirmed_count}** | {'Allowed' if args.allow_confirmed else '0 (Zero Tolerance)'} | {'❌ VIOLATION' if not args.allow_confirmed and confirmed_count > 0 else '✅ PASSED'} |",
            f"| 📊 Total Assessed Findings | **{len(results)}** | N/A | Evaluated |",
            "",
        ]
        if gate_failed:
            md_summary.append("#### 🚨 Policy Violation Reasons:")
            for r_reason in reasons:
                md_summary.append(f"- ❌ {r_reason}")
            md_summary.append("")

        md_output_text = "\n".join(md_summary)

        # Write Markdown summary to specified path (e.g. GITHUB_STEP_SUMMARY)
        summary_path = args.summary_markdown or os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                out_p = Path(summary_path)
                out_p.parent.mkdir(parents=True, exist_ok=True)
                with open(out_p, "a", encoding="utf-8") as f_md:
                    f_md.write("\n" + md_output_text + "\n")
                print(f"[+] Security summary written to: {out_p}")
            except Exception as exc:
                print(f"[!] Warning: Could not write summary markdown: {exc}")

        # Send Webhook Alert if configured
        webhook_target = args.webhook_url or os.environ.get("SECURITY_GATE_WEBHOOK_URL")
        if webhook_target and send_webhook_alert:
            alert_sent = send_webhook_alert(
                webhook_url=webhook_target,
                title=f"API Security Gate: {status_str}",
                summary=f"Gate evaluation completed with {status_str}. Total findings: {len(results)}.",
                status=status_str,
                metrics={
                    "critical": crit_count,
                    "high": high_count,
                    "confirmed": confirmed_count,
                    "total": len(results),
                },
            )
            if alert_sent:
                print(f"[+] Webhook alert delivered to: {webhook_target[:35]}...")

        if gate_failed:
            for r_reason in reasons:
                print(f"[✗] QUALITY GATE VIOLATION: {r_reason}!")
            print("\n[🚨] RESULT: PIPELINE FAILED. DEPLOYMENT BLOCKED BY SECURITY POLICY.\n")
            return 1
        else:
            print("\n[✅] RESULT: SECURITY QUALITY GATE PASSED. CODE APPROVED FOR DEPLOYMENT.\n")
            return 0

    try:
        return run_pipeline()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        return 130
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"\n[X] Pipeline failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
