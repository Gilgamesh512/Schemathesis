#!/usr/bin/env python3
"""Explicit CLI for lab operations, dynamic target scanning, and universal API security fuzzing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Sequence


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

    return parser


def parse_tokens_env(path: Path = TOKENS_FILE) -> dict[str, str]:
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
        if args.auth_token:
            scan_args.extend(["--auth-token", args.auth_token])
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
