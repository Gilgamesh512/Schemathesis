#!/usr/bin/env python3
"""Explicit CLI for lab operations, dynamic target scanning, and the opt-in fuzzing pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
LAB_SCRIPT = ROOT / "lab" / "start_lab.py"
RUN_AUTH = ROOT / "auth" / "run_auth.py"
RUN_DVGA = ROOT / "auth" / "run_dvga.py"
RUN_SECURITY_TESTS = ROOT / "modules" / "security" / "run_security_tests.py"
TOKENS_FILE = ROOT / "tokens.env"
DVGA_SCHEMA = ROOT / "targets" / "schemas" / "dvga" / "dvga_schema.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the local API lab or scan targets dynamically. Fuzzing only runs with 'run' or 'scan'."
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
        description="Scan any API target dynamically by specifying --url and schema/auth options.",
    )
    scan_parser.add_argument("--url", required=True, help="Base URL of the target API (e.g. http://localhost:8000)")
    scan_parser.add_argument("--schema", default=None, help="OpenAPI schema file path or URL (required for REST)")
    scan_parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    scan_parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    scan_parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (if protocol=graphql)")
    scan_parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    scan_parser.add_argument("--target-id", default=None, help="Identifier for this target")
    scan_parser.add_argument("--name", default=None, help="Display name for this target")

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
    result = subprocess.run([PYTHON, str(script), *arguments], cwd=ROOT, check=False)
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

    if args.command == "scan":
        scan_args = [
            "--url", args.url,
            "--protocol", args.protocol,
        ]
        if args.schema:
            scan_args.extend(["--schema", args.schema])
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
