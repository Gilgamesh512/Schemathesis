#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import ProjectPaths, ResultManager, TargetManager


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
    token_env = target.auth.get("token_env")
    value = None
    if isinstance(token_env, str):
        value = tokens.get(token_env) or os.environ.get(token_env)
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
        if target.settings.get("allow_remote_schema", False):
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run configured API security targets")
    parser.add_argument(
        "--target",
        action="append",
        choices=sorted(TARGETS.targets),
        help="Target to run; repeat for multiple targets (default: all configured)",
    )
    args = parser.parse_args()
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
