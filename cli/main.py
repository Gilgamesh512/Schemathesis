from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import TargetManager
from modules.security.run_security_tests import parse_tokens_env, run_target


def _select_target(targets: TargetManager) -> str | None:
    profiles = sorted(targets.targets.values(), key=lambda item: item.target_id)
    print("Configured targets:")
    for index, target in enumerate(profiles, start=1):
        protocol = target.settings.get("protocol", "unknown")
        print(f"  {index}. {target.name} ({target.target_id}, {protocol})")
    print("  q. Quit")

    while True:
        answer = input("Select a target: ").strip()
        if answer.lower() in {"q", "quit"}:
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(profiles):
            return profiles[int(answer) - 1].target_id
        if answer in targets.targets:
            return answer
        print("Enter a listed number, target id, or q.")


def _use_payloads(target_id: str, target: TargetManager) -> bool:
    profile = target.get_target(target_id)
    if profile.settings.get("protocol") != "rest":
        return True
    source = profile.settings.get("payload_source")
    configured_path = (
        target.resolve_source(source)
        if isinstance(source, str) and source
        else None
    )
    if configured_path is None or not configured_path.is_file():
        print("No payload file is configured; using schema-generated requests.")
        return False

    while True:
        answer = input(
            "Use configured payload corpus, or generate cases from the schema? "
            "[p/schema] "
        ).strip().lower()
        if answer in {"p", "payload", "payloads"}:
            return True
        if answer in {"", "s", "schema", "openapi"}:
            return False
        print("Enter p to use payloads or schema to use OpenAPI-generated cases.")


def main() -> int:
    targets = TargetManager(PROJECT_ROOT)
    if not targets.targets:
        print("No targets are configured in targets/registry.yaml.", file=sys.stderr)
        return 2

    target_id = _select_target(targets)
    if target_id is None:
        print("Cancelled.")
        return 0

    target = targets.get_target(target_id)
    include_payload = _use_payloads(target_id, targets)
    print(f"\nTarget: {target.name} ({target.base_url})")
    print(f"Protocol: {target.settings.get('protocol', 'unknown')}")
    print(f"Payload mode: {'configured corpus' if include_payload else 'schema-generated'}")
    confirmation = input("Start this test run? [y/N] ").strip().lower()
    if confirmation not in {"y", "yes"}:
        print("Cancelled.")
        return 0

    try:
        run_target(
            target_id,
            include_payload=include_payload,
            tokens=parse_tokens_env(),
        )
    except (FileNotFoundError, KeyError, ValueError, RuntimeError) as exc:
        print(f"Could not start the selected target: {exc}", file=sys.stderr)
        return 1
    return 0
