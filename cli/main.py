from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import TargetManager
from modules.security.run_security_tests import parse_tokens_env, run_target


ADD_TARGET = "__add_target__"


def _select_target(targets: TargetManager) -> str | None:
    profiles = sorted(targets.targets.values(), key=lambda item: item.target_id)
    print("Configured targets:")
    for index, target in enumerate(profiles, start=1):
        protocol = target.settings.get("protocol", "unknown")
        print(f"  {index}. {target.name} ({target.target_id}, {protocol})")
    print(f"  {len(profiles) + 1}. Add a target")
    print("  q. Quit")

    while True:
        answer = input("Select a target: ").strip()
        if answer.lower() in {"q", "quit"}:
            return None
        if answer == str(len(profiles) + 1):
            return ADD_TARGET
        if answer.isdigit() and 1 <= int(answer) <= len(profiles):
            return profiles[int(answer) - 1].target_id
        if answer.lower() in targets.targets:
            return answer.lower()
        print("Enter a listed number, target id, or q.")


def _prompt_required(label: str) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print(f"{label} is required.")


def _register_target(targets: TargetManager) -> str:
    target_id = _prompt_required("Target id (letters, digits, - or _)")
    name = input(f"Display name [{target_id}]: ").strip() or target_id
    base_url = _prompt_required("Target base URL")
    while True:
        protocol = input("Protocol [rest/graphql]: ").strip().lower()
        if protocol in {"rest", "graphql"}:
            break
        print("Protocol must be rest or graphql.")

    schema_source = input(
        "Schema path or HTTP(S) URL"
        + (" (required for REST)" if protocol == "rest" else " (optional for GraphQL)")
        + ": "
    ).strip()
    if protocol == "rest" and not schema_source:
        raise ValueError("REST targets require an OpenAPI schema source")

    settings: dict[str, Any] = {"protocol": protocol}
    parsed_schema = urlparse(schema_source)
    if parsed_schema.scheme in {"http", "https"}:
        if not parsed_schema.netloc:
            raise ValueError("Schema URL must use HTTP or HTTPS and include a host")
        consent = input(
            "Allow this target to fetch its schema URL when run? [y/N] "
        ).strip().lower()
        if consent not in {"y", "yes"}:
            raise ValueError("Remote schema loading was not enabled")
        settings["allow_remote_schema"] = True
    elif "://" in schema_source:
        raise ValueError(f"Unsupported schema URL scheme: {parsed_schema.scheme}")
    elif schema_source:
        schema_path = targets.resolve_source(schema_source)
        if not schema_path.is_file():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")
        schema_source = str(schema_path.relative_to(PROJECT_ROOT))

    payload_source = input(
        "Optional payload corpus path"
        + (" (required for GraphQL)" if protocol == "graphql" else "")
        + ": "
    ).strip()
    if protocol == "graphql" and not payload_source:
        raise ValueError(
            "GraphQL targets need an explicit payload corpus; automatic query generation is not available"
        )
    if payload_source:
        payload_path = targets.resolve_source(payload_source)
        if not payload_path.is_file():
            raise FileNotFoundError(f"Payload file not found: {payload_path}")
        settings["payload_source"] = str(payload_path.relative_to(PROJECT_ROOT))

    if protocol == "graphql":
        endpoint = input("GraphQL endpoint [/graphql]: ").strip() or "/graphql"
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        settings["endpoint"] = endpoint

    auth: dict[str, str] = {}
    auth_choice = input(
        "Authentication [none/header-from-env] (default none): "
    ).strip().lower()
    if auth_choice in {"header-from-env", "env", "header"}:
        token_env = input(
            "Environment variable (or tokens.env key) containing 'Header: value' "
            "(default "
            f"{target_id.upper().replace('-', '_')}_AUTH_HEADER): "
        ).strip() or f"{target_id.upper().replace('-', '_')}_AUTH_HEADER"
        auth["token_env"] = token_env
    elif auth_choice not in {"", "none"}:
        raise ValueError("Authentication must be none or header-from-env")

    target = targets.add_target(
        target_id,
        name=name,
        base_url=base_url,
        schema_source=schema_source or None,
        auth=auth,
        settings=settings,
    )
    profile_path = targets.save_profile(target.target_id)
    print(f"Registered {target.name} in {profile_path}.")
    return target.target_id


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
    target_id = _select_target(targets)
    if target_id is None:
        print("Cancelled.")
        return 0
    if target_id == ADD_TARGET:
        try:
            target_id = _register_target(targets)
        except (FileExistsError, FileNotFoundError, KeyError, ValueError) as exc:
            print(f"Could not register target: {exc}", file=sys.stderr)
            return 1

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
            targets=targets,
        )
    except (FileNotFoundError, KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"Could not start the selected target: {exc}", file=sys.stderr)
        return 1
    return 0
