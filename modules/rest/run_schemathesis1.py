#!/usr/bin/env python3
"""
run_schemathesis.py
Core REST API Security Fuzzing & Mutation Execution Engine.

Workflow:
  1) Load target OpenAPI specification (or auto-discover).
  2) Generate schema-conforming security mutation probes (UUID, email, URI, boundary) or load external corpus.
  3) Execute baseline and attack requests with adaptive concurrency and backoff.
  4) Analyze responses with FeedbackAnalyzer to detect validation barriers and confirm vulnerabilities.
  5) Persist deduplicated findings across execution lifecycles.
"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import hashlib
import html
import json
import logging
import os
import re
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote, quote_plus, urlparse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import core.schema_validator  # Ensures pure-Python fallback shim is loaded if needed
except Exception as exc:
    logger.debug("Optional schema_validator shim init skipped: %s", exc)

import httpx
import schemathesis
from pydantic import BaseModel, Field, ValidationError

from modules.security import rules_engine
from core import (
    CircuitBreakerTrippedError,
    ConfirmationEngine,
    DetectionResult,
    Evidence,
    Finding,
    LIFECYCLE_RANK,
    Observation,
    RequestScheduler,
    ProjectPaths,
    ResultManager,
    RunState,
    SchemaManager,
    ValidationDecision,
    DEFAULT_ERROR_SIGNALS,
    MAX_ATTEMPTS_PER_FINGERPRINT,
    SEVERITY_BY_STATUS,
    build_curl_command,
    build_finding_from_observations,
    content_hash,
    extract_response_elapsed_ms,
    redact_headers,
    snapshot_response,
    stable_finding_id,
    FeedbackAnalyzer,
    SemanticMutationEngine,
    ParamSchema,
    CleanupTracker,
    get_audit_headers,
    normalize_validation_verdict,
    verify_deep_state_persistence,
)

PROJECT_PATHS = ProjectPaths.from_root(PROJECT_ROOT)
GLOBAL_CLEANUP_TRACKER = CleanupTracker(
    run_id="schemathesis-run",
    out_dir=PROJECT_PATHS.results,
)

# --------------------------------------------------------------------------
# 1. Payload Model
# --------------------------------------------------------------------------

class Payload(BaseModel):
    endpoint: str                     # e.g. "/api/v1/users/{id}"
    method: str                       # GET/POST/PUT/DELETE/PATCH
    target_param: str = ""            # target parameter name (query/path/body field)
    param_location: str = "query"     # "query" | "path" | "body" | "header"
    attack_type: str                  # SQLi, XSS, BOLA, MassAssignment, ...
    payload_value: Any                # actual value injected into the parameter
    owasp_category: Optional[str] = None
    context: Optional[str] = None
    expected_signal: list[str] = Field(default_factory=list)  # expected response indicators
    technology: Optional[dict[str, str]] = None
    mutation_family: Optional[str] = None
    target_app: Optional[str] = None  # Identifier for multi-target tracking


# --------------------------------------------------------------------------
# 2. Evaluation context and run state
# --------------------------------------------------------------------------

# ContextVar so parallel async tasks share the current run_id without plumbing it manually.
STATE_RUN_ID: "contextvars.ContextVar[str]" = contextvars.ContextVar("run_id", default="")


def fingerprint_of(target_app: str, endpoint: str, method: str, param: str,
                   attack_type: str, mutation_family: Optional[str] = None) -> str:
    """Compute a stable fingerprint over (target_app, endpoint, method, param, attack_type).
    target_app is required so identical paths across different targets do not collide."""
    raw = (f"{target_app.lower()}|{method.upper()}|{endpoint}|{param}|"
           f"{attack_type.lower()}|{mutation_family or ''}")
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------
# 4. Load OpenAPI specs and payloads with explicit error diagnostics
# --------------------------------------------------------------------------

def _read_spec_dict(spec_path: str) -> dict:
    """Read an OpenAPI spec into a dict, supporting both JSON and YAML."""
    return SchemaManager(PROJECT_ROOT).load_local(spec_path, allow_outside=True)


def extract_base_url(spec_path: str) -> Optional[str]:
    """Extract base_url from OpenAPI 'servers' or Swagger 2.0 'host'+'basePath'."""
    try:
        raw = _read_spec_dict(spec_path)
    except Exception as exc:
        print(f"[WARNING] Failed to read spec for base_url extraction: {exc}", file=sys.stderr)
        return None
    if not isinstance(raw, dict):
        return None
    servers = raw.get("servers")
    if servers and isinstance(servers, list) and servers[0].get("url"):
        return servers[0]["url"]
    if raw.get("host"):  # Swagger 2.0 style
        scheme = (raw.get("schemes") or ["http"])[0]
        base_path = raw.get("basePath", "")
        return f"{scheme}://{raw['host']}{base_path}"
    return None


def load_schema(
    spec_path: str,
    cli_base_url: Optional[str],
    *,
    allow_remote: bool = False,
):
    schema_manager = SchemaManager(PROJECT_ROOT)
    is_remote = urlparse(spec_path).scheme in {"http", "https"}
    try:
        if is_remote:
            schema_document = schema_manager.load(
                spec_path,
                allow_remote=allow_remote,
            )
            schema = schemathesis.openapi.from_dict(schema_document)
            resolved_spec = spec_path
        else:
            resolved_spec = schema_manager.resolve_local_schema(spec_path, allow_outside=True)
            schema_document = schema_manager.load_local(resolved_spec, allow_outside=True)
            try:
                schema = schemathesis.openapi.from_dict(schema_document)
            except Exception:
                schema = schemathesis.openapi.from_path(str(resolved_spec))
    except Exception as exc:
        print(f"[ERROR] Could not load OpenAPI spec: {spec_path}\n  -> {exc}",
              file=sys.stderr)
        print("  Check: (1) valid OpenAPI 3.0/3.1 (or convertible Swagger 2.0/Postman/HAR), "
              "(2) no circular $ref loops, (3) valid 'servers' or --base-url.",
              file=sys.stderr)
        sys.exit(1)

    base_url = cli_base_url or (
        None if is_remote else extract_base_url(str(resolved_spec))
    )
    if not base_url:
        print("[ERROR] Could not resolve base_url from spec ('servers'/'host'+'basePath'); "
              "re-run with --base-url.",
              file=sys.stderr)
        sys.exit(1)
    # In Schemathesis 4.x, base_url is passed at request construction time (Case.as_transport_kwargs(base_url=...)).
    return schema, base_url


def load_targets(
    targets_arg: str,
    base_urls_arg: Optional[str],
    *,
    allow_remote_schema: bool = False,
) -> dict[str, tuple]:
    """Load multiple OpenAPI specs for multi-target execution.
    --targets 'api1=openapi1.yaml,api2=openapi2.json'
    --base-urls 'api1=http://localhost:8000,api2=http://localhost:8001'
    Returns {target_name: (schema, base_url)}."""
    base_url_overrides: dict[str, str] = {}
    if base_urls_arg:
        for pair in base_urls_arg.split(","):
            name, sep, url = pair.partition("=")
            if not sep:
                print(f"[ERROR] Invalid --base-urls entry '{pair}'. Use 'name=url'.", file=sys.stderr)
                sys.exit(1)
            base_url_overrides[name.strip().lower()] = url.strip()

    targets: dict[str, tuple] = {}
    for pair in targets_arg.split(","):
        name, sep, spec_path = pair.partition("=")
        if not sep:
            print(f"[ERROR] Invalid --targets entry '{pair}'. Use 'name=path', "
                  "e.g. 'api1=openapi.yaml'.", file=sys.stderr)
            sys.exit(1)
        name = name.strip().lower()
        spec_path = spec_path.strip()
        if name in targets:
            print(f"[ERROR] Duplicate target name '{name}' in --targets.", file=sys.stderr)
            sys.exit(1)
        schema, base_url = load_schema(
            spec_path,
            base_url_overrides.get(name),
            allow_remote=allow_remote_schema,
        )
        targets[name] = (schema, base_url)
        print(f"[INFO] Loaded target '{name}': {spec_path} -> base_url={base_url}")

    if not targets:
        print("[ERROR] --targets produced no valid targets.", file=sys.stderr)
        sys.exit(1)
    return targets


_AUTH_ENDPOINT_SEGMENTS = frozenset({
    "login", "signin", "sign-in", "logout", "signout", "token",
    "refresh", "forgot-password", "reset-password", "verify-otp",
})


def _extract_operation_dict(operation: Any) -> dict[str, Any]:
    """Safely extract raw OpenAPI operation dict if available (returns {} on mocks)."""
    definition = getattr(operation, "definition", None)
    raw = getattr(definition, "raw", None)
    if isinstance(raw, dict):
        return raw
    if isinstance(definition, dict):
        return definition
    return {}


def _is_explicit_public_operation(op_raw: dict[str, Any]) -> bool:
    """Return True when OpenAPI operation explicitly sets `security: []`."""
    return "security" in op_raw and op_raw.get("security") == []


def _is_mass_assignment_applicable(operation: Any, op_raw: dict[str, Any]) -> bool:
    """Determine if Mass Assignment injection is applicable to this operation."""
    method = str(getattr(operation, "method", "") or "").upper()
    if method not in ("POST", "PUT", "PATCH"):
        return False

    path_segments = {
        seg.strip().lower()
        for seg in str(getattr(operation, "path", "") or "").split("/")
        if seg.strip()
    }

    body_props: dict[str, Any] = {}
    has_object_body = not op_raw  # Permissive when op_raw is absent (e.g. minimal mocks)
    if op_raw:
        req_body = op_raw.get("requestBody")
        if not isinstance(req_body, dict):
            return False
        content = req_body.get("content")
        if isinstance(content, dict) and content:
            has_object_body = False
            for media_def in content.values():
                if not isinstance(media_def, dict):
                    continue
                sch = media_def.get("schema")
                if not isinstance(sch, dict):
                    continue
                sch_type = str(sch.get("type") or "").lower()
                if sch_type == "object" or isinstance(sch.get("properties"), dict):
                    has_object_body = True
                    if isinstance(sch.get("properties"), dict):
                        body_props.update(sch["properties"])
        elif "requestBody" in op_raw:
            has_object_body = True

    if not has_object_body:
        return False

    if path_segments & _AUTH_ENDPOINT_SEGMENTS:
        # Skip auth/session endpoints unless role/is_admin is explicitly part of body schema
        lower_props = {str(k).lower() for k in body_props}
        if not ({"role", "is_admin"} & lower_props):
            return False

    return True


def schema_payloads(targets: dict[str, tuple], seed_corpus: Any = None) -> list[Payload]:
    """Create built-in schema-conforming security mutation payloads from OpenAPI operations."""
    generated: list[Payload] = []
    import re

    # Auto-load Live Seed Corpus if HAR traffic source is provided
    if seed_corpus is None:
        har_env = os.environ.get("SCHEMATHESIS_SEED_CORPUS")
        if har_env and Path(har_env).is_file():
            try:
                from core import parse_har_file
                seed_corpus = parse_har_file(har_env)
            except Exception as exc:
                logger.warning("Failed to parse HAR seed corpus '%s': %s", har_env, exc)

    for target_name, (schema, _) in sorted(targets.items()):
        for result in schema.get_all_operations():
            if not result.ok():
                continue
            operation = result.ok()
            op_raw = _extract_operation_dict(operation)
            is_explicit_public = _is_explicit_public_operation(op_raw)

            # 1. Baseline case (schema compliance)
            generated.append(Payload(
                endpoint=operation.path,
                method=operation.method,
                target_param="",
                param_location="schema",
                attack_type="schema-generated",
                payload_value=None,
                target_app=target_name,
            ))

            # 2. Schema-Conforming Semantic Mutation Engine for Parameters
            parameters_seen: set[str] = set()
            try:
                for p in operation.iter_parameters():
                    p_name = getattr(p, "name", None)
                    if not p_name or p_name in parameters_seen:
                        continue
                    parameters_seen.add(p_name)
                    loc_raw = getattr(p, "location", "query")
                    loc_val = getattr(loc_raw, "value", loc_raw)
                    loc_str = str(loc_val).lower().strip().split(".")[-1]
                    p_def = getattr(p, "definition", {})

                    param_schema = SemanticMutationEngine.inspect_param(p_name, loc_str, p_def)
                    probes = SemanticMutationEngine.generate_probes(param_schema, seed_corpus=seed_corpus)

                    for probe in probes:
                        if is_explicit_public and probe.attack_type.upper() in ("BOLA", "IDOR"):
                            continue
                        generated.append(Payload(
                            endpoint=operation.path,
                            method=operation.method,
                            target_param=p_name,
                            param_location=loc_str,
                            attack_type=probe.attack_type,
                            payload_value=probe.payload_value,
                            owasp_category=probe.owasp_category,
                            expected_signal=probe.expected_signal,
                            context="schema_conformant",
                            target_app=target_name,
                        ))
            except Exception as exc:
                logger.warning("Parameter inspection failed on %s %s: %s", operation.method, operation.path, exc)

            # Fallback path params if iter_parameters did not catch all path templates
            path_params = re.findall(r"\{([^}]+)\}", operation.path)
            for p_name in path_params:
                if p_name in parameters_seen:
                    continue
                parameters_seen.add(p_name)
                param_schema = SemanticMutationEngine.inspect_param(p_name, "path", {})
                probes = SemanticMutationEngine.generate_probes(param_schema, seed_corpus=seed_corpus)
                for probe in probes:
                    if is_explicit_public and probe.attack_type.upper() in ("BOLA", "IDOR"):
                        continue
                    generated.append(Payload(
                        endpoint=operation.path,
                        method=operation.method,
                        target_param=p_name,
                        param_location="path",
                        attack_type=probe.attack_type,
                        payload_value=probe.payload_value,
                        owasp_category=probe.owasp_category,
                        expected_signal=probe.expected_signal,
                        context="schema_conformant",
                        target_app=target_name,
                    ))

            # 3. Built-in Mass Assignment & Schema Property Injection for applicable state-changing endpoints
            if _is_mass_assignment_applicable(operation, op_raw):
                generated.append(Payload(
                    endpoint=operation.path,
                    method=operation.method,
                    target_param="role",
                    param_location="body",
                    attack_type="MASS_ASSIGNMENT",
                    payload_value="admin",
                    owasp_category="API3:2023",
                    expected_signal=[],
                    context="schema_conformant",
                    target_app=target_name,
                ))
                generated.append(Payload(
                    endpoint=operation.path,
                    method=operation.method,
                    target_param="is_admin",
                    param_location="body",
                    attack_type="MASS_ASSIGNMENT",
                    payload_value=True,
                    owasp_category="API3:2023",
                    expected_signal=[],
                    context="schema_conformant",
                    target_app=target_name,
                ))
    if not generated:
        raise ValueError("No usable operations were found in the selected OpenAPI schema(s)")
    return generated


def load_payloads(payload_path: str) -> list[Payload]:
    path = PROJECT_PATHS.resolve(payload_path, allow_outside=True)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = raw.get("payloads", [raw])

    valid: list[Payload] = []
    for i, item in enumerate(raw):
        try:
            valid.append(Payload(**item))
        except ValidationError as exc:
            # Skip malformed items rather than aborting the entire batch
            print(f"[WARNING] Payload #{i} failed schema validation, skipping:\n{exc}",
                  file=sys.stderr)
    if not valid:
        print("[ERROR] No valid payloads found in payload corpus.", file=sys.stderr)
        sys.exit(1)
    return valid


# --------------------------------------------------------------------------
# 5. Match payloads to OpenAPI operations and build Schemathesis cases
# --------------------------------------------------------------------------

def find_operation(schema, endpoint: str, method: str):
    """Find an operation matching endpoint+method in a schema (with loose path-prefix fallback)."""
    for result in schema.get_all_operations():
        if result.ok():
            op = result.ok()
            if op.method.upper() == method.upper() and op.path == endpoint:
                return op
    norm = lambda p: p.split("{")[0].rstrip("/")
    for result in schema.get_all_operations():
        if result.ok():
            op = result.ok()
            if op.method.upper() == method.upper() and norm(op.path) == norm(endpoint):
                return op
    return None


def find_operation_multi(targets: dict[str, tuple], payload: "Payload"):
    """Resolve which loaded target owns a payload in multi-target mode."""
    if payload.target_app:
        name = payload.target_app.strip().lower()
        if name not in targets:
            print(f"[WARNING] Payload target_app='{payload.target_app}' is not in "
                  f"--targets ({sorted(targets)}) - skipping.",
                  file=sys.stderr)
            return None
        schema, base_url = targets[name]
        op = find_operation(schema, payload.endpoint, payload.method)
        if op is None:
            return None
        return name, schema, base_url, op

    candidates = []
    for name, (schema, base_url) in targets.items():
        op = find_operation(schema, payload.endpoint, payload.method)
        if op is not None:
            candidates.append((name, schema, base_url, op))

    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    if len(candidates) > 1:
        names = [c[0] for c in candidates]
        print(f"[WARNING] Endpoint '{payload.method} {payload.endpoint}' matches "
              f"multiple targets: {names}. Specify 'target_app' in payload to disambiguate; skipping.",
              file=sys.stderr)
        return None
    return candidates[0]


def _normalize_location(loc: Any) -> str:
    if hasattr(loc, "value"):
        loc = loc.value
    s = str(loc or "query").lower().strip()
    return s.split(".")[-1]


def _baseline_component(baseline_case, name: str):
    if baseline_case is None:
        return None
    value = getattr(baseline_case, name, None)
    if value is not None:
        if type(value).__name__ == "NotSet" or getattr(value, "__class__", None).__name__ == "NotSet":
            return None
        if isinstance(value, dict):
            return value.copy()
        elif isinstance(value, list):
            return list(value)
        return value
    return None


def build_case(schema, op, payload: Payload, baseline_case=None):
    kwargs: dict[str, Any] = {"operation": op, "method": op.method, "path": op.path}
    loc = _normalize_location(payload.param_location)

    if loc == "path":
        values = _default_path_parameters(op)
        base_pp = _baseline_component(baseline_case, "path_parameters")
        if isinstance(base_pp, dict):
            values.update({k: v for k, v in base_pp.items() if v not in (None, "")})
        values[payload.target_param] = payload.payload_value
        kwargs["path_parameters"] = values
    else:
        default_pp = _default_path_parameters(op)
        base_pp = _baseline_component(baseline_case, "path_parameters")
        if isinstance(base_pp, dict):
            default_pp.update({k: v for k, v in base_pp.items() if v not in (None, "")})
        if default_pp:
            kwargs["path_parameters"] = default_pp

        if loc == "query":
            values = _baseline_component(baseline_case, "query")
            if not isinstance(values, dict):
                values = {}
            values[payload.target_param] = payload.payload_value
            kwargs["query"] = values
        elif loc in ("header", "headers"):
            values = _baseline_component(baseline_case, "headers")
            if not isinstance(values, dict):
                values = {}
            values[payload.target_param] = str(payload.payload_value)
            kwargs["headers"] = values
        elif loc == "body":
            values = _baseline_component(baseline_case, "body")
            if not isinstance(values, dict):
                values = {}
            values[payload.target_param] = payload.payload_value
            kwargs["body"] = values
        elif loc in ("cookie", "cookies"):
            values = _baseline_component(baseline_case, "cookies")
            if not isinstance(values, dict):
                values = {}
            values[payload.target_param] = str(payload.payload_value)
            kwargs["cookies"] = values
        else:
            raise ValueError(f"Unsupported param_location: {payload.param_location}")
    try:
        return schema.make_case(**kwargs)
    except Exception as exc:
        if "media type" in str(exc).lower() and "media_type" not in kwargs:
            kwargs["media_type"] = "application/json"
            return schema.make_case(**kwargs)
        raise


def _default_path_parameters(op) -> dict[str, Any]:
    """Build schema-valid path parameters for every {param} template in op.path."""
    import re as _re

    template_params = _re.findall(r"\{([^}]+)\}", getattr(op, "path", "") or "")
    if not template_params:
        return {}

    param_defs: dict[str, dict[str, Any]] = {}
    iter_params = getattr(op, "iter_parameters", None)
    if callable(iter_params):
        try:
            for p in iter_params():
                p_name = getattr(p, "name", None)
                if p_name:
                    raw_def = getattr(p, "definition", {})
                    if isinstance(raw_def, dict):
                        param_defs[p_name] = raw_def.get("schema", raw_def)
        except Exception:
            pass

    defaults: dict[str, Any] = {}
    for p_name in template_params:
        p_schema = param_defs.get(p_name, {"type": "string"})
        sample = SemanticMutationEngine.generate_schema_valid_sample(p_schema)
        if sample in ("sample_text", "", None):
            sample = "1"
        defaults[p_name] = sample
    return defaults


def build_baseline_case(schema, op):
    """Generate a valid ordinary case from the operation schema."""
    case = None
    strategy = getattr(op, "as_strategy", None)
    if callable(strategy):
        try:
            case = strategy().example()
        except Exception as exc:
            logger.debug("Hypothesis strategy.example() failed on %s %s; falling back to make_case: %s", op.method, op.path, exc)

    expected_path_params = _default_path_parameters(op)
    if case is not None and expected_path_params:
        existing_pp = _baseline_component(case, "path_parameters")
        if not isinstance(existing_pp, dict) or any(
            k not in existing_pp or existing_pp[k] in (None, "")
            for k in expected_path_params
        ):
            merged_pp = dict(expected_path_params)
            if isinstance(existing_pp, dict):
                for k, v in existing_pp.items():
                    if v not in (None, ""):
                        merged_pp[k] = v
            kwargs: dict[str, Any] = {
                "operation": op,
                "method": op.method,
                "path": op.path,
                "path_parameters": merged_pp,
            }
            for comp_src, comp_dst in (("query", "query"), ("headers", "headers"), ("cookies", "cookies"), ("body", "body")):
                val = _baseline_component(case, comp_src)
                if val is not None:
                    kwargs[comp_dst] = val
            return schema.make_case(**kwargs)

    if case is not None:
        return case

    kwargs = {"operation": op, "method": op.method, "path": op.path}
    if expected_path_params:
        kwargs["path_parameters"] = expected_path_params
    return schema.make_case(**kwargs)


class PreparedCase:
    """Resolved payload bound to its target, base_url, baseline Case, and attack Case."""
    __slots__ = ("fingerprint", "target_app", "base_url", "baseline_case", "case", "payload", "schema", "operation")

    def __init__(self, fingerprint, target_app, base_url, baseline_case, case, payload, schema=None, operation=None):
        self.fingerprint = fingerprint
        self.target_app = target_app
        self.base_url = base_url
        self.baseline_case = baseline_case
        self.case = case
        self.payload = payload
        self.schema = schema
        self.operation = operation


def prepare_cases(payloads: list[Payload], targets: dict[str, tuple]) -> list[PreparedCase]:
    prepared: list[PreparedCase] = []
    for payload in payloads:
        match = find_operation_multi(targets, payload)
        if match is None:
            print(f"[WARNING] Endpoint '{payload.method} {payload.endpoint}' "
                  f"not found in any loaded target ({sorted(targets)}) - skipping.",
                  file=sys.stderr)
            continue
        name, schema, base_url, op = match
        if payload.param_location == "schema":
            try:
                case = build_baseline_case(schema, op)
            except Exception as exc:
                print(f"[WARNING] Could not build schema case for {payload.endpoint} "
                      f"(target={name}): {exc}", file=sys.stderr)
                continue
            fp = fingerprint_of(
                name, payload.endpoint, payload.method, "",
                payload.attack_type, payload.mutation_family,
            )
            prepared.append(PreparedCase(fp, name, base_url, None, case, payload, schema=schema, operation=op))
            continue

        baseline_case = None
        try:
            baseline_case = build_baseline_case(schema, op)
        except Exception as exc:
            print(f"[WARNING] Could not build baseline case for {payload.endpoint} "
                  f"(target={name}); finding will not auto-confirm: {exc}",
                  file=sys.stderr)
        try:
            case = build_case(schema, op, payload, baseline_case)
        except Exception as exc:
            if baseline_case is not None:
                try:
                    case = build_case(schema, op, payload)
                    baseline_case = None
                except Exception:
                    print(f"[WARNING] Could not build attack case for {payload.endpoint} "
                          f"(target={name}): {exc}", file=sys.stderr)
                    continue
            else:
                print(f"[WARNING] Could not build attack case for {payload.endpoint} "
                      f"(target={name}): {exc}", file=sys.stderr)
                continue
        fp = fingerprint_of(name, payload.endpoint, payload.method,
                             payload.target_param, payload.attack_type,
                             payload.mutation_family)
        prepared.append(PreparedCase(fp, name, base_url, baseline_case, case, payload, schema=schema, operation=op))
    return prepared


_GENERIC_NON_EVIDENCE_TOKENS = frozenset({
    "admin", "administrator", "author", "boolean", "content", "created_at",
    "data", "deleted", "email", "error", "errors", "exception", "false",
    "id", "ids", "info", "invalid", "item", "items", "message", "name",
    "negative", "null", "ok", "overflow", "password", "product", "products",
    "required", "role", "roles", "status", "string", "success", "title",
    "token", "true", "unhandled", "user", "username", "users", "value",
})


def _is_generic_or_low_entropy_signal(signal: str) -> bool:
    """Return True if a signal is too generic or low-entropy to stand alone as evidence."""
    norm = signal.strip().lower()
    if not norm or len(norm) <= 2:
        return True
    if norm in _GENERIC_NON_EVIDENCE_TOKENS:
        return True
    if norm.isdigit() and len(norm) <= 3:
        return True
    return False


_MIN_REFLECTION_PAYLOAD_LEN = 4
_TRIVIAL_REFLECTION_TOKENS = frozenset({"true", "false", "null", "none"})


def _build_reflection_variants(payload_value: Any) -> list[str]:
    """Return lowercased deterministic payload encodings for reflection-span matching.

    Only non-trivial string payloads (len >= 4 after strip, excluding boolean/null
    literals) are eligible so numeric/boolean/short values never mask response text.
    """
    if not isinstance(payload_value, str):
        return []
    stripped = payload_value.strip()
    if len(stripped) < _MIN_REFLECTION_PAYLOAD_LEN or stripped.lower() in _TRIVIAL_REFLECTION_TOKENS:
        return []

    raw_variants: list[str] = [payload_value]
    try:
        json_utf8 = json.dumps(payload_value, ensure_ascii=False)[1:-1]
        json_ascii = json.dumps(payload_value, ensure_ascii=True)[1:-1]
        raw_variants.extend((json_utf8, json_ascii, json_utf8.replace("/", r"\/")))
        # HTML-safe JSON escaping used by some serializers (\u003c, \u003e, \u0026, \u0027)
        if any(ch in payload_value for ch in "<>&'"):
            raw_variants.append(
                json_utf8.replace("<", r"\u003c")
                .replace(">", r"\u003e")
                .replace("&", r"\u0026")
                .replace("'", r"\u0027")
            )
    except (TypeError, ValueError):
        pass

    raw_variants.extend((
        quote(payload_value, safe=""),
        quote_plus(payload_value),
        quote(payload_value, safe="/:"),
        quote(payload_value, safe=":"),
    ))

    html_quoted = html.escape(payload_value, quote=True)
    html_unquoted = html.escape(payload_value, quote=False)
    raw_variants.extend((html_quoted, html_unquoted))
    if "'" in payload_value:
        raw_variants.append(html_quoted.replace("&#x27;", "&#39;"))

    deduped: list[str] = []
    seen: set[str] = set()
    for item in raw_variants:
        lowered = item.lower()
        if len(lowered.strip()) >= _MIN_REFLECTION_PAYLOAD_LEN and lowered not in seen:
            seen.add(lowered)
            deduped.append(lowered)
    return deduped


def _find_reflected_spans(body_lower: str, payload_value: Any) -> list[tuple[int, int]]:
    """Locate sorted, merged [start, end) intervals where *payload_value* is reflected."""
    if not body_lower:
        return []
    variants = _build_reflection_variants(payload_value)
    if not variants:
        return []

    spans: list[tuple[int, int]] = []
    for variant in variants:
        v_len = len(variant)
        pos = 0
        while True:
            idx = body_lower.find(variant, pos)
            if idx == -1:
                break
            spans.append((idx, idx + v_len))
            pos = idx + v_len

    if not spans:
        return []

    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for start, end in spans[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            if end > prev_end:
                merged[-1] = (prev_start, end)
        else:
            merged.append((start, end))
    return merged


def _classify_signal_against_spans(
    body_lower: str,
    signal: str,
    reflected_spans: list[tuple[int, int]],
) -> tuple[bool, bool]:
    """Return ``(has_independent_occurrence, has_reflected_occurrence)`` for *signal*."""
    if not body_lower or not signal:
        return False, False
    if not reflected_spans:
        return (signal in body_lower), False

    sig_len = len(signal)
    pos = 0
    has_independent = False
    has_reflected = False
    while True:
        idx = body_lower.find(signal, pos)
        if idx == -1:
            break
        occ_end = idx + sig_len
        inside = any(span_start <= idx and occ_end <= span_end for span_start, span_end in reflected_spans)
        if inside:
            has_reflected = True
        else:
            has_independent = True
            if has_reflected:
                break
        pos = idx + 1
    return has_independent, has_reflected


_MIME_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_HTML_STRUCTURE_RE = re.compile(r"<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]", re.IGNORECASE)
_HTML_TAG_PAIR_RE = re.compile(
    r"<(div|span|p|a|form|input|table|ul|ol|li|h[1-6]|title|meta|section|article|"
    r"main|header|footer|button|label|select|textarea|iframe|svg|img)\b",
    re.IGNORECASE,
)
_UNENCODED_HTML_MARKUP_RE = re.compile(r"<(?:[a-z!/])", re.IGNORECASE)
_SCRIPT_OPEN_RE = re.compile(r"<script(?:\s[^>]*)?>", re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)
_EVENT_OR_URI_ATTR_RE = re.compile(r"(?:on[a-z]+\s*=|javascript:|vbscript:|data\s*:\s*text/html)", re.IGNORECASE)
_URI_ATTR_NAME_RE = re.compile(r"(?:^|[\s<])(href|src|action|formaction|data|poster|cite)\s*=\s*['\"]?$", re.IGNORECASE)


def _parse_content_type(headers: Any) -> tuple[str, str]:
    """Parse Content-Type into ``(normalized_media_type, category)``."""
    raw_ct = ""
    if headers:
        try:
            for k, v in headers.items():
                if str(k).strip().lower() == "content-type":
                    raw_ct = str(v or "")
                    break
        except AttributeError:
            raw_ct = ""

    if not raw_ct.strip():
        return "", "missing"

    essence = raw_ct.split(";", 1)[0].strip().lower()
    if not essence or not _MIME_TYPE_RE.match(essence):
        return essence or raw_ct.strip().lower(), "malformed"

    if essence in ("text/html", "application/xhtml+xml"):
        return essence, "html"
    if essence in ("application/json", "text/json") or (
        essence.startswith("application/") and essence.endswith("+json")
    ):
        return essence, "json"
    return essence, "other"


def _inspect_xss_body_shape(body_text: str) -> tuple[bool, bool]:
    """Return ``(looks_like_json, looks_like_html)`` without trusting a single marker."""
    stripped = (body_text or "").strip()
    if not stripped:
        return False, False

    looks_like_json = False
    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        try:
            parsed = json.loads(stripped)
            looks_like_json = isinstance(parsed, (dict, list))
        except Exception:
            looks_like_json = False

    if looks_like_json:
        return True, False

    if _HTML_STRUCTURE_RE.search(stripped):
        return False, True
    distinct_tags = {m.lower() for m in _HTML_TAG_PAIR_RE.findall(stripped)}
    return False, len(distinct_tags) >= 2


def _find_html_escaped_spans(body_lower: str, payload_value: Any) -> list[tuple[int, int]]:
    """Locate spans in *body_lower* where *payload_value* appears HTML/JSON-escaped."""
    if not body_lower or not isinstance(payload_value, str):
        return []
    stripped = payload_value.strip()
    if len(stripped) < _MIN_REFLECTION_PAYLOAD_LEN:
        return []

    raw_lower = payload_value.lower()
    escaped_variants: list[str] = []
    for candidate in (
        html.escape(payload_value, quote=True),
        html.escape(payload_value, quote=False),
        html.escape(payload_value, quote=True).replace("&#x27;", "&#39;"),
    ):
        low = candidate.lower()
        if low != raw_lower and low not in escaped_variants:
            escaped_variants.append(low)

    try:
        json_utf8 = json.dumps(payload_value, ensure_ascii=False)[1:-1]
        if any(ch in payload_value for ch in "<>&'"):
            html_safe_json = (
                json_utf8.replace("<", r"\u003c")
                .replace(">", r"\u003e")
                .replace("&", r"\u0026")
                .replace("'", r"\u0027")
            ).lower()
            if html_safe_json != raw_lower and html_safe_json not in escaped_variants:
                escaped_variants.append(html_safe_json)
    except (TypeError, ValueError):
        pass

    spans: list[tuple[int, int]] = []
    for variant in escaped_variants:
        v_len = len(variant)
        pos = 0
        while True:
            idx = body_lower.find(variant, pos)
            if idx == -1:
                break
            spans.append((idx, idx + v_len))
            pos = idx + v_len

    if not spans:
        return []
    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for start, end in spans[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            if end > prev_end:
                merged[-1] = (prev_start, end)
        else:
            merged.append((start, end))
    return merged


def _classify_html_offset(body_lower: str, idx: int, matched_text: str) -> tuple[str, bool, str]:
    """Classify an unencoded reflection at *idx* inside an HTML response."""
    prefix = body_lower[:idx]

    last_comment_open = prefix.rfind("<!--")
    last_comment_close = prefix.rfind("-->")
    if last_comment_open > last_comment_close:
        if "-->" in matched_text:
            return "html_text", True, "unencoded HTML comment breakout in HTML response"
        return "html_comment", False, "reflection inside HTML comment without unencoded breakout"

    last_script_open_end = -1
    for m in _SCRIPT_OPEN_RE.finditer(prefix):
        last_script_open_end = m.end()
    last_script_close = -1
    for m in _SCRIPT_CLOSE_RE.finditer(prefix):
        last_script_close = m.start()

    if last_script_open_end > last_script_close:
        if any(ch in matched_text for ch in ("'", '"', ";", "(", ")", "<", ">", "`")):
            return "html_js_context", True, "unencoded reflection with JS syntax inside <script> context"
        return "html_js_context_inert", False, "reflection inside <script> block without JS breakout characters"

    last_lt = prefix.rfind("<")
    last_gt = prefix.rfind(">")
    if last_lt > last_gt:
        tag_fragment = prefix[last_lt:]
        eq_pos = tag_fragment.rfind("=")
        if eq_pos != -1:
            after_eq = tag_fragment[eq_pos + 1:].lstrip()
            quote_char = after_eq[0] if after_eq[:1] in ('"', "'") else ""
            if quote_char and quote_char in after_eq[1:]:
                quote_char = ""
            is_uri_attr = bool(_URI_ATTR_NAME_RE.search(tag_fragment[:eq_pos + 1]))
            has_uri_scheme = is_uri_attr and bool(
                re.search(r"^\s*(?:javascript|vbscript|data\s*:\s*text/html)\s*:", matched_text, re.IGNORECASE)
            )
            if quote_char:
                has_breakout = quote_char in matched_text
            else:
                has_breakout = any(ch.isspace() or ch in ("<", ">", "/") for ch in matched_text) or bool(
                    _EVENT_OR_URI_ATTR_RE.search(matched_text)
                )
            if has_breakout or has_uri_scheme:
                return "html_attribute", True, "unencoded reflection in HTML attribute context"
            return (
                "html_attribute_quoted",
                False,
                "reflection enclosed inside quoted HTML attribute without unencoded breakout characters",
            )

        if _EVENT_OR_URI_ATTR_RE.search(matched_text) or "<" in matched_text or ">" in matched_text:
            return "html_attribute", True, "unencoded reflection inside HTML tag structure"
        return "unknown", False, "reflection inside HTML tag without clear attribute context"

    if _UNENCODED_HTML_MARKUP_RE.search(matched_text):
        return "html_text", True, "unencoded HTML markup reflected in HTML text context"
    return "html_text_plain", False, "plain text reflection in HTML body without executable HTML markup"


def _is_xss_payload_signal(sig: str, payload_value: Any) -> bool:
    """Return True when *sig* corresponds to reflected *payload_value* rather than independent backend data."""
    if not isinstance(payload_value, str):
        return False
    low_payload = payload_value.lower()
    if sig in low_payload:
        return True
    for esc in (
        html.escape(payload_value, quote=True).lower(),
        html.escape(payload_value, quote=False).lower(),
    ):
        if sig in esc:
            return True
    return False


def _evaluate_xss_response_context(
    headers: Any,
    body_text: str,
    body_lower: str,
    payload_value: Any,
    sig: str,
) -> tuple[str, bool, str, str, Optional[str]]:
    """Classify XSS execution context for a reflected signal *sig*.

    Returns ``(xss_context, executable_candidate, detail_reason, media_type, mismatch)``.
    """
    media_type, header_kind = _parse_content_type(headers)
    looks_like_json, looks_like_html = _inspect_xss_body_shape(body_text)

    if header_kind == "json":
        if not looks_like_json and looks_like_html:
            return (
                "mismatch",
                False,
                f"Content-Type '{media_type}' mismatches HTML-like body; ambiguous execution context",
                media_type,
                "json_header_html_body",
            )
        return (
            "json_reflection",
            False,
            f"XSS payload reflected inside JSON response ({media_type}) — not an executable HTML context",
            media_type,
            None,
        )

    if header_kind == "html":
        if looks_like_json:
            return (
                "mismatch",
                False,
                f"Content-Type '{media_type}' mismatches JSON response body; ambiguous execution context",
                media_type,
                "html_header_json_body",
            )

        escaped_spans = _find_html_escaped_spans(body_lower, payload_value)
        sig_len = len(sig)
        pos = 0
        saw_escaped = False
        best_non_exec: Optional[tuple[str, str]] = None

        while True:
            idx = body_lower.find(sig, pos)
            if idx == -1:
                break
            occ_end = idx + sig_len
            if any(s_start <= idx and occ_end <= s_end for s_start, s_end in escaped_spans):
                saw_escaped = True
                pos = idx + 1
                continue
            ctx, is_exec, ctx_reason = _classify_html_offset(body_lower, idx, body_lower[idx:occ_end])
            if is_exec:
                return ctx, True, ctx_reason, media_type, None
            if best_non_exec is None:
                best_non_exec = (ctx, ctx_reason)
            pos = idx + 1

        if best_non_exec is not None:
            return best_non_exec[0], False, best_non_exec[1], media_type, None
        if saw_escaped or escaped_spans:
            return (
                "html_escaped",
                False,
                "XSS payload reflection is HTML/JSON-escaped in HTML response",
                media_type,
                None,
            )
        return "unknown", False, "XSS HTML reflection context could not be reliably determined", media_type, None

    if header_kind in ("missing", "malformed"):
        mismatch = "missing_header_html_body" if (header_kind == "missing" and looks_like_html) else None
        return (
            "unknown",
            False,
            f"Content-Type is {header_kind}; cannot establish executable HTML context",
            media_type or header_kind,
            mismatch,
        )

    # Other explicit non-HTML Content-Type (text/plain, application/xml, etc.)
    if looks_like_html:
        return (
            "mismatch",
            False,
            f"Content-Type '{media_type}' mismatches HTML-like body; ambiguous execution context",
            media_type,
            "non_html_header_html_body",
        )
    return (
        "non_html",
        False,
        f"XSS payload reflected in non-HTML response ({media_type}) — not an executable HTML context",
        media_type,
        None,
    )


def detect_response(
    resp,
    payload: Payload,
    rules: Optional[dict] = None,
    baseline_resp: Any = None,
    *,
    response_differences: Optional[dict[str, Any]] = None,
) -> tuple[DetectionResult, list[str]]:
    """Collect structured detection evidence comparing attack and baseline responses."""
    status = resp.status_code
    body_text = resp.text or ""
    body_lower = body_text.lower()
    attack_type = payload.attack_type.strip().upper()
    is_xss = attack_type == "XSS"

    has_baseline = baseline_resp is not None
    baseline_status = getattr(baseline_resp, "status_code", None) if has_baseline else None
    baseline_text_lower = (getattr(baseline_resp, "text", "") or "").lower() if has_baseline else ""
    baseline_elapsed_ms = extract_response_elapsed_ms(baseline_resp) if has_baseline else None
    baseline_limitation = (
        None if has_baseline
        else "Baseline response unavailable; pre-existing content could not be ruled out"
    )

    diffs = dict(response_differences or {})
    if has_baseline and not diffs:
        if baseline_status is not None and baseline_status != status:
            diffs["status_code"] = {"baseline": baseline_status, "attack": status}
        if baseline_text_lower != body_lower:
            diffs["body_changed"] = True

    expected_signals = list(dict.fromkeys(
        str(signal).strip().lower()
        for signal in payload.expected_signal
        if str(signal).strip()
    ))
    technical_catalog = [
        str(signal).strip().lower()
        for signal in DEFAULT_ERROR_SIGNALS
        if str(signal).strip()
    ]

    generic_signals: list[str] = []
    matched_cves: list[dict] = []
    if rules is not None:
        generic_signals = [
            str(signal).strip().lower()
            for signal in rules_engine.get_all_signals(rules)
            if str(signal).strip()
        ]
        # Only match CVEs when target technology fingerprint is known; avoid guessing CVEs by keyword alone.
        if payload.technology:
            matched_cves = rules_engine.match_cves_by_keyword(
                rules, payload.attack_type, payload.owasp_category,
                payload.technology,
            )

    cve_ids = [item["cve_id"] for item in matched_cves]

    reflected_spans = _find_reflected_spans(body_lower, payload.payload_value)
    payload_reflected = bool(reflected_spans)
    resp_headers = dict(getattr(resp, "headers", {}) or {})
    parsed_media_type, parsed_header_kind = _parse_content_type(resp_headers)
    xss_context: Optional[str] = None
    xss_context_reason: Optional[str] = None
    xss_mismatch: Optional[str] = None

    new_expected: list[str] = []
    preexisting_expected: list[str] = []
    ignored_generic: list[str] = []
    reflection_only: list[str] = []

    for sig in expected_signals:
        if sig not in body_lower:
            continue
        if _is_generic_or_low_entropy_signal(sig):
            ignored_generic.append(sig)
        elif has_baseline and sig in baseline_text_lower:
            preexisting_expected.append(sig)
        elif is_xss:
            is_payload_sig = _is_xss_payload_signal(sig, payload.payload_value)
            if not is_payload_sig and (
                not reflected_spans
                or _classify_signal_against_spans(body_lower, sig, reflected_spans)[0]
            ):
                new_expected.append(sig)
            else:
                ctx, exec_cand, ctx_reason, _, mismatch = _evaluate_xss_response_context(
                    resp_headers, body_text, body_lower, payload.payload_value, sig
                )
                xss_context = ctx
                xss_context_reason = ctx_reason
                xss_mismatch = mismatch
                if exec_cand:
                    new_expected.append(sig)
                elif sig not in reflection_only:
                    reflection_only.append(sig)
        elif reflected_spans:
            has_indep, has_refl = _classify_signal_against_spans(body_lower, sig, reflected_spans)
            if not has_indep and has_refl:
                if sig not in reflection_only:
                    reflection_only.append(sig)
            else:
                new_expected.append(sig)
        else:
            new_expected.append(sig)

    if is_xss and xss_context is None and payload_reflected and not preexisting_expected:
        ctx, _, ctx_reason, _, mismatch = _evaluate_xss_response_context(
            resp_headers, body_text, body_lower, payload.payload_value, str(payload.payload_value or "").lower()
        )
        xss_context = ctx
        xss_context_reason = ctx_reason
        xss_mismatch = mismatch

    technical_hits: list[str] = []
    new_technical_hits: list[str] = []
    for s in technical_catalog:
        if s not in body_lower:
            continue
        in_baseline = bool(has_baseline and s in baseline_text_lower)
        if reflected_spans and not in_baseline:
            has_indep, has_refl = _classify_signal_against_spans(body_lower, s, reflected_spans)
            if not has_indep and has_refl:
                if s not in reflection_only:
                    reflection_only.append(s)
                continue
        technical_hits.append(s)
        if not in_baseline:
            new_technical_hits.append(s)

    for sig in dict.fromkeys(generic_signals):
        if sig not in technical_catalog and sig not in expected_signals and sig in body_lower and sig not in ignored_generic:
            ignored_generic.append(sig)

    validation_barrier = False
    barrier_framework: Optional[str] = None
    barrier_details: list[str] = []
    if status in (400, 422):
        resp_headers = dict(getattr(resp, "headers", {}) or {})
        feedback = FeedbackAnalyzer.analyze_response(status, body_text, resp_headers)
        if feedback.is_validation_error:
            validation_barrier = True
            barrier_framework = feedback.framework_hint
            barrier_details = list(feedback.adaptive_recommendations[:2])

    anomalies: list[str] = []
    if status >= 500:
        anomalies.append(f"http_{status}")
    if "status_code" in diffs:
        anomalies.append("status_changed")
    if "body_hash" in diffs or diffs.get("body_changed"):
        anomalies.append("body_changed")

    elapsed_ms = extract_response_elapsed_ms(resp)
    latency_delta_ms: Optional[float] = None
    if elapsed_ms is not None and baseline_elapsed_ms is not None:
        latency_delta_ms = round(elapsed_ms - baseline_elapsed_ms, 1)
    if elapsed_ms is not None and elapsed_ms >= 3500:
        anomalies.append(f"time_delay_{round(elapsed_ms, 1)}ms")

    detection = DetectionResult(
        attack_type=attack_type,
        target_endpoint=payload.endpoint,
        has_baseline=has_baseline,
        baseline_limitation=baseline_limitation,
        status_code=status,
        baseline_status_code=baseline_status,
        response_differences=diffs,
        new_expected_signals=new_expected,
        preexisting_expected_signals=preexisting_expected,
        ignored_generic_signals=ignored_generic,
        technical_signals=technical_hits,
        new_technical_signals=new_technical_hits,
        payload_reflected=payload_reflected,
        reflection_only_signals=reflection_only,
        validation_barrier=validation_barrier,
        barrier_framework=barrier_framework,
        barrier_details=barrier_details,
        anomalies=anomalies,
        metadata={
            "elapsed_ms": round(elapsed_ms, 1) if elapsed_ms is not None else None,
            "baseline_elapsed_ms": round(baseline_elapsed_ms, 1) if baseline_elapsed_ms is not None else None,
            "latency_delta_ms": latency_delta_ms,
            "payload_preview": str(payload.payload_value)[:120],
            "content_type": parsed_media_type or parsed_header_kind,
            **({"xss_context": xss_context} if xss_context is not None else {}),
            **({"xss_context_reason": xss_context_reason} if xss_context_reason is not None else {}),
            **({"content_type_mismatch": xss_mismatch} if xss_mismatch is not None else {}),
        },
    )
    return detection, cve_ids


def decide_validation(detection: DetectionResult, payload: Payload) -> ValidationDecision:
    """Apply general false-positive policy over DetectionResult without specialized exploit proof."""
    status = detection.status_code or 0
    attack_type = detection.attack_type.upper()
    limitation_suffix = f" ({detection.baseline_limitation})" if detection.baseline_limitation else ""

    def _with_refs(*refs: str) -> list[str]:
        return [r for r in refs if r]

    def _decision(
        *,
        outcome: str,
        confidence: float,
        severity: str,
        reason: str,
        evidence_refs: list[str],
        is_confirmed: bool = False,
    ) -> ValidationDecision:
        verdict = normalize_validation_verdict(
            outcome=outcome,
            severity=severity,
            confidence=confidence,
            confirmed=is_confirmed,
            has_baseline=detection.has_baseline,
            has_independent_evidence=False,
        )
        return ValidationDecision(
            outcome=verdict.outcome,
            confidence=verdict.confidence,
            severity=verdict.severity,
            reason=reason,
            evidence_refs=evidence_refs,
            is_candidate=(verdict.outcome == "candidate"),
            is_confirmed=verdict.confirmed,
        )

    # 1. Invalid/rejected authorization probe is not evidence of a bypass.
    if attack_type in ("BOLA", "IDOR", "BFLA", "AUTH_BYPASS") and status in (400, 401, 403, 404):
        return _decision(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=f"HTTP {status}; authorization probe rejected or invalid; no bypass established",
            evidence_refs=_with_refs(f"http_{status}"),
        )

    # 1b. BOLA/IDOR HTTP 2xx requires dedicated authorization validator — keep inconclusive here.
    if attack_type in ("BOLA", "IDOR") and 200 <= status <= 299:
        return _decision(
            outcome="inconclusive",
            confidence=0.20,
            severity="info",
            reason=(
                f"HTTP {status}; BOLA/IDOR probe returned success; "
                "requires dedicated authorization validator for disposition"
            ),
            evidence_refs=_with_refs(f"http_{status}"),
        )

    relevant_tech = detection.new_technical_signals if detection.has_baseline else detection.technical_signals

    # 2. HTTP 400/422 validation barrier: generic errors cannot raise a candidate,
    # while preserving meaningful new canaries or technical backend faults.
    if detection.validation_barrier:
        if detection.new_expected_signals:
            return _decision(
                outcome="candidate",
                confidence=0.45 if detection.has_baseline else 0.30,
                severity="low",
                reason=(
                    f"HTTP {status}; new payload-specific signal inside error response: "
                    f"{detection.new_expected_signals[:3]}{limitation_suffix}"
                ),
                evidence_refs=detection.new_expected_signals[:3],
            )

        meaningful_tech = [
            s for s in relevant_tech
            if attack_type in ("SQLI", "SQL_INJECTION", "SQL INJECTION")
            or s in ("traceback", "stack trace", "unhandled exception", "internal server error")
        ]
        if meaningful_tech:
            return _decision(
                outcome="candidate",
                confidence=0.40 if detection.has_baseline else 0.30,
                severity="low",
                reason=(
                    f"HTTP {status}; technical backend error signal inside validation response: "
                    f"{meaningful_tech[:3]}{limitation_suffix}"
                ),
                evidence_refs=meaningful_tech[:3],
            )

        barrier_desc = "; ".join(detection.barrier_details) if detection.barrier_details else "input rejected"
        ignored_note = (
            f"; generic keywords ignored as insufficient evidence: {detection.ignored_generic_signals[:3]}"
            if detection.ignored_generic_signals
            else ""
        )
        refl_note = (
            f"; reflection-only signals ignored: {detection.reflection_only_signals[:3]}"
            if detection.reflection_only_signals
            else ""
        )
        xss_ctx = detection.metadata.get("xss_context")
        xss_ctx_reason = detection.metadata.get("xss_context_reason")
        ctx_note = f"; {xss_ctx_reason}" if (attack_type == "XSS" and xss_ctx_reason) else ""
        return _decision(
            outcome="rejected",
            confidence=0.15,
            severity="info",
            reason=f"HTTP {status}; Schema validation barrier ({detection.barrier_framework or 'generic'}): {barrier_desc}{ignored_note}{refl_note}{ctx_note}",
            evidence_refs=_with_refs(f"validation_barrier:{detection.barrier_framework or 'generic'}"),
        )

    # 3. Server 5xx errors warrant investigation unless baseline itself already returned 5xx with no new signals.
    # Unconfirmed 5xx candidates are capped at medium (with meaningful technical signals) or low (generic 5xx).
    if status >= 500:
        details = detection.new_expected_signals + detection.new_technical_signals
        if (
            detection.has_baseline
            and detection.baseline_status_code is not None
            and detection.baseline_status_code >= 500
            and not details
        ):
            return _decision(
                outcome="inconclusive",
                confidence=0.20,
                severity="info",
                reason=(
                    f"HTTP {status}; baseline also returned HTTP {detection.baseline_status_code} "
                    "without new payload-specific or technical error signals"
                ),
                evidence_refs=[f"baseline_http_{detection.baseline_status_code}", f"http_{status}"],
            )

        meaningful_5xx_signals = [s for s in details if s != "internal server error"]
        if meaningful_5xx_signals:
            return _decision(
                outcome="candidate",
                confidence=0.55 if detection.has_baseline else 0.40,
                severity="medium" if detection.has_baseline else "low",
                reason=(
                    f"HTTP {status}; server-error candidate with technical/payload signals: "
                    f"{meaningful_5xx_signals[:3]}{limitation_suffix}"
                ),
                evidence_refs=meaningful_5xx_signals[:3],
            )

        return _decision(
            outcome="candidate",
            confidence=0.40 if detection.has_baseline else 0.30,
            severity="low",
            reason=(
                f"HTTP {status}; generic server-error candidate without specific technical signals"
                f"{limitation_suffix}"
            ),
            evidence_refs=details[:3] or [f"http_{status}"],
        )

    # 4. Only non-generic, high-specificity signals NOT present in baseline may raise a candidate.
    if detection.new_expected_signals:
        xss_ctx = detection.metadata.get("xss_context") if attack_type == "XSS" else None
        xss_ctx_reason = detection.metadata.get("xss_context_reason") if attack_type == "XSS" else None
        ctx_suffix = f" ({xss_ctx}: {xss_ctx_reason})" if xss_ctx and xss_ctx_reason else ""
        refs = list(detection.new_expected_signals[:3])
        if xss_ctx:
            refs.append(f"xss_context:{xss_ctx}")
        return _decision(
            outcome="candidate",
            confidence=0.55 if detection.has_baseline else 0.35,
            severity="low",
            reason=f"HTTP {status}; new payload-specific signal: {detection.new_expected_signals[:3]}{ctx_suffix}{limitation_suffix}",
            evidence_refs=refs,
        )

    # 5. Technical SQL error signals on SQLi probes.
    if relevant_tech and attack_type in ("SQLI", "SQL_INJECTION", "SQL INJECTION"):
        return _decision(
            outcome="candidate",
            confidence=0.55 if detection.has_baseline else 0.35,
            severity="medium" if detection.has_baseline else "low",
            reason=f"HTTP {status}; technical SQL/error signal: {relevant_tech[:3]}{limitation_suffix}",
            evidence_refs=relevant_tech[:3],
        )

    # 6. Time-based blind injection latency anomaly (single-probe remains candidate/medium; requires significant delta when baseline latency is known).
    elapsed_ms = detection.metadata.get("elapsed_ms")
    latency_delta_ms = detection.metadata.get("latency_delta_ms")
    if elapsed_ms is not None and elapsed_ms >= 3500:
        is_time_attack = "TIME" in attack_type or any(
            k in str(payload.payload_value).lower()
            for k in ("sleep", "waitfor", "pg_sleep", "delay")
        )
        if is_time_attack:
            if detection.has_baseline and latency_delta_ms is not None and latency_delta_ms < 3500:
                return _decision(
                    outcome="inconclusive",
                    confidence=0.20,
                    severity="info",
                    reason=(
                        f"HTTP {status}; latency {elapsed_ms}ms >= 3500ms but baseline was also slow "
                        f"(delta={latency_delta_ms}ms < 3500ms)"
                    ),
                    evidence_refs=[f"time_delta_{latency_delta_ms}ms"],
                )
            return _decision(
                outcome="candidate",
                confidence=0.60 if detection.has_baseline else 0.40,
                severity="medium",
                reason=f"HTTP {status}; significant time delay observed ({elapsed_ms}ms >= 3500ms){limitation_suffix}",
                evidence_refs=[f"time_delay_{elapsed_ms}ms"],
            )

    # 7. Pre-existing signal already present in baseline is not evidence of injection/exploit.
    if detection.preexisting_expected_signals:
        return _decision(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=(
                f"HTTP {status}; signal already present in baseline response "
                f"(not introduced by payload): {detection.preexisting_expected_signals[:3]}"
            ),
            evidence_refs=detection.preexisting_expected_signals[:3],
        )

    # 7b. Context-aware XSS disposition when reflection lacks executable HTML evidence.
    if attack_type == "XSS" and detection.metadata.get("xss_context"):
        xss_ctx = str(detection.metadata["xss_context"])
        xss_ctx_reason = str(detection.metadata.get("xss_context_reason") or f"non-executable XSS context '{xss_ctx}'")
        refs = list(detection.reflection_only_signals[:3]) + [f"xss_context:{xss_ctx}"]
        if xss_ctx in ("mismatch", "unknown", "html_attribute_quoted", "html_comment", "html_js_context_inert"):
            return _decision(
                outcome="inconclusive",
                confidence=0.25 if xss_ctx == "mismatch" else 0.20,
                severity="info",
                reason=f"HTTP {status}; {xss_ctx_reason}{limitation_suffix}",
                evidence_refs=refs,
            )
        return _decision(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=f"HTTP {status}; {xss_ctx_reason}{limitation_suffix}",
            evidence_refs=refs,
        )

    # 7c. Signals appearing solely inside reflected payload input are not independent backend evidence.
    if detection.reflection_only_signals:
        return _decision(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=(
                f"HTTP {status}; matched signal(s) appeared only inside reflected payload "
                f"(not independent backend evidence): {detection.reflection_only_signals[:3]}{limitation_suffix}"
            ),
            evidence_refs=detection.reflection_only_signals[:3],
        )

    # 8. Generic or low-entropy keywords alone never create a candidate.
    if detection.ignored_generic_signals:
        return _decision(
            outcome="rejected",
            confidence=0.10,
            severity="info",
            reason=(
                f"HTTP {status}; generic keywords ignored as insufficient evidence: "
                f"{detection.ignored_generic_signals[:3]}{limitation_suffix}"
            ),
            evidence_refs=detection.ignored_generic_signals[:3],
        )

    # 9. Generic response/hash/status differences alone never establish vulnerability.
    if detection.response_differences:
        return _decision(
            outcome="rejected",
            confidence=0.15,
            severity="info",
            reason=(
                f"HTTP {status}; generic response difference without vulnerability evidence "
                f"({sorted(detection.response_differences.keys())}){limitation_suffix}"
            ),
            evidence_refs=sorted(detection.response_differences.keys()),
        )

    return _decision(
        outcome="rejected",
        confidence=0.10,
        severity="info",
        reason=f"HTTP {status}; no sufficiently specific vulnerability signal{limitation_suffix}",
        evidence_refs=[],
    )


def evaluate_response(
    resp,
    payload: Payload,
    rules: Optional[dict] = None,
    baseline_resp: Any = None,
) -> tuple[str, bool, str, list[str]]:
    """Evaluate attack response (and optional baseline) via DetectionResult + ValidationDecision."""
    detection, cve_ids = detect_response(resp, payload, rules, baseline_resp=baseline_resp)
    decision = decide_validation(detection, payload)
    return decision.severity, decision.is_candidate, decision.reason, cve_ids


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------

async def fire_case(client: "httpx.AsyncClient", case, base_url: str, headers: dict, *, strip_auth: bool = False):
    """Translate a Schemathesis Case into an async httpx request via as_transport_kwargs()."""
    kwargs = case.as_transport_kwargs(base_url=base_url)
    req_headers = dict(kwargs.get("headers", {}) or {})
    if strip_auth:
        auth_keys = {"authorization", "cookie", "x-api-key", "x-auth-token"}
        req_headers = {k: v for k, v in req_headers.items() if k.lower() not in auth_keys}
    if headers:
        req_headers.update(headers)
    if req_headers:
        kwargs["headers"] = req_headers
    elif "headers" in kwargs:
        kwargs["headers"] = {}
    if not kwargs.get("cookies"):  # httpx warns on empty cookies={}
        kwargs.pop("cookies", None)
    return await client.request(**kwargs)


_FATAL_PROGRAMMING_ERRORS = (
    AssertionError,
    AttributeError,
    ImportError,
    IndexError,
    KeyError,
    MemoryError,
    NameError,
    RecursionError,
    SyntaxError,
    TypeError,
    ZeroDivisionError,
)


def _extract_response_body(resp_obj: Any) -> Any:
    """Safely extract parsed JSON or raw text from an HTTP response."""
    if resp_obj is None:
        return None
    try:
        return resp_obj.json()
    except Exception:
        return getattr(resp_obj, "text", None)


async def _validate_bola(
    *,
    client: "httpx.AsyncClient",
    scheduler: RequestScheduler,
    pc: PreparedCase,
    attack_response: Any,
    attack_status: int,
    baseline_snapshot: Any,
    baseline_response: Any = None,
    user1_headers: Optional[dict],
    user2_headers: Optional[dict],
) -> Optional[Any]:
    """Delegate BOLA/IDOR validation to BolaValidator, firing unauthenticated control request."""
    from core.bola_validator import BolaValidator

    # Non-2xx → let BolaValidator handle via its own early exits; 5xx → return None to delegate
    if attack_status >= 500:
        return None  # Let decide_validation() handle server errors generically

    auth_mode = BolaValidator.detect_auth_mode(user1_headers, user2_headers)

    # Fire unauthenticated control request for dual-token or single-token modes with 2xx
    unauth_status: Optional[int] = None
    if 200 <= attack_status < 300 and auth_mode in ("dual_token", "single_token"):
        try:
            unauth_resp = await scheduler.request(
                pc.target_app,
                lambda: fire_case(client, pc.case, pc.base_url, {}, strip_auth=True),
            )
            unauth_status = unauth_resp.status_code if unauth_resp is not None else None
        except (asyncio.CancelledError, CircuitBreakerTrippedError):
            raise
        except Exception as exc:
            logger.debug("Unauthenticated BOLA control check failed on %s: %s", pc.payload.endpoint, exc)

    attack_body = _extract_response_body(attack_response)
    baseline_body = _extract_response_body(baseline_response)

    return BolaValidator.validate(
        attack_status=attack_status,
        baseline_status=baseline_snapshot.status_code if baseline_snapshot else None,
        unauth_status=unauth_status,
        attack_response_body=attack_body,
        baseline_response_body=baseline_body,
        user1_headers=user1_headers,
        user2_headers=user2_headers,
        resource_id=str(pc.payload.payload_value) if pc.payload.target_param else None,
        endpoint=pc.payload.endpoint,
        method=pc.payload.method,
    )


class _StaticTransportCase:
    """Minimal Case-compatible wrapper for follow-up differential probes."""

    def __init__(self, kwargs: dict[str, Any]):
        self._kwargs = kwargs

    def as_transport_kwargs(self, base_url: str = "") -> dict[str, Any]:
        return dict(self._kwargs)


def _replace_payload_in_obj(obj: Any, old_str: str, new_str: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(old_str, new_str) if old_str in obj else obj
    if isinstance(obj, dict):
        return {k: _replace_payload_in_obj(v, old_str, new_str) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_payload_in_obj(item, old_str, new_str) for item in obj]
    return obj


def _build_followup_case(pc: PreparedCase, new_payload_value: Any) -> Any:
    """Build a follow-up Schemathesis/transport Case with *new_payload_value*."""
    if pc.schema is not None and pc.operation is not None:
        try:
            updated_payload = pc.payload.model_copy(update={"payload_value": new_payload_value})
            return build_case(pc.schema, pc.operation, updated_payload, pc.baseline_case)
        except Exception as exc:
            logger.debug("build_case failed for follow-up probe on %s: %s", pc.payload.endpoint, exc)

    kwargs = pc.case.as_transport_kwargs(base_url=pc.base_url)
    old_str = str(pc.payload.payload_value)
    new_str = str(new_payload_value)
    mutated = _replace_payload_in_obj(kwargs, old_str, new_str)
    return _StaticTransportCase(mutated)


def _build_safe_curl_for_case(
    pc: PreparedCase,
    headers: dict[str, Any],
    user2_headers: Optional[dict[str, Any]] = None,
) -> Optional[str]:
    """Generate a secret-redacted cURL command from a PreparedCase."""
    try:
        kwargs = pc.case.as_transport_kwargs(base_url=pc.base_url)
        method = str(kwargs.get("method") or pc.payload.method or "GET").upper()
        url = str(kwargs.get("url") or f"{pc.base_url.rstrip('/')}/{pc.payload.endpoint.lstrip('/')}")

        is_bola = pc.payload.attack_type.upper() in ("BOLA", "IDOR")
        effective_auth = user2_headers if (is_bola and user2_headers) else headers

        raw_headers = dict(kwargs.get("headers") or {})
        if effective_auth:
            raw_headers.update(effective_auth)

        safe_headers: dict[str, Any] = {}
        secret_keys = {"authorization", "cookie", "x-api-key", "x-auth-token"}
        for hk, hv in raw_headers.items():
            kl = str(hk).lower()
            if kl in secret_keys:
                if kl == "authorization" and str(hv).lower().startswith("bearer "):
                    safe_headers[hk] = "Bearer <REDACTED>"
                else:
                    safe_headers[hk] = "<REDACTED>"
            elif kl.startswith("x-schemathesis-"):
                continue
            else:
                safe_headers[hk] = hv

        def _clean_opt(val: Any) -> Any:
            if val is None or type(val).__name__ == "NotSet":
                return None
            return val

        params = _clean_opt(kwargs.get("params"))
        json_data = _clean_opt(kwargs.get("json"))
        data = _clean_opt(kwargs.get("data"))
        raw_cookies = _clean_opt(kwargs.get("cookies"))
        safe_cookies = (
            {str(ck): "<REDACTED>" for ck in raw_cookies.keys()}
            if isinstance(raw_cookies, dict) and raw_cookies
            else None
        )

        return build_curl_command(
            method=method,
            url=url,
            headers=safe_headers or None,
            params=params if isinstance(params, dict) and params else None,
            data=data,
            json_data=json_data,
            cookies=safe_cookies,
        )
    except Exception as exc:
        logger.debug("Could not build cURL command for %s: %s", pc.payload.endpoint, exc)
        return None


async def _validate_ssti(
    *,
    client: "httpx.AsyncClient",
    scheduler: RequestScheduler,
    pc: PreparedCase,
    attack_response: Any,
    attack_status: int,
    baseline_response: Any,
    headers: dict[str, Any],
) -> Optional[Any]:
    """Delegate SSTI validation + differential confirmation to SstiValidator."""
    from core.ssti_validator import SstiValidator, build_differential_ssti_probes

    if attack_status >= 500 or attack_status in (400, 422):
        return None

    diff_probes = build_differential_ssti_probes(
        pc.payload.payload_value,
        pc.payload.expected_signal,
    )
    if diff_probes is None:
        return None

    attack_text = getattr(attack_response, "text", None)
    baseline_text = getattr(baseline_response, "text", None) if baseline_response is not None else None

    # First evaluate without follow-up requests; only re-probe if primary canary newly appeared.
    prelim = SstiValidator.validate(
        attack_status=attack_status,
        attack_body=attack_text,
        baseline_body=baseline_text,
        initial_payload=pc.payload.payload_value,
        initial_expected=diff_probes.initial_expected,
    )
    if prelim is None or prelim.outcome != "candidate":
        return prelim

    # Fire differential arithmetic probe + control literal probe
    sec_status: Optional[int] = None
    sec_body: Optional[str] = None
    ctrl_status: Optional[int] = None
    ctrl_body: Optional[str] = None

    try:
        sec_case = _build_followup_case(pc, diff_probes.secondary_payload)
        sec_resp = await scheduler.request(
            pc.target_app,
            lambda: fire_case(client, sec_case, pc.base_url, headers),
        )
        if sec_resp is not None:
            sec_status = sec_resp.status_code
            sec_body = getattr(sec_resp, "text", None)
    except (asyncio.CancelledError, CircuitBreakerTrippedError):
        raise
    except Exception as exc:
        logger.debug("Differential SSTI secondary probe failed on %s: %s", pc.payload.endpoint, exc)

    if sec_status is not None and 200 <= sec_status < 300:
        try:
            ctrl_case = _build_followup_case(pc, diff_probes.control_payload)
            ctrl_resp = await scheduler.request(
                pc.target_app,
                lambda: fire_case(client, ctrl_case, pc.base_url, headers),
            )
            if ctrl_resp is not None:
                ctrl_status = ctrl_resp.status_code
                ctrl_body = getattr(ctrl_resp, "text", None)
        except (asyncio.CancelledError, CircuitBreakerTrippedError):
            raise
        except Exception as exc:
            logger.debug("Differential SSTI control probe failed on %s: %s", pc.payload.endpoint, exc)

    return SstiValidator.validate(
        attack_status=attack_status,
        attack_body=attack_text,
        baseline_body=baseline_text,
        initial_payload=pc.payload.payload_value,
        initial_expected=diff_probes.initial_expected,
        secondary_status=sec_status,
        secondary_body=sec_body,
        secondary_expected=diff_probes.secondary_expected,
        control_status=ctrl_status,
        control_body=ctrl_body,
    )


def _validate_boundary(
    *,
    pc: PreparedCase,
    attack_response: Any,
    attack_status: int,
    baseline_snapshot: Any,
    baseline_response: Any = None,
) -> Optional[Any]:
    """Delegate numeric boundary / overflow HTTP 2xx validation to BoundaryValidator."""
    from core.boundary_validator import BoundaryValidator

    return BoundaryValidator.validate(
        attack_status=attack_status,
        baseline_status=baseline_snapshot.status_code if baseline_snapshot else None,
        attack_body=_extract_response_body(attack_response),
        baseline_body=_extract_response_body(baseline_response),
        param_name=pc.payload.target_param,
        param_location=pc.payload.param_location,
        payload_value=pc.payload.payload_value,
        method=pc.payload.method,
        endpoint=pc.payload.endpoint,
    )


async def process_fingerprint_group(
    client: "httpx.AsyncClient", scheduler: RequestScheduler,
    fp: str, group: list[PreparedCase], headers: dict,
    rules: Optional[dict], state: RunState, rate_limit_s: float,
    user2_headers: Optional[dict] = None,
    cleanup_tracker: Optional[CleanupTracker] = None,
    execution_errors: Optional[list[dict[str, Any]]] = None,
    skip_from_state: bool = False,
) -> list[Finding]:
    """Process one fingerprint group sequentially and aggregate all probe observations into one Finding."""
    tracker = cleanup_tracker or GLOBAL_CLEANUP_TRACKER

    if skip_from_state:
        if state.status(fp) == "confirmed":
            return []
        if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
            return []

    observations: list[Observation] = []
    obs_to_pc: dict[str, PreparedCase] = {}
    cve_matches_acc: list[str] = []
    cve_match_type = ""
    cve_confidence = 0.0
    rep_pc: Optional[PreparedCase] = None
    bola_verdict = None  # Set per-probe by _validate_bola when attack_type is BOLA/IDOR
    boundary_verdict = None  # Set per-probe by _validate_boundary for numeric boundaries
    ssti_verdict = None  # Set per-probe by _validate_ssti for SSTI differential validation

    for idx, pc in enumerate(group):
        if rep_pc is None:
            rep_pc = pc

        payload_value = pc.payload.payload_value
        payload_hash = content_hash(payload_value)
        request_hash = content_hash({
            "target": pc.target_app,
            "method": pc.payload.method,
            "endpoint": pc.payload.endpoint,
            "parameter": pc.payload.target_param,
            "value": payload_value,
        })
        obs_timestamp = datetime.now(timezone.utc).isoformat()
        obs_id = f"OBS-{content_hash({'fp': fp, 'idx': idx, 'req': request_hash, 'ts': obs_timestamp})}"

        attack_response = None
        baseline_response = None
        result = None
        error_text: Optional[str] = None
        circuit_tripped = False
        bola_verdict = None
        boundary_verdict = None
        ssti_verdict = None
        mass_assignment_outcome: Optional[str] = None

        try:
            async def execute_baseline():
                return await scheduler.request(
                    pc.target_app,
                    lambda: fire_case(client, pc.baseline_case, pc.base_url, headers),
                )

            is_bola = pc.payload.attack_type.upper() in ("BOLA", "IDOR")
            attack_headers = user2_headers if (is_bola and user2_headers) else headers

            async def execute_attack():
                nonlocal attack_response
                attack_response = await scheduler.request(
                    pc.target_app,
                    lambda: fire_case(client, pc.case, pc.base_url, attack_headers),
                )
                return attack_response

            cve_ids_for_probe: list[str] = []

            def candidate_detector(attack_resp, baseline_resp=None):
                nonlocal cve_ids_for_probe, baseline_response
                baseline_response = baseline_resp
                detection, cve_ids_for_probe = detect_response(
                    attack_resp, pc.payload, rules, baseline_resp=baseline_resp
                )
                decision = decide_validation(detection, pc.payload)
                return detection, decision

            result = await ConfirmationEngine().confirm(
                candidate_detector,
                execute_baseline if pc.baseline_case is not None else None,
                execute_attack,
                snapshot_response,
            )
        except asyncio.CancelledError:
            raise
        except CircuitBreakerTrippedError as cb_exc:
            circuit_tripped = True
            error_text = str(cb_exc) or "Circuit breaker tripped"
            logger.warning("Circuit breaker tripped for fingerprint %s: %s", fp, error_text)
            if execution_errors is not None:
                execution_errors.append({
                    "fingerprint": fp,
                    "target": pc.target_app,
                    "type": "circuit_breaker",
                    "error": error_text,
                })
        except _FATAL_PROGRAMMING_ERRORS:
            raise
        except (httpx.HTTPError, TimeoutError, OSError, ValueError) as exc:
            attack_response = None
            result = None
            error_text = f"{type(exc).__name__}: {exc}"

        if rate_limit_s and not circuit_tripped:
            await asyncio.sleep(rate_limit_s)

        resp = attack_response
        if resp is None or result is None or getattr(result, "error", None):
            err_detail = error_text or (result.error if result and getattr(result, "error", None) else "No HTTP response received")
            observations.append(Observation(
                observation_id=obs_id,
                timestamp=obs_timestamp,
                role="error",
                payload=payload_value,
                payload_hash=payload_hash,
                request_hash=request_hash,
                status_code=None,
                response_time_ms=0.0,
                response_headers={},
                signals=[f"request error: {err_detail}"],
                differences={},
                baseline_status_code=result.baseline.status_code if result and result.baseline else None,
                baseline_response_time_ms=result.baseline.response_time_ms if result and result.baseline else None,
                outcome="error",
                severity="unknown",
                confidence=0.0,
                validation_result="error",
                error=err_detail,
            ))
            if circuit_tripped:
                break
            continue

        detection_obj = getattr(result, "detection", None)
        decision_obj = getattr(result, "decision", None)
        if detection_obj is not None and decision_obj is not None:
            severity = decision_obj.severity
            evidence = decision_obj.reason
            cve_ids = cve_ids_for_probe
            confidence = decision_obj.confidence
        else:
            severity, _, evidence, cve_ids = evaluate_response(resp, pc.payload, rules)
            confidence = result.confidence
        status_code = resp.status_code
        confirmed = result.confirmed
        confirmation_differences = result.evidence

        # BOLA / IDOR validation via dedicated BolaValidator
        if pc.payload.attack_type.upper() in ("BOLA", "IDOR"):
            bola_verdict = await _validate_bola(
                client=client,
                scheduler=scheduler,
                pc=pc,
                attack_response=resp,
                attack_status=status_code,
                baseline_snapshot=result.baseline,
                baseline_response=baseline_response,
                user1_headers=headers,
                user2_headers=user2_headers,
            )
            if bola_verdict is not None:
                confirmed = bola_verdict.outcome == "confirmed"
                confidence = bola_verdict.confidence
                severity = bola_verdict.severity
                evidence = bola_verdict.reason

        # Numeric Boundary / Integer Overflow validation via dedicated BoundaryValidator
        if pc.payload.attack_type.upper() in ("INTEGER_OVERFLOW", "BOUNDARY_ANALYSIS"):
            boundary_verdict = _validate_boundary(
                pc=pc,
                attack_response=resp,
                attack_status=status_code,
                baseline_snapshot=result.baseline,
                baseline_response=baseline_response,
            )
            if boundary_verdict is not None:
                confirmed = boundary_verdict.outcome == "confirmed"
                confidence = boundary_verdict.confidence
                severity = boundary_verdict.severity
                evidence = boundary_verdict.reason

        # SSTI differential validation via dedicated SstiValidator
        if pc.payload.attack_type.upper() == "SSTI":
            ssti_verdict = await _validate_ssti(
                client=client,
                scheduler=scheduler,
                pc=pc,
                attack_response=resp,
                attack_status=status_code,
                baseline_response=baseline_response,
                headers=headers,
            )
            if ssti_verdict is not None:
                confirmed = ssti_verdict.outcome == "confirmed"
                confidence = ssti_verdict.confidence
                severity = ssti_verdict.severity
                evidence = ssti_verdict.reason

        # Deep State Loopback Verification for Mass Assignment (API3:2023)
        if pc.payload.attack_type.upper() == "MASS_ASSIGNMENT" and status_code in (200, 201) and resp is not None:
            loopback_url = None
            resp_headers = dict(resp.headers)
            loc_header = resp_headers.get("location") or resp_headers.get("Location")
            if loc_header:
                loopback_url = str(loc_header)
            elif pc.payload.method.upper() in ("PUT", "PATCH"):
                loopback_url = pc.payload.endpoint
            else:
                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict):
                        for id_k in ("id", "user_id", "userId", "uuid"):
                            if id_k in resp_json and resp_json[id_k] is not None:
                                loopback_url = f"{pc.payload.endpoint.rstrip('/')}/{resp_json[id_k]}"
                                break
                except Exception as exc:
                    logger.debug("Could not parse JSON for mass-assignment loopback URL on %s: %s", pc.payload.endpoint, exc)

            if loopback_url:
                full_get_url = loopback_url if loopback_url.startswith(("http://", "https://")) else f"{pc.base_url.rstrip('/')}/{loopback_url.lstrip('/')}"
                try:
                    is_persisted, verify_msg = verify_deep_state_persistence(
                        get_url=full_get_url,
                        expected_field=pc.payload.target_param,
                        expected_value="admin" if pc.payload.target_param in ("role", "is_admin") else payload_value,
                        headers=headers,
                    )
                    if is_persisted:
                        confirmed = True
                        mass_assignment_outcome = "confirmed"
                        confidence = 0.98
                        severity = "critical" if pc.payload.target_param in ("role", "is_admin", "admin") else "high"
                        evidence = f"HTTP {status_code}; {verify_msg}"
                    else:
                        confirmed = False
                        mass_assignment_outcome = "rejected"
                        confidence = 0.10
                        severity = "info"
                        evidence = f"HTTP {status_code}; Loopback verification unpersisted: {verify_msg}"
                except Exception as verify_err:
                    evidence += f" (Loopback check: {verify_err})"

        # Staging Safety: Record successful mutations in CleanupTracker
        if pc.payload.method.upper() in ("POST", "PUT", "PATCH") and status_code in (200, 201, 202, 204) and resp is not None:
            try:
                resp_data = None
                try:
                    resp_data = resp.json()
                except Exception:
                    resp_data = resp.text
                tracker.record_mutation(
                    method=pc.payload.method,
                    target_url=pc.base_url,
                    endpoint=pc.payload.endpoint,
                    status_code=status_code,
                    response_data=resp_data,
                    response_headers=dict(resp.headers),
                )
            except Exception as exc:
                logger.debug("CleanupTracker mutation recording failed on %s: %s", pc.payload.endpoint, exc)

        elapsed_ms = result.attack.response_time_ms if result and result.attack else 0.0
        if confirmed:
            outcome = "confirmed"
        elif mass_assignment_outcome is not None:
            outcome = mass_assignment_outcome
        elif bola_verdict is not None and pc.payload.attack_type.upper() in ("BOLA", "IDOR"):
            outcome = bola_verdict.outcome
        elif boundary_verdict is not None and pc.payload.attack_type.upper() in ("INTEGER_OVERFLOW", "BOUNDARY_ANALYSIS"):
            outcome = boundary_verdict.outcome
        elif ssti_verdict is not None and pc.payload.attack_type.upper() == "SSTI":
            outcome = ssti_verdict.outcome
        elif decision_obj is not None:
            outcome = decision_obj.outcome
        else:
            outcome = "candidate" if result.candidate else "rejected"

        has_baseline_obs = baseline_response is not None or (result is not None and result.baseline is not None)
        has_independent_obs = bool(
            (bola_verdict is not None and bola_verdict.outcome in ("confirmed", "candidate"))
            or (boundary_verdict is not None and boundary_verdict.outcome in ("confirmed", "candidate"))
            or (ssti_verdict is not None and ssti_verdict.outcome == "confirmed")
            or mass_assignment_outcome == "confirmed"
        )
        has_val_ev = bool(
            (bola_verdict is not None and bola_verdict.ownership_checked)
            or (boundary_verdict is not None and boundary_verdict.anomaly_kind is not None)
            or (ssti_verdict is not None and ssti_verdict.differential_verified)
            or mass_assignment_outcome == "confirmed"
        ) if outcome == "confirmed" else True

        normalized_verdict = normalize_validation_verdict(
            outcome=outcome,
            severity=severity,
            confidence=confidence,
            confirmed=confirmed,
            has_baseline=has_baseline_obs,
            has_independent_evidence=has_independent_obs,
            has_validation_evidence=has_val_ev,
        )
        outcome = normalized_verdict.outcome
        confirmed = normalized_verdict.confirmed
        severity = normalized_verdict.severity
        confidence = normalized_verdict.confidence

        if cve_ids and outcome in ("candidate", "confirmed") and pc.payload.technology:
            cve_matches_acc = list(dict.fromkeys(cve_matches_acc + cve_ids))
            curr_conf = 0.94
            if curr_conf >= cve_confidence:
                cve_confidence = curr_conf
                cve_match_type = "cpe"

        obs_obj = Observation(
            observation_id=obs_id,
            timestamp=obs_timestamp,
            role="attack",
            payload=payload_value,
            payload_hash=payload_hash,
            request_hash=request_hash,
            status_code=status_code,
            response_time_ms=round(elapsed_ms, 1),
            response_headers=redact_headers(dict(resp.headers)),
            signals=[evidence],
            differences=confirmation_differences,
            baseline_status_code=result.baseline.status_code if result.baseline else None,
            baseline_response_time_ms=result.baseline.response_time_ms if result.baseline else None,
            outcome=outcome,
            severity=severity,
            confidence=confidence,
            validation_result=outcome,
        )
        observations.append(obs_obj)
        obs_to_pc[obs_id] = pc

        if confirmed:
            break

    if not observations or rep_pc is None:
        return []

    rep_obs = max(
        observations,
        key=lambda obs: (
            LIFECYCLE_RANK.get(obs.outcome, 0),
            obs.confidence,
            1 if obs.status_code is not None else 0,
        ),
    )
    curl_pc = obs_to_pc.get(rep_obs.observation_id, rep_pc)
    curl_cmd = _build_safe_curl_for_case(curl_pc, headers, user2_headers=user2_headers)

    finding = build_finding_from_observations(
        finding_id=stable_finding_id(
            rep_pc.target_app,
            rep_pc.payload.method,
            rep_pc.payload.endpoint,
            rep_pc.payload.attack_type,
            rep_pc.payload.target_param,
        ),
        run_id=STATE_RUN_ID.get(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        target_app=rep_pc.target_app,
        endpoint=rep_pc.payload.endpoint,
        method=rep_pc.payload.method,
        tool="schemathesis",
        attack_type=rep_pc.payload.attack_type,
        owasp_category=rep_pc.payload.owasp_category,
        fingerprint=fp,
        observations=observations,
        auth_context=redact_headers(headers),
        cve_matches=cve_matches_acc,
        cve_match_type=cve_match_type,
        cve_confidence=cve_confidence,
        curl_command=curl_cmd,
    )
    state.record(fp, finding.lifecycle)
    return [finding]


async def run_all(prepared: list[PreparedCase], headers: dict,
                   rules: Optional[dict], state: RunState, concurrency: int,
                   rate_limit_ms: int, global_rps: float = 0,
                   user2_headers: Optional[dict] = None,
                   proxy: Optional[str] = None,
                   insecure: bool = False,
                   session_keeper: Optional[Any] = None,
                   proxy_rotator: Optional[Any] = None,
                   auth_manager: Optional[Any] = None,
                   cleanup_tracker: Optional[CleanupTracker] = None,
                   execution_errors: Optional[list[dict[str, Any]]] = None,
                   skip_from_state: bool = False) -> list[Finding]:
    groups: dict[str, list[PreparedCase]] = {}
    for pc in prepared:
        groups.setdefault(pc.fingerprint, []).append(pc)

    merged_headers = dict(headers or {})
    if auth_manager is not None:
        merged_headers.update(auth_manager.get_headers())
    merged_headers.update(get_audit_headers(STATE_RUN_ID.get() or "schemathesis-run"))

    scheduler = RequestScheduler(
        concurrency=concurrency,
        global_rps=global_rps,
        proxy_rotator=proxy_rotator,
        session_keeper=session_keeper,
    )
    client_kwargs: dict[str, Any] = {"timeout": 20.0}
    proxy_url = proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or os.environ.get("ALL_PROXY")
    if not proxy_url and proxy_rotator is not None and proxy_rotator.has_proxies:
        proxy_url = await proxy_rotator.get_next_proxy()
    if proxy_url:
        client_kwargs["proxy"] = proxy_url
    if insecure or os.environ.get("PYTHONHTTPSVERIFY") == "0":
        client_kwargs["verify"] = False
    if auth_manager is not None and auth_manager.get_httpx_cert() is not None:
        client_kwargs["cert"] = auth_manager.get_httpx_cert()

    fp_list = list(groups.keys())
    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [
            process_fingerprint_group(
                client, scheduler, fp, groups[fp], merged_headers,
                rules, state, rate_limit_ms / 1000,
                user2_headers=user2_headers,
                cleanup_tracker=cleanup_tracker,
                execution_errors=execution_errors,
                skip_from_state=skip_from_state,
            )
            for fp in fp_list
        ]
        grouped_results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[Finding] = []
    fatal_error: Optional[BaseException] = None
    for fp, item in zip(fp_list, grouped_results):
        if isinstance(item, asyncio.CancelledError):
            raise item
        if isinstance(item, _FATAL_PROGRAMMING_ERRORS):
            logger.exception("Fatal programming/system error in fingerprint group %s", fp, exc_info=item)
            if execution_errors is not None:
                execution_errors.append({
                    "fingerprint": fp,
                    "type": "fatal_error",
                    "error": f"{type(item).__name__}: {item}",
                })
            if fatal_error is None:
                fatal_error = item
            continue
        if isinstance(item, BaseException):
            logger.error("Fingerprint group %s failed: %s", fp, item, exc_info=item)
            if execution_errors is not None:
                execution_errors.append({
                    "fingerprint": fp,
                    "type": "group_error",
                    "error": f"{type(item).__name__}: {item}",
                })
            continue
        all_findings.extend(item)

    if fatal_error is not None:
        raise fatal_error
    return all_findings


def execute_rest_scan(
    *,
    targets: dict[str, tuple],
    targets_desc: str,
    headers: Optional[dict[str, str]] = None,
    user2_headers: Optional[dict[str, str]] = None,
    payloads_path: Optional[str] = None,
    rules_path: Optional[str | Path] = None,
    results_dir: Optional[str | Path] = None,
    concurrency: int = 10,
    rate_limit_ms: int = 200,
    global_rps: float = 0,
    proxy: Optional[str] = None,
    insecure: bool = False,
    session_keeper: Optional[Any] = None,
    proxy_rotator: Optional[Any] = None,
    auth_manager: Optional[Any] = None,
    seed_corpus: Optional[Any] = None,
    cleanup_tracker: Optional[CleanupTracker] = None,
    resume_state: bool = False,
) -> list[Finding]:
    """Execute REST fuzzing in-process with shared scheduler, session, and proxy hooks."""
    resolved_rules_path = PROJECT_PATHS.resolve(
        rules_path or (PROJECT_PATHS.config / "rules.json"),
        allow_outside=True,
    )
    rules = None
    if resolved_rules_path.exists():
        rules = rules_engine.load_rules(str(resolved_rules_path))
        n_cve = len(rules.get("cve_signals", []))
        last_upd = rules["meta"].get("cve_last_updated")
        print(
            f"[INFO] Loaded rules from {resolved_rules_path}: {n_cve} cached CVEs "
            f"(last updated: {last_upd or 'never'})."
        )
    else:
        print(
            f"[WARNING] Rules file not found at {resolved_rules_path} - using static signals.",
            file=sys.stderr,
        )

    result_manager = ResultManager(PROJECT_ROOT, results_dir=results_dir or PROJECT_PATHS.results)
    resolved_results_dir = result_manager.ensure_results_dir()
    run_id = result_manager.make_run_id(prefix="rest")
    token_reset = STATE_RUN_ID.set(run_id)
    try:
        state = RunState(resolved_results_dir / "state.json")
        tracker = cleanup_tracker or GLOBAL_CLEANUP_TRACKER
        tracker.run_id = run_id
        tracker.out_dir = resolved_results_dir

        payloads = (
            load_payloads(payloads_path)
            if payloads_path
            else schema_payloads(targets, seed_corpus=seed_corpus)
        )
        if not payloads_path:
            print(f"[INFO] Schema-only mode: generated {len(payloads)} cases from OpenAPI.")
        total_payloads = len(payloads)

        prepared = prepare_cases(payloads, targets)
        total_prepared = len(prepared)
        total_dropped_at_prepare = total_payloads - total_prepared

        execution_errors: list[dict[str, Any]] = []
        findings = asyncio.run(run_all(
            prepared,
            headers or {},
            rules,
            state,
            concurrency,
            rate_limit_ms,
            global_rps,
            user2_headers=user2_headers,
            proxy=proxy,
            insecure=insecure,
            session_keeper=session_keeper,
            proxy_rotator=proxy_rotator,
            auth_manager=auth_manager,
            cleanup_tracker=tracker,
            execution_errors=execution_errors,
            skip_from_state=resume_state,
        ))
        total_probes_fired = sum(max(f.observation_count, 1) for f in findings)
        total_findings_emitted = len(findings)
        total_probe_errors = sum(f.error_count for f in findings)
        unique_fps = {pc.fingerprint for pc in prepared}
        total_skipped_groups = max(0, len(unique_fps) - total_findings_emitted)
        has_cb = any(err.get("type") == "circuit_breaker" for err in execution_errors)
        if has_cb:
            scan_status = "aborted_circuit_breaker"
        elif execution_errors or total_probe_errors > 0:
            scan_status = "completed_with_errors"
        else:
            scan_status = "completed"

        result_manager.append_findings(
            findings,
            source="schemathesis",
            fieldnames=list(Finding.model_fields.keys()),
        )
        state.save()

        result_manager.append_run_summary({
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "schemathesis",
            "targets": targets_desc,
            "total_payloads": total_payloads,
            "total_dropped_at_prepare": total_dropped_at_prepare,
            "total_fired": total_probes_fired,
            "total_skipped_dedup": total_skipped_groups,
            "total_confirmed": sum(1 for f in findings if f.confirmed),
            "llm_used": bool(payloads_path),
        }, [
            "run_id", "timestamp", "tool", "targets", "total_payloads",
            "total_dropped_at_prepare", "total_fired", "total_skipped_dedup",
            "total_confirmed", "llm_used",
        ])
        result_manager.write_manifest(
            targets_desc,
            run_id=run_id,
            metadata={
                "tool": "schemathesis",
                "status": scan_status,
                "total_payloads": total_payloads,
                "total_fired": total_probes_fired,
                "total_findings": total_findings_emitted,
                "total_probe_errors": total_probe_errors,
                "execution_errors": execution_errors,
                "total_confirmed": sum(1 for finding in findings if finding.confirmed),
                "payload_mode": "custom" if payloads_path else "openapi",
            },
        )

        try:
            manifest_path = tracker.write_manifest()
            if tracker.created_resources:
                print(
                    f"[STAGING SAFETY] Recorded {len(tracker.created_resources)} "
                    f"created resource(s) in {manifest_path.name}"
                )
        except Exception as exc:
            logger.warning("Failed to write cleanup manifest: %s", exc)

        status_label = "[DONE]" if scan_status == "completed" else f"[WARNING:{scan_status.upper()}]"
        print(
            f"{status_label} run_id={run_id} | prepared={total_prepared}/{total_payloads} "
            f"| probes={total_probes_fired} | findings={total_findings_emitted} "
            f"| errors={total_probe_errors + len(execution_errors)} | skipped_dedup={total_skipped_groups} "
            f"| confirmed={sum(1 for f in findings if f.confirmed)} "
            f"| log: {resolved_results_dir / 'vulnerabilities.csv'}"
        )
        return findings
    finally:
        STATE_RUN_ID.reset(token_reset)


# --------------------------------------------------------------------------
# 6. CLI Entrypoint
# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None):
    ap = argparse.ArgumentParser(description="Schemathesis REST API Security Fuzzer (single and multi-target)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--spec", default=None,
                      help="Single-target mode: path/URL to one OpenAPI spec (.json/.yaml)")
    mode.add_argument("--targets", default=None,
                      help="Multi-target mode: comma-separated 'name=path' entries, "
                           "e.g. 'api1=openapi1.yaml,api2=openapi2.json'")
    ap.add_argument(
        "--payloads",
        default=None,
        help="Optional JSON payload file; without it, generate schema-valid cases from OpenAPI",
    )
    ap.add_argument("--base-url", default=None,
                    help="Override base_url for --spec mode")
    ap.add_argument("--base-urls", default=None,
                    help="Override per-target base_url for --targets mode, e.g. "
                         "'api1=http://localhost:8000,api2=http://localhost:8001'")
    ap.add_argument(
        "--allow-remote-schema",
        action="store_true",
        help="Explicitly allow loading an OpenAPI document from an HTTP(S) URL",
    )
    ap.add_argument("--auth-header", default=None,
                    help="Auth header (prefer FUZZ_AUTH_HEADER env var to avoid shell history leakage)")
    ap.add_argument("--results-dir", default=str(PROJECT_PATHS.results))
    ap.add_argument("--rate-limit-ms", type=int, default=200,
                    help="Delay in ms between requests within the same fingerprint group")
    ap.add_argument("--concurrency", type=int, default=10,
                    help="Maximum concurrent async requests")
    ap.add_argument("--global-rps", type=float, default=0,
                    help="Global requests-per-second limit (0 = unlimited)")
    ap.add_argument(
        "--rules",
        default=str(PROJECT_PATHS.config / "rules.json"),
        help="OWASP+CVE rules JSON file",
    )
    ap.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    ap.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")
    ap.add_argument(
        "--resume",
        action="store_true",
        help="Skip fingerprints already confirmed or at max attempts in state.json",
    )
    args = ap.parse_args(argv)

    if args.spec:
        schema, base_url = load_schema(
            args.spec,
            args.base_url,
            allow_remote=args.allow_remote_schema,
        )
        target_name = Path(args.spec).stem.lower()
        targets = {target_name: (schema, base_url)}
        print(f"[INFO] Single-target mode: '{target_name}'")
        targets_desc = args.spec
    else:
        targets = load_targets(
            args.targets,
            args.base_urls,
            allow_remote_schema=args.allow_remote_schema,
        )
        print(f"[INFO] Multi-target mode: {sorted(targets)}")
        targets_desc = args.targets

    headers = {}
    auth_header = os.environ.get("FUZZ_AUTH_HEADER")
    if auth_header:
        print("[INFO] Loaded auth header from FUZZ_AUTH_HEADER environment variable.")
    elif args.auth_header:
        print("[WARNING] Passing --auth-header via CLI may expose tokens in shell history/ps. "
              "Prefer setting FUZZ_AUTH_HEADER in the environment.",
              file=sys.stderr)
        auth_header = args.auth_header
    if auth_header:
        k, _, v = auth_header.partition(":")
        headers[k.strip()] = v.strip()
    extra_json = os.environ.get("FUZZ_EXTRA_HEADERS_JSON")
    if extra_json:
        try:
            extra_map = json.loads(extra_json)
            if isinstance(extra_map, dict):
                for hk, hv in extra_map.items():
                    headers[str(hk).strip()] = str(hv).strip()
        except Exception as exc:
            logger.warning("Ignoring malformed FUZZ_EXTRA_HEADERS_JSON: %s", exc)

    user2_headers = {}
    auth_header_user2 = os.environ.get("FUZZ_AUTH_HEADER_USER2")
    if auth_header_user2:
        k2, _, v2 = auth_header_user2.partition(":")
        user2_headers[k2.strip()] = v2.strip()
        print("[INFO] Loaded secondary user auth header for cross-user BOLA/IDOR testing.")

    execute_rest_scan(
        targets=targets,
        targets_desc=targets_desc,
        headers=headers,
        user2_headers=user2_headers or None,
        payloads_path=args.payloads,
        rules_path=args.rules,
        results_dir=args.results_dir,
        concurrency=args.concurrency,
        rate_limit_ms=args.rate_limit_ms,
        global_rps=args.global_rps,
        proxy=args.proxy,
        insecure=args.insecure,
        resume_state=args.resume,
    )
