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
import json
import os
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import core.schema_validator  # Ensures pure-Python fallback shim is loaded if needed
except Exception:
    pass

import httpx
import schemathesis
from pydantic import BaseModel, Field, ValidationError

from modules.security import rules_engine
from core import (
    ConfirmationEngine,
    Evidence,
    Finding,
    RequestScheduler,
    ProjectPaths,
    ResultManager,
    RunState,
    SchemaManager,
    DEFAULT_ERROR_SIGNALS,
    MAX_ATTEMPTS_PER_FINGERPRINT,
    SEVERITY_BY_STATUS,
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
    --targets 'vampi=vampi_spec.yaml,crapi=crapi_spec.json'
    --base-urls 'vampi=http://localhost:5002,crapi=http://localhost:8888'
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
                  "e.g. 'vampi=vampi_spec.yaml'.", file=sys.stderr)
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
            except Exception:
                pass

    for target_name, (schema, _) in sorted(targets.items()):
        for result in schema.get_all_operations():
            if not result.ok():
                continue
            operation = result.ok()
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
            except Exception:
                pass

            # Fallback path params if iter_parameters did not catch all path templates
            path_params = re.findall(r"\{([^}]+)\}", operation.path)
            for p_name in path_params:
                if p_name in parameters_seen:
                    continue
                parameters_seen.add(p_name)
                param_schema = SemanticMutationEngine.inspect_param(p_name, "path", {})
                probes = SemanticMutationEngine.generate_probes(param_schema, seed_corpus=seed_corpus)
                for probe in probes:
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

            # 3. Built-in Mass Assignment & Schema Property Injection for state-changing endpoints
            if operation.method.upper() in ("POST", "PUT", "PATCH"):
                generated.append(Payload(
                    endpoint=operation.path,
                    method=operation.method,
                    target_param="role",
                    param_location="body",
                    attack_type="MASS_ASSIGNMENT",
                    payload_value="admin",
                    owasp_category="API3:2023",
                    expected_signal=["admin", "role", "success"],
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
                    expected_signal=["is_admin", "true", "admin"],
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

    if loc == "query":
        values = _baseline_component(baseline_case, "query")
        if not isinstance(values, dict):
            values = {}
        values[payload.target_param] = payload.payload_value
        kwargs["query"] = values
    elif loc == "path":
        values = _baseline_component(baseline_case, "path_parameters")
        if not isinstance(values, dict):
            values = {}
        values[payload.target_param] = payload.payload_value
        kwargs["path_parameters"] = values
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


def build_baseline_case(schema, op):
    """Generate a valid ordinary case from the operation schema."""
    strategy = getattr(op, "as_strategy", None)
    if callable(strategy):
        try:
            return strategy().example()
        except Exception:
            pass
    return schema.make_case(operation=op, method=op.method, path=op.path)


class PreparedCase:
    """Resolved payload bound to its target, base_url, baseline Case, and attack Case."""
    __slots__ = ("fingerprint", "target_app", "base_url", "baseline_case", "case", "payload")

    def __init__(self, fingerprint, target_app, base_url, baseline_case, case, payload):
        self.fingerprint = fingerprint
        self.target_app = target_app
        self.base_url = base_url
        self.baseline_case = baseline_case
        self.case = case
        self.payload = payload


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
            prepared.append(PreparedCase(fp, name, base_url, None, case, payload))
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
        prepared.append(PreparedCase(fp, name, base_url, baseline_case, case, payload))
    return prepared


def evaluate_response(resp, payload: Payload, rules: Optional[dict] = None
                       ) -> tuple[str, bool, str, list[str]]:
    """Return severity, candidate, evidence, and CVE enrichment.

    Generic keywords are context only. They must not independently create
    a candidate. Candidate status is not vulnerability confirmation.
    """
    status = resp.status_code
    body_lower = (resp.text or "").lower()
    attack_type = payload.attack_type.strip().upper()

    expected_signals = list(dict.fromkeys(
        str(signal).strip().lower()
        for signal in payload.expected_signal
        if str(signal).strip()
    ))

    # These are technical error indicators, unlike broad business words
    # such as "admin", "success", "content", or "deleted".
    technical_signals = [
        str(signal).strip().lower()
        for signal in DEFAULT_ERROR_SIGNALS
        if str(signal).strip()
    ]

    generic_signals = []
    matched_cves: list[dict] = []
    if rules is not None:
        generic_signals = [
            str(signal).strip().lower()
            for signal in rules_engine.get_all_signals(rules)
            if str(signal).strip()
        ]
        matched_cves = rules_engine.match_cves_by_keyword(
            rules, payload.attack_type, payload.owasp_category,
            payload.technology,
        )

    cve_ids = [item["cve_id"] for item in matched_cves]
    expected_hits = [s for s in expected_signals if s in body_lower]
    technical_hits = [s for s in technical_signals if s in body_lower]
    generic_hits = [
        s for s in dict.fromkeys(generic_signals)
        if s not in technical_signals and s in body_lower
    ]

    # An invalid/rejected authorization probe is not evidence of a bypass.
    if attack_type in ("BOLA", "IDOR", "BFLA", "AUTH_BYPASS") and status in (
        400, 401, 403, 404
    ):
        return (
            "info", False,
            f"HTTP {status}; authorization probe rejected or invalid; "
            "no bypass established",
            cve_ids,
        )

    # Server errors warrant investigation, but do not prove exploitation.
    if status >= 500:
        severity = SEVERITY_BY_STATUS.get(status, "high")
        details = expected_hits + technical_hits
        return (
            severity, True,
            f"HTTP {status}; server-error candidate; "
            f"technical/payload signals: {details[:3]}",
            cve_ids,
        )

    # Payload-specific signals can raise a candidate; they still do not
    # establish confirmed=True. ConfirmationEngine remains authoritative.
    if expected_hits:
        return (
            "medium", True,
            f"HTTP {status}; payload-specific signal: {expected_hits[:3]}",
            cve_ids,
        )

    # SQL-specific technical errors can be candidates even without a 5xx.
    if technical_hits and attack_type in (
        "SQLI", "SQL_INJECTION", "SQL INJECTION"
    ):
        return (
            "medium", True,
            f"HTTP {status}; technical SQL/error signal: {technical_hits[:3]}",
            cve_ids,
        )

    # Time-based blind injection evaluation
    elapsed_ms = extract_response_elapsed_ms(resp)

    if elapsed_ms is not None and elapsed_ms >= 3500:
        is_time_attack = "TIME" in attack_type or any(
            k in str(payload.payload_value).lower()
            for k in ("sleep", "waitfor", "pg_sleep", "delay")
        )
        if is_time_attack:
            return (
                "high", True,
                f"HTTP {status}; significant time delay observed ({round(elapsed_ms, 1)}ms >= 3500ms)",
                cve_ids,
            )

    # Broad rule keywords alone are weak evidence and must not create
    # a candidate or increase severity.
    if generic_hits:
        return (
            "info", False,
            f"HTTP {status}; generic keywords ignored as insufficient "
            f"evidence: {generic_hits[:3]}",
            cve_ids,
        )

    return (
        "info", False,
        f"HTTP {status}; no sufficiently specific vulnerability signal",
        cve_ids,
    )


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------

async def fire_case(client: "httpx.AsyncClient", case, base_url: str, headers: dict):
    """Translate a Schemathesis Case into an async httpx request via as_transport_kwargs()."""
    kwargs = case.as_transport_kwargs(base_url=base_url)
    if headers:
        kwargs["headers"] = {**kwargs.get("headers", {}), **headers}
    if not kwargs.get("cookies"):  # httpx warns on empty cookies={}
        kwargs.pop("cookies", None)
    return await client.request(**kwargs)


async def process_fingerprint_group(
    client: "httpx.AsyncClient", scheduler: RequestScheduler,
    fp: str, group: list[PreparedCase], headers: dict,
    rules: Optional[dict], state: RunState, rate_limit_s: float,
    user2_headers: Optional[dict] = None,
    cleanup_tracker: Optional[CleanupTracker] = None,
) -> list[Finding]:
    """Process one fingerprint group sequentially (stopping once confirmed or retry budget exhausted),
    while distinct fingerprint groups execute concurrently."""
    results: list[Finding] = []
    tracker = cleanup_tracker or GLOBAL_CLEANUP_TRACKER

    if state.status(fp) == "confirmed":
        return results
    if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
        return results

    for pc in group:
        if state.status(fp) == "confirmed":
            break
        if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
            break

        payload_value = pc.payload.payload_value
        attack_response = None
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

            def candidate_detector(response):
                return evaluate_response(response, pc.payload, rules)[1]

            result = await ConfirmationEngine().confirm(
                candidate_detector,
                execute_baseline if pc.baseline_case is not None else None,
                execute_attack,
                snapshot_response,
            )
            error_text = None
        except Exception as exc:
            attack_response = None
            result = None
            error_text = str(exc)
        if rate_limit_s:
            await asyncio.sleep(rate_limit_s)

        resp = attack_response
        if resp is None or result is None:
            severity, confirmed, evidence, cve_ids = "unknown", False, f"request error: {error_text}", []
            status_code = None
            confidence = 0.1
            confirmation_differences = {}
        else:
            severity, confirmed, evidence, cve_ids = evaluate_response(resp, pc.payload, rules)
            status_code = resp.status_code
            confirmed = result.confirmed
            confidence = result.confidence
            confirmation_differences = result.evidence

            # Schema validation barrier & adaptive feedback analysis
            if status_code in (400, 422):
                feedback = FeedbackAnalyzer.analyze_response(status_code, resp.text, dict(resp.headers))
                if feedback.is_validation_error and feedback.failed_fields:
                    recs_summary = "; ".join(feedback.adaptive_recommendations[:2])
                    evidence = f"HTTP {status_code}; Schema validation barrier ({feedback.framework_hint}): {recs_summary}"

            # Dual-token BOLA / IDOR cross-account verification
            if user2_headers and pc.payload.attack_type.upper() in ("BOLA", "IDOR"):
                if 200 <= status_code < 300:
                    confirmed = True
                    confidence = 0.95
                    severity = "high"
                    evidence = f"HTTP {status_code}; BOLA verified via dual-token cross-user validation (Secondary user accessed primary resource)"
                elif status_code in (401, 403):
                    confirmed = False
                    severity = "info"
                    evidence = f"HTTP {status_code}; Access denied as expected for secondary user (Authorization properly enforced)"

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
                    except Exception:
                        pass

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
                            confidence = 0.98
                            severity = "critical" if pc.payload.target_param in ("role", "is_admin", "admin") else "high"
                            evidence = f"HTTP {status_code}; {verify_msg}"
                        else:
                            confirmed = False
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
                except Exception:
                    pass
        elapsed_ms = result.attack.response_time_ms if result and result.attack else 0

        evidence_model = Evidence(
            status_code=status_code,
            response_headers=redact_headers(dict(resp.headers)) if resp is not None else {},
            response_signal=[evidence],
            response_time_ms=round(elapsed_ms, 1),
            payload_hash=content_hash(payload_value),
            request_hash=content_hash({
                "target": pc.target_app,
                "method": pc.payload.method,
                "endpoint": pc.payload.endpoint,
                "parameter": pc.payload.target_param,
                "value": payload_value,
            }),
            endpoint=pc.payload.endpoint,
            payload=payload_value,
            auth_context=redact_headers(headers),
            previous_observations=([{
                "role": "baseline",
                "status_code": result.baseline.status_code,
                "response_time_ms": result.baseline.response_time_ms,
                "differences": confirmation_differences,
            }] if result and result.baseline else []),
        )
        finding = Finding(
            finding_id=stable_finding_id(
                pc.target_app, pc.payload.method, pc.payload.endpoint,
                pc.payload.attack_type, pc.payload.target_param,
            ),
            run_id=STATE_RUN_ID.get(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool="schemathesis",
            target_app=pc.target_app,
            endpoint=pc.payload.endpoint,
            method=pc.payload.method,
            attack_type=pc.payload.attack_type,
            owasp_category=pc.payload.owasp_category,
            payload=pc.payload.payload_value,
            status_code=status_code,
            response_time_ms=round(elapsed_ms, 1),
            evidence=evidence_model,
            severity=severity,
            confidence=confidence,
            confirmed=confirmed,
            lifecycle=("confirmed" if confirmed else
                       ("candidate" if result and result.candidate else "rejected")),
            fingerprint=fp,
            cve_matches=cve_ids,
            cve_match_type=("cpe" if pc.payload.technology else "keyword") if cve_ids else "",
            cve_confidence=0.94 if pc.payload.technology and cve_ids else (0.2 if cve_ids else 0.0),
        )
        results.append(finding)
        state.record(fp, "confirmed" if confirmed else ("candidate" if result and result.candidate else "rejected"))

    return results


async def run_all(prepared: list[PreparedCase], headers: dict,
                   rules: Optional[dict], state: RunState, concurrency: int,
                   rate_limit_ms: int, global_rps: float = 0,
                   user2_headers: Optional[dict] = None,
                   proxy: Optional[str] = None,
                   insecure: bool = False,
                   session_keeper: Optional[Any] = None,
                   proxy_rotator: Optional[Any] = None,
                   auth_manager: Optional[Any] = None,
                   cleanup_tracker: Optional[CleanupTracker] = None) -> list[Finding]:
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

    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = [
            process_fingerprint_group(
                client, scheduler, fp, group, merged_headers,
                rules, state, rate_limit_ms / 1000,
                user2_headers=user2_headers,
                cleanup_tracker=cleanup_tracker,
            )
            for fp, group in groups.items()
        ]
        grouped_results = await asyncio.gather(*tasks)

    all_findings: list[Finding] = []
    for r in grouped_results:
        all_findings.extend(r)
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
        ))
        total_fired = len(findings)
        total_skipped = total_prepared - total_fired

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
            "total_fired": total_fired,
            "total_skipped_dedup": total_skipped,
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
                "total_payloads": total_payloads,
                "total_fired": total_fired,
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
        except Exception:
            pass

        print(
            f"[DONE] run_id={run_id} | prepared={total_prepared}/{total_payloads} "
            f"| fired={total_fired} | skipped_dedup={total_skipped} "
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
                           "e.g. 'vampi=vampi_spec.yaml,crapi=crapi_spec.json'")
    ap.add_argument(
        "--payloads",
        default=None,
        help="Optional JSON payload file; without it, generate schema-valid cases from OpenAPI",
    )
    ap.add_argument("--base-url", default=None,
                    help="Override base_url for --spec mode")
    ap.add_argument("--base-urls", default=None,
                    help="Override per-target base_url for --targets mode, e.g. "
                         "'vampi=http://localhost:5002,crapi=http://localhost:8888'")
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
        except Exception:
            pass

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
    )
