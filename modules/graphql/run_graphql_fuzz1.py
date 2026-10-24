#!/usr/bin/env python3
"""
run_graphql_fuzz.py
Generic GraphQL API fuzzer.

Dispatches payloads against any GraphQL target registered in
targets/registry.yaml with protocol: graphql.

Expected payload format:
{
  "target_app": "<target_id>",
  "query": "query { ... }",
  "variables": {},
  "operation_name": null,
  "operation": "query",
  "attack_type": "GraphQL Injection",
  "payload_value": "...",
  "owasp_category": "API...",
  "context": "...",
  "expected_signal": ["..."]
}

The target's base_url and endpoint are resolved from the registry or
overridden via CLI:
  --base-url http://<HOST>:<PORT>
  --endpoint /graphql
"""

from __future__ import annotations

import argparse
import asyncio
import csv
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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from pydantic import BaseModel, Field, ValidationError

from modules.security import rules_engine
from core import (ConfirmationEngine, Evidence, Finding, RequestScheduler,
                  ProjectPaths, ResultManager, TargetManager, content_hash,
                  redact_headers, snapshot_response, stable_finding_id)

PROJECT_PATHS = ProjectPaths.from_root(PROJECT_ROOT)


DEFAULT_ERROR_SIGNALS = [
    "internal server error",
    "traceback",
    "stack trace",
    "syntax error",
    "syntaxerror",
    "exception",
    "unhandled",
    "database error",
    "sql syntax",
    "graphql error",
]

SEVERITY_BY_STATUS = {500: "high", 502: "high", 503: "medium"}
MAX_ATTEMPTS_PER_FINGERPRINT = 3
RUN_ID = ""


class GraphQLPayload(BaseModel):
    query: str
    variables: dict[str, Any] = Field(default_factory=dict)
    operation_name: Optional[str] = None

    attack_type: str
    payload_value: Any = None
    owasp_category: Optional[str] = None
    context: Optional[str] = None
    expected_signal: list[str] = Field(default_factory=list)
    technology: Optional[dict[str, str]] = None
    mutation_family: Optional[str] = None

    target_app: Optional[str] = None
    operation: Optional[str] = None


def fingerprint_of(
    target_app: str,
    endpoint: str,
    operation: Optional[str],
    attack_type: str,
    query: str,
    mutation_family: Optional[str] = None,
) -> str:
    query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()[:12]
    clean = endpoint.strip().strip("/") if endpoint else ""
    normalized_endpoint = "/" + clean if clean else (endpoint or "/")
    raw = (
        f"{target_app.lower()}|POST|{normalized_endpoint}|"
        f"{operation or ''}|{attack_type.lower()}|{mutation_family or ''}|{query_hash}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class RunState:
    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, dict[str, Any]] = {}
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8")
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise ValueError(
                        f"State file must contain a JSON object, got {type(parsed).__name__}"
                    )
                self.data = parsed
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                archive = self.path.with_name(f"{self.path.stem}_corrupted{self.path.suffix}")
                suffix = 2
                while archive.exists():
                    archive = self.path.with_name(f"{self.path.stem}_corrupted_{suffix}{self.path.suffix}")
                    suffix += 1
                archive_saved = False
                try:
                    shutil.copy2(self.path, archive)
                    archive_saved = True
                except OSError as copy_exc:
                    print(f"[CANH BAO] Khong the luu ban sao state bi hong: {copy_exc}", file=sys.stderr)

                if archive_saved:
                    archive_msg = f"File goc da duoc luu tai {archive}."
                else:
                    archive_msg = "Khong the tao ban sao luu tru; file goc van duoc giu nguyen tren dia."

                print(
                    f"[CANH BAO] State {self.path} bi loi ({exc}). "
                    f"{archive_msg} "
                    f"Khoi tao state moi rong (du lieu lich su chua duoc khoi phuc).",
                    file=sys.stderr,
                )
                self.data = {}
            except OSError as exc:
                print(
                    f"[CANH BAO] Khong the doc file state {self.path}: {exc}. "
                    "Khoi tao state moi rong.",
                    file=sys.stderr,
                )
                self.data = {}

    def status(self, fp: str) -> Optional[str]:
        return self.data.get(fp, {}).get("status")

    def attempts(self, fp: str) -> int:
        return self.data.get(fp, {}).get("attempts", 0)

    def record(self, fp: str, status: str) -> None:
        entry = self.data.setdefault(fp, {"attempts": 0, "status": "new"})
        entry["attempts"] += 1

        current = entry.get("status", "new")
        if current == "confirmed":
            pass
        elif current == "candidate" and status == "rejected":
            pass
        else:
            entry["status"] = status

        entry["last_seen"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def save(self) -> None:
        temp_path = self.path.with_name(f"{self.path.name}.tmp.{uuid.uuid4().hex[:8]}")
        try:
            temp_path.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            temp_path.replace(self.path)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise


def load_durable_confirmed_fingerprints(results_dir: Path) -> set[str]:
    """Return the set of fingerprints confirmed in durable report artifacts.

    A finding is durable if it is recorded as confirmed in all existing report
    stores (vulnerabilities.csv and vulnerabilities.ndjson).
    """
    csv_path = results_dir / "vulnerabilities.csv"
    ndjson_path = results_dir / "vulnerabilities.ndjson"

    has_csv = csv_path.exists() and csv_path.stat().st_size > 0
    has_ndjson = ndjson_path.exists() and ndjson_path.stat().st_size > 0

    if not has_csv and not has_ndjson:
        return set()

    csv_confirmed: set[str] = set()
    if has_csv:
        try:
            with csv_path.open("r", newline="", encoding="utf-8-sig") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    is_confirmed = (
                        str(row.get("confirmed", "")).strip().lower() == "true"
                        or str(row.get("lifecycle", "")).strip().lower() == "confirmed"
                    )
                    fp = str(row.get("fingerprint", "")).strip()
                    if is_confirmed and fp:
                        csv_confirmed.add(fp)
        except (csv.Error, OSError, UnicodeDecodeError) as exc:
            print(f"[CANH BAO] Khong the doc CSV de kiem tra bao cao ben vung: {exc}", file=sys.stderr)
            return set()

    ndjson_confirmed: set[str] = set()
    if has_ndjson:
        try:
            with ndjson_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    is_confirmed = (
                        record.get("confirmed") is True
                        or record.get("lifecycle") == "confirmed"
                    )
                    fp = str(record.get("fingerprint", "")).strip()
                    if is_confirmed and fp:
                        ndjson_confirmed.add(fp)
        except (OSError, UnicodeDecodeError) as exc:
            print(f"[CANH BAO] Khong the doc NDJSON de kiem tra bao cao ben vung: {exc}", file=sys.stderr)
            return set()

    if has_csv and has_ndjson:
        return csv_confirmed & ndjson_confirmed
    return csv_confirmed if has_csv else ndjson_confirmed


def is_finding_durable(results_dir: Path, fp: str) -> bool:
    """Return True if the confirmed finding is durably persisted in required report artifacts."""
    return fp in load_durable_confirmed_fingerprints(results_dir)


def load_payloads(payload_path: str) -> list[GraphQLPayload]:
    path = PROJECT_PATHS.resolve(payload_path, allow_outside=True)

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[LOI] Khong doc duoc payload file {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(raw, dict):
        raw = raw.get("payloads", [raw])

    if not isinstance(raw, list):
        print("[LOI] Payload JSON phai la list hoac object co key 'payloads'.",
              file=sys.stderr)
        sys.exit(1)

    valid: list[GraphQLPayload] = []

    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            print(f"[CANH BAO] Payload #{i} khong phai object, bo qua.",
                  file=sys.stderr)
            continue
        try:
            valid.append(GraphQLPayload(**item))
        except ValidationError as exc:
            print(
                f"[CANH BAO] GraphQL payload #{i} sai schema, bo qua:\n{exc}",
                file=sys.stderr,
            )

    if not valid:
        print("[LOI] Khong co GraphQL payload hop le nao.", file=sys.stderr)
        sys.exit(1)

    return valid


def build_graphql_request(payload: GraphQLPayload) -> dict[str, Any]:
    body: dict[str, Any] = {
        "query": payload.query,
        "variables": payload.variables,
    }
    if payload.operation_name:
        body["operationName"] = payload.operation_name
    return body


def _replace_value(value: Any, attack_value: Any, baseline_value: Any) -> Any:
    if value == attack_value:
        return baseline_value
    if isinstance(value, dict):
        return {key: _replace_value(item, attack_value, baseline_value)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_value(item, attack_value, baseline_value) for item in value]
    return value


def build_baseline_payload(payload: GraphQLPayload) -> Optional[GraphQLPayload]:
    """Keep GraphQL operation shape while replacing only the attack value."""
    attack_value = payload.payload_value
    if attack_value is None:
        return None
    if isinstance(attack_value, bool):
        baseline_value = False
    elif isinstance(attack_value, int):
        baseline_value = 1
    elif isinstance(attack_value, float):
        baseline_value = 1.0
    elif isinstance(attack_value, list):
        baseline_value = attack_value[:1]
    elif isinstance(attack_value, dict):
        baseline_value = {}
    elif isinstance(attack_value, str):
        baseline_value = "normal"
    else:
        baseline_value = None
    if baseline_value is None:
        return None
    baseline_query = payload.query
    if isinstance(attack_value, str):
        baseline_query = baseline_query.replace(
            json.dumps(attack_value), json.dumps(baseline_value), 1,
        )
    baseline_variables = _replace_value(
        payload.variables, attack_value, baseline_value,
    )
    if baseline_query == payload.query and baseline_variables == payload.variables:
        return None
    return payload.model_copy(update={
        "query": baseline_query,
        "variables": baseline_variables,
        "payload_value": baseline_value,
    })


def extract_graphql_errors(response_json: Any) -> list[str]:
    if not isinstance(response_json, dict):
        return []

    errors = response_json.get("errors")
    if not isinstance(errors, list):
        return []

    messages: list[str] = []
    for error in errors:
        if isinstance(error, dict):
            message = error.get("message")
            if message:
                messages.append(str(message))
        elif error:
            messages.append(str(error))
    return messages


def response_text(response: httpx.Response) -> str:
    try:
        return json.dumps(response.json(), ensure_ascii=False)
    except Exception:
        return response.text or ""


def evaluate_response(
    resp: httpx.Response,
    payload: GraphQLPayload,
    rules: Optional[dict] = None,
) -> tuple[str, bool, str, list[str]]:
    """
    Evaluate one GraphQL response.

    Detection policy:
      1. Payload-specific expected_signal is strong evidence.
      2. Generic rules_engine signals are evidence only; they MUST NOT
         independently make a finding confirmed.
      3. HTTP 5xx remains a strong server-side failure signal.
      4. GraphQL errors/HTTP 4xx are not automatically vulnerabilities.
    """
    status = resp.status_code
    body = response_text(resp)
    body_lower = body.lower()

    # ------------------------------------------------------------
    # 1. Separate payload-specific signals from generic rule signals
    # ------------------------------------------------------------
    expected_signals = [
        str(s).strip().lower()
        for s in payload.expected_signal
        if str(s).strip()
    ]

    if rules is not None:
        generic_signals = [
            str(s).strip().lower()
            for s in rules_engine.get_all_signals(rules)
            if str(s).strip()
        ]
    else:
        generic_signals = [
            str(s).strip().lower()
            for s in DEFAULT_ERROR_SIGNALS
            if str(s).strip()
        ]

    # Deduplicate while preserving order.
    expected_signals = list(dict.fromkeys(expected_signals))
    generic_signals = list(dict.fromkeys(generic_signals))

    # IMPORTANT:
    # Generic signals such as "debug", "exception", "error", etc.
    # are NOT enough to confirm a vulnerability.
    expected_hits = [
        s for s in expected_signals
        if s in body_lower
    ]

    generic_hits = [
        s for s in generic_signals
        if s in body_lower
    ]

    # ------------------------------------------------------------
    # 2. Parse GraphQL errors
    # ------------------------------------------------------------
    try:
        response_json = resp.json()
    except Exception:
        response_json = None

    gql_errors = extract_graphql_errors(response_json)

    # ------------------------------------------------------------
    # 3. Match CVEs as before
    # ------------------------------------------------------------
    matched_cves: list[dict] = []

    if rules is not None:
        matched_cves = rules_engine.match_cves_by_keyword(
            rules,
            payload.attack_type,
            payload.owasp_category,
            payload.technology,
        )

    cve_ids = [c["cve_id"] for c in matched_cves]

    # ------------------------------------------------------------
    # 4. Determine severity + candidate status. Confirmation is done by the
    # shared baseline-vs-attack engine after this detector returns.
    # ------------------------------------------------------------

    # Server-side 5xx is a strong candidate signal, not confirmation.
    if status >= 500:
        severity = SEVERITY_BY_STATUS.get(status, "high")
        candidate = True

        evidence_parts = [
            f"HTTP {status}",
        ]

        if expected_hits:
            evidence_parts.append(
                f"matched expected signal={expected_hits}"
            )

        if generic_hits:
            evidence_parts.append(
                f"generic signal={generic_hits[:5]}"
            )

        if gql_errors:
            evidence_parts.append(
                f"GraphQL errors={gql_errors[:3]}"
            )

        evidence = "; ".join(evidence_parts)

    # Payload-specific expected signal is the primary candidate mechanism.
    elif expected_hits:
        severity = "medium"
        candidate = True

        evidence_parts = [
            f"HTTP {status}",
            f"matched expected signal={expected_hits}",
        ]

        # Generic signals remain useful as supporting evidence.
        if generic_hits:
            evidence_parts.append(
                f"generic signal={generic_hits[:5]}"
            )

        if gql_errors:
            evidence_parts.append(
                f"GraphQL errors={gql_errors[:3]}"
            )

        evidence = "; ".join(evidence_parts)

    # Generic signal only: evidence, NOT a candidate.
    elif generic_hits:
        severity = "info"
        candidate = False

        evidence_parts = [
            f"HTTP {status}",
            f"generic signal only={generic_hits[:5]}",
            "khong du de xac nhan vulnerability",
        ]

        if gql_errors:
            evidence_parts.append(
                f"GraphQL errors={gql_errors[:3]}"
            )

        evidence = "; ".join(evidence_parts)

    # GraphQL errors are not vulnerabilities by themselves.
    elif gql_errors:
        severity = "info"
        candidate = False
        evidence = (
            f"HTTP {status}; "
            f"GraphQL errors={gql_errors[:3]}"
        )

    else:
        severity = "info"
        candidate = False
        evidence = (
            f"HTTP {status}; "
            "khong phat hien dau hieu bat thuong"
        )

    return severity, candidate, evidence, cve_ids


async def fire_case(
    client: httpx.AsyncClient,
    url: str,
    payload: GraphQLPayload,
    headers: dict[str, str],
) -> httpx.Response:
    return await client.post(
        url,
        json=build_graphql_request(payload),
        headers=headers,
    )


async def process_payload(
    client: httpx.AsyncClient,
    scheduler: RequestScheduler,
    payload: GraphQLPayload,
    base_url: str,
    endpoint: str,
    headers: dict[str, str],
    rules: Optional[dict],
    state: RunState,
    rate_limit_s: float,
    target_id: str = "dvga",
) -> Optional[Finding]:
    target_app = (payload.target_app or target_id).strip().lower()

    fp = fingerprint_of(
        target_app,
        endpoint,
        payload.operation or payload.operation_name,
        payload.attack_type,
        payload.query,
        payload.mutation_family,
    )

    if state.status(fp) == "confirmed" and is_finding_durable(state.path.parent, fp):
        return None
    if state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT and state.status(fp) != "confirmed":
        return None

    url = base_url.rstrip("/") + "/" + endpoint.lstrip("/")
    baseline_payload = build_baseline_payload(payload)
    attack_response = None
    try:
        async def execute_baseline():
            return await scheduler.request(
                target_app,
                lambda: fire_case(client, url, baseline_payload, headers),
            )

        async def execute_attack():
            nonlocal attack_response
            attack_response = await scheduler.request(
                target_app,
                lambda: fire_case(client, url, payload, headers),
            )
            return attack_response

        def candidate_detector(response):
            return evaluate_response(response, payload, rules)[1]

        result = await ConfirmationEngine().confirm(
            candidate_detector,
            execute_baseline if baseline_payload is not None else None,
            execute_attack,
            lambda response, elapsed: snapshot_response(response, elapsed, graphql=True),
        )
        error_text = None
    except Exception as exc:
        attack_response = None
        result = None
        error_text = str(exc)
    resp = attack_response

    if rate_limit_s:
        await asyncio.sleep(rate_limit_s)

    if resp is None or result is None:
        severity = "unknown"
        confirmed = False
        evidence = f"request loi: {error_text}"
        status_code = None
        cve_ids: list[str] = []
        confidence = 0.1
        confirmation_differences = {}
    else:
        severity, confirmed, evidence, cve_ids = evaluate_response(
            resp, payload, rules
        )
        status_code = resp.status_code
        # A baseline/attack difference alone is not proof of exploitation.
        # Require a payload-specific expected signal in the attack response.
        attack_body = response_text(resp).lower()
        expected_signals = [
            str(signal).strip().lower()
            for signal in payload.expected_signal
            if str(signal).strip()
        ]
        matched_expected_signals = [
            signal for signal in expected_signals
            if signal in attack_body
        ]

        # A response difference is not proof of exploitation.
        # Keep findings as candidates until a vulnerability-specific
        # confirmation strategy is implemented and tested.
        confirmed = False
        confidence = min(result.confidence, 0.55)
        confirmation_differences = dict(result.evidence)
        confirmation_differences["confirmation_policy"] = (
            "candidate_only_pending_vulnerability_specific_validation"
        )
        if expected_signals and not matched_expected_signals:
            confirmation_differences["expected_signal_match"] = {
                "matched": False,
                "required_signals": expected_signals,
            }

    elapsed_ms = result.attack.response_time_ms if result and result.attack else 0

    request_payload = {
        "query": payload.query,
        "variables": payload.variables,
        "operation_name": payload.operation_name,
        "payload_value": payload.payload_value,
    }
    evidence_model = Evidence(
        status_code=status_code,
        response_headers=redact_headers(dict(resp.headers)) if resp is not None else {},
        response_signal=[evidence],
        response_time_ms=round(elapsed_ms, 1),
        payload_hash=content_hash(payload.payload_value),
        request_hash=content_hash(request_payload),
        endpoint=endpoint,
        payload=request_payload,
        auth_context=redact_headers(headers),
        previous_observations=([{
            "role": "baseline",
            "status_code": result.baseline.status_code,
            "response_time_ms": result.baseline.response_time_ms,
            "graphql_errors": result.baseline.graphql_errors,
            "data_shape": result.baseline.data_shape,
            "differences": confirmation_differences,
        }] if result and result.baseline else []),
    )
    finding = Finding(
        finding_id=stable_finding_id(
            target_app, "POST", endpoint, payload.attack_type,
            payload.operation or payload.operation_name or "graphql",
        ),
        run_id=RUN_ID,
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool="schemathesis",
        target_app=target_app,
        endpoint=endpoint,
        method="POST",
        attack_type=payload.attack_type,
        owasp_category=payload.owasp_category,
        payload={
            "query": payload.query,
            "variables": payload.variables,
            "operation_name": payload.operation_name,
            "payload_value": payload.payload_value,
        },
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
        cve_match_type=("cpe" if payload.technology else "keyword") if cve_ids else "",
        cve_confidence=0.94 if payload.technology and cve_ids else (0.2 if cve_ids else 0.0),
    )

    state.record(fp, "confirmed" if confirmed else ("candidate" if result and result.candidate else "rejected"))
    return finding


async def run_all(
    payloads: list[GraphQLPayload],
    base_url: str,
    endpoint: str,
    headers: dict[str, str],
    rules: Optional[dict],
    state: RunState,
    concurrency: int,
    rate_limit_ms: int,
    global_rps: float = 0,
    target_id: str = "dvga",
) -> list[Finding]:
    scheduler = RequestScheduler(concurrency=concurrency, global_rps=global_rps)
    results_dir = state.path.parent
    durable_confirmed = load_durable_confirmed_fingerprints(results_dir)

    # Deduplicate identical fingerprints within this batch while preserving order.
    unique_payloads = []
    seen_fingerprints = set()
    for payload in payloads:
        target_app = (payload.target_app or target_id).strip().lower()
        fp = fingerprint_of(
            target_app,
            endpoint,
            payload.operation or payload.operation_name,
            payload.attack_type,
            payload.query,
            payload.mutation_family,
        )
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        # Skip findings already confirmed in the durable report artifacts.
        if fp in durable_confirmed:
            if state.status(fp) != "confirmed":
                state.record(fp, "confirmed")
            continue

        # If state marks it confirmed, but report artifacts do not have it:
        # It was interrupted before persistence! Do NOT skip it!
        if state.status(fp) == "confirmed" and fp not in durable_confirmed:
            print(
                f"[CANH BAO] Fingerprint '{fp}' da duoc ghi nhan confirmed trong state "
                "nhung chua co trong bao cao ben vung (vulnerabilities.csv/ndjson). "
                "Khoi phuc de chay lai va bao cao.",
                file=sys.stderr,
            )
        elif state.attempts(fp) >= MAX_ATTEMPTS_PER_FINGERPRINT:
            continue

        unique_payloads.append(payload)

    async with httpx.AsyncClient(timeout=20.0) as client:
        tasks = [
            process_payload(
                client, scheduler, payload, base_url, endpoint,
                headers, rules, state, rate_limit_ms / 1000, target_id,
            )
            for payload in unique_payloads
        ]
        raw_results = await asyncio.gather(*tasks)

    return [result for result in raw_results if result is not None]


def write_results(
    findings: list[Finding],
    results_dir: Path,
    run_id: str,
    target_desc: str,
    total_payloads: int,
    total_skipped_dedup: int,
) -> None:
    result_manager = ResultManager(PROJECT_ROOT, results_dir=results_dir)

    # Avoid duplicate rows in vulnerabilities.csv if some findings were already in CSV
    # (e.g. prior interrupted run that wrote CSV but failed before NDJSON or state save).
    existing_csv_fps: set[str] = set()
    csv_path = results_dir / "vulnerabilities.csv"
    if csv_path.exists() and csv_path.stat().st_size > 0:
        try:
            with csv_path.open("r", newline="", encoding="utf-8-sig") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    if str(row.get("confirmed", "")).strip().lower() == "true":
                        fp = str(row.get("fingerprint", "")).strip()
                        if fp:
                            existing_csv_fps.add(fp)
        except Exception:
            pass

    new_findings = [f for f in findings if f.fingerprint not in existing_csv_fps]

    if new_findings:
        result_manager.append_findings(
            new_findings,
            source="graphql",
            fieldnames=list(Finding.model_fields.keys()),
        )
    elif findings:
        # All findings already in CSV; ensure NDJSON has them without duplicating CSV
        ndjson_path = results_dir / "vulnerabilities.ndjson"
        existing_ndjson_fps: set[str] = set()
        if ndjson_path.exists() and ndjson_path.stat().st_size > 0:
            try:
                with ndjson_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                            if record.get("confirmed") is True and record.get("fingerprint"):
                                existing_ndjson_fps.add(str(record["fingerprint"]).strip())
                        except Exception:
                            continue
            except Exception:
                pass
        missing_ndjson = [f for f in findings if f.fingerprint not in existing_ndjson_fps]
        if missing_ndjson:
            with ndjson_path.open("a", encoding="utf-8") as output:
                for finding in missing_ndjson:
                    record = finding.model_dump()
                    record["source"] = "graphql"
                    output.write(json.dumps(record, ensure_ascii=False) + "\n")

    fields = [
        "run_id", "timestamp", "tool", "targets", "total_payloads",
        "total_dropped_at_prepare", "total_fired", "total_skipped_dedup",
        "total_confirmed", "llm_used",
    ]
    result_manager.append_run_summary({
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "graphql",
        "targets": target_desc,
        "total_payloads": total_payloads,
        "total_dropped_at_prepare": 0,
        "total_fired": len(findings),
        "total_skipped_dedup": total_skipped_dedup,
        "total_confirmed": sum(1 for x in findings if x.confirmed),
        "llm_used": True,
    }, fields)
    result_manager.write_manifest(
        target_desc,
        run_id=run_id,
        metadata={
            "tool": "graphql",
            "total_payloads": total_payloads,
            "total_fired": len(findings),
            "total_confirmed": sum(1 for finding in findings if finding.confirmed),
            "payload_mode": "custom",
        },
    )


def main() -> None:
    global RUN_ID

    ap = argparse.ArgumentParser(
        description="GraphQL API fuzzer"
    )

    ap.add_argument("--target-id", default="dvga",
                     help="Target identifier from targets/registry.yaml (default: dvga)")
    ap.add_argument("--payloads", required=True)
    ap.add_argument(
        "--base-url",
        default=None,
        help="Override target base URL from registry (or DVGA_BASE_URL when target is dvga)",
    )
    ap.add_argument(
        "--endpoint",
        default=None,
    )
    ap.add_argument("--results-dir", default=str(PROJECT_PATHS.results))
    ap.add_argument("--rate-limit-ms", type=int, default=200)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--global-rps", type=float, default=0,
                    help="Gioi han request/giay toan cuc (0 = tat)")
    ap.add_argument("--rules", default=str(PROJECT_PATHS.config / "rules.json"))
    ap.add_argument("--auth-header", default=None)

    args = ap.parse_args()

    args.target_id = args.target_id.strip().lower()
    target = TargetManager(PROJECT_ROOT).get_target(args.target_id)
    if target.settings.get("protocol") != "graphql":
        ap.error(f"Target '{args.target_id}' is not configured for GraphQL")
    base_url = (
        args.base_url
        or (os.environ.get("DVGA_BASE_URL") if args.target_id == "dvga" else None)
        or target.base_url
    )

    configured_endpoint = target.settings.get("endpoint", "/graphql")
    endpoint = "/" + (args.endpoint or str(configured_endpoint)).strip("/")
    print(f"[INFO] GraphQL target: {base_url.rstrip('/')}{endpoint}")

    rules_path = PROJECT_PATHS.resolve(args.rules, allow_outside=True)
    rules = None
    if rules_path.exists():
        rules = rules_engine.load_rules(str(rules_path))
        n_cve = len(rules.get("cve_signals", []))
        last_upd = rules.get("meta", {}).get("cve_last_updated")
        print(
            f"[INFO] Rules nap tu {rules_path}: {n_cve} CVE cache "
            f"(cap nhat: {last_upd or 'chua tung'})."
        )
    else:
        print(
            f"[CANH BAO] Khong thay {args.rules} - dung signal mac dinh.",
            file=sys.stderr,
        )

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    auth_header = os.environ.get("FUZZ_AUTH_HEADER") or args.auth_header
    if auth_header:
        key, sep, value = auth_header.partition(":")
        if sep:
            headers[key.strip()] = value.strip()
        else:
            print(
                "[CANH BAO] Auth header phai co dang 'Header: value'.",
                file=sys.stderr,
            )

    payloads = load_payloads(args.payloads)
    total_payloads = len(payloads)

    selected = []
    for payload in payloads:
        payload_target = (payload.target_app or args.target_id).strip().lower()
        if payload_target != args.target_id:
            print(
                f"[CANH BAO] target_app='{payload_target}' khac "
                f"{args.target_id} -> bo qua.",
                file=sys.stderr,
            )
            continue
        selected.append(payload)

    if not selected:
        print(f"[LOI] Khong co GraphQL payload target_app='{args.target_id}'.",
              file=sys.stderr)
        sys.exit(1)

    result_manager = ResultManager(PROJECT_ROOT, results_dir=args.results_dir)
    results_dir = result_manager.ensure_results_dir()

    RUN_ID = result_manager.make_run_id(prefix="graphql")
    state = RunState(results_dir / "state_graphql.json")

    before_attempts = {}
    for payload in selected:
        fp = fingerprint_of(
            (payload.target_app or args.target_id).lower(),
            endpoint,
            payload.operation or payload.operation_name,
            payload.attack_type,
            payload.query,
            payload.mutation_family,
        )
        before_attempts[fp] = state.attempts(fp)

    findings = asyncio.run(
        run_all(
            selected,
            base_url,
            endpoint,
            headers,
            rules,
            state,
            max(1, args.concurrency),
            max(0, args.rate_limit_ms),
            args.global_rps,
            args.target_id,
        )
    )

    fired_fps = {x.fingerprint for x in findings}
    total_skipped_dedup = sum(
        1
        for fp, attempts in before_attempts.items()
        if (
            (attempts >= MAX_ATTEMPTS_PER_FINGERPRINT)
            or (state.status(fp) == "confirmed" and fp not in fired_fps)
        )
    )

    try:
        write_results(
            findings,
            results_dir,
            RUN_ID,
            f"{base_url.rstrip('/')}{endpoint}",
            total_payloads,
            total_skipped_dedup,
        )
    except Exception as exc:
        print(f"[LOI] Khong the luu bao cao ket qua: {exc}", file=sys.stderr)
        sys.exit(1)

    state.save()

    print(
        f"[XONG] run_id={RUN_ID} | "
        f"payload_hop_le={len(selected)}/{total_payloads} | "
        f"ban={len(findings)} | "
        f"bo_qua(dedup)={total_skipped_dedup} | "
        f"phat_hien={sum(1 for x in findings if x.confirmed)} | "
        f"log: {results_dir / 'vulnerabilities.csv'}"
    )


if __name__ == "__main__":
    main()
