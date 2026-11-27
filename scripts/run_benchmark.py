#!/usr/bin/env python3
"""P1.6 Benchmark CLI & Orchestrator.

Starts the local deterministic BenchmarkLabServer on an ephemeral loopback port,
runs ``execute_rest_scan()`` against it into an isolated results directory,
verifies main ``results/`` integrity before/after execution, and computes
Ground Truth metrics without modifying scanner logic or existing artifacts.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import (
    BenchmarkEvaluator,
    CleanupTracker,
    ProjectPaths,
    load_ground_truth_manifest,
    normalize_vuln_class,
    run_auth_preflight,
    snapshot_files_integrity,
    verify_isolation,
)
from modules.rest import run_schemathesis1 as rest
from targets.benchmark_lab import (
    GROUND_TRUTH_PATH,
    OPENAPI_SPEC_PATH,
    BenchmarkLabServer,
    build_lab_auth_headers,
)


def _git_commit_short() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _protected_main_result_paths(paths: ProjectPaths) -> list[Path]:
    return [
        paths.results / "vulnerabilities.csv",
        paths.results / "vulnerabilities.ndjson",
        paths.results / "state.json",
        paths.results / "experiment_runs.csv",
    ]


def _read_ndjson_findings(ndjson_path: Path) -> list[dict[str, Any]]:
    if not ndjson_path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in ndjson_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw:
            continue
        rows.append(json.loads(raw))
    return rows


def _read_scan_telemetry(isolated_dir: Path) -> dict[str, Any]:
    telemetry: dict[str, Any] = {
        "probes_fired": 0,
        "probes_skipped_dedup": 0,
        "findings_emitted": 0,
        "scan_status": "unknown",
        "execution_errors": [],
    }
    runs_csv = isolated_dir / "experiment_runs.csv"
    if runs_csv.is_file():
        with runs_csv.open("r", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if rows:
            last = rows[-1]
            telemetry["probes_fired"] = int(last.get("total_fired") or 0)
            telemetry["probes_skipped_dedup"] = int(last.get("total_skipped_dedup") or 0)

    manifests = sorted(isolated_dir.glob("rest-*/manifest.json"))
    if manifests:
        m_data = json.loads(manifests[-1].read_text(encoding="utf-8"))
        meta = m_data.get("metadata") or {}
        telemetry["findings_emitted"] = int(meta.get("total_findings") or 0)
        telemetry["probes_fired"] = int(meta.get("total_fired") or telemetry["probes_fired"])
        telemetry["scan_status"] = str(meta.get("status") or "unknown")
        telemetry["execution_errors"] = list(meta.get("execution_errors") or [])
    return telemetry


def run_benchmark_suite(
    *,
    spec_path: Path = OPENAPI_SPEC_PATH,
    manifest_path: Path = GROUND_TRUTH_PATH,
    output_root: Optional[Path] = None,
    concurrency: int = 4,
    rate_limit_ms: int = 0,
) -> tuple[dict[str, Any], Path]:
    """Execute the full P1.6 benchmark against a live local BenchmarkLabServer."""
    paths = ProjectPaths.from_root(PROJECT_ROOT)
    manifest = load_ground_truth_manifest(manifest_path)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    benchmark_run_id = f"bench-{ts}-{uuid.uuid4().hex[:8]}"
    base_out = output_root or (paths.results / "benchmark_runs")
    isolated_dir = (base_out / benchmark_run_id).resolve()
    isolated_dir.mkdir(parents=True, exist_ok=True)

    protected_paths = _protected_main_result_paths(paths)
    before_snap = snapshot_files_integrity(protected_paths)

    user1_headers, user2_headers = build_lab_auth_headers()
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()

    lab = BenchmarkLabServer()
    execution_status = "completed"
    lab_status = "stopped"
    auth_preflight = None
    planned_pairs: set[tuple[str, str, str]] = set()
    server_request_count = 0
    telemetry: dict[str, Any] = {}
    ndjson_findings: list[dict[str, Any]] = []

    try:
        lab.start()
        lab_status = "running"

        schema, base_url = rest.load_schema(str(spec_path), lab.base_url)
        targets = {manifest.target_app: (schema, base_url)}

        auth_preflight = run_auth_preflight(
            base_url,
            user1_headers,
            user2_headers,
            execute_scan_fn=rest.execute_rest_scan,
        )

        # Compute exact planned (method, endpoint, vuln_class) pairs from schema_payloads + prepare_cases
        planned_payloads = rest.schema_payloads(targets)
        prepared_cases = rest.prepare_cases(planned_payloads, targets)
        for pc in prepared_cases:
            if pc.payload.param_location == "schema" or pc.payload.attack_type.lower() == "schema-generated":
                continue
            planned_pairs.add((
                pc.payload.method.upper(),
                pc.payload.endpoint,
                normalize_vuln_class(pc.payload.attack_type),
            ))

        # Reset server request counter after preflight so server_request_count reflects scan requests only.
        lab.reset()

        tracker = CleanupTracker(run_id=benchmark_run_id, out_dir=isolated_dir)
        rest.execute_rest_scan(
            targets=targets,
            targets_desc=f"{manifest.target_app}={spec_path}",
            headers=user1_headers,
            user2_headers=user2_headers,
            rules_path=paths.config / "rules.json",
            results_dir=isolated_dir,
            concurrency=concurrency,
            rate_limit_ms=rate_limit_ms,
            cleanup_tracker=tracker,
            resume_state=False,
        )

        server_request_count = lab.request_count
        ndjson_findings = _read_ndjson_findings(isolated_dir / "vulnerabilities.ndjson")
        telemetry = _read_scan_telemetry(isolated_dir)
        if telemetry.get("scan_status") not in ("completed", "unknown"):
            execution_status = str(telemetry["scan_status"])
    except Exception as exc:
        execution_status = f"failed: {type(exc).__name__}: {exc}"
        raise
    finally:
        lab.stop()
        lab_status = "stopped"

    duration_s = round(time.perf_counter() - t0, 3)
    finished_at = datetime.now(timezone.utc).isoformat()
    after_snap = snapshot_files_integrity(protected_paths)
    isolation = verify_isolation(before_snap, after_snap)

    evaluation = BenchmarkEvaluator.evaluate(
        manifest,
        ndjson_findings,
        planned_pairs=planned_pairs,
        auth_preflight=auth_preflight,
    )

    # Combine operational errors from scanner manifest (if any) with finding errors
    for exec_err in telemetry.get("execution_errors") or []:
        evaluation["operational_errors"].append({
            "method": "*",
            "endpoint": "*",
            "vuln_class": "*",
            "error_type": str(exec_err.get("type") or "execution_error"),
            "stage": "scan_execution",
            "reason": str(exec_err.get("error") or ""),
        })

    unique_main_endpoints = {(e.method, e.endpoint) for e in manifest.expectations}
    report: dict[str, Any] = {
        "benchmark_run_id": benchmark_run_id,
        "benchmark_version": manifest.benchmark_version,
        "target_version": manifest.target_version,
        "timestamp": finished_at,
        "started_at": started_at,
        "finished_at": finished_at,
        "scan_duration_s": duration_s,
        "scanner_commit": _git_commit_short(),
        "lab_status": lab_status,
        "execution_status": execution_status,
        "auth_preflight": auth_preflight.model_dump() if auth_preflight else None,
        "isolation": isolation,
        "telemetry": {
            "total_main_endpoints": len(unique_main_endpoints),
            "noise_control_endpoints": len(manifest.noise_control_endpoints),
            "applicable_endpoint_class_pairs": evaluation["overall"]["applicable_pairs"],
            "tested_endpoint_class_pairs": evaluation["overall"]["tested_pairs"],
            "skipped_pairs_count": evaluation["overall"]["skipped"],
            "server_request_count": server_request_count,
            "probes_fired": telemetry.get("probes_fired", 0),
            "probes_skipped_dedup": telemetry.get("probes_skipped_dedup", 0),
            "findings_emitted": len(ndjson_findings),
        },
        **evaluation,
    }

    report_path = isolated_dir / "benchmark_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return report, report_path


def _fmt_pct(val: Optional[float]) -> str:
    if val is None:
        return "N/A"
    return f"{val * 100:.1f}%"


def print_console_summary(report: dict[str, Any], report_path: Path) -> None:
    ov = report["overall"]
    tel = report["telemetry"]
    preflight = report.get("auth_preflight") or {}
    isolation = report.get("isolation") or {}

    print("\n" + "=" * 76)
    print("  P1.6 GROUND TRUTH BENCHMARK REPORT")
    print("=" * 76)
    print(f"Run ID          : {report['benchmark_run_id']}")
    print(f"Scanner Commit  : {report['scanner_commit']} | Duration: {report['scan_duration_s']}s")
    print(f"Auth Preflight  : {preflight.get('status', 'unknown')} (dual_token={preflight.get('dual_token_supported')})")
    print(f"Isolation Check : {'VERIFIED' if isolation.get('verified') else 'FAILED'}")
    print(
        f"Telemetry       : endpoints={tel['total_main_endpoints']}+{tel['noise_control_endpoints']} noise | "
        f"pairs={tel['tested_endpoint_class_pairs']}/{tel['applicable_endpoint_class_pairs']} | "
        f"requests={tel['server_request_count']} | probes={tel['probes_fired']} | findings={tel['findings_emitted']}"
    )
    print("\nOVERALL METRICS:")
    print(
        f"  TP={ov['tp']} (confirmed={ov['confirmed_tp']}, candidate={ov['candidate_tp']}) | "
        f"FP={ov['fp']} (confirmed={ov['confirmed_fp']}, candidate={ov['candidate_fp']}, cross_class={ov['cross_class_fp']}) | "
        f"TN={ov['tn']} | FN={ov['fn']}"
    )
    print(
        f"  Precision={_fmt_pct(ov['precision'])} | Recall={_fmt_pct(ov['recall'])} | "
        f"FPR={_fmt_pct(ov['fpr'])} | ConfPrecision={_fmt_pct(ov['confirmation_precision'])} | "
        f"ConfRecall={_fmt_pct(ov['confirmed_recall'])} | CandRecall={_fmt_pct(ov['candidate_recall'])} | "
        f"Coverage={_fmt_pct(ov['coverage'])} | ErrorRate={_fmt_pct(ov['error_rate'])}"
    )
    print("\nPER-CLASS METRICS:")
    print(f"  {'CLASS':<16} {'STAT':<10} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} {'PREC':>7} {'RECALL':>7} {'FPR':>7} {'CONF_REC':>9} {'COV':>7}")
    for vc, m in report["per_class"].items():
        print(
            f"  {vc:<16} {m['status'][:10]:<10} {m['tp']:>3} {m['fp']:>3} {m['tn']:>3} {m['fn']:>3} "
            f"{_fmt_pct(m['precision']):>7} {_fmt_pct(m['recall']):>7} {_fmt_pct(m['fpr']):>7} "
            f"{_fmt_pct(m['confirmed_recall']):>9} {_fmt_pct(m['coverage']):>7}"
        )
    gate = report["initial_quality_gate"]
    print(f"\nInitial Gate ({gate['rule']}): {'PASSED' if gate['passed'] else 'FAILED'} (confirmed_fp={gate['confirmed_fp']})")
    print(f"Report JSON     : {report_path}")
    print("=" * 76 + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run P1.6 Ground Truth DAST Benchmark against local deterministic lab.")
    parser.add_argument("--spec", default=str(OPENAPI_SPEC_PATH), help="Path to OpenAPI spec")
    parser.add_argument("--manifest", default=str(GROUND_TRUTH_PATH), help="Path to ground_truth.json")
    parser.add_argument("--output-root", default=None, help="Isolated directory root for benchmark outputs")
    parser.add_argument("--concurrency", type=int, default=4, help="Scanner concurrency")
    parser.add_argument("--rate-limit-ms", type=int, default=0, help="Per-group delay in ms")
    args = parser.parse_args(argv)

    out_root = Path(args.output_root).resolve() if args.output_root else None
    report, report_path = run_benchmark_suite(
        spec_path=Path(args.spec).resolve(),
        manifest_path=Path(args.manifest).resolve(),
        output_root=out_root,
        concurrency=args.concurrency,
        rate_limit_ms=args.rate_limit_ms,
    )
    print_console_summary(report, report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
