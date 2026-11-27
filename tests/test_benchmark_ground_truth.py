"""Tests for P1.6 Benchmark & Ground Truth Harness (manifest, evaluator, lab server, and E2E integration)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import requests

from core import (
    AuthPreflightResult,
    BenchmarkEvaluator,
    GroundTruthManifest,
    load_ground_truth_manifest,
    normalize_vuln_class,
    snapshot_files_integrity,
    verify_isolation,
)
from scripts.run_benchmark import run_benchmark_suite
from targets.benchmark_lab import (
    ALICE_ID,
    BOB_ID,
    GROUND_TRUTH_PATH,
    OPENAPI_SPEC_PATH,
    BenchmarkLabServer,
    build_lab_auth_headers,
)
from targets.benchmark_lab.server import safe_eval_mul_template


# ----------------------------------------------------------------------
# 1. Manifest & Class Normalization Unit Tests
# ----------------------------------------------------------------------


def test_real_ground_truth_manifest_loads_and_matches_requirements():
    manifest = load_ground_truth_manifest(GROUND_TRUTH_PATH)
    assert manifest.target_app == "benchmark_lab"
    unique_endpoints = {(e.method, e.endpoint) for e in manifest.expectations}
    assert len(unique_endpoints) == 16
    assert sum(1 for e in manifest.expectations if e.vulnerable) == 8
    assert sum(1 for e in manifest.expectations if not e.vulnerable) == 8
    assert len(manifest.noise_control_endpoints) == 1


def test_manifest_validation_rejects_duplicates_and_bad_paths():
    with pytest.raises(ValueError):
        GroundTruthManifest.model_validate({
            "benchmark_version": "1.0",
            "expectations": [],
        })

    with pytest.raises(ValueError):
        GroundTruthManifest.model_validate({
            "benchmark_version": "1.0",
            "expectations": [
                {
                    "case_id": "c1",
                    "method": "GET",
                    "endpoint": "/a",
                    "vuln_class": "BOLA",
                    "vulnerable": True,
                },
                {
                    "case_id": "c2",
                    "method": "GET",
                    "endpoint": "/a",
                    "vuln_class": "IDOR",  # normalizes to same (GET, /a, BOLA)
                    "vulnerable": False,
                },
            ],
        })

    with pytest.raises(ValueError):
        GroundTruthManifest.model_validate({
            "benchmark_version": "1.0",
            "expectations": [
                {
                    "case_id": "bad_ep",
                    "method": "GET",
                    "endpoint": "no-leading-slash",
                    "vuln_class": "SSTI",
                    "vulnerable": True,
                }
            ],
        })


def test_vuln_class_normalization_is_deterministic_without_arbitrary_mapping():
    assert normalize_vuln_class("BOLA") == "BOLA"
    assert normalize_vuln_class("idor") == "BOLA"
    assert normalize_vuln_class("INTEGER_OVERFLOW") == "BOUNDARY"
    assert normalize_vuln_class("boundary-analysis") == "BOUNDARY"
    assert normalize_vuln_class("SQL_INJECTION") == "SQLI"
    assert normalize_vuln_class("time_based_sqli") == "SQLI"
    assert normalize_vuln_class("ssti") == "SSTI"
    assert normalize_vuln_class("mass_assignment") == "MASS_ASSIGNMENT"
    # Unmapped classes keep their normalized uppercase name
    assert normalize_vuln_class("XSS") == "XSS"
    assert normalize_vuln_class("path_traversal") == "PATH_TRAVERSAL"

    with pytest.raises(ValueError):
        normalize_vuln_class("   ")


# ----------------------------------------------------------------------
# 2. Evaluator Matrix, Cross-Class FP, No Double-Count & Zero Denom Tests
# ----------------------------------------------------------------------


def _mini_manifest() -> GroundTruthManifest:
    return GroundTruthManifest.model_validate({
        "benchmark_version": "1.0",
        "evaluated_classes": ["BOLA", "BOUNDARY", "SSTI"],
        "expectations": [
            {
                "case_id": "b_vuln",
                "method": "GET",
                "endpoint": "/orders/{id}",
                "vuln_class": "BOLA",
                "vulnerable": True,
                "expected_confirmation": True,
            },
            {
                "case_id": "b_sec",
                "method": "GET",
                "endpoint": "/secure-orders/{id}",
                "vuln_class": "BOLA",
                "vulnerable": False,
            },
            {
                "case_id": "b_skip",
                "method": "GET",
                "endpoint": "/catalog/{id}",
                "vuln_class": "BOLA",
                "vulnerable": False,
                "applicable": False,
                "exclusion_reason": "explicit_security_empty",
            },
            {
                "case_id": "bnd_vuln",
                "method": "GET",
                "endpoint": "/products",
                "vuln_class": "BOUNDARY",
                "vulnerable": True,
            },
            {
                "case_id": "ssti_sec",
                "method": "GET",
                "endpoint": "/echo",
                "vuln_class": "SSTI",
                "vulnerable": False,
            },
        ],
        "noise_control_endpoints": [
            {"case_id": "noise", "method": "GET", "endpoint": "/status"},
        ],
    })


def test_evaluator_tp_fp_tn_fn_cross_class_and_no_double_count():
    manifest = _mini_manifest()
    findings = [
        # Two findings for same (GET, /orders/{id}, BOLA) via BOLA and IDOR -> must count as ONE TP
        {
            "finding_id": "F-1",
            "fingerprint": "fp1",
            "method": "GET",
            "endpoint": "/orders/{id}",
            "attack_type": "IDOR",
            "lifecycle": "candidate",
            "severity": "medium",
            "confidence": 0.65,
            "confirmed": False,
            "evidence": "cand",
        },
        {
            "finding_id": "F-2",
            "fingerprint": "fp2",
            "method": "GET",
            "endpoint": "/orders/{id}",
            "attack_type": "BOLA",
            "lifecycle": "confirmed",
            "severity": "high",
            "confidence": 0.95,
            "confirmed": True,
            "evidence": "conf",
        },
        # Cross-class FP: /orders/{id} is only BOLA-vulnerable, NOT BOUNDARY
        {
            "finding_id": "F-3",
            "fingerprint": "fp3",
            "method": "GET",
            "endpoint": "/orders/{id}",
            "attack_type": "INTEGER_OVERFLOW",
            "lifecycle": "candidate",
            "severity": "medium",
            "confidence": 0.60,
            "confirmed": False,
            "evidence": "cross fp",
        },
        # Secure BOLA rejected -> TN
        {
            "finding_id": "F-4",
            "fingerprint": "fp4",
            "method": "GET",
            "endpoint": "/secure-orders/{id}",
            "attack_type": "BOLA",
            "lifecycle": "rejected",
            "severity": "info",
            "confidence": 0.10,
            "confirmed": False,
            "evidence": "403",
        },
        # Vulnerable BOUNDARY rejected -> FN (rejected_fn)
        {
            "finding_id": "F-5",
            "fingerprint": "fp5",
            "method": "GET",
            "endpoint": "/products",
            "attack_type": "INTEGER_OVERFLOW",
            "lifecycle": "rejected",
            "severity": "info",
            "confidence": 0.10,
            "confirmed": False,
            "evidence": "missed overflow",
        },
        # Secure SSTI returned inconclusive -> NOT TN!
        {
            "finding_id": "F-6",
            "fingerprint": "fp6",
            "method": "GET",
            "endpoint": "/echo",
            "attack_type": "SSTI",
            "lifecycle": "inconclusive",
            "severity": "info",
            "confidence": 0.20,
            "confirmed": False,
            "evidence": "inconclusive",
        },
        # Noise control returned error for SSTI -> NOT TN!
        {
            "finding_id": "F-7",
            "fingerprint": "fp7",
            "method": "GET",
            "endpoint": "/status",
            "attack_type": "SSTI",
            "lifecycle": "error",
            "severity": "unknown",
            "confidence": 0.0,
            "confirmed": False,
            "evidence": "timeout",
        },
    ]

    res = BenchmarkEvaluator.evaluate(manifest, findings)
    ov = res["overall"]

    # Unique pairs evaluated:
    # 1. (GET, /orders/{id}, BOLA) -> TP (confirmed, deduplicated from 2 findings)
    # 2. (GET, /orders/{id}, BOUNDARY) -> cross-class FP (candidate)
    # 3. (GET, /secure-orders/{id}, BOLA) -> TN (rejected)
    # 4. (GET, /catalog/{id}, BOLA) -> skipped (not_applicable, no finding)
    # 5. (GET, /products, BOUNDARY) -> FN (rejected_fn)
    # 6. (GET, /echo, SSTI) -> inconclusive (not TN)
    # 7. (GET, /status, SSTI) -> error (not TN)
    assert ov["tp"] == 1
    assert ov["confirmed_tp"] == 1
    assert ov["candidate_tp"] == 0
    assert ov["fp"] == 1
    assert ov["candidate_fp"] == 1
    assert ov["confirmed_fp"] == 0
    assert ov["cross_class_fp"] == 1
    assert ov["tn"] == 1
    assert ov["fn"] == 1
    assert ov["rejected_fn"] == 1
    assert ov["inconclusive"] == 1
    assert ov["error"] == 1
    assert ov["skipped"] == 1
    assert ov["missed"] == 0
    assert ov["precision"] == 0.5
    assert ov["recall"] == 0.5
    assert ov["fpr"] == 0.5  # FP=1, TN=1 (inconclusive & error excluded from TN!)
    assert ov["confirmation_precision"] == 1.0
    assert ov["confirmed_recall"] == 0.5
    assert ov["candidate_recall"] == 0.0

    # Verify cross-class FP attributed to BOUNDARY, not ignored
    bnd = res["per_class"]["BOUNDARY"]
    assert bnd["fp"] == 1
    assert bnd["cross_class_fp"] == 1
    assert bnd["fn"] == 1
    assert len(res["cross_class_false_positives"]) == 1
    assert res["cross_class_false_positives"][0]["actual_class"] == "BOUNDARY"


def test_evaluator_zero_denominators_return_none_and_auth_unavailable_marks_bola():
    manifest = GroundTruthManifest.model_validate({
        "benchmark_version": "1.0",
        "evaluated_classes": ["BOLA", "SSTI"],
        "expectations": [
            {
                "case_id": "b1",
                "method": "GET",
                "endpoint": "/orders/{id}",
                "vuln_class": "BOLA",
                "vulnerable": True,
            },
            {
                "case_id": "s1",
                "method": "GET",
                "endpoint": "/echo",
                "vuln_class": "SSTI",
                "vulnerable": False,
            },
        ],
    })
    preflight = AuthPreflightResult(
        status="auth_prerequisite_unavailable",
        dual_token_supported=False,
    )
    res = BenchmarkEvaluator.evaluate(manifest, [], auth_preflight=preflight)
    assert res["per_class"]["BOLA"]["status"] == "incomplete_auth_unavailable"
    assert res["per_class"]["BOLA"]["fn"] == 0  # not counted as false negative
    assert res["per_class"]["BOLA"]["skipped"] == 1
    assert res["per_class"]["BOLA"]["precision"] is None
    assert res["per_class"]["BOLA"]["recall"] is None
    assert res["per_class"]["BOLA"]["fpr"] is None
    assert res["overall"]["precision"] is None
    assert res["overall"]["recall"] is None


def test_isolation_snapshot_detects_unchanged_and_changed(tmp_path: Path):
    f1 = tmp_path / "a.json"
    f1.write_text('{"x": 1}', encoding="utf-8")
    before = snapshot_files_integrity([f1, tmp_path / "missing.csv"])
    after_same = snapshot_files_integrity([f1, tmp_path / "missing.csv"])
    assert verify_isolation(before, after_same)["verified"] is True

    f1.write_text('{"x": 2}', encoding="utf-8")
    after_diff = snapshot_files_integrity([f1, tmp_path / "missing.csv"])
    diff_res = verify_isolation(before, after_diff)
    assert diff_res["verified"] is False
    assert str(f1) in diff_res["changed_files"]


# ----------------------------------------------------------------------
# 3. Lab Server Deterministic Behavior Tests
# ----------------------------------------------------------------------


def test_safe_eval_mul_template_rejects_arbitrary_code():
    assert safe_eval_mul_template("{{9187*8431}}") == "77455597"
    assert safe_eval_mul_template("prefix.${9199*8443}.suffix") == "prefix.77667157.suffix"
    assert safe_eval_mul_template("<%= 9187*8431 %>") == "77455597"
    assert safe_eval_mul_template("{{ssti_ctrl_canary_7x}}") == "{{ssti_ctrl_canary_7x}}"
    assert safe_eval_mul_template("{{__import__('os').system('id')}}") == "{{__import__('os').system('id')}}"


def test_benchmark_lab_server_endpoints_and_reset():
    user1_headers, user2_headers = build_lab_auth_headers()
    with BenchmarkLabServer() as lab:
        assert lab.base_url.startswith("http://127.0.0.1:")
        with httpx.Client(base_url=lab.base_url, timeout=5.0) as client:
            # BOLA endpoints
            assert client.get("/api/bola/vuln/orders/1").status_code == 401
            r_bola_leak = client.get("/api/bola/vuln/orders/1", headers=user2_headers)
            assert r_bola_leak.status_code == 200
            assert r_bola_leak.json()["owner_id"] == ALICE_ID

            assert client.get("/api/bola/secure/orders/1", headers=user2_headers).status_code == 403
            r_bob_own = client.get("/api/bola/secure/orders/2", headers=user2_headers)
            assert r_bob_own.status_code == 200 and r_bob_own.json()["owner_id"] == BOB_ID
            assert client.get("/api/bola/secure/public-items/1").status_code == 200

            # Boundary endpoints
            assert client.get("/api/boundary/vuln/wraparound?amount=2147483647").json()["amount"] == -2147483648
            assert len(client.get("/api/boundary/vuln/products?limit=-1").json()["products"]) == 150
            assert len(client.get("/api/boundary/secure/products?limit=2147483647").json()["products"]) == 30
            assert client.get("/api/boundary/secure/strict?amount=2147483647").status_code == 422

            # Mass assignment persistence vs DTO echo via synchronous requests.get (same path as loopback verifier)
            client.put("/api/mass/vuln/profile", json={"display_name": "X", "is_admin": True})
            assert requests.get(f"{lab.base_url}/api/mass/vuln/profile", timeout=3.0).json()["is_admin"] is True

            put_sec = client.put("/api/mass/secure/profile", json={"display_name": "X", "is_admin": True})
            assert put_sec.json()["is_admin"] is True  # echoed in DTO
            assert requests.get(f"{lab.base_url}/api/mass/secure/profile", timeout=3.0).json()["is_admin"] is False

        assert lab.request_count > 0
        lab.reset()
        assert lab.request_count == 0
        with httpx.Client(base_url=lab.base_url, timeout=5.0) as client:
            assert client.get("/api/mass/vuln/profile").json()["is_admin"] is False


# ----------------------------------------------------------------------
# 4. Full End-to-End Benchmark Integration Test (Real execute_rest_scan)
# ----------------------------------------------------------------------


def test_full_p16_benchmark_integration_real_scanner_pipeline(tmp_path: Path):
    report, report_path = run_benchmark_suite(
        spec_path=OPENAPI_SPEC_PATH,
        manifest_path=GROUND_TRUTH_PATH,
        output_root=tmp_path,
        concurrency=4,
        rate_limit_ms=0,
    )

    assert report_path.is_file()
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["execution_status"] == "completed"
    assert saved["lab_status"] == "stopped"
    assert saved["auth_preflight"]["status"] == "passed"
    assert saved["auth_preflight"]["dual_token_supported"] is True
    assert saved["isolation"]["verified"] is True

    tel = saved["telemetry"]
    assert tel["total_main_endpoints"] == 16
    assert tel["noise_control_endpoints"] == 1
    assert tel["server_request_count"] > 0
    assert tel["probes_fired"] > 0
    assert tel["findings_emitted"] > 0

    # Initial Quality Gate: zero confirmed false positives
    assert saved["initial_quality_gate"]["passed"] is True
    assert saved["overall"]["confirmed_fp"] == 0

    # All 4 benchmark classes must actually be evaluated with coverage == 1.0 and real TPs
    for vc in ("BOLA", "BOUNDARY", "SSTI", "MASS_ASSIGNMENT"):
        cls_m = saved["per_class"][vc]
        assert cls_m["status"] == "evaluated"
        assert cls_m["coverage"] == 1.0
        assert cls_m["tp"] == cls_m["total_vulnerable"]
        assert cls_m["fp"] == 0

    # Explicit open-catalog BOLA pair skipped by Test Planner, not missed
    assert any(
        s["endpoint"] == "/api/bola/secure/open-catalog/{id}" and s["vuln_class"] == "BOLA"
        for s in saved["skipped_pairs"]
    )
    assert saved["overall"]["missed"] == 0
