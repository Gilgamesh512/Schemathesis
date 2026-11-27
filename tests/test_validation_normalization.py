"""Tests for validation verdict normalization, confidence/severity invariants, and export consistency (P1.5)."""

from __future__ import annotations

import asyncio
import csv
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

import run_all
from core import (
    BolaValidator,
    Evidence,
    Finding,
    Observation,
    ResultManager,
    RunState,
    SecurityReporter,
    SstiValidator,
    build_finding_from_observations,
    normalize_validation_verdict,
    sanitize_confidence,
)
from core.sarif_exporter import build_sarif_document
from modules.rest import run_schemathesis1 as rest


class _DummyCase:
    def __init__(self, method: str, path: str, query: dict | None = None, json_body: dict | None = None):
        self.method = method
        self.path = path
        self.query = query or {}
        self.json_body = json_body

    def as_transport_kwargs(self, base_url: str) -> dict:
        kwargs: dict = {
            "method": self.method,
            "url": f"{base_url.rstrip('/')}{self.path}",
            "headers": {},
        }
        if self.query:
            kwargs["params"] = dict(self.query)
        if self.json_body is not None:
            kwargs["json"] = dict(self.json_body)
        return kwargs


def _make_payload(
    *,
    attack_type: str = "SQL_INJECTION",
    method: str = "GET",
    endpoint: str = "/items",
    target_param: str = "q",
    param_location: str = "query",
    payload_value="test",
    expected_signal: list[str] | None = None,
    owasp_category: str = "API8:2023",
) -> rest.Payload:
    return rest.Payload(
        endpoint=endpoint,
        method=method,
        target_param=target_param,
        param_location=param_location,
        attack_type=attack_type,
        payload_value=payload_value,
        expected_signal=expected_signal or [],
        owasp_category=owasp_category,
        target_app="norm_api",
    )


# ----------------------------------------------------------------------
# 1-7. Central Normalization Policy Invariants & Idempotency
# ----------------------------------------------------------------------


def test_confirmed_outcome_invariants_and_downgrades():
    ok = normalize_validation_verdict(
        outcome="confirmed",
        severity="high",
        confidence=0.95,
        confirmed=True,
        has_validation_evidence=True,
    )
    assert ok.outcome == "confirmed"
    assert ok.confirmed is True
    assert ok.severity == "high"
    assert ok.confidence == 0.95
    assert ok.downgraded is False

    # Confidence < 0.85 cannot stay confirmed and confidence is never inflated
    low_conf = normalize_validation_verdict(
        outcome="confirmed",
        severity="critical",
        confidence=0.60,
        confirmed=True,
        has_validation_evidence=True,
    )
    assert low_conf.outcome == "candidate"
    assert low_conf.confirmed is False
    assert low_conf.severity == "medium"
    assert low_conf.confidence == 0.60
    assert low_conf.downgraded is True

    # Missing validation evidence forces downgrade even with high numeric confidence
    no_ev = normalize_validation_verdict(
        outcome="confirmed",
        severity="high",
        confidence=0.95,
        confirmed=True,
        has_validation_evidence=False,
    )
    assert no_ev.outcome == "candidate"
    assert no_ev.confirmed is False
    assert no_ev.severity == "medium"
    assert no_ev.confidence == 0.75
    assert no_ev.downgraded is True

    # Contradictory confirmed=False never promotes to confirmed
    contradicted = normalize_validation_verdict(
        outcome="confirmed",
        severity="high",
        confidence=0.95,
        confirmed=False,
        has_validation_evidence=True,
    )
    assert contradicted.confirmed is False
    assert contradicted.outcome == "candidate"
    assert contradicted.severity == "medium"

    # Info severity on confirmed never upgrades severity -> downgrades to inconclusive
    info_conf = normalize_validation_verdict(
        outcome="confirmed",
        severity="info",
        confidence=0.95,
        confirmed=True,
    )
    assert info_conf.outcome == "inconclusive"
    assert info_conf.confirmed is False
    assert info_conf.severity == "info"
    assert info_conf.confidence <= 0.30


def test_candidate_severity_and_missing_baseline_confidence_ceilings():
    capped = normalize_validation_verdict(
        outcome="candidate",
        severity="critical",
        confidence=0.92,
        has_baseline=True,
    )
    assert capped.outcome == "candidate"
    assert capped.confirmed is False
    assert capped.severity == "medium"
    assert capped.confidence == 0.75

    no_baseline = normalize_validation_verdict(
        outcome="candidate",
        severity="high",
        confidence=0.70,
        has_baseline=False,
        has_independent_evidence=False,
    )
    assert no_baseline.outcome == "candidate"
    assert no_baseline.confirmed is False
    assert no_baseline.severity == "medium"
    assert no_baseline.confidence == 0.50

    # Candidate with info severity never upgrades severity -> downgrades to inconclusive
    info_cand = normalize_validation_verdict(
        outcome="candidate",
        severity="info",
        confidence=0.55,
    )
    assert info_cand.outcome == "inconclusive"
    assert info_cand.confirmed is False
    assert info_cand.severity == "info"
    assert info_cand.confidence <= 0.30


def test_rejected_inconclusive_and_error_invariants():
    rej = normalize_validation_verdict(
        outcome="rejected",
        severity="high",
        confidence=0.90,
    )
    assert rej.outcome == "rejected"
    assert rej.confirmed is False
    assert rej.severity == "info"
    assert rej.confidence == 0.15

    inc = normalize_validation_verdict(
        outcome="inconclusive",
        severity="medium",
        confidence=0.65,
    )
    assert inc.outcome == "inconclusive"
    assert inc.confirmed is False
    assert inc.severity == "info"
    assert inc.confidence == 0.30

    err = normalize_validation_verdict(
        outcome="error",
        severity="high",
        confidence=0.80,
    )
    assert err.outcome == "error"
    assert err.confirmed is False
    assert err.severity == "unknown"
    assert err.confidence == 0.0


def test_malformed_nan_infinite_confidence_handling():
    for bad in (float("nan"), float("inf"), float("-inf"), "not-a-number", True, None):
        val, valid = sanitize_confidence(bad)
        assert val == 0.0
        assert valid is False

    assert sanitize_confidence(-0.4) == (0.0, True)
    assert sanitize_confidence(1.8) == (1.0, True)

    v = normalize_validation_verdict(
        outcome="confirmed",
        severity="high",
        confidence=float("nan"),
        confirmed=True,
    )
    assert v.confirmed is False
    assert v.outcome == "inconclusive"
    assert v.severity == "info"
    assert v.confidence == 0.0


def test_normalization_is_deterministic_and_idempotent():
    cases = [
        ("confirmed", "critical", 0.96, True, True, False, True),
        ("confirmed", "high", 0.90, True, True, False, False),
        ("confirmed", "high", 0.55, True, True, False, True),
        ("candidate", "high", 0.90, False, False, False, True),
        ("candidate", "info", 0.60, False, True, False, True),
        ("inconclusive", "high", 0.70, False, True, False, True),
        ("rejected", "medium", 0.85, False, True, False, True),
        ("error", "high", float("inf"), True, True, False, True),
    ]
    for outcome, sev, conf, confirmed, has_base, has_indep, has_ev in cases:
        v1 = normalize_validation_verdict(
            outcome=outcome,
            severity=sev,
            confidence=conf,
            confirmed=confirmed,
            has_baseline=has_base,
            has_independent_evidence=has_indep,
            has_validation_evidence=has_ev,
        )
        v2 = normalize_validation_verdict(
            outcome=v1.outcome,
            severity=v1.severity,
            confidence=v1.confidence,
            confirmed=v1.confirmed,
            has_baseline=has_base,
            has_independent_evidence=has_indep,
            has_validation_evidence=has_ev,
        )
        assert (v2.outcome, v2.confirmed, v2.severity, v2.confidence) == (
            v1.outcome,
            v1.confirmed,
            v1.severity,
            v1.confidence,
        )


# ----------------------------------------------------------------------
# 8-14. REST Decision, TIME_BASED, MASS_ASSIGNMENT & Validators
# ----------------------------------------------------------------------


def test_http_500_502_generic_and_technical_remain_unconfirmed_and_le_medium():
    payload = _make_payload(attack_type="SQL_INJECTION", payload_value="'")
    baseline = httpx.Response(200, json={"ok": True})

    # Generic 500 and 502 without specific SQL/traceback signals -> candidate/low
    for code in (500, 502):
        generic_resp = httpx.Response(code, json={"error": "Internal Server Error"})
        det, _ = rest.detect_response(generic_resp, payload, baseline_resp=baseline)
        dec = rest.decide_validation(det, payload)
        assert dec.outcome == "candidate"
        assert dec.is_confirmed is False
        assert dec.severity == "low"
        assert dec.confidence <= 0.50

    # 500 with meaningful SQL syntax error -> candidate/medium (with baseline), candidate/low (without baseline)
    tech_resp = httpx.Response(500, text="You have an error in your SQL syntax near '''")
    det_with_base, _ = rest.detect_response(tech_resp, payload, baseline_resp=baseline)
    dec_with_base = rest.decide_validation(det_with_base, payload)
    assert dec_with_base.outcome == "candidate"
    assert dec_with_base.is_confirmed is False
    assert dec_with_base.severity == "medium"

    det_no_base, _ = rest.detect_response(tech_resp, payload, baseline_resp=None)
    dec_no_base = rest.decide_validation(det_no_base, payload)
    assert dec_no_base.outcome == "candidate"
    assert dec_no_base.is_confirmed is False
    assert dec_no_base.severity == "low"
    assert dec_no_base.confidence <= 0.50


def test_single_probe_time_based_e2e_is_candidate_medium_never_high(tmp_path: Path):
    pc = rest.PreparedCase(
        "fp-time-1",
        "norm_api",
        "http://api.test",
        _DummyCase("GET", "/items", {"q": "normal"}),
        _DummyCase("GET", "/items", {"q": "1' AND SLEEP(4)--"}),
        _make_payload(attack_type="TIME_BASED_SQLI", payload_value="1' AND SLEEP(4)--"),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        resp = httpx.Response(200, json={"ok": True})
        resp.elapsed_ms = 4200.0 if "SLEEP" in q else 25.0  # type: ignore[attr-defined]
        return resp

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await rest.process_fingerprint_group(
                client, scheduler, "fp-time-1", [pc], {}, None, state, 0.0
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert findings[0].lifecycle == "candidate"
    assert findings[0].confirmed is False
    assert findings[0].severity == "medium"
    assert findings[0].confidence <= 0.75


def test_mass_assignment_unpersisted_loopback_becomes_rejected_info(tmp_path: Path):
    payload = _make_payload(
        attack_type="MASS_ASSIGNMENT",
        method="PUT",
        endpoint="/profile",
        target_param="is_admin",
        param_location="body",
        payload_value=True,
        expected_signal=["admin-echo-canary-91827"],
        owasp_category="API3:2023",
    )
    pc = rest.PreparedCase(
        "fp-mass-unpersisted",
        "norm_api",
        "http://api.test",
        _DummyCase("PUT", "/profile", json_body={"display": "alice"}),
        _DummyCase("PUT", "/profile", json_body={"display": "alice", "is_admin": True}),
        payload,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Echoes canary in PUT response so generic detector initially sees a new signal (candidate),
        # while loopback persistence returns False.
        body = json.loads(request.content.decode("utf-8"))
        if "is_admin" in body:
            return httpx.Response(200, json={"id": 1, "note": "admin-echo-canary-91827"})
        return httpx.Response(200, json={"id": 1, "note": "clean"})

    async def _run():
        state = RunState(tmp_path / "state.json")
        scheduler = rest.RequestScheduler(max_retries=0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with patch.object(
                rest,
                "verify_deep_state_persistence",
                return_value=(False, "Field 'is_admin' was NOT persisted in DB state"),
            ):
                return await rest.process_fingerprint_group(
                    client, scheduler, "fp-mass-unpersisted", [pc], {}, None, state, 0.0
                )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    f = findings[0]
    assert f.lifecycle == "rejected"
    assert f.confirmed is False
    assert f.severity == "info"
    assert f.confidence <= 0.15
    assert f.observations[0].outcome == "rejected"
    assert f.observations[0].severity == "info"
    assert "Loopback verification unpersisted" in f.evidence.response_signal[0]


def test_bola_and_ssti_rejected_branches_have_low_vulnerability_confidence():
    bola_verdicts = [
        BolaValidator.validate(attack_status=200),
        BolaValidator.validate(attack_status=401),
        BolaValidator.validate(
            attack_status=200,
            baseline_status=200,
            unauth_status=200,
            user1_headers={"Authorization": "Bearer t1"},
        ),
        BolaValidator.validate(
            attack_status=200,
            baseline_status=200,
            unauth_status=401,
            attack_response_body={"id": 1},
            baseline_response_body={"id": 1},
            user1_headers={"Authorization": "Bearer t1"},
        ),
        BolaValidator.validate(
            attack_status=200,
            unauth_status=200,
            user1_headers={"Authorization": "Bearer t1"},
            user2_headers={"Authorization": "Bearer t2"},
        ),
    ]
    for bv in bola_verdicts:
        assert bv.outcome == "rejected"
        assert bv.severity == "info"
        assert bv.confidence <= 0.15
        assert bv.evidence_refs

    ssti_verdicts = [
        SstiValidator.validate(
            attack_status=200,
            attack_body="Echo {{9187*8431}}",
            baseline_body="Echo hi",
            initial_payload="{{9187*8431}}",
            initial_expected="77455597",
        ),
        SstiValidator.validate(
            attack_status=200,
            attack_body="Val 77455597",
            baseline_body="Val 77455597",
            initial_payload="{{9187*8431}}",
            initial_expected="77455597",
        ),
        SstiValidator.validate(
            attack_status=200,
            attack_body="Val 77455597",
            baseline_body="Val 100",
            initial_payload="{{9187*8431}}",
            initial_expected="77455597",
            secondary_status=200,
            secondary_body="Val {{9199*8443}}",
            secondary_expected="77667157",
        ),
    ]
    for sv in ssti_verdicts:
        assert sv is not None
        assert sv.outcome == "rejected"
        assert sv.severity == "info"
        assert sv.confidence <= 0.15
        assert sv.evidence_refs


# ----------------------------------------------------------------------
# 15-20. Aggregation, Reporting (CSV/NDJSON/SARIF/HTML), Quality Gate & P0
# ----------------------------------------------------------------------


def test_build_finding_from_observations_enforces_invariants_and_preserves_p0():
    bad_confirmed = Observation(
        observation_id="OBS-1",
        timestamp="2026-11-27T00:00:00+00:00",
        outcome="confirmed",
        severity="high",
        confidence=0.60,  # too low for confirmed -> downgraded to candidate/medium
        validation_result="confirmed",
    )
    bad_rejected = Observation(
        observation_id="OBS-2",
        timestamp="2026-11-27T00:01:00+00:00",
        outcome="rejected",
        severity="high",
        confidence=0.90,
        validation_result="rejected",
    )
    bad_error = Observation(
        observation_id="OBS-3",
        timestamp="2026-11-27T00:02:00+00:00",
        outcome="error",
        severity="high",
        confidence=0.70,
        validation_result="error",
        error="timeout",
    )
    finding = build_finding_from_observations(
        finding_id="F-NORM-1",
        run_id="run-norm",
        timestamp="2026-11-27T00:02:00+00:00",
        target_app="norm_api",
        endpoint="/orders",
        method="GET",
        tool="schemathesis",
        attack_type="BOLA",
        fingerprint="fp-norm-1",
        observations=[bad_confirmed, bad_rejected, bad_error],
    )
    assert finding.observation_count == 3
    assert finding.error_count == 1
    assert finding.lifecycle == "candidate"
    assert finding.confirmed is False
    assert finding.severity == "medium"
    assert finding.confidence == 0.60
    assert finding.observations[0].outcome == "candidate"
    assert finding.observations[1].severity == "info"
    assert finding.observations[1].confidence == 0.15
    assert finding.observations[2].severity == "unknown"
    assert finding.observations[2].confidence == 0.0

    # Inconclusive cannot hold medium/high severity
    inc_obs = Observation(
        observation_id="OBS-4",
        timestamp="2026-11-27T00:03:00+00:00",
        outcome="inconclusive",
        severity="high",
        confidence=0.80,
        validation_result="inconclusive",
    )
    inc_finding = build_finding_from_observations(
        finding_id="F-NORM-2",
        run_id="run-norm",
        timestamp="2026-11-27T00:03:00+00:00",
        target_app="norm_api",
        endpoint="/health",
        method="GET",
        tool="schemathesis",
        attack_type="BOLA",
        fingerprint="fp-norm-2",
        observations=[inc_obs],
    )
    assert inc_finding.lifecycle == "inconclusive"
    assert inc_finding.confirmed is False
    assert inc_finding.severity == "info"
    assert inc_finding.confidence == 0.30


def test_reporter_sarif_html_csv_ndjson_consistency(tmp_path: Path):
    results_dir = tmp_path / "results"
    manager = ResultManager(root=tmp_path, results_dir=results_dir)

    findings = [
        build_finding_from_observations(
            finding_id="F-CONF",
            run_id="run-rep",
            timestamp="2026-11-27T00:00:00+00:00",
            target_app="norm_api",
            endpoint="/render",
            method="GET",
            tool="schemathesis",
            attack_type="SSTI",
            owasp_category="API8:2023",
            fingerprint="fp-conf",
            observations=[
                Observation(
                    observation_id="OBS-C",
                    timestamp="2026-11-27T00:00:00+00:00",
                    outcome="confirmed",
                    severity="critical",
                    confidence=0.95,
                    signals=["SSTI differential confirmed"],
                    validation_result="confirmed",
                )
            ],
        ),
        build_finding_from_observations(
            finding_id="F-CAND",
            run_id="run-rep",
            timestamp="2026-11-27T00:01:00+00:00",
            target_app="norm_api",
            endpoint="/search",
            method="GET",
            tool="schemathesis",
            attack_type="SQL_INJECTION",
            owasp_category="API8:2023",
            fingerprint="fp-cand",
            observations=[
                Observation(
                    observation_id="OBS-K",
                    timestamp="2026-11-27T00:01:00+00:00",
                    outcome="candidate",
                    severity="medium",
                    confidence=0.55,
                    signals=["SQL syntax error"],
                    validation_result="candidate",
                )
            ],
        ),
        build_finding_from_observations(
            finding_id="F-INC",
            run_id="run-rep",
            timestamp="2026-11-27T00:02:00+00:00",
            target_app="norm_api",
            endpoint="/users/1",
            method="GET",
            tool="schemathesis",
            attack_type="BOLA",
            owasp_category="API1:2023",
            fingerprint="fp-inc",
            observations=[
                Observation(
                    observation_id="OBS-I",
                    timestamp="2026-11-27T00:02:00+00:00",
                    outcome="inconclusive",
                    severity="info",
                    confidence=0.25,
                    signals=["single-token diff"],
                    validation_result="inconclusive",
                )
            ],
        ),
        build_finding_from_observations(
            finding_id="F-REJ",
            run_id="run-rep",
            timestamp="2026-11-27T00:03:00+00:00",
            target_app="norm_api",
            endpoint="/public",
            method="GET",
            tool="schemathesis",
            attack_type="BOLA",
            owasp_category="API1:2023",
            fingerprint="fp-rej",
            observations=[
                Observation(
                    observation_id="OBS-R",
                    timestamp="2026-11-27T00:03:00+00:00",
                    outcome="rejected",
                    severity="info",
                    confidence=0.10,
                    signals=["public endpoint"],
                    validation_result="rejected",
                )
            ],
        ),
        build_finding_from_observations(
            finding_id="F-ERR",
            run_id="run-rep",
            timestamp="2026-11-27T00:04:00+00:00",
            target_app="norm_api",
            endpoint="/timeout",
            method="GET",
            tool="schemathesis",
            attack_type="SQL_INJECTION",
            owasp_category="API8:2023",
            fingerprint="fp-err",
            observations=[
                Observation(
                    observation_id="OBS-E",
                    timestamp="2026-11-27T00:04:00+00:00",
                    outcome="error",
                    severity="unknown",
                    confidence=0.0,
                    signals=["ReadTimeout"],
                    validation_result="error",
                    error="ReadTimeout",
                )
            ],
        ),
    ]

    fields = list(Finding.model_fields.keys())
    manager.append_findings(findings, source="schemathesis", fieldnames=fields)

    with (results_dir / "vulnerabilities.csv").open("r", newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))
    assert len(csv_rows) == 5
    assert csv_rows[1]["severity"] == "medium"
    assert float(csv_rows[1]["confidence"]) == 0.55

    reporter = SecurityReporter(results_dir)
    loaded = reporter.load_findings(run_id="run-rep")
    assert [item["lifecycle"] for item in loaded] == [
        "confirmed",
        "candidate",
        "inconclusive",
        "rejected",
        "error",
    ]
    assert [item["confidence"] for item in loaded] == [0.95, 0.55, 0.25, 0.10, 0.0]
    assert loaded[4]["severity"] == "unknown"
    assert loaded[4]["outcome"] == "error"

    err_norm = reporter._normalize_finding({
        "finding_id": "err-only",
        "lifecycle": "error",
        "severity": "unknown",
        "confidence": 0.0,
    })
    assert err_norm["severity"] == "unknown"
    assert err_norm["confidence"] == 0.0
    assert err_norm["lifecycle"] == "error"
    assert err_norm["outcome"] == "error"

    invalid_sev_norm = reporter._normalize_finding({
        "finding_id": "bad-sev",
        "lifecycle": "candidate",
        "severity": "bogus",
    })
    assert invalid_sev_norm["severity"] == "info"

    # Legacy finding without confidence must default to 0.0 (never invented)
    legacy_norm = reporter._normalize_finding({"finding_id": "leg", "severity": "medium", "confirmed": False})
    assert legacy_norm["confidence"] == 0.0
    nan_norm = reporter._normalize_finding({"finding_id": "nan", "confidence": "nan"})
    assert nan_norm["confidence"] == 0.0

    html_path = reporter.generate_html_report(loaded)
    html_text = html_path.read_text(encoding="utf-8")
    for label in ("CONFIRMED VULNERABILITY", "CANDIDATE", "INCONCLUSIVE", "REJECTED", "ERROR"):
        assert f">{label}<" in html_text
    assert "Confidence: 95%" in html_text
    assert "Confidence: 55%" in html_text
    assert "PROBE / UNCONFIRMED" not in html_text

    sarif_doc = build_sarif_document(
        loaded,
        owasp_metadata={},
        project_root=tmp_path,
        sign_fn=lambda _: "sig",
    )
    sarif_results = sarif_doc["runs"][0]["results"]
    assert [r["level"] for r in sarif_results] == ["error", "warning", "note", "note", "note"]
    assert [r["properties"]["lifecycle"] for r in sarif_results] == [
        "confirmed",
        "candidate",
        "inconclusive",
        "rejected",
        "error",
    ]
    assert [r["properties"]["confidence"] for r in sarif_results] == [0.95, 0.55, 0.25, 0.10, 0.0]
    assert sarif_results[4]["properties"]["severity"] == "unknown"


def test_quality_gate_compatibility_with_normalized_pipeline(tmp_path: Path):
    # 1. End-to-end unconfirmed HTTP 500 & TIME_BASED must normalize <= medium and pass --max-high 0
    group = [
        rest.PreparedCase(
            "fp-500",
            "norm_api",
            "http://api.test",
            _DummyCase("GET", "/crash", {"q": "ok"}),
            _DummyCase("GET", "/crash", {"q": "'"}),
            _make_payload(endpoint="/crash", attack_type="SQL_INJECTION", payload_value="'"),
        ),
        rest.PreparedCase(
            "fp-slow",
            "norm_api",
            "http://api.test",
            _DummyCase("GET", "/slow", {"q": "ok"}),
            _DummyCase("GET", "/slow", {"q": "1' AND SLEEP(4)--"}),
            _make_payload(endpoint="/slow", attack_type="TIME_BASED_SQLI", payload_value="1' AND SLEEP(4)--"),
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/crash" and request.url.params.get("q") == "'":
            return httpx.Response(500, text="You have an error in your SQL syntax")
        resp = httpx.Response(200, json={"ok": True})
        if request.url.path == "/slow" and "SLEEP" in request.url.params.get("q", ""):
            resp.elapsed_ms = 4100.0  # type: ignore[attr-defined]
        else:
            resp.elapsed_ms = 20.0  # type: ignore[attr-defined]
        return resp

    orig_async_client = httpx.AsyncClient

    async def _run():
        state = RunState(tmp_path / "state.json")
        with patch.object(
            rest.httpx,
            "AsyncClient",
            side_effect=lambda **kw: orig_async_client(transport=httpx.MockTransport(handler), **kw),
        ):
            return await rest.run_all(group, {}, None, state, 2, 0)

    emitted = asyncio.run(_run())
    assert len(emitted) == 2
    assert all(not f.confirmed for f in emitted)
    assert all(f.severity == "medium" for f in emitted)

    reporter = SecurityReporter(results_dir=tmp_path)
    cand_sarif = reporter.generate_sarif_report(
        [reporter._normalize_finding(f.model_dump()) for f in emitted],
        output_file=tmp_path / "candidates.sarif",
    )
    assert run_all.main(["gate", "--sarif", str(cand_sarif), "--max-critical", "0", "--max-high", "0"]) == 0

    # 2. Confirmed high still fails --max-high 0 (even with --allow-confirmed)
    confirmed_high_sarif = reporter.generate_sarif_report(
        [{
            "finding_id": "F-CH",
            "method": "GET",
            "endpoint": "/orders/1",
            "attack_type": "BOLA",
            "owasp_category": "API1:2023",
            "severity": "high",
            "confidence": 0.95,
            "confirmed": True,
            "lifecycle": "confirmed",
            "evidence": "BOLA confirmed",
        }],
        output_file=tmp_path / "confirmed_high.sarif",
    )
    assert run_all.main([
        "gate", "--sarif", str(confirmed_high_sarif),
        "--max-critical", "0", "--max-high", "0", "--allow-confirmed",
    ]) == 1

    # 3. Confirmed critical still fails --max-critical 0 (even with --allow-confirmed)
    confirmed_crit_sarif = reporter.generate_sarif_report(
        [{
            "finding_id": "F-CC",
            "method": "GET",
            "endpoint": "/render",
            "attack_type": "SSTI",
            "owasp_category": "API8:2023",
            "severity": "critical",
            "confidence": 0.95,
            "confirmed": True,
            "lifecycle": "confirmed",
            "evidence": "SSTI confirmed",
        }],
        output_file=tmp_path / "confirmed_crit.sarif",
    )
    assert run_all.main([
        "gate", "--sarif", str(confirmed_crit_sarif),
        "--max-critical", "0", "--max-high", "5", "--allow-confirmed",
    ]) == 1
