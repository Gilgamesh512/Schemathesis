import csv
import json

from core.evidence import Evidence, Finding
from core.result_manager import ResultManager


def make_finding(confirmed=False, lifecycle="candidate"):
    evidence = Evidence(
        status_code=200,
        response_headers={},
        response_signal=["test evidence"],
        response_time_ms=12.0,
        payload_hash="payload-hash",
        request_hash="request-hash",
        endpoint="/test",
        payload={"test": True},
        auth_context={},
        previous_observations=[],
    )
    return Finding(
        finding_id="test-finding",
        run_id="test-run",
        timestamp="2026-10-18T00:00:00+00:00",
        target_app="test-target",
        endpoint="/test",
        method="GET",
        tool="schemathesis",
        attack_type="BOLA",
        payload={"test": True},
        status_code=200,
        response_time_ms=12.0,
        evidence=evidence,
        severity="info",
        confidence=0.55,
        confirmed=confirmed,
        lifecycle=lifecycle,
        fingerprint="test-fingerprint",
    )


def test_candidate_lifecycle_persists_to_csv_and_ndjson(tmp_path):
    results_dir = tmp_path / "results"
    manager = ResultManager(root=tmp_path, results_dir=results_dir)
    finding = make_finding()
    fields = list(finding.model_dump().keys())

    manager.append_findings(
        [finding], source="test", fieldnames=fields
    )

    with (results_dir / "vulnerabilities.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["confirmed"].lower() == "false"
    assert rows[0]["lifecycle"] == "candidate"
    assert float(rows[0]["confidence"]) == 0.55
    assert json.loads(rows[0]["payload"]) == {"test": True}

    with (results_dir / "vulnerabilities.ndjson").open(
        encoding="utf-8"
    ) as handle:
        record = json.loads(handle.readline())

    assert record["confirmed"] is False
    assert record["lifecycle"] == "candidate"
    assert record["source"] == "test"


def test_confirmed_lifecycle_persists_consistently(tmp_path):
    results_dir = tmp_path / "results"
    manager = ResultManager(root=tmp_path, results_dir=results_dir)
    finding = make_finding(confirmed=True, lifecycle="confirmed")
    fields = list(finding.model_dump().keys())

    manager.append_findings(
        [finding], source="test", fieldnames=fields
    )

    with (results_dir / "vulnerabilities.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["confirmed"].lower() == "true"
    assert rows[0]["lifecycle"] == "confirmed"
