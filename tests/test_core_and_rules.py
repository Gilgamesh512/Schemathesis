from unittest.mock import Mock, patch

from core import redact_headers, stable_finding_id
from rules_engine import fetch_cves_for_keyword


def test_finding_id_is_stable_and_payload_independent():
    first = stable_finding_id("VAmPI", "post", "/users/", "SQLi", "username")
    second = stable_finding_id("vampi", "POST", "/users", "sqli", "username")
    assert first == second


def test_auth_headers_are_redacted_but_correlatable():
    result = redact_headers({"Authorization": "Bearer secret", "Accept": "application/json"})
    assert result["Authorization"] == "<REDACTED>"
    assert result["Authorization_hash"]
    assert result["Accept"] == "application/json"


def test_nvd_fetch_paginates_until_total_results():
    def response(items, total):
        mocked = Mock()
        mocked.json.return_value = {
            "totalResults": total,
            "vulnerabilities": [{"cve": item} for item in items],
        }
        mocked.raise_for_status.return_value = None
        return mocked

    pages = [
        response([{"id": "CVE-1", "descriptions": []}], 2),
        response([{"id": "CVE-2", "descriptions": []}], 2),
    ]
    with patch("rules_engine.requests.get", side_effect=pages) as get:
        result = fetch_cves_for_keyword("SQL injection API", 30, None)

    assert [item["cve_id"] for item in result] == ["CVE-1", "CVE-2"]
    assert get.call_count == 2
