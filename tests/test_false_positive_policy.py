import httpx

import modules.rest.run_schemathesis1 as rest


def make_payload(attack_type="BOLA", expected_signal=None):
    return rest.Payload(
        endpoint="/api/items/{id}",
        method="GET",
        target_param="id",
        param_location="path",
        attack_type=attack_type,
        payload_value="1",
        expected_signal=expected_signal or [],
    )


def test_generic_keywords_on_bad_request_do_not_create_bola_candidate(monkeypatch):
    monkeypatch.setattr(
        rest.rules_engine, "get_all_signals",
        lambda rules: ["content", "title", "author", "admin", "deleted"],
    )
    monkeypatch.setattr(
        rest.rules_engine, "match_cves_by_keyword",
        lambda *args: [],
    )
    response = httpx.Response(
        400, json={"content": "invalid id", "title": "Bad Request"}
    )

    severity, candidate, evidence, cves = rest.evaluate_response(
        response, make_payload("BOLA"), rules={}
    )

    assert candidate is False
    assert severity == "info"
    assert "rejected or invalid" in evidence
    assert cves == []


def test_generic_keyword_on_success_response_is_not_enough(monkeypatch):
    monkeypatch.setattr(
        rest.rules_engine, "get_all_signals",
        lambda rules: ["admin", "success", "deleted"],
    )
    monkeypatch.setattr(
        rest.rules_engine, "match_cves_by_keyword",
        lambda *args: [],
    )
    response = httpx.Response(200, json={"message": "success"})

    _, candidate, evidence, _ = rest.evaluate_response(
        response, make_payload("AUTH_BYPASS"), rules={}
    )

    assert candidate is False
    assert "generic keywords ignored" in evidence


def test_payload_specific_signal_creates_candidate_not_confirmation():
    response = httpx.Response(200, json={"marker": "unique-canary-value"})
    payload = make_payload("XSS", ["unique-canary-value"])

    _, candidate, _, _ = rest.evaluate_response(response, payload)

    # evaluate_response returns candidate status, never confirmation status.
    assert candidate is True


def test_server_error_is_candidate_not_confirmation():
    response = httpx.Response(500, text="Internal Server Error")

    _, candidate, _, _ = rest.evaluate_response(
        response, make_payload("SQL_INJECTION")
    )

    assert candidate is True


def test_bola_200_with_generic_admin_email_fields_is_not_candidate(monkeypatch):
    monkeypatch.setattr(
        rest.rules_engine, "get_all_signals",
        lambda rules: ["admin", "email", "username", "content"],
    )
    monkeypatch.setattr(
        rest.rules_engine, "match_cves_by_keyword",
        lambda *args: [],
    )
    response = httpx.Response(
        200,
        json={"username": "admin", "email": "admin@example.test"},
    )

    _, candidate, evidence, _ = rest.evaluate_response(
        response, make_payload("BOLA"), rules={}
    )

    assert candidate is False
    assert "generic keywords ignored" in evidence


def test_generic_content_title_author_on_400_is_not_sqli_candidate(monkeypatch):
    monkeypatch.setattr(
        rest.rules_engine, "get_all_signals",
        lambda rules: ["content", "title", "author"],
    )
    monkeypatch.setattr(
        rest.rules_engine, "match_cves_by_keyword",
        lambda *args: [],
    )
    response = httpx.Response(
        400,
        json={"content": "invalid input", "title": "Bad Request"},
    )

    _, candidate, evidence, _ = rest.evaluate_response(
        response, make_payload("SQL_INJECTION"), rules={}
    )

    assert candidate is False
    assert "generic keywords ignored" in evidence
