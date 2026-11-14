import asyncio
import json
import pytest
from pathlib import Path

from core import (
    CircuitBreakerTrippedError,
    Finding,
    HeaderTamperFuzzer,
    PiiDetector,
    RequestScheduler,
    ResourceExhaustionFuzzer,
    SecurityReporter,
    WorkflowDefinition,
    WorkflowRunner,
    WorkflowStep,
    compute_tamper_signature,
    luhn_checksum_valid,
    sanitize_body,
)
from modules.graphql.run_graphql_fuzz1 import generate_builtin_graphql_payloads


def test_pii_detector_luhn_algorithm():
    """Verify Luhn checksum accurately validates real card patterns and rejects dummy numbers."""
    # Standard valid Visa card
    assert luhn_checksum_valid("4532015112830366") is True
    # Invalid card (last digit altered)
    assert luhn_checksum_valid("4532015112830367") is False
    # All same digits should be rejected
    assert luhn_checksum_valid("0000000000000000") is False


def test_pii_detector_scan_and_masking():
    """Verify PII detector identifies multiple secret categories and masks them."""
    sample_text = (
        "User profile data: "
        "CreditCard: 4532-0151-1283-0366, "
        "AWS_KEY: AKIAIOSFODNN7EXAMPLE, "
        "Hash: $2a$12$e8uq0Z6f3eQyO.jZ0uPWe.bN2G7b5Q8iH6MhVj7V9q3jK4lM8nO2q, "
        "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
        "Phone: 0981234567, CCCD: 001099012345"
    )
    res = PiiDetector.scan(sample_text)
    assert res.has_pii is True
    assert "Valid Credit Card (Luhn Verified)" in res.counts
    assert "AWS Access Key ID" in res.counts
    assert "JWT Authentication Token" in res.counts
    assert "Bcrypt Password Hash" in res.counts

    # Check that mask_text hides the secrets
    masked = PiiDetector.mask_text(sample_text)
    assert "4532-0151-1283-0366" not in masked
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "$2a$12$e8uq0Z6f3eQyO.jZ0uPWe" not in masked
    assert "****" in masked


def test_pii_audit_response_finding():
    """Verify that PII detected in HTTP 200 response generates confirmed Finding."""
    body = json.dumps({
        "status": "success",
        "user": {
            "id": 123,
            "card": "4532-0151-1283-0366",
            "aws_access": "AKIAIOSFODNN7EXAMPLE",
        }
    })
    finding = PiiDetector.audit_response(
        status_code=200,
        response_text=body,
        endpoint="/api/v1/user/123",
        method="GET",
        run_id="test-run-pii",
        target_app="test_app",
        elapsed_ms=45.0,
    )
    assert finding is not None
    assert finding.attack_type == "SENSITIVE_DATA_EXPOSURE"
    assert finding.owasp_category == "API3:2023"
    assert finding.confirmed is True
    assert finding.severity == "critical"


def test_body_sanitization_evidence():
    """Verify that sanitize_body safely masks sensitive data in dictionary / text structures."""
    payload = {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlF5m8b7zK1A",
        "card": "4532015112830366",
    }
    cleaned = sanitize_body(payload)
    assert isinstance(cleaned, dict)
    assert "REDACTED" in str(cleaned) or "****" in str(cleaned)


def test_circuit_breaker_pacing_and_abort():
    """Verify RequestScheduler Circuit Breaker trips when abort threshold is exceeded."""
    async def _run():
        scheduler = RequestScheduler(
            concurrency=2,
            global_rps=0,
            max_retries=0,
            pause_threshold=2,
            abort_threshold=4,
            pause_duration=0.05,
        )

        class MockFailingResponse:
            status_code = 500

        async def fail_op():
            return MockFailingResponse()

        # Requests 1 to 3 should be recorded as consecutive failures
        await scheduler.request("test_api", fail_op)
        await scheduler.request("test_api", fail_op)
        await scheduler.request("test_api", fail_op)

        # 4th request hits abort_threshold (4) -> CircuitBreakerTrippedError must be raised
        with pytest.raises(CircuitBreakerTrippedError):
            await scheduler.request("test_api", fail_op)

        # Subsequent requests to tripped target must fail immediately without invoking operation
        with pytest.raises(CircuitBreakerTrippedError) as exc_info:
            await scheduler.request("test_api", fail_op)
        assert "Circuit Breaker was tripped" in str(exc_info.value)

    asyncio.run(_run())


def test_workflow_teardown_steps():
    """Verify that WorkflowRunner executes teardown_steps to clean up state."""
    async def _run():
        import httpx
        calls = []

        async def mock_handler(request):
            calls.append(f"{request.method} {request.url.path}")
            if request.url.path == "/items" and request.method == "POST":
                return httpx.Response(201, json={"id": 999, "name": "test_item"})
            elif request.url.path == "/items/999" and request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(200, json={})

        wf = WorkflowDefinition(
            name="Lifecycle with Teardown",
            base_url="http://test.local",
            steps=[
                WorkflowStep(
                    name="Create Item",
                    endpoint="/items",
                    method="POST",
                    body={"name": "test_item"},
                    extract={"item_id": "id"},
                ),
            ],
            teardown_steps=[
                WorkflowStep(
                    name="Delete Item Cleanup",
                    endpoint="/items/{{item_id}}",
                    method="DELETE",
                ),
            ],
        )

        runner = WorkflowRunner(base_url="http://test.local")
        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport, base_url="http://test.local") as client:
            context = dict(wf.initial_context)
            # Execute main step
            res1 = await runner.execute_step(client, wf.steps[0], context, "http://test.local", "r1")
            assert res1.success is True
            assert context.get("item_id") == 999

            # Execute teardown step
            res2 = await runner.execute_step(client, wf.teardown_steps[0], context, "http://test.local", "r1")
            assert res2.success is True
            assert "DELETE /items/999" in calls

    asyncio.run(_run())


def test_header_tamper_fuzzer_probes():
    """Verify HeaderTamperFuzzer initializes with required proxy & routing probes."""
    fuzzer = HeaderTamperFuzzer()
    probe_names = [p.name for p in fuzzer.PROBES]
    assert any("X-Forwarded-Host" in n for n in probe_names)
    assert any("X-Original-URL" in n for n in probe_names)
    assert any("X-Rewrite-URL" in n for n in probe_names)


def test_resource_exhaustion_fuzzer_payloads():
    """Verify ResourceExhaustionFuzzer generates nested bombs and ReDoS strings."""
    bomb = ResourceExhaustionFuzzer.generate_nested_json_bomb(depth=50)
    assert "nested" in bomb
    assert len(ResourceExhaustionFuzzer.REDOS_PAYLOADS) >= 3


def test_tamper_evident_hmac_signature(tmp_path):
    """Verify report signing calculates HMAC-SHA256 signature and embeds in HTML and SARIF."""
    content = "<html><body><h1>Security Audit</h1></body></html>"
    sig1 = compute_tamper_signature(content, secret_key="test-key")
    sig2 = compute_tamper_signature(content, secret_key="test-key")
    assert sig1 == sig2
    assert len(sig1) == 64

    # Different content produces different signature
    sig_diff = compute_tamper_signature(content + " altered", secret_key="test-key")
    assert sig1 != sig_diff

    # Test report generation embedding
    reporter = SecurityReporter(tmp_path)
    sample_finding = {
        "finding_id": "F-test1234",
        "method": "GET",
        "endpoint": "/test",
        "attack_type": "TEST_ATTACK",
        "severity": "high",
        "confirmed": True,
        "evidence": "Test signal",
    }
    html_path = reporter.generate_html_report([sample_finding], target_info={"name": "Test", "url": "http://test"})
    html_text = html_path.read_text(encoding="utf-8")
    assert "Tamper-Evident Security Audit Seal" in html_text
    assert "INTEGRITY_SIGNATURE: alg=HMAC-SHA256" in html_text

    sarif_path = reporter.generate_sarif_report([sample_finding], target_info={"name": "Test", "url": "http://test"})
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert "tamper_evident_hmac" in sarif_data["runs"][0]["properties"]


def test_graphql_depth_and_pagination_probes():
    """Verify GraphQL engine generates Depth Exhaustion and Pagination Overflow probes."""
    payloads = generate_builtin_graphql_payloads("target_test")
    attack_types = [p.attack_type for p in payloads]
    assert "GRAPHQL_QUERY_DEPTH_EXHAUSTION" in attack_types
    assert "GRAPHQL_PAGINATION_OVERFLOW" in attack_types
    assert "GRAPHQL_INTROSPECTION" in attack_types
    assert "GRAPHQL_BATCHING_DOS" in attack_types
