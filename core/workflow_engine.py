"""Stateful Workflow Chaining Engine for multi-step API business logic testing.

Enables sequential, state-dependent API execution where data generated from
preceding steps (IDs, tokens, timestamps) dynamically populates succeeding requests.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field
import yaml

from .evidence import Evidence, Finding, content_hash, redact_headers, stable_finding_id


def resolve_selector(data: Any, selector: str) -> Any:
    """Resolve a dot-notated or indexed path from a nested dictionary or list.

    Examples:
        - "id" -> data["id"]
        - "user.profile.name" -> data["user"]["profile"]["name"]
        - "items.0.id" -> data["items"][0]["id"]
    """
    if not selector:
        return None

    current = data
    parts = selector.strip().split(".")
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                # Try case-insensitive lookup
                part_lower = part.lower()
                matched = next((v for k, v in current.items() if k.lower() == part_lower), None)
                if matched is not None:
                    current = matched
                else:
                    return None
        elif isinstance(current, (list, tuple)):
            try:
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            except ValueError:
                return None
        else:
            return None
    return current


def interpolate_template(value: Any, context: dict[str, Any]) -> Any:
    """Recursively interpolate {{variable}} placeholders using context values."""
    if isinstance(value, str):
        # Exact match single token: "{{user_id}}" -> preserve original type (int, bool, dict, etc.)
        exact_match = re.fullmatch(r"\{\{\s*([a-zA-Z0-9_-]+)\s*\}\}", value.strip())
        if exact_match:
            var_name = exact_match.group(1)
            if var_name in context:
                return context[var_name]

        # Substring replacement for composite strings: "/users/{{user_id}}/profile"
        def _repl(match: re.Match) -> str:
            v_name = match.group(1).strip()
            v_val = context.get(v_name)
            return str(v_val) if v_val is not None else match.group(0)

        return re.sub(r"\{\{\s*([a-zA-Z0-9_-]+)\s*\}\}", _repl, value)

    if isinstance(value, dict):
        return {k: interpolate_template(v, context) for k, v in value.items()}

    if isinstance(value, list):
        return [interpolate_template(item, context) for item in value]

    return value


class WorkflowStep(BaseModel):
    """Specification of an individual step in a stateful workflow."""

    name: str
    endpoint: str
    method: str = "GET"
    headers: dict[str, Any] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    extract: dict[str, str] = Field(default_factory=dict)
    expected_status: list[int] = Field(default_factory=lambda: [200, 201, 204])
    assert_denied: bool = False
    auth_user: Optional[str] = None
    description: str = ""


class WorkflowDefinition(BaseModel):
    """Declarative specification of an end-to-end API workflow."""

    name: str
    description: str = ""
    base_url: Optional[str] = None
    initial_context: dict[str, Any] = Field(default_factory=dict)
    steps: list[WorkflowStep] = Field(default_factory=list)
    on_failure: str = "abort"  # "abort" | "continue"

    @classmethod
    def from_yaml(cls, path_or_content: str | Path) -> "WorkflowDefinition":
        content = ""
        if isinstance(path_or_content, Path) or (
            isinstance(path_or_content, str) and "\n" not in path_or_content and Path(path_or_content).exists()
        ):
            content = Path(path_or_content).read_text(encoding="utf-8")
        else:
            content = str(path_or_content)

        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("Workflow definition must be a YAML mapping")
        return cls(**data)


class StepExecutionResult(BaseModel):
    """Outcome of an individual workflow step execution."""

    step_name: str
    method: str
    url: str
    status_code: Optional[int] = None
    elapsed_ms: float = 0.0
    success: bool = True
    extracted: dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    response_body: Any = None
    finding: Optional[Finding] = None


class WorkflowExecutionReport(BaseModel):
    """Consolidated summary report of an entire workflow run."""

    workflow_name: str
    started_at: str
    completed_at: str
    duration_ms: float
    total_steps: int
    passed_steps: int
    failed_steps: int
    results: list[StepExecutionResult] = Field(default_factory=list)
    final_context: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    success: bool = True


class WorkflowRunner:
    """Async runner for stateful workflow execution with context chaining."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        proxy: Optional[str] = None,
        insecure: bool = False,
        timeout: float = 20.0,
        user_tokens: Optional[dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.proxy = proxy
        self.insecure = insecure
        self.timeout = timeout
        self.user_tokens = user_tokens or {}

    async def execute_step(
        self,
        client: httpx.AsyncClient,
        step: WorkflowStep,
        context: dict[str, Any],
        base_url: str,
        run_id: str,
    ) -> StepExecutionResult:
        # Interpolate variables in endpoint, query, headers, and body
        raw_endpoint = interpolate_template(step.endpoint, context)
        endpoint = "/" + str(raw_endpoint).lstrip("/")
        full_url = f"{base_url}{endpoint}"

        query_params = interpolate_template(step.query, context)
        request_headers = interpolate_template(step.headers, context)
        request_body = interpolate_template(step.body, context)

        # Apply user auth context if specified
        if step.auth_user:
            user_key = step.auth_user.lower()
            token = self.user_tokens.get(user_key)
            if token:
                if ":" in token:
                    h_name, _, h_val = token.partition(":")
                    request_headers[h_name.strip()] = h_val.strip()
                elif token.lower().startswith("bearer "):
                    request_headers["Authorization"] = token
                else:
                    request_headers["Authorization"] = f"Bearer {token}"

        req_kwargs: dict[str, Any] = {
            "method": step.method.upper(),
            "url": full_url,
            "headers": request_headers,
            "params": query_params if query_params else None,
        }
        if request_body is not None:
            if isinstance(request_body, (dict, list)):
                req_kwargs["json"] = request_body
            else:
                req_kwargs["content"] = str(request_body)

        started = time.perf_counter()
        finding: Optional[Finding] = None
        extracted_vars: dict[str, Any] = {}

        try:
            response = await client.request(**req_kwargs)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

            resp_json = None
            try:
                resp_json = response.json()
            except Exception:
                resp_json = None

            # Variable extraction from response body or response headers
            if step.extract:
                data_scope = {
                    **(resp_json if isinstance(resp_json, dict) else {"data": resp_json}),
                    "headers": dict(response.headers),
                    "status_code": response.status_code,
                }
                for var_name, selector in step.extract.items():
                    extracted_val = resolve_selector(data_scope, selector)
                    if extracted_val is not None:
                        extracted_vars[var_name] = extracted_val
                        context[var_name] = extracted_val

            # Evaluation of assertions and security checks
            status = response.status_code
            success = True
            error_message = None

            if step.assert_denied:
                # Expecting access denied (401 or 403)
                if status == 200:
                    success = False
                    error_message = f"Broken Object Authorization (BOLA): Step '{step.name}' expected 401/403 but got 200 OK."
                    finding = Finding(
                        finding_id=stable_finding_id(
                            "workflow", step.method, endpoint, "BOLA", step.name,
                        ),
                        run_id=run_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        tool="workflow_engine",
                        target_app="workflow",
                        endpoint=endpoint,
                        method=step.method.upper(),
                        attack_type="BOLA",
                        owasp_category="API1:2023",
                        payload=request_body,
                        status_code=status,
                        response_time_ms=elapsed_ms,
                        evidence=Evidence(
                            status_code=status,
                            response_headers=redact_headers(dict(response.headers)),
                            response_signal=[error_message],
                            response_time_ms=elapsed_ms,
                            payload_hash=content_hash(request_body),
                            request_hash=content_hash(full_url),
                            endpoint=endpoint,
                            payload=request_body,
                        ),
                        severity="high",
                        confidence=0.95,
                        confirmed=True,
                        lifecycle="confirmed",
                        fingerprint=content_hash(f"{step.method}|{endpoint}|BOLA"),
                    )
                elif status not in (401, 403, 404):
                    success = False
                    error_message = f"Expected access denial (401/403) but got HTTP {status}"
            elif step.expected_status and status not in step.expected_status:
                success = False
                error_message = f"Expected HTTP status in {step.expected_status}, but received HTTP {status}"

            return StepExecutionResult(
                step_name=step.name,
                method=step.method.upper(),
                url=full_url,
                status_code=status,
                elapsed_ms=elapsed_ms,
                success=success,
                extracted=extracted_vars,
                error_message=error_message,
                response_body=resp_json if resp_json is not None else response.text[:200],
                finding=finding,
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            return StepExecutionResult(
                step_name=step.name,
                method=step.method.upper(),
                url=full_url,
                status_code=None,
                elapsed_ms=elapsed_ms,
                success=False,
                extracted={},
                error_message=f"Request failed: {exc}",
                response_body=None,
                finding=None,
            )

    async def run(
        self,
        workflow: WorkflowDefinition,
        extra_context: Optional[dict[str, Any]] = None,
        run_id: Optional[str] = None,
    ) -> WorkflowExecutionReport:
        started_iso = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()
        actual_run_id = run_id or f"wf-{int(time.time())}"

        context: dict[str, Any] = {**workflow.initial_context, **(extra_context or {})}
        effective_base_url = (workflow.base_url or self.base_url).rstrip("/")
        if not effective_base_url:
            raise ValueError(
                f"Workflow '{workflow.name}' has no base_url configured and runner has no default base_url"
            )

        client_kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.proxy:
            client_kwargs["proxy"] = self.proxy
        if self.insecure:
            client_kwargs["verify"] = False

        results: list[StepExecutionResult] = []
        findings: list[Finding] = []
        overall_success = True

        async with httpx.AsyncClient(**client_kwargs) as client:
            for step in workflow.steps:
                res = await self.execute_step(client, step, context, effective_base_url, actual_run_id)
                results.append(res)

                if res.finding:
                    findings.append(res.finding)

                if not res.success:
                    overall_success = False
                    if workflow.on_failure == "abort":
                        break

        total_duration = round((time.perf_counter() - start_time) * 1000, 1)
        passed = sum(1 for r in results if r.success)
        failed = len(results) - passed

        return WorkflowExecutionReport(
            workflow_name=workflow.name,
            started_at=started_iso,
            completed_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=total_duration,
            total_steps=len(workflow.steps),
            passed_steps=passed,
            failed_steps=failed,
            results=results,
            final_context=context,
            findings=findings,
            success=overall_success,
        )
