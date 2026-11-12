"""Autonomous API Dependency Graph & Stateful Workflow Synthesizer.

Automatically inspects OpenAPI 3.x / Swagger specifications, infers CRUD lifecycles,
pairs resource Producer operations (POST, PUT) with Consumer operations (GET, DELETE, PATCH),
and synthesizes end-to-end multi-step stateful workflows with automated variable extraction
and dual-user BOLA/IDOR assertions without requiring manual YAML authoring.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Optional
import yaml
from pydantic import BaseModel, Field

from .workflow_engine import WorkflowDefinition, WorkflowStep


ID_PARAM_CANDIDATES = {
    "id", "user_id", "userid", "username", "uuid", "guid",
    "post_id", "postid", "order_id", "orderid", "item_id", "itemid",
    "vehicle_id", "vehicleid", "account_id", "accountid", "token",
}


class ProducerCandidate(BaseModel):
    """An operation that creates or provides identifiable resource entities."""
    endpoint: str
    method: str
    summary: str = ""
    produced_fields: list[str] = Field(default_factory=list)
    request_body_sample: Any = None


class ConsumerCandidate(BaseModel):
    """An operation that requires an identifier parameter in path or query."""
    endpoint: str
    method: str
    summary: str = ""
    required_params: list[str] = Field(default_factory=list)


class ApiDependencyGraph:
    """Infers producer-consumer data relationships and auto-synthesizes workflows."""

    def __init__(self, spec_data: dict[str, Any]):
        self.spec = spec_data
        self.producers: list[ProducerCandidate] = []
        self.consumers: list[ConsumerCandidate] = []
        self._analyze_spec()

    @classmethod
    def from_file(cls, path_or_content: str | Path | dict[str, Any]) -> "ApiDependencyGraph":
        """Load from JSON/YAML file path or parsed dictionary."""
        if isinstance(path_or_content, dict):
            return cls(path_or_content)

        path = Path(path_or_content)
        raw = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except Exception:
            data = yaml.safe_load(raw)

        if not isinstance(data, dict):
            raise ValueError(f"Specification must be a JSON/YAML mapping: {path}")
        return cls(data)

    def _analyze_spec(self) -> None:
        """Scan paths and operations to identify producers and consumers."""
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Path parameter check: e.g. /users/{id}
            path_params = re.findall(r"\{([^}]+)\}", path)

            for method_key, op in path_item.items():
                method = method_key.lower()
                if method not in {"get", "post", "put", "patch", "delete"} or not isinstance(op, dict):
                    continue

                summary = op.get("summary") or f"{method.upper()} {path}"

                # 1. Evaluate as Consumer if endpoint takes an identifiable path parameter
                consumer_params = [p for p in path_params if any(cand in p.lower() for cand in ID_PARAM_CANDIDATES) or p]
                if consumer_params and method in {"get", "put", "patch", "delete"}:
                    self.consumers.append(ConsumerCandidate(
                        endpoint=path,
                        method=method.upper(),
                        summary=summary,
                        required_params=consumer_params,
                    ))

                # 2. Evaluate as Producer if endpoint is a state-changing creation endpoint (POST)
                if method == "post":
                    produced = self._extract_produced_fields(op)
                    body_sample = self._extract_request_body_sample(op)
                    self.producers.append(ProducerCandidate(
                        endpoint=path,
                        method="POST",
                        summary=summary,
                        produced_fields=produced,
                        request_body_sample=body_sample,
                    ))

    def _extract_produced_fields(self, op: dict[str, Any]) -> list[str]:
        """Infer response field names produced by this operation."""
        fields: list[str] = []
        responses = op.get("responses", {})
        for code in ("200", "201", "default"):
            resp = responses.get(code)
            if not isinstance(resp, dict):
                continue
            content = resp.get("content", {})
            json_schema = content.get("application/json", {}).get("schema", {})
            props = json_schema.get("properties", {})
            for p_name in props:
                fields.append(p_name)
        # Default fallback common identifiers if schema doesn't specify detailed response
        if not fields:
            fields = ["id", "user_id", "username", "uuid"]
        return list(dict.fromkeys(fields))

    def _extract_request_body_sample(self, op: dict[str, Any]) -> Any:
        """Create a default sample body from operation requestBody schema."""
        req_body = op.get("requestBody", {})
        if not isinstance(req_body, dict):
            return None
        content = req_body.get("content", {})
        json_media = content.get("application/json", {})
        example = json_media.get("example")
        if example is not None:
            return example

        schema = json_media.get("schema", {})
        props = schema.get("properties", {})
        sample: dict[str, Any] = {}
        for prop_name, prop_def in props.items():
            if isinstance(prop_def, dict):
                p_type = prop_def.get("type", "string")
                if p_type == "string":
                    fmt = prop_def.get("format")
                    if fmt == "email":
                        sample[prop_name] = "autotest_user@example.com"
                    elif fmt == "uuid":
                        sample[prop_name] = "11111111-1111-1111-1111-111111111111"
                    else:
                        sample[prop_name] = f"test_{prop_name}"
                elif p_type in ("integer", "number"):
                    sample[prop_name] = 100
                elif p_type == "boolean":
                    sample[prop_name] = False
                else:
                    sample[prop_name] = "sample"
        return sample if sample else {"name": "autotest_entity"}

    def synthesize_workflows(self, max_workflows: int = 5) -> list[WorkflowDefinition]:
        """Synthesize end-to-end BOLA testing workflows pairing producers and consumers."""
        workflows: list[WorkflowDefinition] = []

        for prod in self.producers:
            # Find matching consumers whose path parameter shares root name with produced fields or path
            prod_root = prod.endpoint.strip("/").split("/")[0]

            for cons in self.consumers:
                cons_root = cons.endpoint.strip("/").split("/")[0]
                # Match by path domain similarity (e.g. /users and /users/{id})
                is_domain_match = prod_root == cons_root
                matching_param = cons.required_params[0] if cons.required_params else "id"

                # Check if produced fields has a match for this parameter
                field_match = None
                for f in prod.produced_fields:
                    if f.lower() == matching_param.lower() or f.lower() in matching_param.lower() or matching_param.lower() in f.lower():
                        field_match = f
                        break
                if not field_match:
                    field_match = matching_param if matching_param in prod.produced_fields else "id"

                if is_domain_match or (prod_root in cons.endpoint):
                    wf_name = f"Auto-Synthesized Flow: {prod.summary} -> {cons.summary}"
                    steps: list[WorkflowStep] = []

                    # Step 1: Create resource via Producer (User 1)
                    var_name = f"extracted_{matching_param}"
                    steps.append(WorkflowStep(
                        name=f"Seed Resource: {prod.method} {prod.endpoint}",
                        endpoint=prod.endpoint,
                        method=prod.method,
                        body=prod.request_body_sample,
                        extract={var_name: field_match},
                        expected_status=[200, 201, 204],
                        description="Provision initial resource entity as primary user",
                    ))

                    # Step 2: Validate baseline access as Primary User
                    interpolated_endpoint = cons.endpoint
                    for p in cons.required_params:
                        interpolated_endpoint = interpolated_endpoint.replace(f"{{{p}}}", f"{{{{{var_name}}}}}")

                    steps.append(WorkflowStep(
                        name=f"Baseline Verification: {cons.method} {cons.endpoint}",
                        endpoint=interpolated_endpoint,
                        method=cons.method,
                        expected_status=[200, 204],
                        auth_user="user1",
                        description="Verify owner can access their own resource",
                    ))

                    # Step 3: Dual-User BOLA probe with User 2
                    steps.append(WorkflowStep(
                        name=f"BOLA Cross-User Assertion: {cons.method} {cons.endpoint}",
                        endpoint=interpolated_endpoint,
                        method=cons.method,
                        auth_user="user2",
                        assert_denied=True,
                        description="Assert that secondary user (attacker) cannot read/tamper with resource",
                    ))

                    wf = WorkflowDefinition(
                        name=wf_name,
                        description=f"Automated BOLA validation chain for {cons.endpoint}",
                        steps=steps,
                        on_failure="continue",
                    )
                    workflows.append(wf)
                    if len(workflows) >= max_workflows:
                        return workflows

        return workflows

    def export_workflow_yaml(self, workflow: WorkflowDefinition, output_path: str | Path) -> Path:
        """Export synthesized workflow to YAML file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        data = workflow.model_dump(exclude_none=True)
        out.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return out
