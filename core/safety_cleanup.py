"""core/safety_cleanup.py — Staging Data Integrity, Audit Headers & Rollback Cleanup Manifest.

Protects staging/UAT environments during automated testing:
- Attaches `X-Fuzzer-Audit: true` and `X-Fuzzer-Run-Id: <id>` headers so WAF/SIEM can isolate test traffic.
- Tracks created resources (POST/PUT/PATCH) and writes `cleanup_manifest.json` for rollback.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


def get_audit_headers(run_id: str = "") -> dict[str, str]:
    """Return transparent audit headers for all outbound security test requests."""
    rid = run_id or "schemathesis-run"
    return {
        "X-Fuzzer-Audit": "true",
        "X-Fuzzer-Run-Id": rid,
    }


@dataclass
class CreatedResource:
    run_id: str
    target_url: str
    endpoint: str
    method: str
    created_id: Any | None = None
    rollback_method: str = "DELETE"
    rollback_url: str = ""
    status_code: int = 0
    timestamp: str = ""


class CleanupTracker:
    """Tracks resources created during fuzzing so they can be safely rolled back."""

    def __init__(self, run_id: str, out_dir: str | Path = "results") -> None:
        self.run_id = run_id
        self.out_dir = Path(out_dir)
        self.created_resources: list[CreatedResource] = []

    def record_mutation(
        self,
        method: str,
        target_url: str,
        endpoint: str,
        status_code: int,
        response_data: Any = None,
        response_headers: dict[str, Any] | None = None,
    ) -> None:
        """Record a successful state-mutating request (POST/PUT/PATCH returning 2xx)."""
        clean_method = method.upper().strip()
        if clean_method not in ("POST", "PUT", "PATCH") or status_code not in (200, 201, 202, 204):
            return

        created_id = None
        rollback_url = ""

        # 1. Try extracting resource location from Location header
        if response_headers:
            loc = response_headers.get("Location") or response_headers.get("location")
            if loc:
                rollback_url = str(loc)
                parts = rollback_url.rstrip("/").split("/")
                if parts:
                    created_id = parts[-1]

        # 2. Try extracting created ID from JSON response body
        if not created_id and isinstance(response_data, dict):
            for id_key in ("id", "user_id", "userId", "order_id", "orderId", "uuid", "key", "account_id"):
                if id_key in response_data and response_data[id_key] is not None:
                    created_id = response_data[id_key]
                    break

        # Infer rollback URL only when a concrete resource ID was discovered
        if not rollback_url:
            if created_id is not None:
                base = endpoint.rstrip("/")
                rollback_url = f"{base}/{created_id}"
            else:
                rollback_url = ""  # Never issue DELETE against an entire collection endpoint without an ID

        res = CreatedResource(
            run_id=self.run_id,
            target_url=target_url,
            endpoint=endpoint,
            method=clean_method,
            created_id=created_id,
            rollback_method="DELETE",
            rollback_url=rollback_url,
            status_code=status_code,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.created_resources.append(res)

    def write_manifest(self) -> Path:
        """Write cleanup_manifest.json to facilitate staging data rollback."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = self.out_dir / "cleanup_manifest.json"

        data = {
            "run_id": self.run_id,
            "total_created_resources": len(self.created_resources),
            "instructions": (
                "This file lists resources created during security testing. "
                "Run the listed DELETE rollback URLs or invoke execute_auto_cleanup() to revert state."
            ),
            "resources": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "created_id": r.created_id,
                    "rollback_method": r.rollback_method,
                    "rollback_url": r.rollback_url,
                    "status_code": r.status_code,
                    "timestamp": r.timestamp,
                }
                for r in self.created_resources
            ],
        }

        with manifest_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return manifest_file

    def execute_auto_cleanup(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
        insecure: bool = False,
    ) -> dict[str, Any]:
        """Automatically execute DELETE requests for tracked created resources."""
        results = {"total": len(self.created_resources), "deleted": 0, "failed": 0, "skipped": 0}
        req_headers = dict(headers or {})
        req_headers.update(get_audit_headers(self.run_id))

        for r in self.created_resources:
            if not r.rollback_url:
                results["skipped"] += 1
                continue

            target = r.rollback_url
            if not (target.startswith("http://") or target.startswith("https://")):
                target = f"{base_url.rstrip('/')}/{target.lstrip('/')}"

            try:
                resp = requests.delete(
                    target,
                    headers=req_headers,
                    timeout=timeout,
                    verify=not insecure,
                )
                if resp.status_code in (200, 202, 204, 404):
                    results["deleted"] += 1
                else:
                    results["failed"] += 1
            except Exception as e:
                logger.warning("Failed to auto-delete %s: %s", target, e)
                results["failed"] += 1

        return results
