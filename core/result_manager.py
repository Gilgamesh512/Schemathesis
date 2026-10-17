from __future__ import annotations

import csv
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .path_manager import ProjectPaths


class ResultManager:
    def __init__(self, root: str | Path | None = None,
                 results_dir: str | Path | None = None):
        self.paths = ProjectPaths.from_root(root)
        self.results_dir = (
            self.paths.results
            if results_dir is None
            else self.paths.resolve(results_dir, allow_outside=True)
        )

    def ensure_results_dir(self) -> Path:
        self.results_dir.mkdir(parents=True, exist_ok=True)
        return self.results_dir

    def make_run_id(self, *, prefix: str = "run") -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}"

    def ensure_run_dir(self, run_id: str | None = None) -> Path:
        run_id = run_id or self.make_run_id()
        if (
            run_id in {".", ".."}
            or "/" in run_id
            or "\\" in run_id
            or Path(run_id).is_absolute()
        ):
            raise ValueError(f"Invalid run identifier: {run_id}")
        path = self.ensure_results_dir() / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def append_findings(self, findings: list[Any], *, source: str,
                        fieldnames: list[str]) -> None:
        results_dir = self.ensure_results_dir()
        csv_path = results_dir / "vulnerabilities.csv"
        needs_header = not csv_path.exists()
        with csv_path.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            if needs_header:
                writer.writeheader()
            for finding in findings:
                record = finding.model_dump()
                record["payload"] = json.dumps(record["payload"], ensure_ascii=False)
                writer.writerow(record)

        ndjson_path = results_dir / "vulnerabilities.ndjson"
        with ndjson_path.open("a", encoding="utf-8") as output:
            for finding in findings:
                record = finding.model_dump()
                record["source"] = source
                output.write(json.dumps(record, ensure_ascii=False) + "\n")

    def append_run_summary(self, summary: dict[str, Any],
                           fieldnames: list[str]) -> None:
        runs_path = self.ensure_results_dir() / "experiment_runs.csv"
        needs_header = not runs_path.exists()
        with runs_path.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            if needs_header:
                writer.writeheader()
            writer.writerow(summary)

    def write_manifest(
        self,
        target: str,
        *,
        run_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        manifest_path = self.ensure_run_dir(run_id) / "manifest.json"
        payload = {
            "run_id": run_id or manifest_path.parent.name,
            "target": target,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return manifest_path


def make_run_id(*, prefix: str = "run") -> str:
    return ResultManager().make_run_id(prefix=prefix)


__all__ = ["ResultManager", "make_run_id"]
