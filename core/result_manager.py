from __future__ import annotations

import csv
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .path_manager import ProjectPaths


class ResultManager:
    def __init__(
        self,
        root: str | Path | None = None,
        results_dir: str | Path | None = None,
    ):
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

    def _prepare_findings_csv(self, fieldnames):
        """Preserve old-schema CSV and initialize the canonical CSV safely."""
        self.results_dir.mkdir(parents=True, exist_ok=True)
        csv_path = self.results_dir / "vulnerabilities.csv"

        if not csv_path.exists() or csv_path.stat().st_size == 0:
            return csv_path

        with csv_path.open(
            "r", newline="", encoding="utf-8-sig"
        ) as source_file:
            old_header = next(csv.reader(source_file), [])

        if old_header == list(fieldnames):
            return csv_path

        # Preserve the original CSV before changing the canonical file.
        archive = self.results_dir / "vulnerabilities_legacy.csv"
        suffix = 2
        while archive.exists():
            archive = self.results_dir / (
                f"vulnerabilities_legacy_{suffix}.csv"
            )
            suffix += 1

        shutil.copy2(csv_path, archive)

        if (
            not archive.exists()
            or archive.stat().st_size != csv_path.stat().st_size
        ):
            raise RuntimeError(
                "Khong the xac minh ban sao CSV lich su; "
                "da dung de tranh mat du lieu."
            )

        print(
            "[CANH BAO] CSV schema cu khong khop schema hien tai.\\n"
            f"  Lich su duoc luu tai: {archive}\\n"
            f"  Bat dau CSV schema moi tai: {csv_path}"
        )

        # Start a fresh canonical CSV with the current schema.
        # The old data remains in the verified archive above.
        with csv_path.open(
            "w", newline="", encoding="utf-8"
        ) as output_file:
            csv.writer(output_file).writerow(fieldnames)

        return csv_path

    def append_findings(
        self,
        findings: list[Any],
        *,
        source: str,
        fieldnames: list[str],
    ) -> None:
        csv_path = self._prepare_findings_csv(fieldnames)

        # Append CSV records using the verified current schema.
        with csv_path.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=fieldnames,
                extrasaction="raise",
            )
            if output.tell() == 0:
                writer.writeheader()

            for finding in findings:
                record = finding.model_dump()
                if "payload" in record:
                    record["payload"] = json.dumps(
                        record["payload"],
                        ensure_ascii=False,
                    )
                writer.writerow(record)

        # Keep the existing NDJSON behavior and source attribution.
        ndjson_path = self.ensure_results_dir() / "vulnerabilities.ndjson"
        with ndjson_path.open("a", encoding="utf-8") as output:
            for finding in findings:
                record = finding.model_dump()
                record["source"] = source
                output.write(json.dumps(record, ensure_ascii=False) + "\n")

    def append_run_summary(
        self,
        summary: dict[str, Any],
        fieldnames: list[str],
    ) -> None:
        runs_path = self.ensure_results_dir() / "experiment_runs.csv"
        needs_header = (
            not runs_path.exists() or runs_path.stat().st_size == 0
        )

        with runs_path.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(
                output,
                fieldnames=fieldnames,
                extrasaction="raise",
            )
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
        manifest_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return manifest_path


def make_run_id(*, prefix: str = "run") -> str:
    return ResultManager().make_run_id(prefix=prefix)


__all__ = ["ResultManager", "make_run_id"]
