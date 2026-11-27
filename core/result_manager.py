from __future__ import annotations

import csv
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import Finding, merge_findings, sanitize_body
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
                "Could not verify legacy CSV archive; aborting to prevent data loss."
            )

        print(
            "[WARNING] Legacy CSV schema does not match current schema.\n"
            f"  Archived history at: {archive}\n"
            f"  Starting new canonical CSV at: {csv_path}"
        )

        # Start a fresh canonical CSV with the current schema.
        # The old data remains in the verified archive above.
        with csv_path.open(
            "w", newline="", encoding="utf-8"
        ) as output_file:
            csv.writer(output_file).writerow(fieldnames)

        return csv_path

    @staticmethod
    def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
        """Sanitize sensitive values in top-level payload, evidence, and observations."""
        if record.get("payload") is not None:
            record["payload"] = sanitize_body(record["payload"])
        if isinstance(record.get("evidence"), dict) and record["evidence"].get("payload") is not None:
            record["evidence"]["payload"] = sanitize_body(record["evidence"]["payload"])
        if isinstance(record.get("observations"), list):
            sanitized_obs = []
            for obs in record["observations"]:
                if isinstance(obs, dict):
                    obs_copy = dict(obs)
                    if obs_copy.get("payload") is not None:
                        obs_copy["payload"] = sanitize_body(obs_copy["payload"])
                    if isinstance(obs_copy.get("signals"), list):
                        obs_copy["signals"] = [
                            sanitize_body(s) if isinstance(s, str) else s
                            for s in obs_copy["signals"]
                        ]
                    if isinstance(obs_copy.get("error"), str):
                        obs_copy["error"] = sanitize_body(obs_copy["error"])
                    sanitized_obs.append(obs_copy)
                else:
                    sanitized_obs.append(obs)
            record["observations"] = sanitized_obs
        return record

    @staticmethod
    def _format_csv_row(record: dict[str, Any], fieldnames: list[str]) -> dict[str, Any]:
        """Convert a sanitized finding dict into a CSV-safe row matching fieldnames."""
        row = {k: record.get(k) for k in fieldnames}
        if "payload" in row and row["payload"] is not None:
            row["payload"] = json.dumps(row["payload"], ensure_ascii=False)
        if "observations" in row and isinstance(row["observations"], list):
            row["observations"] = json.dumps(row["observations"], ensure_ascii=False)
        return row

    @staticmethod
    def _deduplicate_batch(findings: list[Finding]) -> list[Finding]:
        """Merge duplicate (run_id, fingerprint) findings within a single batch."""
        merged: list[Finding] = []
        index_by_key: dict[tuple[str, str], int] = {}
        for finding in findings:
            key = (finding.run_id, finding.fingerprint)
            if key in index_by_key:
                idx = index_by_key[key]
                merged[idx] = merge_findings(merged[idx], finding)
            else:
                index_by_key[key] = len(merged)
                merged.append(finding)
        return merged

    def append_findings(
        self,
        findings: list[Any],
        *,
        source: str,
        fieldnames: list[str],
    ) -> None:
        if not findings:
            return

        deduped_batch = self._deduplicate_batch(list(findings))
        csv_path = self._prepare_findings_csv(fieldnames)
        ndjson_path = self.ensure_results_dir() / "vulnerabilities.ndjson"

        incoming_by_key = {(f.run_id, f.fingerprint): f for f in deduped_batch}

        # Check whether any (run_id, fingerprint) in this batch already exists on disk.
        existing_records: list[dict[str, Any]] = []
        has_collision = False
        if ndjson_path.exists() and ndjson_path.stat().st_size > 0:
            for raw_line in ndjson_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    key = (str(rec.get("run_id") or ""), str(rec.get("fingerprint") or ""))
                    if key in incoming_by_key:
                        has_collision = True
                    existing_records.append(rec)

        if not has_collision:
            # Fast path: no same-run collisions on disk; append atomically per row/line.
            with csv_path.open("a", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=fieldnames,
                    extrasaction="raise",
                )
                if output.tell() == 0:
                    writer.writeheader()
                for finding in deduped_batch:
                    record = self._sanitize_record(finding.model_dump())
                    writer.writerow(self._format_csv_row(record, fieldnames))

            with ndjson_path.open("a", encoding="utf-8") as output:
                for finding in deduped_batch:
                    record = self._sanitize_record(finding.model_dump())
                    record["source"] = source
                    output.write(json.dumps(record, ensure_ascii=False) + "\n")
            return

        # Collision path: merge with existing same-(run_id, fingerprint) records and rewrite atomically.
        updated_records: list[dict[str, Any]] = []
        merged_keys: set[tuple[str, str]] = set()
        for rec in existing_records:
            key = (str(rec.get("run_id") or ""), str(rec.get("fingerprint") or ""))
            if key in incoming_by_key and key not in merged_keys:
                incoming_f = incoming_by_key[key]
                existing_source = str(rec.get("source") or source)
                try:
                    existing_f = Finding.model_validate(rec)
                    merged_f = merge_findings(existing_f, incoming_f)
                    merged_rec = self._sanitize_record(merged_f.model_dump())
                except Exception:
                    merged_rec = self._sanitize_record(incoming_f.model_dump())
                merged_rec["source"] = (
                    existing_source
                    if existing_source == source
                    else ",".join(dict.fromkeys([*existing_source.split(","), source]))
                )
                updated_records.append(merged_rec)
                merged_keys.add(key)
            else:
                updated_records.append(rec)

        for finding in deduped_batch:
            key = (finding.run_id, finding.fingerprint)
            if key not in merged_keys:
                record = self._sanitize_record(finding.model_dump())
                record["source"] = source
                updated_records.append(record)

        ndjson_tmp = ndjson_path.with_name(f"{ndjson_path.name}.tmp.{uuid.uuid4().hex[:8]}")
        try:
            ndjson_tmp.write_text(
                "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in updated_records),
                encoding="utf-8",
            )
            ndjson_tmp.replace(ndjson_path)
        except Exception:
            if ndjson_tmp.exists():
                ndjson_tmp.unlink(missing_ok=True)
            raise

        csv_tmp = csv_path.with_name(f"{csv_path.name}.tmp.{uuid.uuid4().hex[:8]}")
        try:
            with csv_tmp.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=fieldnames,
                    extrasaction="raise",
                )
                writer.writeheader()
                for rec in updated_records:
                    writer.writerow(self._format_csv_row(rec, fieldnames))
            csv_tmp.replace(csv_path)
        except Exception:
            if csv_tmp.exists():
                csv_tmp.unlink(missing_ok=True)
            raise

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
