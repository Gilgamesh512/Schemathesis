"""Shared run-state persistence, token env parsing, and fuzzer constants."""

from __future__ import annotations

import json
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DEFAULT_ERROR_SIGNALS = [
    "sql syntax",
    "syntaxerror",
    "traceback",
    "stack trace",
    "internal server error",
    "unhandled exception",
    "odbc",
    "psql",
    "sqlite",
    "ora-",
    "you have an error in your sql",
]

SEVERITY_BY_STATUS = {
    500: "high",
    502: "high",
    503: "medium",
}

MAX_ATTEMPTS_PER_FINGERPRINT = 3


class RunState:
    """Persistent deduplication and retry-tracking state across fuzzing runs."""

    def __init__(self, path: Path, *, auto_save: bool = False):
        self.path = path
        self.auto_save = auto_save
        self.data: dict[str, dict[str, Any]] = {}
        if path.exists():
            try:
                raw = path.read_text(encoding="utf-8")
                parsed = json.loads(raw)
                if not isinstance(parsed, dict):
                    raise ValueError(
                        f"State file must contain a JSON object, got {type(parsed).__name__}"
                    )
                self.data = parsed
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                archive = self.path.with_name(f"{self.path.stem}_corrupted{self.path.suffix}")
                suffix = 2
                while archive.exists():
                    archive = self.path.with_name(
                        f"{self.path.stem}_corrupted_{suffix}{self.path.suffix}"
                    )
                    suffix += 1
                archive_saved = False
                try:
                    shutil.copy2(self.path, archive)
                    archive_saved = True
                except OSError as copy_exc:
                    print(
                        f"[WARNING] Failed to save backup of corrupted state: {copy_exc}",
                        file=sys.stderr,
                    )

                if archive_saved:
                    archive_msg = f"Original file archived at {archive}."
                else:
                    archive_msg = (
                        "Could not create backup archive; original file preserved on disk."
                    )

                print(
                    f"[WARNING] State file {self.path} is corrupted ({exc}). "
                    f"{archive_msg} "
                    "Initializing empty state (historical data not restored).",
                    file=sys.stderr,
                )
                self.data = {}
            except OSError as exc:
                print(
                    f"[WARNING] Could not read state file {self.path}: {exc}. "
                    "Initializing empty state.",
                    file=sys.stderr,
                )
                self.data = {}

    def status(self, fp: str) -> Optional[str]:
        return self.data.get(fp, {}).get("status")

    def attempts(self, fp: str) -> int:
        return self.data.get(fp, {}).get("attempts", 0)

    def record(self, fp: str, status: str) -> None:
        entry = self.data.setdefault(fp, {"attempts": 0, "status": "new"})
        entry["attempts"] += 1

        current = entry.get("status", "new")
        if current == "confirmed":
            pass
        elif current == "candidate" and status == "rejected":
            pass
        else:
            entry["status"] = status

        entry["last_seen"] = datetime.now(timezone.utc).isoformat()
        if self.auto_save:
            self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_name(f"{self.path.name}.tmp.{uuid.uuid4().hex[:8]}")
        try:
            temp_path.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            temp_path.replace(self.path)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise


def normalize_auth_header(token_or_header: str | None) -> str | None:
    """Normalize raw token or header string into 'Header: Value' format."""
    if not token_or_header:
        return None
    val = token_or_header.strip()
    if not val:
        return None
    if ":" in val:
        return val
    if val.lower().startswith("bearer "):
        return f"Authorization: {val}"
    return f"Authorization: Bearer {val}"


def parse_tokens_env(
    path: Path,
    *,
    auth_headers_only: bool = False,
    warn_missing: bool = False,
) -> dict[str, str]:
    """Parse KEY=VALUE / export KEY='VALUE' lines from a tokens.env file."""
    if not path.exists():
        if warn_missing:
            print(f"[WARNING] {path} not found - fuzzing will run WITHOUT auth headers.")
        return {}

    tokens: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if auth_headers_only and not key.endswith("_AUTH_HEADER"):
            continue
        tokens[key] = value
    return tokens


def extract_response_elapsed_ms(resp: Any) -> Optional[float]:
    """Safely extract response latency in milliseconds from an httpx or mock response."""
    try:
        if hasattr(resp, "elapsed_ms"):
            val = getattr(resp, "elapsed_ms", None)
            if val is not None:
                return float(val)
        if hasattr(resp, "_elapsed") and getattr(resp, "_elapsed", None) is not None:
            return float(resp._elapsed.total_seconds() * 1000)
    except Exception:
        return None
    return None


__all__ = [
    "DEFAULT_ERROR_SIGNALS",
    "MAX_ATTEMPTS_PER_FINGERPRINT",
    "RunState",
    "SEVERITY_BY_STATUS",
    "extract_response_elapsed_ms",
    "normalize_auth_header",
    "parse_tokens_env",
]
