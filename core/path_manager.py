from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


def resolve_project_root(start: str | Path | None = None) -> Path:
    """Resolve the repository root without depending on the current shell working directory."""
    if start is None:
        return Path(__file__).resolve().parent.parent
    candidate = Path(start).resolve()
    if candidate.is_file():
        candidate = candidate.parent
    for parent in (candidate, *candidate.parents):
        if (parent / ".git").exists() or (parent / "requirements.txt").exists():
            return parent
    return candidate


@dataclass(frozen=True)
class ProjectPaths:
    root: Path
    targets: Path
    schemas: Path
    payloads: Path
    config: Path
    results: Path
    auth: Path

    @classmethod
    def from_root(cls, root: str | Path | None = None) -> "ProjectPaths":
        project_root = resolve_project_root(root)
        return cls(
            root=project_root,
            targets=project_root / "targets",
            schemas=project_root / "targets" / "schemas",
            payloads=project_root / "payloads",
            config=project_root / "config",
            results=project_root / "results",
            auth=project_root / "auth",
        )

    def resolve(self, path: str | Path, *, allow_outside: bool = False) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        resolved = candidate.resolve()
        root = self.root.resolve()
        if not allow_outside and root not in resolved.parents and resolved != root:
            raise ValueError(f"Refusing to resolve path outside project root: {path}")
        return resolved

    def ensure_dirs(self) -> None:
        for directory in (self.targets, self.schemas, self.payloads, self.config, self.results, self.auth):
            directory.mkdir(parents=True, exist_ok=True)


def safe_project_path(path: str | Path, *, root: str | Path | None = None, allow_outside: bool = False) -> Path:
    project = ProjectPaths.from_root(root)
    return project.resolve(path, allow_outside=allow_outside)


__all__ = ["ProjectPaths", "resolve_project_root", "safe_project_path"]
