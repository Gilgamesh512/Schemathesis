from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from .path_manager import ProjectPaths


@dataclass
class TargetConfig:
    target_id: str
    name: str
    base_url: str
    schema_source: str | None = None
    auth: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)


class TargetManager:
    def __init__(self, root: str | Path | None = None):
        self.paths = ProjectPaths.from_root(root)
        self.targets: dict[str, TargetConfig] = {}
        self._load_default_profiles()

    def _load_default_profiles(self) -> None:
        registry_file = self.paths.targets / "registry.yaml"
        profile_dir = self.paths.targets / "profiles"
        if registry_file.exists():
            self._load_registry(registry_file)
        if profile_dir.exists():
            for path in sorted(profile_dir.glob("*.yaml")):
                self._load_profile(path)

    def _load_registry(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Target registry must contain a mapping: {path}")
        profiles = data.get("profiles", [])
        if not isinstance(profiles, list):
            raise ValueError(f"'profiles' must be a list in {path}")
        for item in profiles:
            if not isinstance(item, dict):
                raise ValueError(f"Target profile entries must be mappings in {path}")
            allowed = {
                "target_id", "name", "base_url", "schema_source", "auth", "settings"
            }
            unknown = item.keys() - allowed
            if unknown:
                raise ValueError(
                    f"Unknown target profile fields in {path}: {', '.join(sorted(unknown))}"
                )
            self._register(TargetConfig(**item))

    def _load_profile(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Target profile must contain a mapping: {path}")
        target_id = str(data.get("target_id") or path.stem)
        self._register(
            TargetConfig(
                target_id=target_id,
                name=str(data.get("display_name") or target_id),
                base_url=str(data.get("base_url") or ""),
                schema_source=data.get("schema_source"),
                auth=data.get("auth") or {},
                settings=data.get("settings") or {},
            )
        )

    def _register(self, config: TargetConfig) -> None:
        validated = self.validate(config)
        if validated.target_id in self.targets:
            raise ValueError(f"Duplicate target identifier: {validated.target_id}")
        self.targets[validated.target_id] = validated

    @staticmethod
    def validate(config: TargetConfig) -> TargetConfig:
        if not config.target_id:
            raise ValueError("Target identifier is required")
        if not config.name:
            raise ValueError(f"Target '{config.target_id}' is missing a name")
        if not config.base_url:
            raise ValueError(f"Target '{config.target_id}' is missing a base_url")
        parsed = urlparse(config.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Target '{config.target_id}' has an invalid base URL: {config.base_url}")
        if not isinstance(config.auth, dict):
            raise ValueError(f"Target '{config.target_id}' auth must be a mapping")
        if not isinstance(config.settings, dict):
            raise ValueError(f"Target '{config.target_id}' settings must be a mapping")
        if config.schema_source is not None and not isinstance(config.schema_source, str):
            raise ValueError(f"Target '{config.target_id}' schema_source must be a string")
        return config

    def get_target(self, target_id: str) -> TargetConfig:
        if target_id not in self.targets:
            raise KeyError(f"Unknown target '{target_id}'")
        return self.targets[target_id]

    def resolve_source(self, source: str | Path) -> Path:
        return self.paths.resolve(source)

    def add_target(self, target_id: str, *, base_url: str, schema_source: str | None = None,
                   auth: dict[str, Any] | None = None, settings: dict[str, Any] | None = None,
                   name: str | None = None) -> TargetConfig:
        config = TargetConfig(
            target_id=target_id,
            name=name or target_id,
            base_url=base_url,
            schema_source=schema_source,
            auth=auth or {},
            settings=settings or {},
        )
        self._register(config)
        return self.targets[target_id]

TargetRegistry = TargetManager

__all__ = ["TargetConfig", "TargetManager", "TargetRegistry"]
