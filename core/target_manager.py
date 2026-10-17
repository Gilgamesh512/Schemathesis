from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
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
            for path in sorted((*profile_dir.glob("*.yaml"), *profile_dir.glob("*.yml"))):
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
            try:
                self._register(TargetConfig(**item), source=path)
            except TypeError as exc:
                raise ValueError(f"Invalid target profile in {path}: {exc}") from exc

    def _load_profile(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Target profile must contain a mapping: {path}")
        target_id = str(data.get("target_id") or path.stem)
        allowed = {
            "target_id", "name", "display_name", "base_url", "schema_source",
            "auth", "settings",
        }
        unknown = data.keys() - allowed
        if unknown:
            raise ValueError(
                f"Unknown target profile fields in {path}: {', '.join(sorted(unknown))}"
            )
        self._register(
            TargetConfig(
                target_id=target_id,
                name=str(data.get("name") or data.get("display_name") or target_id),
                base_url=str(data.get("base_url") or ""),
                schema_source=data.get("schema_source"),
                auth=data.get("auth", {}),
                settings=data.get("settings", {}),
            ),
            source=path,
        )

    def _register(self, config: TargetConfig, *, source: Path | None = None) -> None:
        validated = self.validate(config)
        if validated.target_id in self.targets:
            location = f" in {source}" if source else ""
            raise ValueError(
                f"Duplicate target identifier '{validated.target_id}'{location}; "
                "target IDs must be unique across the registry and profiles"
            )
        self.targets[validated.target_id] = validated

    def validate(self, config: TargetConfig) -> TargetConfig:
        if not isinstance(config.target_id, str) or not config.target_id.strip():
            raise ValueError("Target identifier is required")
        config.target_id = config.target_id.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", config.target_id):
            raise ValueError(
                "Target identifier must start with a letter or digit and contain "
                "only letters, digits, hyphens, or underscores"
            )
        if not isinstance(config.name, str) or not config.name.strip():
            raise ValueError(f"Target '{config.target_id}' is missing a name")
        config.name = config.name.strip()
        if not isinstance(config.base_url, str) or not config.base_url.strip():
            raise ValueError(f"Target '{config.target_id}' is missing a base_url")
        config.base_url = config.base_url.strip()
        parsed = urlparse(config.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Target '{config.target_id}' has an invalid base URL: {config.base_url}")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in a target base URL")
        if not isinstance(config.auth, dict):
            raise ValueError(f"Target '{config.target_id}' auth must be a mapping")
        if not isinstance(config.settings, dict):
            raise ValueError(f"Target '{config.target_id}' settings must be a mapping")
        if config.schema_source is not None and not isinstance(config.schema_source, str):
            raise ValueError(f"Target '{config.target_id}' schema_source must be a string")
        protocol = config.settings.get("protocol")
        if protocol not in {"rest", "graphql"}:
            raise ValueError(
                f"Target '{config.target_id}' protocol must be 'rest' or 'graphql'"
            )
        if protocol == "rest" and not config.schema_source:
            raise ValueError(f"REST target '{config.target_id}' requires a schema_source")
        if config.schema_source:
            source_scheme = urlparse(config.schema_source).scheme
            if source_scheme in {"http", "https"}:
                parsed_source = urlparse(config.schema_source)
                if not parsed_source.netloc or parsed_source.username or parsed_source.password:
                    raise ValueError(
                        f"Target '{config.target_id}' has an invalid remote schema URL"
                    )
                if not config.settings.get("allow_remote_schema", False):
                    raise ValueError(
                        f"Target '{config.target_id}' uses a remote schema without "
                        "allow_remote_schema: true"
                    )
            elif "://" in config.schema_source:
                raise ValueError(
                    f"Target '{config.target_id}' has an unsupported schema source"
                )
            else:
                self.resolve_source(config.schema_source)
        payload_source = config.settings.get("payload_source")
        if payload_source is not None:
            if not isinstance(payload_source, str):
                raise ValueError(
                    f"Target '{config.target_id}' payload_source must be a string"
                )
            self.resolve_source(payload_source)
        allow_remote_schema = config.settings.get("allow_remote_schema", False)
        if not isinstance(allow_remote_schema, bool):
            raise ValueError(
                f"Target '{config.target_id}' allow_remote_schema must be boolean"
            )
        token_env = config.auth.get("token_env")
        if token_env is not None and (
            not isinstance(token_env, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env)
        ):
            raise ValueError(f"Target '{config.target_id}' has an invalid auth token_env")
        return config

    def get_target(self, target_id: str) -> TargetConfig:
        target_id = target_id.strip().lower()
        if target_id not in self.targets:
            raise KeyError(f"Unknown target '{target_id}'")
        return self.targets[target_id]

    def load_targets(self) -> "TargetManager":
        return self

    def resolve_source(self, source: str | Path) -> Path:
        return self.paths.resolve(source)

    def add_target(self, target_id: str, *, base_url: str, schema_source: str | None = None,
                   auth: dict[str, Any] | None = None, settings: dict[str, Any] | None = None,
                   name: str | None = None) -> TargetConfig:
        config = TargetConfig(
            target_id=target_id.strip().lower(),
            name=name or target_id,
            base_url=base_url,
            schema_source=schema_source,
            auth=auth or {},
            settings=settings or {},
        )
        self._register(config)
        return self.targets[config.target_id]

    def save_profile(self, target_id: str) -> Path:
        config = self.get_target(target_id)
        profile_dir = self.paths.targets / "profiles"
        profile_dir.mkdir(parents=True, exist_ok=True)
        path = profile_dir / f"{config.target_id}.yaml"
        if path.exists():
            raise FileExistsError(f"Target profile already exists: {path}")
        document = {
            "target_id": config.target_id,
            "name": config.name,
            "base_url": config.base_url,
            "schema_source": config.schema_source,
            "auth": config.auth,
            "settings": config.settings,
        }
        path.write_text(
            yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        return path


TargetRegistry = TargetManager

target_config = TargetManager()

__all__ = ["TargetConfig", "TargetManager", "TargetRegistry", "target_config"]
