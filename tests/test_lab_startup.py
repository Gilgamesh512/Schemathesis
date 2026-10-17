from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
import yaml

from core import TargetManager
from lab import start_lab


def test_missing_dependency_reports_setup_command(tmp_path: Path):
    with pytest.raises(start_lab.LabError, match="python lab/start_lab.py setup"):
        start_lab.validate_installation(tmp_path)


def test_missing_compose_file_reports_exact_dependency_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dependency_root = tmp_path / ".lab" / "dependencies"
    for dependency in start_lab.DEPENDENCIES:
        location = dependency_root / dependency.name
        location.mkdir(parents=True)
        for relative_path in dependency.required_paths:
            required = location / relative_path
            if dependency.name == "crapi" and relative_path == "deploy/docker/docker-compose.yml":
                continue
            required.parent.mkdir(parents=True, exist_ok=True)
            required.write_text("", encoding="utf-8")
    (tmp_path / ".env").write_text("", encoding="utf-8")
    revisions = {item.name: item.revision for item in start_lab.DEPENDENCIES}
    monkeypatch.setattr(
        start_lab,
        "_git_revision",
        lambda path: next(
            (revision for name, revision in revisions.items() if name == path.name),
            None,
        ),
    )

    with pytest.raises(start_lab.LabError, match="docker-compose.yml"):
        start_lab.validate_installation(tmp_path)


def test_runtime_missing_is_reported(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(start_lab.shutil, "which", lambda _: None)
    with pytest.raises(start_lab.LabError, match="No supported container runtime"):
        start_lab.detect_runtime()


def test_runtime_requires_compose_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        start_lab.shutil,
        "which",
        lambda name: "C:\\docker.exe" if name == "docker" else None,
    )
    monkeypatch.setattr(
        start_lab,
        "_probe",
        lambda command: subprocess.CompletedProcess(
            command, 1, "", "compose plugin unavailable"
        ),
    )

    with pytest.raises(start_lab.LabError, match="Compose provider"):
        start_lab.detect_runtime()


def test_compose_start_and_stop_never_delete_containers_or_volumes(tmp_path: Path):
    runtime = start_lab.Runtime("Docker", "docker", ("docker", "compose"))
    compose = tmp_path / "compose.yaml"
    override = tmp_path / "override.yaml"
    compose.write_text("services: {}", encoding="utf-8")
    override.write_text("services: {}", encoding="utf-8")
    commands: list[list[str]] = []

    def record(command, **kwargs):
        commands.append(list(command))
        assert kwargs["cwd"] == compose.parent
        assert "SCHEMATHESIS_INSTANCE" in kwargs["env"]
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch.object(start_lab, "_run", side_effect=record):
        start_lab._compose_config(runtime, tmp_path, compose, override, "test-project")
        start_lab._start_compose(runtime, tmp_path, compose, override, "test-project")
        start_lab._stop_compose(runtime, tmp_path, compose, override, "test-project")

    assert commands[0][-2:] == ["config", "--quiet"]
    assert commands[1][-3:] == ["up", "-d", "--build"]
    assert commands[2][-1] == "stop"
    assert all("down" not in command and "-v" not in command for command in commands)
    assert commands[-1][-1] == "stop"


def test_setup_preserves_existing_env_file(tmp_path: Path):
    (tmp_path / ".env.example").write_text("VERSION=latest\n", encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("VERSION=custom\n", encoding="utf-8")

    start_lab._ensure_env_file(tmp_path)

    assert env_file.read_text(encoding="utf-8") == "VERSION=custom\n"


def test_setup_preserves_partial_checkout_if_windows_copy_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dependency = start_lab.DEPENDENCIES[0]
    destination = tmp_path / ".lab" / "dependencies" / dependency.name
    monkeypatch.setattr(start_lab, "_run", lambda command: None)
    monkeypatch.setattr(start_lab, "_git_revision", lambda path: dependency.revision)

    def fail_rename(self: Path, target: Path):
        raise PermissionError("simulated Windows rename failure")

    def fail_copy(source: Path, target: Path):
        target.mkdir()
        raise OSError("simulated copy failure")

    monkeypatch.setattr(Path, "rename", fail_rename)
    monkeypatch.setattr(start_lab.shutil, "copytree", fail_copy)

    with pytest.raises(start_lab.LabError, match="partial directory was preserved"):
        start_lab._setup_dependency(dependency, destination)

    assert destination.is_dir()


@pytest.mark.parametrize(
    ("key", "value"),
    (("LISTEN_IP", "0.0.0.0"), ("TLS_ENABLED", "true"), ("VERSION", "1.1.6")),
)
def test_env_rejects_unpinned_or_nonlocal_overrides(
    tmp_path: Path, key: str, value: str
):
    settings = {
        "LISTEN_IP": "127.0.0.1",
        "TLS_ENABLED": "false",
        "VERSION": start_lab.CRAPI_IMAGE_TAG,
    }
    settings[key] = value
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(f"{name}={setting}" for name, setting in settings.items()),
        encoding="utf-8",
    )

    with pytest.raises(start_lab.LabError, match=f"{key}="):
        start_lab._validate_env_file(env_file)


def test_compose_runtime_environment_enforces_pinned_local_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    runtime = start_lab.Runtime("Docker", "docker", ("docker", "compose"))
    monkeypatch.setenv("LISTEN_IP", "0.0.0.0")
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("VERSION", "develop")

    _, env = start_lab._compose_command(
        runtime,
        tmp_path,
        tmp_path / "compose.yaml",
        tmp_path / "override.yaml",
        "test-project",
        "config",
    )

    assert env["LISTEN_IP"] == "127.0.0.1"
    assert env["TLS_ENABLED"] == "false"
    assert env["VERSION"] == start_lab.CRAPI_IMAGE_TAG


def test_startup_requires_http_health_and_initializes_vampi(
    monkeypatch: pytest.MonkeyPatch
):
    urls = {
        "vampi": "http://127.0.0.1:5002",
        "crapi": "http://127.0.0.1:8888",
        "dvga": "http://127.0.0.1:5013",
    }
    calls: list[str] = []
    monkeypatch.setattr(start_lab, "_target_urls", lambda _: urls)

    def status(url: str) -> int:
        calls.append(url)
        return 200 if not url.endswith("/createdb") else 201

    monkeypatch.setattr(start_lab, "_http_status", status)

    start_lab._wait_for_targets(Path("."))

    assert calls == [
        urls["vampi"],
        urls["crapi"],
        urls["dvga"],
        f"{urls['vampi']}/createdb",
    ]


def test_startup_timeout_names_unhealthy_endpoints(monkeypatch: pytest.MonkeyPatch):
    urls = {
        "vampi": "http://127.0.0.1:5002",
        "crapi": "http://127.0.0.1:8888",
        "dvga": "http://127.0.0.1:5013",
    }
    monkeypatch.setattr(start_lab, "_target_urls", lambda _: urls)
    monkeypatch.setattr(start_lab, "_http_status", lambda _: 503)

    with pytest.raises(start_lab.LabError, match="vampi.*HTTP 503"):
        start_lab._wait_for_targets(Path("."), timeout=0)


def test_registered_target_schema_and_payload_files_exist():
    targets = TargetManager()
    assert targets.targets
    for target in targets.targets.values():
        if target.schema_source and not target.schema_source.startswith(("http://", "https://")):
            assert targets.resolve_source(target.schema_source).is_file()
        payload_source = target.settings.get("payload_source")
        if payload_source:
            assert targets.resolve_source(payload_source).is_file()


def test_crapi_compose_override_pins_each_image_and_scopes_names():
    override_path = (
        Path(__file__).resolve().parents[1]
        / "lab"
        / "docker-compose.crapi.override.yaml"
    )
    override = yaml.safe_load(override_path.read_text(encoding="utf-8"))

    assert override["services"]
    for service in override["services"].values():
        assert "@sha256:" in service["image"]
        assert "${SCHEMATHESIS_INSTANCE}" in service["container_name"]


def test_run_all_help_does_not_start_pipeline():
    result = subprocess.run(
        [sys.executable, "run_all.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "setup" in result.stdout
    assert "run" in result.stdout
    assert "RUNNING:" not in result.stdout
