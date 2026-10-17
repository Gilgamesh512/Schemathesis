#!/usr/bin/env python3
"""Set up and manage the pinned, local vulnerable API lab."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

try:
    import yaml
except ModuleNotFoundError as exc:
    if exc.name != "yaml":
        raise
    raise SystemExit(
        "Missing runtime dependency PyYAML. Install project dependencies with "
        "`python -m pip install -r requirements-dev.txt` and retry."
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY_ROOT = PROJECT_ROOT / ".lab" / "dependencies"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
STARTUP_TIMEOUT = 300
POLL_INTERVAL = 3
CRAPI_IMAGE_TAG = "latest"
DVGA_CONTAINER_LABEL = "com.schemathesis.dvga.revision"
VAMPI_CONTAINER_LABEL = "com.schemathesis.vampi.revision"


@dataclass(frozen=True)
class Dependency:
    name: str
    url: str
    revision: str
    required_paths: tuple[str, ...]


DEPENDENCIES = (
    Dependency(
        "vampi",
        "https://github.com/erev0s/VAmPI.git",
        "f16052dce83f05847133ec98f01c5193a41de7d8",
        ("Dockerfile",),
    ),
    Dependency(
        "crapi",
        "https://github.com/OWASP/crAPI.git",
        "700f03d12a392d9e408260b4beae72ed02a4a1a4",
        ("deploy/docker/docker-compose.yml", "deploy/docker/keys/jwks.json"),
    ),
    Dependency(
        "dvga",
        "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git",
        "a961308c02d1fb462b192681c336b0739e432da7",
        ("Dockerfile",),
    ),
)


class LabError(RuntimeError):
    pass


@dataclass(frozen=True)
class Runtime:
    kind: str
    executable: str
    compose_prefix: tuple[str, ...]


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            text=True,
            capture_output=capture_output,
            check=False,
        )
    except FileNotFoundError as exc:
        raise LabError(f"Required command not found: {command[0]}") from exc
    if result.returncode:
        details = (result.stderr or result.stdout or "").strip()
        message = f"Command failed with exit code {result.returncode}: {' '.join(command)}"
        if details:
            message = f"{message}\n{details}"
        raise LabError(message)
    return result


def _probe(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(list(command), 127, "", "command not found")


def _git_revision(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    result = _probe(["git", "-C", str(path), "rev-parse", "HEAD"])
    if result.returncode:
        raise LabError(f"Cannot read the Git revision in {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def _setup_dependency(dependency: Dependency, destination: Path) -> None:
    if destination.exists():
        revision = _git_revision(destination)
        if revision == dependency.revision:
            print(f"[+] {dependency.name}: already at pinned revision {revision[:12]}")
            return
        actual = revision or "not a Git working tree"
        raise LabError(
            f"Refusing to overwrite {destination} ({actual}); expected "
            f"{dependency.revision}. Move that directory yourself, then run setup again."
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{dependency.name}-", dir=destination.parent
    ) as temporary:
        checkout = Path(temporary) / "checkout"
        print(f"[*] Fetching {dependency.name} at {dependency.revision[:12]}")
        _run(["git", "init", "-q", str(checkout)])
        _run(["git", "-C", str(checkout), "remote", "add", "origin", dependency.url])
        _run([
            "git", "-C", str(checkout), "fetch", "--depth", "1", "origin",
            dependency.revision,
        ])
        _run([
            "git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD",
        ])
        actual_revision = _git_revision(checkout)
        if actual_revision != dependency.revision:
            raise LabError(
                f"Fetched {dependency.name} revision {actual_revision}, "
                f"expected {dependency.revision}"
            )
        try:
            checkout.rename(destination)
        except PermissionError:
            try:
                shutil.copytree(checkout, destination)
            except OSError as exc:
                raise LabError(
                    f"Could not copy the verified {dependency.name} checkout to "
                    f"{destination}: {exc}. Any partial directory was preserved; "
                    "inspect it and move it yourself before retrying setup."
                ) from exc


def _ensure_env_file(root: Path) -> None:
    example = root / ".env.example"
    env_file = root / ".env"
    if not example.is_file():
        raise LabError(f"Missing {example}; restore the tracked .env.example file.")
    try:
        with env_file.open("x", encoding="utf-8", newline="\n") as output:
            output.write(example.read_text(encoding="utf-8"))
    except FileExistsError:
        print(f"[+] Preserving existing {env_file.name}")
    else:
        print(f"[+] Created {env_file.name} from .env.example")


def _validate_env_file(path: Path) -> None:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise LabError(f"Invalid .env entry at {path}:{line_number}; expected KEY=VALUE.")
        values[key.strip()] = value.strip().strip("\"'")

    expected = {
        "LISTEN_IP": "127.0.0.1",
        "TLS_ENABLED": "false",
        "VERSION": CRAPI_IMAGE_TAG,
    }
    for key, value in expected.items():
        actual = values.get(key)
        if actual is None or actual.lower() != value.lower():
            raise LabError(
                f"{path} must set {key}={value} for this pinned, localhost-only lab."
            )


def setup(root: Path = PROJECT_ROOT) -> None:
    dependency_root = root / ".lab" / "dependencies"
    for dependency in DEPENDENCIES:
        _setup_dependency(dependency, dependency_root / dependency.name)
    _ensure_env_file(root)
    validate_installation(root)
    print("[+] Lab sources and local configuration are ready.")


def validate_installation(root: Path = PROJECT_ROOT) -> dict[str, Path]:
    dependency_root = root / ".lab" / "dependencies"
    locations: dict[str, Path] = {}
    for dependency in DEPENDENCIES:
        location = dependency_root / dependency.name
        revision = _git_revision(location)
        if revision != dependency.revision:
            actual = revision or "missing"
            raise LabError(
                f"{dependency.name} dependency is {actual}; expected "
                f"{dependency.revision}. Run `python lab/start_lab.py setup`."
            )
        for relative_path in dependency.required_paths:
            required = location / relative_path
            if not required.is_file():
                raise LabError(
                    f"Required lab file is missing: {required}. "
                    f"Run `python lab/start_lab.py setup` to fetch pinned dependencies."
                )
        locations[dependency.name] = location

    env_file = root / ".env"
    if not env_file.is_file():
        raise LabError(
            f"Missing {env_file}; run `python lab/start_lab.py setup` "
            "to create it from .env.example."
        )
    _validate_env_file(env_file)
    override_file = root / "lab" / "docker-compose.crapi.override.yaml"
    if not override_file.is_file():
        raise LabError(f"Required Compose override is missing: {override_file}")

    project_root = str(root.resolve())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    try:
        from core import TargetManager

        targets = TargetManager(root)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise LabError(f"Cannot load targets/registry.yaml: {exc}") from exc
    if not targets.targets:
        raise LabError(f"No targets are configured in {root / 'targets' / 'registry.yaml'}")
    for target in targets.targets.values():
        if target.schema_source and not target.schema_source.startswith(("http://", "https://")):
            schema = targets.resolve_source(target.schema_source)
            if not schema.is_file():
                raise LabError(
                    f"Schema for target '{target.target_id}' is missing: {schema}"
                )
        payload_source = target.settings.get("payload_source")
        if payload_source:
            payload = targets.resolve_source(payload_source)
            if not payload.is_file():
                raise LabError(
                    f"Payload for target '{target.target_id}' is missing: {payload}"
                )
    return locations


def detect_runtime() -> Runtime:
    failures: list[str] = []
    candidates: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = []

    docker = shutil.which("docker")
    if docker:
        compose_prefix = (docker, "compose")
        if _probe([*compose_prefix, "version"]).returncode:
            docker_compose = shutil.which("docker-compose")
            if docker_compose:
                compose_prefix = (docker_compose,)
            else:
                failures.append("Docker Compose is unavailable.")
                compose_prefix = ()
        if compose_prefix:
            candidates.append(
                ("Docker", docker, compose_prefix, (docker, "info"))
            )

    podman = shutil.which("podman")
    if podman:
        compose_prefix = (podman, "compose")
        if _probe([*compose_prefix, "version"]).returncode:
            podman_compose = shutil.which("podman-compose")
            if podman_compose and not _probe([podman_compose, "--version"]).returncode:
                compose_prefix = (podman_compose,)
            else:
                failures.append("Podman Compose is unavailable.")
                compose_prefix = ()
        if compose_prefix:
            candidates.append(
                ("Podman", podman, compose_prefix, (podman, "info"))
            )

    if not candidates and failures:
        raise LabError(
            "No supported runtime/Compose provider was found: " + " | ".join(failures)
        )
    if not candidates:
        raise LabError(
            "No supported container runtime was found. Install Docker with the "
            "Compose v2 plugin, or Podman with Podman Compose, then retry."
        )

    for kind, executable, compose_prefix, info_command in candidates:
        info_result = _probe(info_command)
        if info_result.returncode:
            failures.append(
                f"{kind} is installed but its service is unavailable: "
                f"{(info_result.stderr or info_result.stdout).strip()}"
            )
            continue
        return Runtime(kind, executable, compose_prefix)

    raise LabError(
        "No usable container runtime and Compose provider were found. "
        + " | ".join(failures)
    )


def _instance_name(root: Path) -> str:
    digest = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()[:10]
    return f"schemathesis-{digest}"


def _compose_command(
    runtime: Runtime,
    root: Path,
    compose_file: Path,
    override_file: Path,
    project: str,
    action: str,
    *arguments: str,
) -> tuple[list[str], dict[str, str]]:
    command = [
        *runtime.compose_prefix,
        "--project-name", project,
        "--env-file", str(root / ".env"),
        "-f", str(compose_file),
        "-f", str(override_file),
        action,
        *arguments,
    ]
    env = os.environ.copy()
    env["SCHEMATHESIS_INSTANCE"] = _instance_name(root)
    env["LISTEN_IP"] = "127.0.0.1"
    env["TLS_ENABLED"] = "false"
    env["VERSION"] = CRAPI_IMAGE_TAG
    return command, env


def _compose_config(
    runtime: Runtime,
    root: Path,
    compose_file: Path,
    override_file: Path,
    project: str,
) -> None:
    command, env = _compose_command(
        runtime, root, compose_file, override_file, project, "config", "--quiet"
    )
    _run(command, cwd=compose_file.parent, env=env)


def _start_compose(
    runtime: Runtime,
    root: Path,
    compose_file: Path,
    override_file: Path,
    project: str,
) -> None:
    command, env = _compose_command(
        runtime, root, compose_file, override_file, project, "up", "-d", "--build"
    )
    _run(command, cwd=compose_file.parent, env=env)


def _stop_compose(
    runtime: Runtime,
    root: Path,
    compose_file: Path,
    override_file: Path,
    project: str,
) -> None:
    command, env = _compose_command(
        runtime, root, compose_file, override_file, project, "stop"
    )
    _run(command, cwd=compose_file.parent, env=env)


def _container_inspect(runtime: Runtime, name: str) -> dict | None:
    result = _probe([runtime.executable, "container", "inspect", name])
    if result.returncode:
        detail = (result.stderr or result.stdout).lower()
        if "no such" in detail or "not found" in detail:
            return None
        raise LabError(
            f"Cannot inspect container {name}: "
            f"{(result.stderr or result.stdout).strip()}"
        )
    try:
        data = json.loads(result.stdout)
        return data[0] if isinstance(data, list) and data else data
    except (json.JSONDecodeError, IndexError) as exc:
        raise LabError(f"Container runtime returned invalid inspect data for {name}") from exc


def _image_exists(runtime: Runtime, image: str) -> bool:
    result = _probe([runtime.executable, "image", "inspect", image])
    if result.returncode == 0:
        return True
    detail = (result.stderr or result.stdout).lower()
    if ("no such" in detail or "not found" in detail or "no image" in detail or "image not known" in detail):
        return False
    raise LabError(f"Cannot inspect image {image}: {(result.stderr or result.stdout).strip()}")


def _ensure_container(
    runtime: Runtime,
    *,
    name: str,
    image: str,
    label: str,
    revision: str,
    host_port: int,
    container_port: int,
    environment: tuple[str, ...],
) -> None:
    existing = _container_inspect(runtime, name)
    if existing is not None:
        config = existing.get("Config", {})
        labels = config.get("Labels") or {}
        port_bindings = existing.get("HostConfig", {}).get("PortBindings") or {}
        ports = port_bindings.get(f"{container_port}/tcp") or []
        configured_environment = set(config.get("Env") or ())
        if (
            labels.get(label) != revision
            or config.get("Image") != image
            or not any(port.get("HostPort") == str(host_port) for port in ports)
            or not set(environment).issubset(configured_environment)
        ):
            raise LabError(
                f"Container {name} exists but does not match this pinned lab "
                "configuration. It was left untouched."
            )
        if not existing.get("State", {}).get("Running", False):
            _run([runtime.executable, "container", "start", name])
        else:
            print(f"[+] Container {name} is already running.")
        return

    command = [
        runtime.executable, "run", "--detach", "--name", name,
        "--publish", f"127.0.0.1:{host_port}:{container_port}",
        "--label", f"{label}={revision}",
    ]
    for value in environment:
        command.extend(["--env", value])
    command.append(image)
    _run(command)


def _build_image(runtime: Runtime, root: Path, source: Path, image: str) -> None:
    if not _image_exists(runtime, image):
        _run([runtime.executable, "build", "--tag", image, str(source)], cwd=root)


def _start_vampi(runtime: Runtime, root: Path, source: Path) -> None:
    revision = next(item.revision for item in DEPENDENCIES if item.name == "vampi")
    image = f"schemathesis/vampi:{revision[:12]}"
    _build_image(runtime, root, source, image)
    instance = _instance_name(root)
    for suffix, port, vulnerable in (
        ("secure", 5001, "0"),
        ("vulnerable", 5002, "1"),
    ):
        _ensure_container(
            runtime,
            name=f"{instance}-vampi-{suffix}",
            image=image,
            label=VAMPI_CONTAINER_LABEL,
            revision=revision,
            host_port=port,
            container_port=5000,
            environment=(f"vulnerable={vulnerable}", "tokentimetolive=3600"),
        )


def _start_dvga(runtime: Runtime, root: Path, source: Path) -> None:
    revision = next(item.revision for item in DEPENDENCIES if item.name == "dvga")
    image = f"schemathesis/dvga:{revision[:12]}"
    _build_image(runtime, root, source, image)
    _ensure_container(
        runtime,
        name=f"{_instance_name(root)}-dvga",
        image=image,
        label=DVGA_CONTAINER_LABEL,
        revision=revision,
        host_port=5013,
        container_port=5013,
        environment=("WEB_HOST=0.0.0.0",),
    )


def _target_urls(root: Path) -> dict[str, str]:
    project_root = str(root.resolve())
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from core import TargetManager

    targets = TargetManager(root)
    required = ("vampi", "crapi", "dvga")
    missing = [target_id for target_id in required if target_id not in targets.targets]
    if missing:
        raise LabError(
            f"Missing lab targets in targets/registry.yaml: {', '.join(missing)}"
        )
    return {
        target_id: targets.get_target(target_id).base_url.rstrip("/")
        for target_id in required
    }


def _http_status(url: str) -> int:
    try:
        with urlopen(url, timeout=5) as response:
            return response.status
    except HTTPError as exc:
        return exc.code
    except URLError as exc:
        raise LabError(f"Cannot reach {url}: {exc.reason}") from exc
    except OSError as exc:
        raise LabError(f"Cannot reach {url}: {exc}") from exc


def _wait_for_targets(root: Path, timeout: int = STARTUP_TIMEOUT) -> None:
    urls = _target_urls(root)
    deadline = time.monotonic() + timeout
    pending = dict(urls)
    last_errors: dict[str, str] = {}
    while pending:
        for target_id, base_url in list(pending.items()):
            try:
                status = _http_status(base_url)
            except LabError as exc:
                last_errors[target_id] = str(exc)
                continue
            if 200 <= status < 400:
                print(f"[+] {target_id}: HTTP {status} at {base_url}")
                del pending[target_id]
            else:
                last_errors[target_id] = f"HTTP {status}"
                print(f"[*] {target_id}: HTTP {status} at {base_url}; waiting")
        if not pending:
            break
        if time.monotonic() >= deadline:
            failed = ", ".join(
                f"{target_id} ({url}): {last_errors.get(target_id, 'no response')}"
                for target_id, url in pending.items()
            )
            raise LabError(f"Timed out waiting for application health: {failed}")
        time.sleep(POLL_INTERVAL)

    createdb_url = f"{urls['vampi']}/createdb"
    status = _http_status(createdb_url)
    if not 200 <= status < 300:
        raise LabError(f"VAmPI database initialization failed: {createdb_url} returned HTTP {status}")
    print("[+] VAmPI database initialized.")


def start(root: Path = PROJECT_ROOT) -> None:
    locations = validate_installation(root)
    runtime = detect_runtime()
    print(f"[*] Using {runtime.kind} and Compose.")

    crapi_compose = locations["crapi"] / "deploy" / "docker" / "docker-compose.yml"
    crapi_override = root / "lab" / "docker-compose.crapi.override.yaml"
    if not crapi_override.is_file():
        raise LabError(f"Missing repository Compose override: {crapi_override}")

    instance = _instance_name(root)
    _compose_config(
        runtime, root, crapi_compose, crapi_override, f"{instance}-crapi"
    )
    _start_vampi(runtime, root, locations["vampi"])
    _start_compose(
        runtime, root, crapi_compose, crapi_override, f"{instance}-crapi"
    )
    _start_dvga(runtime, root, locations["dvga"])
    _wait_for_targets(root)
    print("[+] All lab endpoints responded successfully.")


def check(root: Path = PROJECT_ROOT) -> None:
    validate_installation(root)
    urls = _target_urls(root)
    failures: list[str] = []
    for target_id, base_url in urls.items():
        try:
            status = _http_status(base_url)
            if 200 <= status < 400:
                print(f"[+] {target_id}: HTTP {status} at {base_url}")
            else:
                failures.append(f"{target_id} returned HTTP {status} at {base_url}")
        except LabError as exc:
            failures.append(f"{target_id}: {exc}")
    if failures:
        raise LabError("Lab health check failed:\n- " + "\n- ".join(failures))


def stop(root: Path = PROJECT_ROOT) -> None:
    locations = validate_installation(root)
    runtime = detect_runtime()
    instance = _instance_name(root)
    _stop_compose(
        runtime,
        root,
        locations["crapi"] / "deploy" / "docker" / "docker-compose.yml",
        root / "lab" / "docker-compose.crapi.override.yaml",
        f"{instance}-crapi",
    )
    for name, label, revision in (
        (
            f"{instance}-vampi-secure",
            VAMPI_CONTAINER_LABEL,
            next(item.revision for item in DEPENDENCIES if item.name == "vampi"),
        ),
        (
            f"{instance}-vampi-vulnerable",
            VAMPI_CONTAINER_LABEL,
            next(item.revision for item in DEPENDENCIES if item.name == "vampi"),
        ),
        (
            f"{instance}-dvga",
            DVGA_CONTAINER_LABEL,
            next(item.revision for item in DEPENDENCIES if item.name == "dvga"),
        ),
    ):
        container = _container_inspect(runtime, name)
        if container is None:
            continue
        labels = container.get("Config", {}).get("Labels") or {}
        if labels.get(label) != revision:
            raise LabError(f"Refusing to stop unrecognized container {name}.")
        if container.get("State", {}).get("Running", False):
            _run([runtime.executable, "container", "stop", name])
    print("[+] Lab stopped. Containers and volumes were preserved.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Set up, start, check, or stop the local vulnerable API lab."
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("setup", "start", "check", "stop"),
        help="setup downloads pinned sources; start/check/stop never run fuzzing",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.action is None:
        parser.print_help()
        return 2
    try:
        if args.action == "setup":
            setup()
        elif args.action == "start":
            start()
        elif args.action == "check":
            check()
        elif args.action == "stop":
            stop()
    except (LabError, OSError, ValueError) as exc:
        print(f"[X] Lab {args.action} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
