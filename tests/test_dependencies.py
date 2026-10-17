import re
from importlib.metadata import distribution
from pathlib import Path

from packaging.requirements import Requirement


ROOT = Path(__file__).resolve().parents[1]


def _requirements(path: Path) -> list[Requirement]:
    return [
        Requirement(line.strip())
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and not line.startswith("-r ")
    ]


def test_runtime_and_development_requirements_are_separated_and_compatible():
    runtime = _requirements(ROOT / "requirements.txt")
    development = _requirements(ROOT / "requirements-dev.txt")
    runtime_by_name = {requirement.name.lower(): requirement for requirement in runtime}
    development_by_name = {
        requirement.name.lower(): requirement for requirement in development
    }

    assert "pytest" not in runtime_by_name
    assert str(runtime_by_name["schemathesis"].specifier) == "==4.24.3"
    assert "pyyaml" in runtime_by_name
    assert (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()[0] == (
        "-r requirements.txt"
    )

    pytest_requirement = development_by_name["pytest"]
    assert str(pytest_requirement.specifier) == "==9.0.2"

    schemathesis_metadata = distribution("schemathesis").requires or []
    pytest_constraints = [
        Requirement(requirement)
        for requirement in schemathesis_metadata
        if Requirement(requirement).name.lower() == "pytest"
    ]
    assert pytest_constraints
    assert all(
        constraint.specifier.contains("9.0.2")
        for constraint in pytest_constraints
    )


def test_kali_setup_instructions_install_and_check_dependencies_before_setup():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    runbook = (ROOT / "RUNBOOK.md").read_text(encoding="utf-8")

    assert "Fresh clone setup on Kali Linux" in readme
    fail_fast = readme.index("set -euo pipefail", readme.index("Fresh clone setup"))
    create_venv = readme.index("python3 -m venv .venv", fail_fast)
    activate_venv = readme.index(". .venv/bin/activate", create_venv)
    install_dev = readme.index("python -m pip install -r requirements-dev.txt", activate_venv)
    check_dependencies = readme.index("python -m pip check", install_dev)
    setup_lab = readme.index("python lab/start_lab.py setup", check_dependencies)
    assert fail_fast < create_venv < activate_venv < install_dev < check_dependencies < setup_lab
    assert "requirements-dev.txt" in runbook
    assert runbook.index("set -euo pipefail") < runbook.index("python3 -m venv .venv")
    assert not re.search(r"powershell|\\.venv\\Scripts\\python", readme, re.IGNORECASE)
