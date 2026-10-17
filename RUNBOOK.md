# Schemathesis operational runbook

Run commands from the repository root. For Python environment creation,
supported runtime requirements, pinned lab source revisions, configuration,
startup checks, troubleshooting, and clean-clone instructions, see
[README.md](./README.md).

## Fresh clone

On Kali Linux, install Git, Python 3.10-3.13 with `venv`, and a supported local
container runtime with Compose. From a fresh clone, run:

```bash
set -euo pipefail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip && \
  python -m pip install -r requirements-dev.txt && \
  python -m pip check && \
  python lab/start_lab.py setup
```

Start the local container runtime before starting the lab.

## Normal lab lifecycle

```bash
python run_all.py start
python run_all.py check
python run_all.py stop
```

`stop` preserves containers and volumes. No startup or stop command runs
fuzzing or deletes volumes.

## Explicit fuzzing

Only run this command when a fuzzing run is intended; it updates generated
authentication/schema artifacts and writes findings under `results/`:

```bash
python run_all.py run
```
