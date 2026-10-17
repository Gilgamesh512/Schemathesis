# Schemathesis operational runbook

Run commands from the repository root. For Python environment creation,
supported runtime requirements, pinned lab source revisions, configuration,
startup checks, troubleshooting, and clean-clone instructions, see
[README.md](./README.md).

## Fresh clone

1. Create a Python 3.10-3.13 virtual environment (3.12 recommended).
2. Install `requirements-dev.txt`.
3. Run `python run_all.py setup` to fetch the three pinned lab dependencies and
   create `.env` from `.env.example`.
4. Start the local container runtime.
5. Run `python run_all.py start`, then `python run_all.py check`.

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
