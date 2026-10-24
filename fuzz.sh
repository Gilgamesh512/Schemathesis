#!/usr/bin/env bash
# ==============================================================================
# API Security Fuzzing Framework - Launcher Script
# ==============================================================================
set -e

# Resolve repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect Python interpreter (priority: local .venv -> system python3/python)
if [ -f ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
elif [ -f ".venv/Scripts/python.exe" ]; then
    PYTHON=".venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "[X] Error: Python 3 is required but was not found."
    exit 1
fi

# Run the CLI dashboard / dynamic runner with passed arguments
exec "$PYTHON" -m cli "$@"
