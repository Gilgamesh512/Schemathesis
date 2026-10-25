#!/usr/bin/env bash
# ==============================================================================
# API Security Fuzzing Framework - Launcher Script
# ==============================================================================
set -e

# Resolve repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect Python interpreter (priority: active virtualenv -> local .venv -> system python3/python)
if [ -n "$VIRTUAL_ENV" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python"
elif [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
elif [ -x ".venv/Scripts/python.exe" ]; then
    PYTHON=".venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON="python"
else
    echo "[X] Error: Python 3 is required but was not found."
    exit 1
fi

# Check if required dependencies are installed
if ! "$PYTHON" -c "import pydantic, schemathesis, httpx, yaml, requests" >/dev/null 2>&1; then
    echo "[!] Missing required dependencies in Python environment ($PYTHON)."
    if [ -f "requirements.txt" ]; then
        echo "[*] Auto-installing dependencies from requirements.txt..."
        "$PYTHON" -m pip install -r requirements.txt
    else
        echo "[X] requirements.txt not found. Please run: pip install pydantic schemathesis httpx pyyaml requests"
        exit 1
    fi
fi

# Run the CLI dashboard / dynamic runner with passed arguments
exec "$PYTHON" -m cli "$@"
