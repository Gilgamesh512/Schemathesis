#!/usr/bin/env bash
# ==============================================================================
# Schemathesis Pro - Universal API DAST Launcher (Linux/macOS)
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

# ------------------------------------------------------------------------------
# Argument Dispatcher
# ------------------------------------------------------------------------------
if [ "$1" = "auto" ]; then
    if [ -z "$2" ]; then
        echo "[!] Please specify an OpenAPI schema, e.g.: ./fuzz.sh auto ./openapi.json --url http://127.0.0.1:8000"
        exit 1
    fi
    shift
    echo "[*] Running Autonomous BOLA Workflow..."
    exec "$PYTHON" run_all.py auto-workflow "$@"
fi

if [ "$1" = "profiles" ]; then
    echo "[*] Running Saved Target Profiles..."
    exec "$PYTHON" run_all.py profiles
fi

if [ "$1" = "report" ]; then
    exec "$PYTHON" -m cli --report
fi

if [ "$1" = "dashboard" ]; then
    exec "$PYTHON" -m cli --dashboard
fi

if [ "$1" = "gate" ]; then
    shift
    exec "$PYTHON" run_all.py gate "$@"
fi

if [ "$1" = "scan" ]; then
    if [ -z "$2" ]; then
        echo "[!] Please specify a target URL, e.g.: ./fuzz.sh scan http://localhost:8000"
        exit 1
    fi
    shift
    if [[ "$1" != --* ]]; then
        TARGET_URL="$1"
        shift
        exec "$PYTHON" run_all.py scan --url "$TARGET_URL" "$@"
    else
        exec "$PYTHON" run_all.py scan "$@"
    fi
fi

if [ -n "$1" ]; then
    # Forward arbitrary arguments directly to run_all.py
    exec "$PYTHON" run_all.py "$@"
fi

# ------------------------------------------------------------------------------
# Interactive One-Click Menu (When launched with no arguments)
# ------------------------------------------------------------------------------
clear
echo "=================================================================================="
echo "            SCHEMATHESIS PRO - AUTOMATED API DAST SCANNER"
echo "=================================================================================="
echo ""
echo "  [1] Quick Scan Custom API URL (Auto-Discovery)            [DEFAULT - Press Enter]"
echo "  [2] Auto-Synthesize BOLA Workflows (OpenAPI -> Zero-YAML)"
echo "  [3] Run Saved Target Profiles"
echo "  [4] Open Interactive Terminal Dashboard (TUI)"
echo "  [5] Open Latest Interactive HTML Report in Browser"
echo "  [q] Exit"
echo ""
echo "=================================================================================="
read -r -p "Select an option [1]: " CHOICE
CHOICE="${CHOICE:-1}"

case "$CHOICE" in
    1)
        echo ""
        read -r -p "Enter API Target Base URL: " SCAN_URL
        if [ -n "$SCAN_URL" ]; then
            "$PYTHON" run_all.py scan --url "$SCAN_URL"
            read -r -p "Open interactive HTML report in browser now? [Y/n]: " OPEN_REP
            OPEN_REP="${OPEN_REP:-y}"
            if [[ "$OPEN_REP" =~ ^[Yy]$ ]]; then
                "$PYTHON" -m cli --report || true
            fi
        fi
        ;;
    2)
        echo ""
        read -r -p "Enter OpenAPI Schema path: " SCHEMA_PATH
        read -r -p "Enter Target Base URL (optional): " BASE_URL
        if [ -n "$SCHEMA_PATH" ]; then
            if [ -n "$BASE_URL" ]; then
                "$PYTHON" run_all.py auto-workflow "$SCHEMA_PATH" --url "$BASE_URL"
            else
                "$PYTHON" run_all.py auto-workflow "$SCHEMA_PATH"
            fi
        fi
        ;;
    3)
        echo ""
        echo "[*] Running saved target profiles..."
        "$PYTHON" run_all.py profiles
        ;;
    4)
        exec "$PYTHON" -m cli
        ;;
    5)
        exec "$PYTHON" -m cli --report
        ;;
    [qQ])
        exit 0
        ;;
    *)
        echo "[!] Invalid selection."
        exit 1
        ;;
esac
