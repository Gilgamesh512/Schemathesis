# Schemathesis API DAST Operational Runbook

Run all commands from the repository root with `.venv` activated.

## Setup

```bash
set -euo pipefail
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip && \
  python -m pip install -r requirements-dev.txt && \
  python -m pip check
```

## Quick Execution

```bash
# Windows
fuzz.bat scan <URL>
fuzz.bat auto <SCHEMA> --url <URL>
fuzz.bat report

# Linux / macOS
./fuzz.sh scan <URL>
./fuzz.sh auto <SCHEMA> --url <URL>
./fuzz.sh report
```

## Dynamic Target Scanning

```bash
# Auto-discover OpenAPI / GraphQL and scan
python run_all.py scan --url http://127.0.0.1:8000 --auth-token "Bearer <TOKEN>"

# Explicit OpenAPI, Postman Collection, or HAR log
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url http://127.0.0.1:8000 --postman ./collection.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url http://127.0.0.1:8000 --har ./traffic.har --auth-token "Bearer <TOKEN>"

# Route through Burp Suite / Caido / ZAP proxy
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --proxy http://127.0.0.1:8080 --insecure

# GraphQL target
python run_all.py scan --url http://127.0.0.1:8000 --protocol graphql --endpoint /graphql --auth-token "Bearer <TOKEN>"
```

## Stateful Workflows & Quality Gate

```bash
# Auto-synthesize BOLA workflows directly from OpenAPI schema
python run_all.py auto-workflow ./openapi.json --url http://127.0.0.1:8000

# Run declarative workflow YAML
python run_all.py workflow targets/workflows/sample_workflow.yaml --url http://127.0.0.1:8000

# Enforce CI/CD quality gate
python run_all.py gate --max-critical 0 --max-high 2
```

## Dashboard & Rules Maintenance

```bash
python -m cli
python -m cli --report
python -m cli --sarif
python -m cli --dashboard
python -m modules.security.rules_engine --update
```
