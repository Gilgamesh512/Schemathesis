# Schemathesis Operational Runbook

Run commands from the repository root. For Python environment creation,
supported runtime requirements, pinned lab source revisions, configuration,
startup checks, troubleshooting, and clean-clone instructions, see
[README.md](./README.md).

## Fresh clone setup

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

## One-click quick execution

```bash
# Windows
fuzz.bat auto          # 1-click Autonomous BOLA workflow
fuzz.bat all           # 1-click Full Security Testing Pipeline
fuzz.bat scan <URL>    # 1-click Quick scan API target
fuzz.bat report        # Open latest HTML report in browser

# Linux / macOS
./fuzz.sh auto         # 1-click Autonomous BOLA workflow
./fuzz.sh all          # 1-click Full Security Testing Pipeline
./fuzz.sh scan <URL>   # 1-click Quick scan API target
./fuzz.sh report       # Open latest HTML report in browser
```

## Normal lab lifecycle

```bash
python run_all.py start
python run_all.py check
python run_all.py stop
```

`stop` preserves containers and volumes. No startup or stop command runs
fuzzing or deletes volumes.

## Full lab security testing

Only run this command when a fuzzing run is intended; it refreshes generated
authentication/schema artifacts, provisions dual testing accounts for BOLA
cross-verification, and writes findings under `results/`:

```bash
python run_all.py run
```

## Dynamic target scanning (No Docker required)

Scan any local or remote API target on demand:

```bash
# REST API scan (OpenAPI, Postman Collection, or HAR file)
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url http://127.0.0.1:8000 --postman ./collection.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url http://127.0.0.1:8000 --har ./traffic.har --auth-token "Bearer <TOKEN>"

# Intercept and debug traffic with Burp Suite / Caido / ZAP proxy
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --proxy http://127.0.0.1:8080 --insecure

# Audit RFC 7519 Token Authentication & Loopback SSRF Callbacks
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --auth-token "Bearer <TOKEN>" --verify-tokens --verify-callbacks

# Audit Out-of-Band Blind SSRF via External Canary Webhook
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --verify-callbacks --callback-url https://webhook.site/your-id

# GraphQL API scan
python run_all.py scan --url http://127.0.0.1:8000 --protocol graphql --endpoint /graphql --auth-token "Bearer <TOKEN>"
```

If `--payloads` is omitted, the built-in security mutation engine generates
test cases automatically from the schema.

## Stateful workflow & autonomous BOLA testing

Execute multi-step chained API workflows:

```bash
# Auto-synthesize and execute BOLA workflows directly from OpenAPI schema (Zero-YAML)
python run_all.py auto-workflow targets/schemas/vampi/vampi_spec.yaml --url http://127.0.0.1:5002

# Run declarative workflow YAML
python run_all.py workflow targets/workflows/sample_workflow.yaml

# Run workflow with upstream proxy
python run_all.py workflow targets/workflows/sample_workflow.yaml --proxy http://127.0.0.1:8080 --insecure
```

## Interactive dashboard & DevSecOps reporting

```bash
# Launch interactive terminal control center
python -m cli

# Open latest interactive HTML report in browser
python -m cli --report

# Export findings to OASIS SARIF v2.1.0 for CI/CD
python -m cli --sarif

# Render executive dashboard directly in terminal
python -m cli --dashboard
```

## Rules and CVE cache maintenance

```bash
python -m modules.security.rules_engine --update
```
