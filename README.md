# Schemathesis Automated API DAST Framework

An automated, target-agnostic API Security Testing (DAST) and fuzzing engine
for modern REST (OpenAPI 3.x / Swagger / Postman / HAR) and GraphQL APIs, aligned
with the **OWASP API Security Top 10 (2023)**.

## Key Capabilities

- **Zero-Config API Auto-Discovery**: Automatically probes target URLs for OpenAPI/Swagger specs or GraphQL introspection endpoints.
- **Schema-Conforming Semantic Mutation Engine**: Tailors security probes to match required parameter types and formats (UUID v4, RFC 5322 email, URI, ISO-8601 date-time, integer boundaries, and privilege enums) to pass strict DTO validation.
- **Adaptive Validation Feedback Engine**: Inspects HTTP 400/422 responses to diagnose validation failures and guide payload repair.
- **Autonomous API Dependency Graph & Workflow Synthesizer**: Infers Producer (POST) and Consumer (GET/PUT/DELETE) relationships from OpenAPI specs to synthesize end-to-end BOLA validation chains automatically.
- **RFC 7519 Token Authentication Auditor**: Tests JWT validation (`alg: none`, stripped signature, expired `exp`) for Broken Authentication (API2:2023).
- **Dual-Mode SSRF & Callback Auditor**: Verifies URL parameters with an in-memory loopback listener or external OOB canary polling (API7:2023).
- **Concurrency, PII, Header Tampering & Resource Exhaustion Auditors**: Detects race conditions (API4), PII/secret leakage (API3), proxy/host header poisoning (API8), ReDoS/JSON bombs (API4), and GraphQL query batching / alias overload DoS.
- **Multi-Format Reporting & DevSecOps Gate**: Interactive TUI, offline dark-themed HTML report with 1-click cURL reproduction, OASIS SARIF v2.1.0 export, and CI/CD Quality Gate enforcement.

## Requirements

- Python 3.10–3.13 with `venv` and `pip`.
- Network access to the target API being scanned.

## Setup

```bash
set -euo pipefail
git clone https://github.com/Gilgamesh512/Schemathesis.git
cd Schemathesis
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip && \
  python -m pip install -r requirements-dev.txt && \
  python -m pip check
```

## Running Tests

```bash
. .venv/bin/activate
python -m pytest
```

## Quick Launchers (`fuzz.bat` & `fuzz.sh`)

```bash
# Windows
fuzz.bat                       # Interactive launcher
fuzz.bat scan <URL>            # Quick scan any API target with auto-discovery
fuzz.bat auto <SCHEMA> --url <URL>
fuzz.bat report                # Open interactive HTML report in browser

# Linux / macOS
./fuzz.sh                      # Interactive launcher
./fuzz.sh scan <URL>           # Quick scan any API target with auto-discovery
./fuzz.sh auto <SCHEMA> --url <URL>
./fuzz.sh report               # Open interactive HTML report in browser
```

## Dynamic API Scanning

```bash
# REST API with auto-discovery or explicit OpenAPI specification (URL or file)
python run_all.py scan --url https://api.example.com --auth-token "Bearer <TOKEN>"
python run_all.py scan --url https://api.example.com --schema ./openapi.json --auth-token "Bearer <TOKEN>"

# REST API from Postman Collection or HAR traffic capture
python run_all.py scan --url https://api.example.com --postman ./collection.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url https://api.example.com --har ./traffic.har --auth-token "Bearer <TOKEN>"

# Upstream Proxy (Burp Suite / Caido / ZAP) with SSL ignore
python run_all.py scan --url https://api.example.com --schema ./openapi.json --proxy http://127.0.0.1:8080 --insecure

# Full active security audits (JWT, SSRF callbacks, Race Conditions, PII, Headers, Resources)
python run_all.py scan --url https://api.example.com --schema ./openapi.json \
  --auth-token "Bearer <TOKEN>" \
  --verify-tokens --verify-callbacks --verify-concurrency --verify-pii --verify-headers --verify-resources

# GraphQL API scan (auto-generates probes + batching/alias DoS audit)
python run_all.py scan --url https://api.example.com --protocol graphql --endpoint /graphql --auth-token "Bearer <TOKEN>"
```

## Stateful Workflows & DevSecOps Quality Gate

```bash
# Auto-synthesize and run BOLA workflows from OpenAPI spec
python run_all.py auto-workflow ./openapi.json --url http://127.0.0.1:8000

# Run declarative workflow YAML
python run_all.py workflow targets/workflows/sample_workflow.yaml --url http://127.0.0.1:8000

# Evaluate SARIF findings in CI/CD
python run_all.py gate --max-critical 0 --max-high 2
```

## Interactive Terminal UI (TUI)

```bash
python -m cli
python -m cli --dashboard
python -m cli --report
python -m cli --sarif
```

## Updating CVE Rules Cache

```bash
python -m modules.security.rules_engine --update
```
