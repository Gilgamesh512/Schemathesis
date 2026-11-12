# Schemathesis API Security Testing Framework & Lab

This repository provides an automated API security testing and fuzzing framework
designed for modern REST (OpenAPI 3.x / Swagger) and GraphQL APIs, aligned with
the **OWASP API Security Top 10 (2023)**.

The framework operates in two modes:
1. **Local Lab Mode**: Automatically manages an isolated, localhost-only testing lab
   containing VAmPI, crAPI, and Damn Vulnerable GraphQL Application (DVGA).
2. **Dynamic Ingestion Mode**: Scans any external or local target API dynamically
   without local Docker setup, using either OpenAPI definitions or live GraphQL endpoints.

## Key Capabilities

- **Schema-Conforming Semantic Mutation Engine**: Bypasses frontend/framework validation barriers (FastAPI/Pydantic, NestJS class-validator, Spring Boot) by tailoring security probes to match required data types and formats (UUID v4 tampering, RFC 5322 email canary probes, loopback URI probes, ISO-8601 date-time boundaries, integer overflow/boundaries, and privilege enum overrides) without being rejected at HTTP 400/422.
- **Adaptive Validation Feedback Engine**: Inspects HTTP 400 and HTTP 422 error structures to identify specific rejected fields and constraints, generating adaptive recommendations and payload repairs.
- **Autonomous API Dependency Graph & Workflow Synthesizer**: Inspects OpenAPI 3.x specifications to discover resource Producers (POST) and Consumers (GET, PUT, DELETE), pairing them automatically to execute end-to-end BOLA cross-user assertions with zero manual YAML authoring.
- **RFC 7519 Token Authentication Auditor**: Inspects JWT tokens and generates compliance probes (`alg: none`, stripped signature verification, expired `exp` claim) to detect Broken Authentication (OWASP API2:2023) vulnerabilities.
- **Dual-Mode SSRF & Callback Auditor**: Verifies URL-receiving parameters using either an in-memory loopback callback listener (localhost) or an external canary listener (interactsh / webhook.site) to confirm SSRF (OWASP API7:2023) with zero false positives.
- **Dual-User Authorization Verification**: Employs a paired user model (Victim vs. Attacker) to cross-validate Broken Object Level Authorization (BOLA / IDOR - API1:2023) and Broken Function Level Authorization (BFLA - API5:2023) with high confidence.
- **WAF & Rate-Limit Resilience**: Intelligent `RequestScheduler` detects HTTP 429, 503, and WAF blocks, honors `Retry-After` response headers, and applies adaptive exponential backoff with jitter to protect target availability.
- **Multi-Format Reporting**:
  - Live ANSI Terminal Dashboard with KPI summaries and OWASP Top 10 breakdown.
  - Interactive, standalone Dark-Themed HTML report (zero external CDN dependencies).
  - Standard **OASIS SARIF v2.1.0** export (`results/vulnerabilities.sarif`) for GitHub Code Scanning and DevSecOps CI/CD integration.
- **Resilient Rules Engine**: Enriches findings with CVSS scores from NVD NIST, with automatic fallback to the Google Open Source Vulnerabilities (OSV) API (`api.osv.dev`).

## Requirements

- Git, for fetching the pinned lab sources.
- Python 3.10-3.13 for compatibility with the pinned dependencies, plus
  `venv` and `pip`.
- One supported local container runtime (required only for Lab Mode):
  - Docker Engine with the Compose v2 plugin or standalone `docker-compose`; or
  - Podman with `podman compose` or `podman-compose`.
- Internet access during setup, CVE updates, and container builds.
- Dynamic scan mode requires only Python and network access to the target API.

The container runtime must be started and available to the current user; the
scripts do not invoke `sudo`.

## Fresh clone setup on Kali Linux

Install the host tools and a supported Python version:

```bash
set -euo pipefail
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip docker.io docker-compose
python3 --version
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Log out and back in after adding your user to the `docker` group.

Use Python 3.10-3.13. If Kali's `python3` is outside that range, install a
supported interpreter before creating the virtual environment.

```bash
set -euo pipefail
git clone https://github.com/Gilgamesh512/Schemathesis.git
cd Schemathesis
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip &&
  python -m pip install -r requirements-dev.txt &&
  python -m pip check &&
  python lab/start_lab.py setup
```

The chained commands stop at the first failed installation or dependency
check, so setup is not attempted in a partially installed environment.
`requirements.txt` contains runtime dependencies; `requirements-dev.txt`
includes those plus the test runner.

The setup command fetches these source revisions:

| Application | Revision | Compose/build source |
|---|---|---|
| VAmPI | `f16052dce83f05847133ec98f01c5193a41de7d8` | pinned repository `Dockerfile` |
| crAPI | `700f03d12a392d9e408260b4beae72ed02a4a1a4` (release `v1.1.6`) | `deploy/docker/docker-compose.yml` |
| DVGA | `a961308c02d1fb462b192681c336b0739e432da7` (release `2.2.0`) | repository `Dockerfile` |

Setup verifies those checkouts, required Compose/Docker files, the crAPI JWKS
file, and every local schema and payload referenced by `targets/registry.yaml`.
It creates `.env` from the tracked `.env.example` only when `.env` does not
already exist. Existing dependency folders at a different revision are never
overwritten; move the conflicting folder yourself if you intentionally want a
fresh setup.

The crAPI Compose file bind-mounts its `deploy/docker/keys` directory. The
pinned crAPI source includes the required `jwks.json`; setup checks for it.
This upstream lab fixture contains private signing-key material used by crAPI
to issue test JWTs. It is not a user-provided secret or a TLS certificate, and
no key needs to be generated for this pinned lab. Treat it as intentionally
insecure test data: do not reuse it elsewhere, and keep the lab bound to
localhost. No real user credentials or API keys are required for lab startup.

## Running tests

No container startup or fuzzing is needed for the unit tests:

```bash
. .venv/bin/activate
python -m pytest
```

## One-Click Quick Launchers (fuzz.bat & fuzz.sh)

To avoid typing long command lines, use the provided one-click launchers:

```bash
# Windows (or simply double-click fuzz.bat)
fuzz.bat               # Interactive 1-click launcher (Press Enter to auto-run BOLA workflow)
fuzz.bat auto          # Direct 1-touch execution of Autonomous BOLA Workflow
fuzz.bat all           # Direct 1-touch execution of Full Security Pipeline
fuzz.bat scan <URL>    # Quick scan any API target with auto-discovery
fuzz.bat report        # Immediately open interactive HTML report in browser

# Linux / macOS
./fuzz.sh              # Interactive 1-click launcher (Press Enter to auto-run BOLA workflow)
./fuzz.sh auto         # Direct 1-touch execution of Autonomous BOLA Workflow
./fuzz.sh all          # Direct 1-touch execution of Full Security Pipeline
./fuzz.sh scan <URL>   # Quick scan any API target with auto-discovery
./fuzz.sh report       # Immediately open interactive HTML report in browser
```

## Lab operations

All commands below are run from the repository root with `.venv` activated:

```bash
python run_all.py --help
python run_all.py start
python run_all.py check
python run_all.py stop
```

- `start`: Validates runtime, Compose provider, and configuration; builds/starts
  services and waits for HTTP readiness from VAmPI, crAPI, and DVGA. Calls VAmPI's
  `/createdb` endpoint to initialize test data.
- `check`: Verifies target HTTP endpoints without modifying containers.
- `stop`: Gracefully stops lab containers while retaining data and volumes.

Default lab endpoints:
- VAmPI: `http://localhost:5002`
- crAPI: `http://localhost:8888`
- DVGA: `http://localhost:5013` (GraphQL at `/graphql`)

## Running lab security fuzzing

To run full automated authentication, GraphQL schema introspection, and
fuzzing against all lab targets:

```bash
python run_all.py run
```

Authentication provisions dual accounts (primary victim and secondary attacker)
to enable automated BOLA/IDOR cross-user verification. Output findings are
persisted to `results/vulnerabilities.csv`, `results/vulnerabilities.ndjson`,
`results/latest_report.html`, and `results/vulnerabilities.sarif`.

## Dynamic API target scanning

Scan external or ad-hoc API targets without Docker:

```bash
# REST API with OpenAPI specification (URL or file)
python run_all.py scan --url https://api.example.com --schema https://api.example.com/openapi.json --auth-token "Bearer <TOKEN>"

# REST API with Postman Collection or HAR log file
python run_all.py scan --url https://api.example.com --postman ./collection.json --auth-token "Bearer <TOKEN>"
python run_all.py scan --url https://api.example.com --har ./traffic.har --auth-token "Bearer <TOKEN>"

# Routing traffic through Upstream Proxy (Burp Suite / Caido / ZAP) with SSL ignore
python run_all.py scan --url https://api.example.com --schema ./openapi.json --proxy http://127.0.0.1:8080 --insecure

# Dynamic scanning with RFC 7519 Token Authentication & SSRF Callback Auditing
python run_all.py scan --url https://api.example.com --schema ./openapi.json --auth-token "Bearer <TOKEN>" --verify-tokens --verify-callbacks

# Scanning with External Canary Callback Listener with automated Polling (Blind SSRF / API7:2023)
python run_all.py scan --url https://api.example.com --schema ./openapi.json --verify-callbacks --callback-url https://webhook.site/your-uuid --poll-url "https://webhook.site/token/your-uuid/requests?query={token}&sorting=newest"

# Scanning targets inside Docker containers with advertised host override
python run_all.py scan --url http://127.0.0.1:8000 --schema ./openapi.json --verify-callbacks --advertised-host host.docker.internal

# GraphQL API with endpoint
python run_all.py scan --url https://api.example.com --protocol graphql --endpoint /graphql --auth-token "Bearer <TOKEN>"
```

If no custom payload corpus is supplied via `--payloads`, the built-in security
mutation engine automatically constructs security probes from the target schema
(including SQL Injection, Time-based blind delay probes, Path Traversal, SSTI,
BOLA/IDOR, and Mass Assignment).

## Enterprise DevSecOps & Container Execution

Run the scanner in an isolated, pre-built Docker container within CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins):

```bash
# Build scanner image
docker build -t schemathesis-scanner:latest .

# Run dynamic scan from container with results mounted locally
docker run --rm --net=host \
  -v "$(pwd)/results:/app/results" \
  schemathesis-scanner:latest scan \
  --url https://api.example.com \
  --schema https://api.example.com/openapi.json \
  --auth-token "Bearer <TOKEN>"

# Or using docker-compose
docker compose -f docker-compose.scanner.yaml run --rm api-scanner scan --url https://api.example.com --schema https://api.example.com/openapi.json
```

## Stateful Workflow & Autonomous BOLA Chaining

Execute multi-step business logic workflows with sequential variable extraction and BOLA validation:

```bash
# 1. Autonomous Workflow Synthesis (Zero manual YAML):
# Auto-pairs CRUD producers and consumers directly from OpenAPI spec
python run_all.py auto-workflow targets/schemas/vampi/vampi_spec.yaml --url http://127.0.0.1:5002

# 2. Execute declarative stateful workflow YAML:
python run_all.py workflow targets/workflows/sample_workflow.yaml

# 3. Execute workflow with upstream proxy (Burp Suite/Caido/ZAP)
python run_all.py workflow targets/workflows/sample_workflow.yaml --url http://127.0.0.1:5002 --proxy http://127.0.0.1:8080 --insecure
```

## Interactive Terminal UI (TUI) Dashboard

Launch the interactive control center:

```bash
python -m cli
```

Command-line reporting flags:
- `python -m cli --dashboard`: Prints the latest executive summary and OWASP breakdown.
- `python -m cli --report`: Generates and opens the latest interactive HTML report in your browser.
- `python -m cli --sarif`: Exports findings to `results/vulnerabilities.sarif` for CI/CD ingestion.

## Updating CVE rules cache

To refresh the local CVE cache in `config/rules.json`:

```bash
python -m modules.security.rules_engine --update
```

This queries the NVD CVE API 2.0 with rate-limit pacing and automatically falls
back to the Google OSV API (`api.osv.dev`) for core API packages if NVD is
throttled or unreachable.

## Common startup failures

- **No supported runtime:** Install Docker with Compose or Podman with Compose,
  then start the engine and retry.
- **Runtime installed but unavailable:** Start Docker with `sudo systemctl start docker`.
- **Pinned source or crAPI `jwks.json` missing:** Run `python run_all.py setup`.
- **Port already in use:** Ports 5001, 5002, 8888, or 5013 are in use by another
  process. Stop the conflicting service and retry.
- **Service health check timeout:** Check container logs with `docker compose logs`
  or run `python run_all.py check`. Readiness requires HTTP response, not just
  container state.
