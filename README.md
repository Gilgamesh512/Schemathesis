# Schemathesis — Automated REST & GraphQL API Security Testing

Automated API security testing and fuzzing pipeline built around **Schemathesis** for REST APIs and a dedicated GraphQL fuzzer for DVGA.

The repository orchestrates a local vulnerable API lab, creates authentication material, discovers the DVGA GraphQL schema, runs the REST and GraphQL fuzzers, performs fingerprint-based deduplication/confirmation, and writes machine-readable findings.

> **Scope:** This repository is designed for an authorized local security-testing lab using VAmPI, crAPI, and DVGA. Do not point the pipeline at systems you do not have explicit permission to test.

## 1. What the pipeline does

The main entry point is:

```bash
python3 run_all.py
```

The end-to-end flow is:

```text
run_all.py
    |
    +--> start_lab.py
    |       +--> VAmPI
    |       +--> crAPI
    |       +--> DVGA
    |
    +--> run_auth.py
    |       +--> VAMPI_AUTH_HEADER
    |       +--> CRAPI_AUTH_HEADER
    |
    +--> run_dvga.py
    |       +--> DVGA_AUTH_HEADER
    |       +--> dvga_schema.json
    |
    +--> validate handoff
    |       +--> tokens.env
    |       +--> dvga_schema.json
    |
    +--> run_security_tests.py
            |
            +--> run_schemathesis1.py
            |       +--> VAmPI REST fuzzing
            |       +--> crAPI REST fuzzing
            |
            +--> run_graphql_fuzz1.py
                    +--> DVGA GraphQL fuzzing

                         |
                         v
                    results/
                    ├── vulnerabilities.csv
                    ├── vulnerabilities.ndjson
                    ├── experiment_runs.csv
                    ├── state.json
                    └── state_graphql.json
```

`run_all.py` is the actual end-to-end controller: after starting the lab and preparing authentication/schema handoff, it invokes `run_security_tests.py`, which then runs the three fuzzing stages. The current source code confirms this execution chain. 

## 2. Targets

| Target | Protocol | Endpoint | Pipeline component |
|---|---|---|---|
| VAmPI | REST | `http://localhost:5002` | `run_schemathesis1.py` |
| crAPI | REST | `http://localhost:8888` | `run_schemathesis1.py` |
| DVGA | GraphQL | `http://localhost:5013/graphql` | `run_graphql_fuzz1.py` |

The lab launcher expects the vulnerable applications at these local paths:

```text
~/VAmPI
~/crAPI
~/Damn-Vulnerable-GraphQL-Application
```

`start_lab.py` stops/restarts the VAmPI and crAPI Docker Compose stacks, initializes the VAmPI database, builds the DVGA Docker image, and starts DVGA on port `5013`.

## 3. Repository layout

The current repository is **not** organized around a `main_pipeline/` subdirectory. The active pipeline scripts and inputs are located at the repository root:

```text
Schemathesis/
├── README.md
├── RUNBOOK.md
├── requirements.txt
├── .gitignore
│
├── run_all.py
├── start_lab.py
├── run_auth.py
├── run_dvga.py
├── run_security_tests.py
├── run_schemathesis1.py
├── run_graphql_fuzz1.py
├── rules_engine.py
│
├── payload_rest.json
├── payload_crapi.json
├── payload_graphql.json
├── vampi_spec.yaml
├── vampi_spec.json
├── crapi_openapi_spec.json
├── crapi_spec.yaml
├── rules.json
│
├── tokens.env              # generated at runtime; do not commit
├── dvga_schema.json        # generated/updated at runtime
└── results/                # generated at runtime
    ├── vulnerabilities.csv
    ├── vulnerabilities.ndjson
    ├── experiment_runs.csv
    ├── state.json
    └── state_graphql.json
```

`tokens.env` and `results/` are ignored by Git in the current repository configuration.

## 4. Requirements

### Host requirements

The pipeline requires:

- Linux environment with Python 3
- Docker
- Docker Compose / `docker-compose`
- `curl`
- the three vulnerable target applications at the paths expected by `start_lab.py`

### Python requirements

The repository pins the Python dependencies in `requirements.txt`:

```text
schemathesis==4.24.3
pydantic==2.9.2
httpx==0.28.1
pyyaml==6.0.3
requests==2.32.3
```

## 5. Installation

Clone the repository into the directory name `Schemathesis`:

```bash
git clone https://github.com/Gilgamesh512/Schemathesis.git
cd Schemathesis
```

Create a project-local virtual environment. This removes the dependency on an external environment such as `~/fuzzenv`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Every new terminal session should activate the same environment before running Python scripts:

```bash
cd ~/Schemathesis
source .venv/bin/activate
```

### Verify the installation

```bash
python --version
python -c "import schemathesis, pydantic, httpx, yaml, requests; print('Python dependencies OK')"
docker --version
sudo docker-compose --version
curl --version
```

## 6. Prepare the vulnerable lab

`start_lab.py` does not clone the vulnerable applications. It expects them to already exist at:

```text
~/VAmPI
~/crAPI
~/Damn-Vulnerable-GraphQL-Application
```

After those directories are present, the Schemathesis repository itself is the only directory you need to enter when running the pipeline:

```bash
cd ~/Schemathesis
source .venv/bin/activate
```

You do **not** need to `cd` into a `main_pipeline/` directory because that directory is not part of the current repository layout.

## 7. Recommended execution

For a complete run from a clean terminal:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_all.py
```

This performs the following sequence:

1. Verify required pipeline scripts exist.
2. Start VAmPI, crAPI, and DVGA.
3. Create/login the automated VAmPI and crAPI test accounts.
4. Write `VAMPI_AUTH_HEADER` and `CRAPI_AUTH_HEADER` to `tokens.env`.
5. Create/login a temporary DVGA user.
6. Write `DVGA_AUTH_HEADER` to `tokens.env`.
7. Run GraphQL introspection and save `dvga_schema.json`.
8. Validate the authentication/schema handoff.
9. Run VAmPI REST fuzzing.
10. Run crAPI REST fuzzing.
11. Run DVGA GraphQL fuzzing.
12. Write findings and run statistics under `results/`.

## 8. Authentication handoff

The pipeline uses one generated handoff file:

```text
tokens.env
```

Expected values are:

```text
VAMPI_AUTH_HEADER
CRAPI_AUTH_HEADER
DVGA_AUTH_HEADER
```

The REST authentication helper owns VAmPI and crAPI authentication. The DVGA helper owns GraphQL registration/login and schema discovery. The security-test controller reads these values and passes each target's token to the corresponding fuzzing process as `FUZZ_AUTH_HEADER`.

You normally do **not** need to `source tokens.env` yourself.

The code writes restrictive file permissions where supported, but `tokens.env` must still be treated as sensitive authentication material.

## 9. Run individual stages

### Start only the target lab

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 start_lab.py
```

### Refresh VAmPI + crAPI authentication

```bash
python3 run_auth.py
```

This updates:

```text
tokens.env
```

with:

```text
VAMPI_AUTH_HEADER
CRAPI_AUTH_HEADER
```

### Refresh DVGA authentication + schema

```bash
python3 run_dvga.py
```

This:

- waits for DVGA;
- creates a unique temporary user;
- logs in through the GraphQL `login` mutation;
- stores `DVGA_AUTH_HEADER` in `tokens.env`;
- runs GraphQL introspection;
- writes `dvga_schema.json`.

### Run fuzzing only

Use this when the lab is already running and authentication artifacts are still usable:

```bash
python3 run_security_tests.py
```

The controller performs:

```text
VAmPI REST
    ↓
crAPI REST
    ↓
DVGA GraphQL
```

### Refresh authentication/schema, then fuzz

```bash
python3 run_auth.py
python3 run_dvga.py
python3 run_security_tests.py
```

## 10. REST fuzzing details

`run_schemathesis1.py` is the REST fuzzing engine. It accepts either a single OpenAPI specification (`--spec`) or multiple target/spec mappings (`--targets`). The normal controller uses the multi-target form one target at a time.

Example VAmPI execution from the repository root:

```bash
python3 run_schemathesis1.py \
  --targets "vampi=./vampi_spec.yaml" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads ./payload_rest.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

Example crAPI execution:

```bash
python3 run_schemathesis1.py \
  --targets "crapi=./crapi_openapi_spec.json" \
  --base-urls "crapi=http://localhost:8888" \
  --payloads ./payload_crapi.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

Authentication is preferably supplied with an environment variable rather than the CLI, because CLI arguments can appear in shell history/process listings:

```bash
export FUZZ_AUTH_HEADER='Authorization: Bearer <jwt>'
```

The REST runner records findings in CSV and NDJSON and persists fingerprint state in `results/state.json`.

## 11. GraphQL fuzzing details

`run_graphql_fuzz1.py` is the DVGA GraphQL fuzzer.

Direct execution:

```bash
python3 run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --endpoint /graphql \
  --payloads ./payload_graphql.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

The script can also read the base URL from `DVGA_BASE_URL`.

Authentication is passed as:

```bash
export FUZZ_AUTH_HEADER='Authorization: Bearer <jwt>'
```

The GraphQL runner filters the payload corpus to entries whose `target_app` is `dvga`, performs fingerprint-based deduplication, and persists GraphQL state in `results/state_graphql.json`.

## 12. Rules and CVE signals

`rules_engine.py` manages the shared rule data in `rules.json`.

Inspect the current rules/cache:

```bash
python3 rules_engine.py --rules ./rules.json
```

Refresh CVE signals from the NVD API:

```bash
python3 rules_engine.py \
  --update \
  --rules ./rules.json \
  --days 30
```

With an NVD API key:

```bash
python3 rules_engine.py \
  --update \
  --rules ./rules.json \
  --days 90 \
  --api-key <NVD_API_KEY>
```

Optional custom search terms:

```bash
python3 rules_engine.py \
  --update \
  --rules ./rules.json \
  --days 30 \
  --keywords "SQL injection" "GraphQL" "SSRF"
```

The rule engine treats CVE matches as contextual applicability/severity signals. A CVE match alone is not proof that a target is exploitable.

OWASP API Security categories are stored in `rules.json`; they are not automatically pulled from an OWASP API by this repository.

## 13. Finding confirmation and false-positive handling

The fuzzers distinguish between a candidate finding and a confirmed finding.

The general confirmation model is:

```text
baseline request
      ↓
baseline response
      ↓
attack request
      ↓
attack response
      ↓
compare status / body / headers / timing
      ↓
confirmation result
```

The implementation also uses expected payload-specific signals, server-side `5xx` responses, fingerprint state, and (where applicable) CVE/CPE context.

The following are **not** automatically treated as proof of a vulnerability:

- a generic `debug`, `exception`, or `error` string;
- a GraphQL error response by itself;
- a keyword CVE match by itself.

This is intended to reduce false positives and keep candidate/confirmed findings distinct.

## 14. Output files

All runtime results are written to:

```text
results/
```

### `vulnerabilities.csv`

Tabular findings. Current finding records include fields such as:

```text
finding_id
run_id
timestamp
tool
target_app
endpoint
method
attack_type
owasp_category
payload
status_code
response_time_ms
evidence
severity
confidence
confirmed
lifecycle
fingerprint
cve_matches
cve_match_type
cve_confidence
```

### `vulnerabilities.ndjson`

One JSON object per line. REST findings are tagged with `source=schemathesis`; GraphQL findings are produced by the GraphQL runner.

### `experiment_runs.csv`

Run-level statistics, including fields such as:

```text
run_id
timestamp
tool
targets
total_payloads
total_dropped_at_prepare
total_fired
total_skipped_dedup
total_confirmed
llm_used
```

### State files

```text
results/state.json
results/state_graphql.json
```

These persist fingerprint/attempt state across runs and support deduplication.

## 15. Viewing results

From the repository root:

```bash
cat results/vulnerabilities.csv
cat results/vulnerabilities.ndjson
cat results/experiment_runs.csv
```

For a quick overview:

```bash
python3 - <<'PY'
import csv
from pathlib import Path
p = Path('results/vulnerabilities.csv')
if not p.exists():
    print('No vulnerabilities.csv yet')
    raise SystemExit(0)
with p.open(newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
print(f'Findings: {len(rows)}')
print(f'Confirmed: {sum(r.get("confirmed", "").lower() == "true" for r in rows)}')
PY
```

## 16. Common execution patterns

### First run

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_all.py
```

### Lab already running, refresh only the tokens/schema

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_auth.py
python3 run_dvga.py
python3 run_security_tests.py
```

### Lab + tokens/schema already ready

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_security_tests.py
```

### Weekly CVE cache refresh

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 rules_engine.py --update --rules ./rules.json --days 30
```

## 17. Security notes

### Authentication material

`tokens.env` contains bearer tokens. Never commit it.

### Runtime results

`results/` may contain request/response evidence and other test-environment data. Treat it as runtime security-test data rather than source code.

### Authorized targets only

The default endpoints are local lab applications. Do not change the target URLs to systems you are not explicitly authorized to assess.

## 18. Current code audit — important notes

The documentation above intentionally follows the **current repository code**, rather than the older `main_pipeline/` documentation.

There are a few implementation/documentation inconsistencies worth fixing in the codebase itself:

1. **`run_all.py` has a stale module docstring.** Its opening text says it stops before the fuzzers, but the actual `main()` function executes `run_security_tests.py` after handoff validation. The runtime behavior is the authoritative behavior for the current pipeline.

2. **`run_security_tests.py` contains old `main_pipeline` wording and parent-root compatibility logic.** The file now lives at repository root, so those messages should be renamed to simply refer to the Schemathesis project/root pipeline.

3. **Individual fuzzer defaults still mention `main_pipeline/results`.** For manual execution from the current root repository, explicitly pass `--results-dir ./results` as shown above. The main controller already passes the repository's actual `results/` directory.

4. **`start_lab.py` hard-codes target application locations under `$HOME`.** This is why the repository cannot currently be made completely self-contained by cloning only the Schemathesis repo. The target repositories must still exist at the expected paths.

5. **`start_lab.py` uses `sudo docker-compose`.** The operator therefore needs sudo/docker-compose access. If the host uses the modern `docker compose` command instead, the launcher itself would need to be changed; documentation should not pretend that the current script supports that automatically.

6. **`run_security_tests.py` is tolerant of missing authentication.** It warns and can launch a fuzzing stage without an auth header. For authenticated security testing, the recommended path is `run_all.py` or the explicit token-refresh sequence so that all three headers are validated before testing.

## 19. One-command quick start

After the three vulnerable applications have been installed at the expected paths:

```bash
git clone https://github.com/Gilgamesh512/Schemathesis.git
cd Schemathesis
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run_all.py
```

That is the intended operator experience for the current repository.
