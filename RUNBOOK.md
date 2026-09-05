# Schemathesis Runbook

Operational runbook for the current **Schemathesis** repository layout.

The important rule is simple: once the repository is cloned, all pipeline commands are run from the repository root:

```bash
cd ~/Schemathesis
source .venv/bin/activate
```

There is no `main_pipeline/` directory in the current repository layout.

---

## 1. Initial setup

### Clone

```bash
git clone https://github.com/Gilgamesh512/Schemathesis.git
cd Schemathesis
```

### Create the project-local virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Verify dependencies

```bash
python -c "import schemathesis, pydantic, httpx, yaml, requests; print('Python dependencies OK')"
docker --version
sudo docker-compose --version
curl --version
```

---

## 2. Required lab directories

Before running `run_all.py`, verify that the three vulnerable targets exist where `start_lab.py` expects them:

```bash
ls -ld ~/VAmPI
ls -ld ~/crAPI
ls -ld ~/Damn-Vulnerable-GraphQL-Application
```

The current launcher expects:

```text
~/VAmPI
~/crAPI
~/Damn-Vulnerable-GraphQL-Application
```

If any directory is missing, `start_lab.py` will fail before the corresponding target can be started.

---

## 3. Standard terminal preparation

Every new terminal:

```bash
cd ~/Schemathesis
source .venv/bin/activate
```

Optional sanity check:

```bash
pwd
python --version
```

`pwd` should show the Schemathesis repository root.

---

## 4. Full end-to-end run — recommended

Use this for a normal complete execution:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_all.py
```

### Expected stages

```text
1. Check pipeline files
2. Start VAmPI
3. Start crAPI
4. Build/start DVGA
5. Authenticate VAmPI
6. Authenticate crAPI
7. Create/login temporary DVGA user
8. Save tokens.env
9. Run DVGA GraphQL introspection
10. Save dvga_schema.json
11. Validate auth/schema handoff
12. REST fuzzing — VAmPI
13. REST fuzzing — crAPI
14. GraphQL fuzzing — DVGA
15. Write results/
```

The main controller invokes `run_security_tests.py`, so this one command is the preferred operator workflow.

---

## 5. Start the lab only

Use this when you want to bring up the vulnerable targets without running fuzzing:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 start_lab.py
```

The script currently:

- stops old VAmPI Docker Compose containers;
- starts VAmPI;
- calls `http://localhost:5002/createdb`;
- stops old crAPI Docker Compose containers;
- starts crAPI;
- stops/removes the old `dvga` container;
- builds the `dvga` image;
- starts DVGA with `5013:5013`.

### Quick service checks

```bash
curl -i http://localhost:5002
curl -i http://localhost:8888
curl -i http://localhost:5013
```

A response from each endpoint is a basic reachability check; it is not a complete application-health test.

---

## 6. Refresh VAmPI + crAPI tokens

Run:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_auth.py
```

The script owns REST authentication and writes/updates:

```text
tokens.env
```

Expected keys:

```text
VAMPI_AUTH_HEADER
CRAPI_AUTH_HEADER
```

Inspect only the variable names, not the token values:

```bash
grep -E '^export (VAMPI_AUTH_HEADER|CRAPI_AUTH_HEADER)=' tokens.env | sed 's/=.*/=<redacted>/'
```

### Failure conditions

If either target cannot authenticate, the script exits non-zero.

Common causes:

- target service is not reachable;
- login endpoint changed;
- credentials in `run_auth.py` no longer work with the installed target version;
- application startup is incomplete.

---

## 7. Refresh DVGA token + GraphQL schema

Run:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_dvga.py
```

This stage:

1. waits for DVGA;
2. creates a unique temporary test account;
3. logs in via the GraphQL `login` mutation;
4. stores `DVGA_AUTH_HEADER` in `tokens.env`;
5. runs GraphQL introspection;
6. saves the schema to `dvga_schema.json`.

### Verify generated artifacts

```bash
python3 - <<'PY'
import json
from pathlib import Path

for p in [Path('tokens.env'), Path('dvga_schema.json')]:
    print(f'{p}: {"READY" if p.exists() else "MISSING"}')

if Path('dvga_schema.json').exists():
    data = json.loads(Path('dvga_schema.json').read_text())
    print('target   :', data.get('target'))
    print('protocol :', data.get('protocol'))
    print('graphQL  :', data.get('graphql_url'))
    print('analysis :', data.get('analysis', {}))
PY
```

---

## 8. Validate the handoff manually

`run_all.py` performs its own handoff validation. If you need to inspect the artifacts separately:

```bash
cd ~/Schemathesis
source .venv/bin/activate
```

Check tokens without printing their values:

```bash
grep -E '^export (VAMPI_AUTH_HEADER|CRAPI_AUTH_HEADER|DVGA_AUTH_HEADER)=' tokens.env \
  | sed 's/=.*/=<redacted>/'
```

Check DVGA schema metadata:

```bash
python3 - <<'PY'
import json
from pathlib import Path

p = Path('dvga_schema.json')
if not p.exists():
    raise SystemExit('dvga_schema.json is missing')

data = json.loads(p.read_text())
assert data.get('target') == 'dvga', 'target != dvga'
assert data.get('protocol') == 'graphql', 'protocol != graphql'
print('DVGA schema handoff: READY')
PY
```

---

## 9. Fuzzing only

Use this when the lab is already running and you want to run the security-testing controller:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_security_tests.py
```

The controller resolves the payload/spec inputs and executes:

```text
VAmPI REST
    ↓
crAPI REST
    ↓
DVGA GraphQL
```

Each stage receives its corresponding authentication value through `FUZZ_AUTH_HEADER` when that token exists in `tokens.env`.

---

## 10. Refresh tokens/schema, then fuzz

Use this when the lab is up but authentication artifacts need to be refreshed:

```bash
cd ~/Schemathesis
source .venv/bin/activate

python3 run_auth.py
python3 run_dvga.py
python3 run_security_tests.py
```

---

## 11. REST fuzzer — manual execution

### VAmPI

```bash
cd ~/Schemathesis
source .venv/bin/activate

export FUZZ_AUTH_HEADER="$VAMPI_AUTH_HEADER"
python3 run_schemathesis1.py \
  --targets "vampi=./vampi_spec.yaml" \
  --base-urls "vampi=http://localhost:5002" \
  --payloads ./payload_rest.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

### crAPI

```bash
cd ~/Schemathesis
source .venv/bin/activate

export FUZZ_AUTH_HEADER="$CRAPI_AUTH_HEADER"
python3 run_schemathesis1.py \
  --targets "crapi=./crapi_openapi_spec.json" \
  --base-urls "crapi=http://localhost:8888" \
  --payloads ./payload_crapi.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

### Important

Prefer the controller (`run_security_tests.py`) for normal operation because it reads the correct token from `tokens.env` and passes it only to the relevant stage.

Avoid placing a real bearer token directly in `--auth-header` because it can remain in shell history or process listings.

---

## 12. GraphQL fuzzer — manual execution

```bash
cd ~/Schemathesis
source .venv/bin/activate

export FUZZ_AUTH_HEADER="$DVGA_AUTH_HEADER"
python3 run_graphql_fuzz1.py \
  --base-url http://localhost:5013 \
  --endpoint /graphql \
  --payloads ./payload_graphql.json \
  --rules ./rules.json \
  --results-dir ./results \
  --concurrency 3
```

The current filename is:

```text
run_graphql_fuzz1.py
```

Do **not** use the old/non-existent command:

```text
run_graphql_fuzz.py
```

The GraphQL runner expects payload entries for `target_app=dvga` and maintains:

```text
results/state_graphql.json
```

---

## 13. CVE/rules maintenance

### Inspect rules

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 rules_engine.py --rules ./rules.json
```

### Refresh recent CVE signals

```bash
python3 rules_engine.py \
  --update \
  --rules ./rules.json \
  --days 30
```

### Refresh with an NVD API key

```bash
python3 rules_engine.py \
  --update \
  --rules ./rules.json \
  --days 90 \
  --api-key <NVD_API_KEY>
```

Recommended operational cadence: refresh the CVE cache periodically, for example weekly, when internet access is available.

The rule engine does not treat a CVE keyword match as proof of a vulnerability. Target behavior remains the primary evidence.

---

## 14. Results inspection

Main artifacts:

```text
results/vulnerabilities.csv
results/vulnerabilities.ndjson
results/experiment_runs.csv
results/state.json
results/state_graphql.json
```

### CSV

```bash
column -s, -t < results/vulnerabilities.csv | less -S
```

### NDJSON

```bash
less results/vulnerabilities.ndjson
```

### Run statistics

```bash
column -s, -t < results/experiment_runs.csv | less -S
```

### Count confirmed findings

```bash
python3 - <<'PY'
import csv
from pathlib import Path
p = Path('results/vulnerabilities.csv')
if not p.exists():
    raise SystemExit('No results yet')
with p.open(newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
confirmed = [r for r in rows if r.get('confirmed', '').lower() == 'true']
print('total findings   :', len(rows))
print('confirmed        :', len(confirmed))
print('candidate/rejected:', len(rows) - len(confirmed))
PY
```

---

## 15. What counts as a confirmed result

The current engines do not treat every error response as a confirmed vulnerability.

The general logic compares a baseline response with the attack response, using status/body/header/timing differences and payload-specific evidence.

Keep these distinctions in mind:

```text
candidate != confirmed
CVE match != proof
GraphQL error != proof
5xx != automatic proof
```

A `5xx` is a strong candidate signal, but the confirmation result still depends on the engine's evidence/comparison logic.

---

## 16. Troubleshooting

### `Missing required script` / file not found

Verify the working directory:

```bash
cd ~/Schemathesis
pwd
ls run_all.py run_security_tests.py run_schemathesis1.py run_graphql_fuzz1.py
```

Do not use old paths such as:

```text
~/fuzzing-tool/main_pipeline/...
```

### VAmPI / crAPI cannot start

Check the required directories:

```bash
ls -ld ~/VAmPI ~/crAPI
```

Then test Docker Compose manually in the target directory if necessary.

### DVGA cannot start

Check:

```bash
ls -ld ~/Damn-Vulnerable-GraphQL-Application
sudo docker ps -a | grep -i dvga
```

The current launcher builds the image and runs a container named `dvga` on host port `5013`.

### Authentication failed

Refresh the relevant target and inspect service reachability:

```bash
python3 run_auth.py
python3 run_dvga.py
```

Do not print token values into shared terminals/logs.

### `dvga_schema.json` missing or invalid

Run:

```bash
python3 run_dvga.py
```

Then validate:

```bash
python3 - <<'PY'
import json
with open('dvga_schema.json', encoding='utf-8') as f:
    d = json.load(f)
print(d.get('target'), d.get('protocol'))
PY
```

Expected:

```text
dvga graphql
```

### Fuzzer runs without authentication

`run_security_tests.py` is deliberately tolerant when an auth header is missing, so a stage can run unauthenticated.

Check token keys:

```bash
grep -E '^export .*AUTH_HEADER=' tokens.env | sed 's/=.*/=<redacted>/'
```

For a fully authenticated run, rerun:

```bash
python3 run_auth.py
python3 run_dvga.py
python3 run_security_tests.py
```

### Results are appearing under the wrong path

When running the fuzzers directly, always pass:

```bash
--results-dir ./results
```

The individual runners still have a legacy default that references `main_pipeline/results`; the main controller overrides this with the actual repository-root `results/` directory.

---

## 17. Runtime artifacts and cleanup

### Inspect containers

```bash
sudo docker ps -a
```

### Re-run from a clean lab state

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 start_lab.py
python3 run_auth.py
python3 run_dvga.py
python3 run_security_tests.py
```

### Remove runtime outputs

Only do this when you intentionally want to reset findings/state:

```bash
rm -rf results
rm -f tokens.env dvga_schema.json
```

The next full run will recreate the runtime artifacts.

Do not remove `rules.json`, OpenAPI specs, payload corpora, or source scripts unless you intend to change the test configuration itself.

---

## 18. Permissions

The current `start_lab.py` invokes Docker Compose with `sudo` and the DVGA container with `sudo docker` commands.

Therefore verify:

```bash
sudo -v
sudo docker ps
sudo docker-compose --version
```

The runtime token file is written with restrictive permissions where the OS supports `chmod 0600`.

---

## 19. Operational quick reference

### Full pipeline

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_all.py
```

### Start lab only

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 start_lab.py
```

### Refresh REST tokens

```bash
python3 run_auth.py
```

### Refresh DVGA token + schema

```bash
python3 run_dvga.py
```

### Fuzz with current handoff

```bash
python3 run_security_tests.py
```

### Update CVE cache

```bash
python3 rules_engine.py --update --rules ./rules.json --days 30
```

### View findings

```bash
cat results/vulnerabilities.csv
cat results/vulnerabilities.ndjson
```

---

## 20. Code/documentation issues to track

These are not operator mistakes; they are current codebase inconsistencies worth cleaning up in a future revision:

1. `run_all.py` contains a stale docstring claiming that the controller stops before fuzzing, while its `main()` function does launch `run_security_tests.py`.
2. `run_security_tests.py` still prints `main_pipeline` terminology even though the scripts are now at repository root.
3. Individual fuzzer defaults still mention `main_pipeline/results`; direct execution should therefore specify `--results-dir ./results`.
4. `start_lab.py` hard-codes target paths under `$HOME` instead of reading configurable environment variables/CLI options.
5. `start_lab.py` depends on `sudo docker-compose`; the script does not automatically translate to the modern `docker compose` command.
6. Authentication is intentionally optional at the `run_security_tests.py` layer. For authenticated testing, use `run_all.py` or refresh the token handoff first.

---

## 21. Stop condition

A normal successful run should end with these artifacts present:

```text
results/vulnerabilities.csv
results/vulnerabilities.ndjson
results/experiment_runs.csv
results/state.json
results/state_graphql.json
```

Also verify:

```text
tokens.env
DVGA schema metadata in dvga_schema.json
```

The end-to-end operator command remains:

```bash
cd ~/Schemathesis
source .venv/bin/activate
python3 run_all.py
```
