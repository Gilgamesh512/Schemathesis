# Schemathesis API Security Lab

This repository runs a local API security-testing lab containing VAmPI, crAPI,
and Damn Vulnerable GraphQL Application (DVGA). It is intended for authorized
testing of these intentionally vulnerable applications only.

The lab sources are fetched by the setup command at pinned Git revisions. They
are stored beneath `.lab/dependencies/`; no pre-existing lab checkout, user
home directory, VM transfer folder, or old container is used.

## Requirements

- Git, for fetching the pinned lab sources.
- Python 3.10-3.13 for compatibility with the pinned dependencies, plus
  `venv` and `pip`.
- One supported local container runtime:
  - Docker Engine with the Compose v2 plugin or standalone `docker-compose`; or
  - Podman with `podman compose` or `podman-compose`.
- Internet access during setup and when building/pulling container images.
- Enough disk space for the three source checkouts and images. crAPI is the
  largest service.

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

## Lab operations

All commands below are run from the repository root with `.venv` activated:

```bash
python run_all.py --help
python run_all.py start
python run_all.py check
python run_all.py stop
```

`start` validates the runtime, Compose provider, configuration, and local
resources; it then builds/starts services and waits for HTTP responses from
the registered VAmPI, crAPI, and DVGA base URLs. It also calls VAmPI's
`/createdb` initialization endpoint and checks its HTTP status. A container
being `Up` by itself is not treated as a healthy target.

VAmPI's upstream Compose file publishes ports on all interfaces. To keep this
lab localhost-only, startup builds its pinned Dockerfile and starts the secure
and vulnerable services directly with explicit `127.0.0.1` port bindings.
crAPI uses the pinned upstream Compose file plus a repository override that
scopes its container names to this clone; `.env` sets its host bind address to
`127.0.0.1`.

The endpoints used by the checked-in target registry are:

- VAmPI: `http://localhost:5002`
- crAPI: `http://localhost:8888`
- DVGA: `http://localhost:5013` (GraphQL at `/graphql`)

`check` tests those HTTP endpoints without starting or modifying containers.
`stop` stops the Compose services and DVGA container without removing
containers or volumes. Data and containers are retained for a later `start`.
The project names and service container names are scoped to this clone's
resolved path so this lab does not adopt or stop unrelated containers.

The crAPI source sets its own container-level database credentials for the
intentionally vulnerable lab. They are not credentials to reuse elsewhere.
Keep the lab bound to localhost and do not expose it to an untrusted network.

## Running tests

No container startup or fuzzing is needed for the unit tests:

```bash
. .venv/bin/activate
python -m pytest
```

The CLI help is safe and does not start the lab or run the fuzzers:

```bash
python run_all.py --help
```

## Run fuzzing intentionally

Fuzzing is opt-in. The following command starts the lab, refreshes
authentication and DVGA schema artifacts, then runs the REST and GraphQL
fuzzers. It writes to `results/`:

```bash
python run_all.py run
```

Do not use `run` merely to check startup. Use `start` and `check` for lab
deployment/health verification. `tokens.env` is generated by authentication
steps, is ignored by Git, and must be treated as sensitive. The included
automated lab accounts are only for these local vulnerable targets.

## Local configuration

`.env.example` contains non-secret Compose settings. `setup` copies it to
`.env` once; the ignored `.env` is preserved on later setup runs. Startup
requires `LISTEN_IP=127.0.0.1`, `TLS_ENABLED=false`, and `VERSION=latest` and
passes these values to Compose even if the shell has conflicting environment
variables. The Compose override pins each crAPI service and database image by
OCI digest; `VERSION=latest` is retained because that is the variable used by
the upstream Compose file before image overrides are merged. This keeps the
lab localhost-only and its images immutable. To use different values, update
and validate the source configuration rather than silently overriding the
local-only defaults.

Target base URLs, schema paths, payload paths, and authentication environment
variable names are defined in `targets/registry.yaml`. Local schema and payload
paths are resolved relative to this repository, not the current shell
directory. All checked-in local schema and payload references are required
files; startup reports the missing path instead of silently skipping it.

## Common startup failures

- **No supported runtime:** install Docker with Compose or Podman with a Compose
  provider, then open/start the engine and retry.
- **Runtime installed but unavailable:** start Docker with
  `sudo systemctl start docker` or start the configured Podman service, then
  retry. No resources are deleted to work around a daemon error.
- **Pinned source, Compose file, or crAPI `jwks.json` missing:** run
  `python run_all.py setup`. If a local directory is at the wrong revision,
  move it aside yourself; setup will not overwrite it.
- **Port already in use:** stop the process that owns the conflicting port,
  then retry. The default lab exposes ports 5001, 5002, 8888, and 5013 on
  localhost.
- **A service starts but health times out:** inspect that service's runtime
  logs and check its endpoint with `python run_all.py check`. HTTP health,
  rather than container state, determines readiness.
- **Image build/pull fails:** check network access, runtime disk space, and
  that the runtime is configured for Linux containers.

Do not use `docker compose down -v`, `podman compose down -v`, or volume-prune
commands as a startup or troubleshooting step.
