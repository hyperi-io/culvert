# Culvert Test Suite

This directory contains the test framework for the culvert deployment.

## Test Structure

```
tests/
|-- unit/           # Python unit tests (pytest)
|-- smoke/          # Container startup smoke test (BATS)
|-- integration/    # Docker-based integration tests (BATS)
|-- e2e/            # Full VPN connectivity over docker-compose (pytest)
|-- k8s/            # Helm chart on a real cluster (pytest, opt-in)
|-- fixtures/       # Test data and mock files
|-- helpers/        # Shared BATS helpers
|-- cleanup.py      # Remove infrastructure an interrupted run left behind
|-- tidy.py         # Session-end cleanup registry used by e2e and k8s
`-- conftest.py     # pytest fixtures (temp_dir, clean_env, mock_pki_dir)
```

## Test Types

### Unit Tests (`tests/unit/`)

Fast, isolated tests for Python modules. Run locally without Docker.

- **Framework:** pytest
- **Purpose:** Test config parsing, validation, template generation, metrics parsing
- **Dependencies:** `uv sync --dev`
- **Run time:** < 15 seconds

```bash
# Run all unit tests
python3 -m pytest tests/unit/ -v

# Run a specific test file
python3 -m pytest tests/unit/test_config.py -v

# Run with coverage
python3 -m pytest tests/unit/ --cov=scripts/lib --cov-report=term
```

### Integration Tests (`tests/integration/`)

Test container functionality in Docker environment.

- **Framework:** BATS + Docker
- **Purpose:** Test container startup, PKI initialisation, config generation
- **Dependencies:** Docker, bats-core
- **Run time:** 2-5 minutes

```bash
./tests/run-integration.sh
```

### End-to-End Tests (`tests/e2e/`)

Test full VPN connectivity against a self-contained docker-compose stack
(server + client + target containers brought up by `conftest.py`).

- **Framework:** pytest + docker-compose
- **Purpose:** Validate real VPN connections (OpenVPN UDP/TCP/HTTPS,
  WireGuard, WireGuard over HTTPS via wstunnel) end to end
- **Dependencies:** Docker
- **Run time:** 5-15 minutes

```bash
# Run e2e tests (brings up the compose stack automatically)
pytest tests/e2e/ -m e2e -v
```

### Cluster Tests (`tests/k8s/`)

Install the real Helm chart on a real cluster and assert on what the cluster
does with it - capabilities, ip_forward in the pod netns, probes, SIGTERM
drain, external PKI, and real client tunnels carrying traffic.

- **Framework:** pytest + kubectl + helm
- **Dependencies:** a cluster you can install into, and an image reference it
  can pull
- **Run time:** 1-2 minutes

Every site-specific value comes from `tests/k8s/.env` (gitignored); copy
`tests/k8s/.env.example` and fill it in. Unconfigured, every test SKIPS with a
message naming what is missing, so a plain `pytest` run stays green. They never
run in CI - the `k8s` marker is deselected and the tier is disabled in
`.hyperi-ci.yaml`.

```bash
pytest tests/k8s/ -m k8s -v
```

## Test Infrastructure Naming and Cleanup

Everything the docker and cluster tiers create is named for the tier that owns
it, so you can tell at a glance what a stray object belongs to:

| Tier | Names |
|------|-------|
| docker e2e connectivity | `culvert-test-e2e-server`, `-client`, `-target` |
| docker e2e routing control | `culvert-test-e2e-routing-server`, `-receiver`, `-client-a`, `-client-b`, `-admin`, `-nonadmin` |
| integration (BATS) | `culvert-test-integration-<test file>`, one per test file |
| cluster | `culvert-test-k8s-client`, `culvert-test-k8s-target`, release `culvert-test` |

Both tiers sweep what they own BEFORE they build, so a run that was killed
cannot make the next one fail on a name collision or a stale volume. They also
tear down at session end however the session ends - a normal finish, a
collection error, Ctrl-C, or SIGTERM - because the cleanups are registered with
`tidy.py` rather than left to a fixture finaliser, which is skipped when the
process is signalled. `SIGKILL` cannot be trapped by anything, so for that case
the pre-run sweep is the guarantee.

To tidy up immediately rather than waiting for the next run:

```bash
python3 tests/cleanup.py                 # every tier
python3 tests/cleanup.py docker          # e2e compose stacks only
python3 tests/cleanup.py integration     # BATS integration containers only
python3 tests/cleanup.py k8s             # cluster objects only
```

The cluster sweep removes releases installed from the culvert chart in the
configured test namespace plus the pods this tier creates. It deliberately does
not delete the namespace: a namespace still Terminating when the next run starts
makes every pod creation fail, which reads as a cluster fault rather than as
leftover state.

## Running All Tests

```bash
# Unit tests only (fast, no Docker)
python3 -m pytest tests/unit/ -v

# All test suites
./tests/run-all.sh
```

## Test Coverage by Module

| Module | Unit Tests |
|--------|-----------|
| `lib/config.py` | Config defaults, env overrides, validation, network profiles |
| `lib/process.py` | run/run_quiet, ProcessManager lifecycle, directory setup |
| `lib/network.py` | CIDR-to-netmask conversion, edge cases |
| `lib/pki.py` | External PKI file validation (present/missing/partial) |
| `lib/openvpn.py` | Template substitution, common options, timestamp stripping |
| `lib/stunnel.py` | Config generation with valid/missing certs |
| `lib/health.py` | Liveness, readiness, state transitions, retired paths 404 |
| `lib/download.py` | File listing, download, path traversal prevention |
| `lib/metrics.py` | OpenVPN status v3 parsing, WG transfer/handshake parsing |
| `lib/wireguard.py` | Key gen, IP allocation, config gen, subnet validation |
