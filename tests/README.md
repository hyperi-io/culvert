# Culvert Test Suite

This directory contains the test framework for the culvert deployment.

## Test Structure

```
tests/
├── unit/           # Python unit tests (pytest)
├── integration/    # Docker-based integration tests (BATS)
├── e2e/            # End-to-end tests against real VMs (BATS)
├── fixtures/       # Test data and mock files
├── helpers/        # Shared test utilities
└── conftest.py     # pytest fixtures (clean_env, sample_env)
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
  WireGuard, wstunnel DPI bypass) end to end
- **Dependencies:** Docker
- **Run time:** 5-15 minutes

```bash
# Run e2e tests (brings up the compose stack automatically)
pytest tests/e2e/ -m e2e -v
```

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
| `lib/health.py` | Liveness, readiness, startup probes, state transitions |
| `lib/download.py` | File listing, download, path traversal prevention |
| `lib/metrics.py` | OpenVPN status v3 parsing, WG transfer/handshake parsing |
| `lib/wireguard.py` | Key gen, IP allocation, config gen, subnet validation |
