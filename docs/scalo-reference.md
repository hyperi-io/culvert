# scalo Reference for culvert

How culvert actually uses [scalo](https://pypi.org/project/scalo/),
the Apache-2.0 Python runtime it depends on. This documents the calls that
exist in `scripts/`, not the full library surface. The
[scalo repo](https://github.com/hyperi-io/scalo-py) is the API SSoT.

## Installation

In `pyproject.toml`, which holds the version range (granular extras - one
per backend culvert actually uses, not the blanket `[secrets]`):

```toml
dependencies = ["scalo[metrics,secrets-vault,secrets-aws]..."]
```

The container installs the full runtime tree (scalo + those extras +
`[opentelemetry]`) from a hash-pinned lockfile: `pip install
--require-hashes -r requirements-docker.txt`, where the lockfile is
exported from `uv.lock` (see `Dockerfile`). Every dependency is verified
against a SHA256 held in-repo, so the build fails closed on any drift.

## Config Cascade

culvert builds a fresh settings instance per load via `get_config`, so env
changes (and test monkeypatching) are always reflected.

```python
from scalo.config import get_config

settings = get_config(
    env_prefix="CULVERT",
    additional_files=["/etc/vpn/profiles/example.yaml"],  # optional profile
)
value = settings.get("udp_port", 1194)
```

See `scripts/lib/config.py:_get_settings()`. Every variable uses the
`CULVERT_` prefix exclusively (e.g. `CULVERT_UDP_PORT`). There are no
legacy aliases. An optional profile YAML is layered in via `additional_files`
when `CULVERT_PROFILE` is set.

Cascade priority, highest wins: `CULVERT_*` env vars (a `./.env` loads
beneath any set in the environment) -> the profile YAML -> `settings.{env}.yaml` ->
`settings.yaml` -> `defaults.yaml` -> the fallback each `Config.from_settings`
read passes.

## Structured Logging

```python
from scalo.logger import logger

logger.info("WireGuard peer connected", peer=name, handshake_age=age)
logger.error(f"Failed to start WireGuard: {result.stderr}")
```

Loguru-based singleton: RFC 3339 timestamps, JSON in containers / coloured in a
terminal (auto-detected), automatic masking of secrets. culvert's log lines
are structured, and OpenVPN, stunnel, wstunnel and WireGuard keep their
native log formats.

## Metrics (Prometheus + OpenTelemetry)

culvert calls `create_metrics` directly, registers its metric handles,
and registers scalo's `AppMetrics` group beside them.

```python
from scalo.metrics import create_metrics

mgr = create_metrics(
    "culvert",
    backend="prometheus",  # or "opentelemetry"
    backend_config=None,  # OTel: {"opentelemetry": {"endpoint": ..., "protocol": ...}}
    enable_auto_update=False,
)

g_up = mgr.gauge("vpn_openvpn_up", "Whether OpenVPN is running")
g_clients = mgr.gauge(
    "vpn_connected_clients",
    "Connected clients per listener",
    labels=["listener", "protocol"],
)
c_rx = mgr.counter("vpn_bytes_received_total", "Total bytes received")

g_up.set(1)
g_clients.labels(listener="udp", protocol="openvpn").set(3)
body = mgr.metrics  # exposition bytes for the /metrics response
content_type = mgr.content_type
```

See `scripts/lib/metrics.py`. When OTel is enabled the same metrics push via
OTLP and serve on the Prometheus `/metrics` endpoint as well. Otherwise the
Prometheus scrape is all there is. OTLP needs `CULVERT_METRICS_ENABLED=true` as well,
because nothing initialises metrics without it.

In OTel mode the `process_*`, `python_gc_*` and `python_info` families that
`/metrics` serves push over OTLP as well, under the same names and labels, so a
collector that does not scrape the pod still receives them. They go through a
second MeterProvider that holds an OTLP reader and nothing else, built from scalo's
resolved OTLP settings (`resolve_otel_config`), exporter factory and backoff
gate, with the same resource and scope as the `vpn_*` push. On scalo's
provider they would render on `/metrics` a second time, beside
prometheus_client's copy.

**Naming:** the app name is `culvert`, and registered metric names use the
`vpn_*` namespace (e.g. `vpn_connected_clients`, `vpn_bytes_received_total`).

**Identity:** `AppMetrics` registers scalo's standard service metrics, among
them the `info` gauge (labels `version`, `commit` and `app`, value 1) that a
collector-side liveness check keys on, and `start_time_seconds`. `version` and
`commit` come from the `VERSION` and `COMMIT` files the image build bakes under
`/etc/vpn`, and read `dev` and `unknown` where a file is absent or empty. The
same version is the OTLP resource's `service.version` on both pushes. The
group's throughput and memory instruments are registered but never recorded, so
the OTLP push does not include them.

## Secrets / External PKI

culvert fetches external PKI material through scalo's SecretsManager
(`scripts/lib/pki.py:create_manager`), built via the documented
`from_config` path with the disk cache disabled (a cache would write a
second copy of the server key outside the PKI dir).

```python
from scalo.secrets import SecretsManager

manager = SecretsManager.from_config(
    {
        "cache": {"enabled": False},
        "openbao": {"address": ..., "auth": {"method": "kubernetes", "role": ...}},
        # or "aws": {"region": "ap-southeast-2"}; file provider is always present
    }
)

result = manager.get_sync(secret_ref, provider="openbao")  # result.data -> bytes
manager.health_check_sync()  # dict of provider name -> bool
await manager.close()  # async - pki.py runs it via asyncio.run
```

## What culvert uses

| Need | scalo module | Call site |
|------|---------------------|-----------|
| Logging | `scalo.logger.logger` | every `scripts/lib/*.py` module except `client_state.py` and `deployment.py` |
| Logging setup | `scalo.logger.setup` | `scripts/entrypoint.py`, `scripts/generate-client.py`, `scripts/revoke-client.py`, `scripts/update-crl.py` |
| Config | `scalo.config.get_config` | `scripts/lib/config.py` |
| Metrics | `scalo.metrics.create_metrics` | `scripts/lib/metrics.py` |
| Service identity (`info`) | `scalo.metrics.groups.AppMetrics` | `scripts/lib/metrics.py` |
| Runtime metrics over OTLP | `scalo.metrics.opentelemetry_backend.resolve_otel_config`, `_create_otlp_exporter`, `SHUTDOWN_FLUSH_MILLIS`, `scalo.otel_backoff.GatedMetricExporter` | `scripts/lib/metrics.py` |
| Health probes and the observability port | `scalo.health.HealthManager`, `scalo.health.serve_observability` | `scripts/lib/health.py` |
| Secrets | `scalo.secrets.SecretsManager` | `scripts/lib/pki.py` |
| Deployment contract (dev and CI only) | `scalo.deployment` | `scripts/lib/deployment.py`, `scripts/generate-deploy-artefacts.py` |
