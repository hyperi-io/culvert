# scalo Reference for culvert

How culvert actually uses [scalo](https://pypi.org/project/scalo/)
(v2.29+, the Apache-2.0 continuation of hyperi-pylib - same codebase,
same version line). This documents the calls that exist in
`scripts/lib/`, not the full library surface; the
[scalo repo](https://github.com/hyperi-io/scalo-py) is the API SSoT.

## Installation

In `pyproject.toml` (granular extras - one per backend culvert actually
uses, not the blanket `[secrets]`):

```toml
dependencies = ["scalo[metrics,secrets-vault,secrets-aws]>=2.29.11,<3"]
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

**Cascade priority (highest wins):** ENV vars -> profile YAML (if set) ->
library defaults -> dataclass defaults in `Config`.

## Structured Logging

```python
from scalo.logger import logger

logger.info("WireGuard peer connected", peer=name, handshake_age=age)
logger.error(f"Failed to start WireGuard: {result.stderr}")
```

Loguru-based singleton: RFC 3339 timestamps, JSON in containers / coloured in a
terminal (auto-detected), automatic masking of secrets. Only the entrypoint's
own log lines are structured; OpenVPN/stunnel/wstunnel/WireGuard keep their
native log formats.

## Metrics (Prometheus + OpenTelemetry)

culvert calls `create_metrics` directly and registers metric handles; it
does not use the higher-level application helpers.

```python
from scalo.metrics import create_metrics

mgr = create_metrics(
    "culvert",
    backend="prometheus",          # or "opentelemetry"
    backend_config=None,           # OTel: {"endpoint", "protocol", "insecure"}
    enable_auto_update=False,
)

g_up = mgr.gauge("vpn_openvpn_up", "Whether OpenVPN is running")
g_clients = mgr.gauge(
    "vpn_connected_clients", "Connected clients per listener",
    labels=["listener", "protocol"],
)
c_rx = mgr.counter("vpn_bytes_received_total", "Total bytes received")

g_up.set(1)
g_clients.labels(listener="udp", protocol="openvpn").set(3)
text = mgr.get_metrics_text()          # Prometheus exposition format
content_type = mgr.get_content_type()  # for the /metrics HTTP response
```

See `scripts/lib/metrics.py`. When OTel is enabled the same metrics push via
OTLP and also serve on the Prometheus `/metrics` endpoint; otherwise only the
Prometheus scrape is available.

**Naming:** the app name is `culvert`; registered metric names use the
`vpn_*` namespace (e.g. `vpn_connected_clients`, `vpn_bytes_received_total`).

## Secrets / External PKI

culvert fetches external PKI material through scalo's SecretsManager
(`scripts/lib/pki.py:create_manager`), built via the documented
`from_config` path with the disk cache disabled (a cache would write a
second copy of the server key outside the PKI dir).

```python
from scalo.secrets import SecretsManager

manager = SecretsManager.from_config({
    "cache": {"enabled": False},
    "openbao": {"address": ..., "auth": {"method": "kubernetes", "role": ...}},
    # or "aws": {"region": "ap-southeast-2"}; file provider is always present
})

result = manager.get_sync(secret_ref, provider="openbao")  # result.data -> bytes
manager.health_check_sync()   # dict of provider name -> bool
await manager.close()         # async - pki.py runs it via asyncio.run
```

## What culvert uses

| Need | scalo module | Call site |
|------|---------------------|-----------|
| Logging | `scalo.logger.logger` | all `scripts/lib/*.py` |
| Config | `scalo.config.get_config` | `scripts/lib/config.py` |
| Metrics | `scalo.metrics.create_metrics` | `scripts/lib/metrics.py` |
| Secrets | `scalo.secrets.providers.*` | `scripts/lib/pki.py` |
