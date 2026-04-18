# hyperi-pylib Reference for hyperi-vpn

Reference for how hyperi-vpn uses hyperi-pylib (v2.25.1+) to align with all other DFE apps.

## Installation

```bash
pip install "hyperi-pylib[metrics]"
```

In pyproject.toml:
```toml
dependencies = ["hyperi-pylib[metrics]"]
```

## Config Cascade (8 Layers)

```python
from hyperi_pylib.config import settings

# Direct attribute access (Dynaconf-based)
host = settings.database.host
timeout = settings.get("api.timeout", 30)
```

**Cascade priority (highest wins):**
1. CLI args
2. ENV variables (auto-generated: `database.host` -> `HYPERI_VPN_DATABASE_HOST`)
3. `.env` file
4. PostgreSQL (optional, if `HYPERI_CONFIG_DSN` set)
5. `settings.{env}.yaml`
6. `settings.yaml`
7. `defaults.yaml`
8. Hard-coded defaults

**Env prefix:** Set via `HYPERI_LIB_ENV_PREFIX` or passed to `get_config()`.

**Auto-discovery locations:** `./`, `./config/`, `/config/`, `~/.config/{app_name}/`

## Structured Logging

```python
from hyperi_pylib.logger import logger

logger.info("Processing", user_id=123)
logger.error("Failed", error=str(e), exc_info=True)
```

**Features:**
- RFC 3339 timestamps with timezone
- Solarized colours (terminal) / JSON (containers) -- auto-detected
- Automatic sensitive data masking (passwords, tokens, API keys, JWTs)
- Loguru-based singleton

**ENV config:**
```bash
LOG_LEVEL=DEBUG          # DEBUG, INFO (default), WARNING, ERROR, CRITICAL
LOG_FORMAT=json          # "json" or "text" (auto-detects container)
LOG_OUTPUT=stdout        # stdout or stderr (stderr default)
```

## Metrics (OpenTelemetry + Prometheus)

```python
from hyperi_pylib.metrics import create_metrics, AppMetrics

metrics = create_metrics("dfe_vpn")
app = AppMetrics(metrics, version="2.0.0", commit="abc123")
app.record_received(1)
```

**DFE metric groups (composable, same as hyperi-rustlib):**
- `AppMetrics` -- mandatory for all DFE apps (info, uptime, records, memory)
- `BufferMetrics` -- buffer flush stats
- `ConsumerMetrics` -- Kafka consumer lag
- `SinkMetrics` -- downstream write latency

**Naming:** `dfe_{app}_{metric}[_{unit}]` (e.g. `dfe_vpn_connections_active`)

**Config:**
```yaml
metrics:
  backend: opentelemetry
  opentelemetry:
    endpoint: http://otel-collector:4317
    prometheus_scrape: true
```

## CLI Framework (DfeApp)

```python
from hyperi_pylib.cli import DfeApp, VersionInfo, CommonArgs

class MyService(DfeApp):
    name = "hyperi-vpn"
    env_prefix = "HYPERI_VPN"

    def version_info(self) -> VersionInfo:
        return VersionInfo(self.name, __version__, __commit__)

    def run_service(self, config, args: CommonArgs) -> None:
        args.init_logger()
        cfg = args.load_config(self.env_prefix)
        # ...

if __name__ == "__main__":
    MyService().cli()
```

**Built-in subcommands:** `run`, `version`, `config-check`
**Built-in flags:** `--config`, `--log-level`, `--log-format`, `--verbose`, `--quiet`, `--metrics-addr`

## Utility Functions

```python
from hyperi_pylib import get_runtime_paths, get_environment

runtime = get_runtime_paths()  # Container-aware path resolution
env = get_environment()        # Environment detection
```

## What hyperi-vpn Uses

| Need | hyperi-pylib Module | Notes |
|------|-------------------|-------|
| Logging | `hyperi_pylib.logger` | Replace hand-rolled Logger class |
| Config | `hyperi_pylib.config.settings` | Replace hand-rolled env() cascade |
| Metrics | `hyperi_pylib.metrics` | OTel + Prometheus, same API as rustlib |
| CLI | `hyperi_pylib.cli.DfeApp` | If fits entrypoint pattern (server/healthcheck subcommands) |

## What We Don't Transform

- OpenVPN process logs (stay as OpenVPN format)
- stunnel logs (stay as stunnel format)
- wstunnel logs (stay as wstunnel format)
- WireGuard kernel logs (go to dmesg, not capturable)

Only the entrypoint's own log lines use hyperi-pylib structured logging.
