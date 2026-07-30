#  Project:      culvert
#  File:         metrics.py
#  Purpose:      Metrics via scalo (Prometheus + OTel)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Metrics collection for culvert.

Uses scalo MetricsManager for dual Prometheus/OTel export.
When OTel is configured, the same metrics push via OTLP AND serve on
the Prometheus /metrics endpoint. When OTel is not configured, only
Prometheus scrape is available. The scrape itself is served by the
observability port (lib.health.start_observability) - init_metrics()
returns the adapter that port renders from.

Parses OpenVPN status files and WireGuard show output to collect
connection metrics.
"""

import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from scalo.logger import logger
from scalo.metrics import create_metrics

# ---------------------------------------------------------------------------
# Data types (used by parsers and tests)
# ---------------------------------------------------------------------------


@dataclass
class OpenVPNStatus:
    """Parsed OpenVPN status-version 3 data."""

    client_count: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    clients: list[dict] = field(default_factory=list)


@dataclass
class WgPeerTransfer:
    """Transfer data for a single WireGuard peer."""

    rx: int = 0
    tx: int = 0


@dataclass
class WgPeerHandshake:
    """Latest handshake for a WireGuard peer."""

    timestamp: int = 0


# ---------------------------------------------------------------------------
# Parsers (non-fragile - skip malformed lines, never crash)
# ---------------------------------------------------------------------------


def parse_openvpn_status_v3(content: str) -> OpenVPNStatus:
    """Parse OpenVPN status-version 3 (tab-delimited) content."""
    result = OpenVPNStatus()

    for line in content.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 2 or parts[0] != "CLIENT_LIST":
            continue
        if len(parts) < 8:
            result.client_count += 1
            continue
        try:
            client = {
                "common_name": parts[1],
                "real_address": parts[2],
                "virtual_address": parts[3],
                "bytes_received": int(parts[5]),
                "bytes_sent": int(parts[6]),
                "connected_since": parts[7],
            }
            result.clients.append(client)
            result.client_count += 1
            result.bytes_received += client["bytes_received"]
            result.bytes_sent += client["bytes_sent"]
        except (ValueError, IndexError):
            result.client_count += 1

    return result


def parse_wg_transfer(output: str) -> dict[str, WgPeerTransfer]:
    """Parse output of 'wg show wg0 transfer'."""
    peers: dict[str, WgPeerTransfer] = {}

    for line in output.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            pubkey = parts[0]
            peers[pubkey] = WgPeerTransfer(
                rx=int(parts[1]),
                tx=int(parts[2]),
            )
        except (ValueError, IndexError):
            continue

    return peers


def parse_wg_handshakes(
    output: str,
) -> dict[str, WgPeerHandshake]:
    """Parse output of 'wg show wg0 latest-handshakes'."""
    peers: dict[str, WgPeerHandshake] = {}

    for line in output.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        try:
            pubkey = parts[0]
            peers[pubkey] = WgPeerHandshake(
                timestamp=int(parts[1]),
            )
        except (ValueError, IndexError):
            continue

    return peers


def collect_openvpn_status(status_path: str, listener: str) -> OpenVPNStatus | None:
    """Read and parse an OpenVPN status file."""
    path = Path(status_path)
    if not path.exists():
        return None

    try:
        content = path.read_text()
        return parse_openvpn_status_v3(content)
    except Exception as e:
        logger.warning(
            f"Failed to parse status file: {status_path}",
            error=str(e),
        )
        return None


# ---------------------------------------------------------------------------
# WireGuard collectors
# ---------------------------------------------------------------------------


def _collect_wg_peer_count() -> int:
    """Get the number of WireGuard peers with recent handshakes."""
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "latest-handshakes"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return 0

        now = int(time.time())
        handshakes = parse_wg_handshakes(result.stdout)
        return sum(
            1
            for hs in handshakes.values()
            if hs.timestamp > 0 and (now - hs.timestamp) < 180
        )
    except Exception:
        return 0


def _collect_wg_transfer() -> tuple[int, int]:
    """Get total WireGuard rx/tx bytes."""
    try:
        result = subprocess.run(
            ["wg", "show", "wg0", "transfer"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return 0, 0

        transfers = parse_wg_transfer(result.stdout)
        total_rx = sum(t.rx for t in transfers.values())
        total_tx = sum(t.tx for t in transfers.values())
        return total_rx, total_tx
    except Exception:
        return 0, 0


# ---------------------------------------------------------------------------
# MetricsManager integration (Prometheus + OTel)
# ---------------------------------------------------------------------------

# Module-level state - set by init_metrics
_mgr = None
_max_clients: int = 100
_protocol: str = "openvpn"
_update_lock = threading.Lock()

# Metric handles (set during init)
_g_openvpn_up = None
_g_wireguard_up = None
_g_connected = None
_g_connected_total = None
_c_bytes_rx = None
_c_bytes_tx = None
_g_utilisation = None
_g_max_clients = None

# Last-seen cumulative byte totals. The OpenVPN status files and
# `wg show transfer` report per-session cumulative bytes that reset when a
# client disconnects or the interface restarts, so the snapshot total is not
# monotonic. We convert it into counter increments by reporting only the
# positive delta between polls. None until the first poll, so a process
# restart re-baselines rather than emitting a spurious initial spike.
_last_bytes: dict[str, int | None] = {"rx": None, "tx": None}


def _gauge_set(gauge, value: float, **labels: str) -> None:
    """Set a gauge, tolerating backend errors -- metrics must never break the VPN."""
    if gauge is None:
        return
    try:
        target = gauge.labels(**labels) if labels else gauge
        target.set(value)
    except Exception as e:
        logger.debug(f"Metric update failed: {e}")


def _reset_byte_tracking() -> None:
    """Forget last-seen byte totals so the next poll re-establishes a baseline."""
    _last_bytes["rx"] = None
    _last_bytes["tx"] = None


def _byte_delta(key: str, current: int) -> int:
    """Return the monotonic counter increment for a snapshot byte total.

    Records ``current`` as the new baseline and returns the bytes to add to
    the counter: 0 on the first poll or whenever the snapshot decreased (a
    client left or the interface restarted), otherwise the positive delta.
    """
    last = _last_bytes[key]
    _last_bytes[key] = current
    if last is None or current <= last:
        return 0
    return current - last


def _advance_byte_counter(counter, key: str, current: int) -> None:
    """Advance a byte counter by the positive delta, tolerating backend errors."""
    delta = _byte_delta(key, current)
    if counter is None or delta <= 0:
        return
    try:
        counter.inc(delta)
    except Exception as e:
        logger.debug(f"Counter update failed: {e}")


def _init_metrics(
    app_name: str,
    otel_enabled: bool,
    otel_endpoint: str,
    otel_protocol: str,
    otel_insecure: bool,
) -> None:
    """Initialise MetricsManager with Prometheus or OTel backend."""
    global _mgr
    global _g_openvpn_up, _g_wireguard_up
    global _g_connected, _g_connected_total
    global _c_bytes_rx, _c_bytes_tx
    global _g_utilisation, _g_max_clients

    backend = "prometheus"
    backend_config = None

    if otel_enabled and otel_endpoint:
        backend = "opentelemetry"
        backend_config = {
            "endpoint": otel_endpoint,
            "protocol": otel_protocol or "grpc",
            "insecure": otel_insecure,
        }
        logger.info(
            "Metrics: OpenTelemetry + Prometheus",
            endpoint=otel_endpoint,
            protocol=otel_protocol,
        )
    else:
        logger.info("Metrics: Prometheus only")

    _mgr = create_metrics(
        app_name,
        backend=backend,
        backend_config=backend_config,
        enable_auto_update=False,
    )

    # Register VPN-specific metrics
    _g_openvpn_up = _mgr.gauge("vpn_openvpn_up", "Whether OpenVPN is running")
    _g_wireguard_up = _mgr.gauge(
        "vpn_wireguard_up",
        "Whether WireGuard interface is active",
    )
    _g_connected = _mgr.gauge(
        "vpn_connected_clients",
        "Connected VPN clients per listener",
        labels=["listener", "protocol"],
    )
    _g_connected_total = _mgr.gauge(
        "vpn_connected_clients_total",
        "Total connected VPN clients",
    )
    _c_bytes_rx = _mgr.counter(
        "vpn_bytes_received_total",
        "Total bytes received from clients",
    )
    _c_bytes_tx = _mgr.counter(
        "vpn_bytes_sent_total",
        "Total bytes sent to clients",
    )
    _g_utilisation = _mgr.gauge(
        "vpn_connection_utilisation",
        "Ratio of connected clients to max capacity",
    )
    _g_max_clients = _mgr.gauge("vpn_max_clients", "Maximum client capacity")
    _reset_byte_tracking()


def update_metrics() -> None:
    """Collect current VPN state and update all metric values.

    Serialised: the scrape path and the background refresh loop both
    land here, and the byte-delta counters do a read-modify-write on
    module state that would over-count if two runs interleave.
    """
    if _mgr is None:
        return

    with _update_lock:
        _update_metrics_locked()


def _update_metrics_locked() -> None:
    total_clients = 0
    total_rx = 0
    total_tx = 0

    # OpenVPN
    if _protocol in ("openvpn", "both"):
        from lib.health import _check_openvpn

        _gauge_set(_g_openvpn_up, 1 if _check_openvpn() else 0)

        for status_file, listener_name in [
            ("/var/log/vpn/status.log", "udp"),
            ("/var/log/vpn/status-https.log", "https"),
            ("/var/log/vpn/status-tcp.log", "tcp"),
        ]:
            status = collect_openvpn_status(status_file, listener_name)
            if status is not None:
                total_clients += status.client_count
                total_rx += status.bytes_received
                total_tx += status.bytes_sent
                _gauge_set(
                    _g_connected,
                    status.client_count,
                    listener=listener_name,
                    protocol="openvpn",
                )

    # WireGuard
    if _protocol in ("wireguard", "both"):
        from lib.health import _check_wireguard

        _gauge_set(_g_wireguard_up, 1 if _check_wireguard() else 0)

        wg_peers = _collect_wg_peer_count()
        total_clients += wg_peers
        _gauge_set(_g_connected, wg_peers, listener="wg0", protocol="wireguard")

        wg_rx, wg_tx = _collect_wg_transfer()
        total_rx += wg_rx
        total_tx += wg_tx

    # Totals
    _gauge_set(_g_connected_total, total_clients)
    _gauge_set(_g_max_clients, _max_clients)
    _gauge_set(
        _g_utilisation,
        total_clients / _max_clients if _max_clients > 0 else 0,
    )
    _advance_byte_counter(_c_bytes_rx, "rx", total_rx)
    _advance_byte_counter(_c_bytes_tx, "tx", total_tx)


def _metrics_update_loop(interval: int = 15) -> None:
    """Background loop that periodically updates metrics."""
    while True:
        time.sleep(interval)
        try:
            update_metrics()
        except Exception as e:
            logger.warning(f"Metrics update error: {e}")


# ---------------------------------------------------------------------------
# Observability-port integration
# ---------------------------------------------------------------------------


class ScrapeAdapter:
    """Render metrics for the observability port, refreshing first.

    The observability server calls get_metrics()/get_content_type() on
    each scrape, so refreshing here keeps every scrape current rather
    than serving whatever the 15s poll last left behind.
    """

    def get_metrics(self) -> bytes:
        update_metrics()
        assert _mgr is not None  # init_metrics sets it before handing out
        return _mgr.get_metrics()

    def get_content_type(self) -> str:
        assert _mgr is not None
        return _mgr.get_content_type()


def init_metrics(
    max_clients: int,
    protocol: str,
    otel_enabled: bool = False,
    otel_endpoint: str = "",
    otel_protocol: str = "grpc",
    otel_insecure: bool = False,
) -> ScrapeAdapter:
    """Initialise metrics collection.

    Sets up the MetricsManager (Prometheus or OTel backend), starts the
    background update loop, and returns the adapter the observability
    port serves /metrics from.
    """
    global _max_clients, _protocol
    _max_clients = max_clients
    _protocol = protocol

    _init_metrics(
        "culvert",
        otel_enabled=otel_enabled,
        otel_endpoint=otel_endpoint,
        otel_protocol=otel_protocol,
        otel_insecure=otel_insecure,
    )

    update_thread = threading.Thread(target=_metrics_update_loop, daemon=True)
    update_thread.start()

    return ScrapeAdapter()
