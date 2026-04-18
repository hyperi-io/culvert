#  Project:      hyperi-vpn
#  File:         metrics.py
#  Purpose:      DFE-standard metrics via hyperi-pylib (Prometheus + OTel)
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Metrics collection for dfe-vpn.

Uses hyperi-pylib MetricsManager for dual Prometheus/OTel export.
When OTel is configured, the same metrics push via OTLP AND serve on
the Prometheus /metrics endpoint. When OTel is not configured, only
Prometheus scrape is available.

Parses OpenVPN status files and WireGuard show output to collect
connection metrics.
"""

import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import HTTPServer
from pathlib import Path

from hyperi_pylib.logger import logger
from hyperi_pylib.metrics import create_metrics

from lib.health import BaseHandler

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
# Parsers (non-fragile — skip malformed lines, never crash)
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

# Module-level state — set by start_metrics_server
_mgr = None
_max_clients: int = 100
_protocol: str = "openvpn"

# Metric handles (set during init)
_g_openvpn_up = None
_g_wireguard_up = None
_g_connected = None
_g_connected_total = None
_c_bytes_rx = None
_c_bytes_tx = None
_g_utilisation = None
_g_max_clients = None


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


def update_metrics() -> None:
    """Collect current VPN state and update all metric values."""
    if _mgr is None:
        return

    total_clients = 0
    total_rx = 0
    total_tx = 0

    # OpenVPN
    if _protocol in ("openvpn", "both"):
        from lib.health import _check_openvpn

        try:
            _g_openvpn_up.set(1 if _check_openvpn() else 0)
        except Exception:
            pass

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
                try:
                    _g_connected.labels(
                        listener=listener_name,
                        protocol="openvpn",
                    ).set(status.client_count)
                except Exception:
                    pass

    # WireGuard
    if _protocol in ("wireguard", "both"):
        from lib.health import _check_wireguard

        try:
            _g_wireguard_up.set(1 if _check_wireguard() else 0)
        except Exception:
            pass

        wg_peers = _collect_wg_peer_count()
        total_clients += wg_peers
        try:
            _g_connected.labels(listener="wg0", protocol="wireguard").set(wg_peers)
        except Exception:
            pass

        wg_rx, wg_tx = _collect_wg_transfer()
        total_rx += wg_rx
        total_tx += wg_tx

    # Totals
    try:
        _g_connected_total.set(total_clients)
        _g_max_clients.set(_max_clients)
        utilisation = total_clients / _max_clients if _max_clients > 0 else 0
        _g_utilisation.set(utilisation)
    except Exception:
        pass


def _metrics_update_loop(interval: int = 15) -> None:
    """Background loop that periodically updates metrics."""
    while True:
        time.sleep(interval)
        try:
            update_metrics()
        except Exception as e:
            logger.warning(f"Metrics update error: {e}")


# ---------------------------------------------------------------------------
# HTTP server for /metrics endpoint
# ---------------------------------------------------------------------------


class MetricsHandler(BaseHandler):
    """HTTP handler for Prometheus /metrics endpoint."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/metrics":
            # Collect fresh metrics before serving
            update_metrics()
            if _mgr is not None:
                text = _mgr.get_metrics_text()
                self.send_text(text, _mgr.get_content_type())
            else:
                self.send_text("", "text/plain; version=0.0.4")
        else:
            self.send_error(404, "Not Found")


def start_metrics_server(
    port: int,
    max_clients: int,
    protocol: str,
    otel_enabled: bool = False,
    otel_endpoint: str = "",
    otel_protocol: str = "grpc",
    otel_insecure: bool = False,
) -> None:
    """Start metrics collection and HTTP server.

    Initialises MetricsManager with the appropriate backend
    (Prometheus or OpenTelemetry) and starts:
    - A background update loop (15s interval)
    - An HTTP server on the given port for /metrics
    """
    global _max_clients, _protocol
    _max_clients = max_clients
    _protocol = protocol

    _init_metrics(
        "dfe_vpn",
        otel_enabled=otel_enabled,
        otel_endpoint=otel_endpoint,
        otel_protocol=otel_protocol,
        otel_insecure=otel_insecure,
    )

    # Start background update loop
    update_thread = threading.Thread(target=_metrics_update_loop, daemon=True)
    update_thread.start()

    # Start HTTP server
    try:
        server = HTTPServer(("0.0.0.0", port), MetricsHandler)
    except OSError as e:
        logger.error(f"Failed to start metrics server on port {port}: {e}")
        raise

    logger.info("Metrics server started", port=port)

    def run_server():
        try:
            server.serve_forever()
        except Exception as e:
            logger.error(f"Metrics server error: {e}")

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
