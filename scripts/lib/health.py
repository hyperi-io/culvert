#  Project:      culvert
#  File:         health.py
#  Purpose:      Health check HTTP server (liveness and readiness probes)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Health state and observability listener for culvert.

Uses scalo's HealthManager + observability server: ONE port (default
0.0.0.0:9090) serves /livez, /readyz and /metrics. That is the whole
surface - there is no startup route, so a startupProbe targets /livez
(Kubernetes suspends liveness until the startup probe passes).

BaseHandler stays here for the client download server, which serves
user-facing files and must not share the operator port.
"""

import json
import subprocess
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from scalo.health import HealthManager, serve_observability
from scalo.logger import logger

# Shared health state - the entrypoint marks set_started()/set_ready(),
# the observability server answers probes from it
health = HealthManager()

# Protocol mode - set by entrypoint so liveness knows what to check
_protocol = "openvpn"


def set_protocol(protocol: str) -> None:
    """Set the VPN protocol mode for health checks."""
    global _protocol
    _protocol = protocol


def _vpn_live() -> bool:
    """Liveness: pass while still initialising, then require VPN processes."""
    if not health.is_started():
        return True
    return _check_vpn_alive()


health.register_live_check("vpn", _vpn_live)


def start_observability(addr: str, metrics=None):
    """Serve health + metrics on the single observability port.

    ``metrics`` is any object with get_metrics()/get_content_type()
    (None -> /metrics answers 404, health still served).
    """
    server = serve_observability(health, metrics, addr)
    logger.info("Observability server started", addr=addr)
    return server


class BaseHandler(BaseHTTPRequestHandler):
    """Base HTTP handler with shared utilities."""

    def log_message(self, format: str, *args) -> None:
        """Suppress default access logging."""
        pass

    def send_json(self, data: dict, status: int = 200) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_text(
        self,
        text: str,
        content_type: str = "text/plain",
        status: int = 200,
    ) -> None:
        """Send text response."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(text.encode())

    def send_file(self, file_path: Path, filename: str | None = None) -> None:
        """Send file as download."""
        if not file_path.exists():
            self.send_error(404, "File not found")
            return

        content = file_path.read_bytes()
        download_name = filename or file_path.name

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{download_name}"',
        )
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def send_html(self, html: str, status: int = 200) -> None:
        """Send HTML response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())


def _check_openvpn() -> bool:
    """Check if at least one OpenVPN process is running."""
    result = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True)
    return result.returncode == 0


def _check_wireguard() -> bool:
    """Check if wg0 interface exists and has a listening port."""
    result = subprocess.run(
        ["ip", "link", "show", "wg0"],
        capture_output=True,
    )
    return result.returncode == 0


def _check_vpn_alive() -> bool:
    """Check VPN processes are alive based on protocol mode."""
    if _protocol == "openvpn":
        return _check_openvpn()
    if _protocol == "wireguard":
        return _check_wireguard()
    # both
    return _check_openvpn() and _check_wireguard()
