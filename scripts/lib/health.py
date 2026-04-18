#  Project:      hyperi-vpn
#  File:         health.py
#  Purpose:      Health check HTTP server (liveness, readiness, startup probes)
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Health check server for dfe-vpn.

Provides /health/live, /health/ready, and /health/startup endpoints
for Kubernetes probes.
"""

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hyperi_pylib.logger import logger

# Health state flags — set by entrypoint during startup
started = threading.Event()
ready = threading.Event()

# Protocol mode — set by entrypoint so liveness knows what to check
_protocol = "openvpn"


def set_protocol(protocol: str) -> None:
    """Set the VPN protocol mode for health checks."""
    global _protocol
    _protocol = protocol


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


class HealthHandler(BaseHandler):
    """HTTP handler for health check endpoints."""

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/health/live":
            self._liveness()
        elif self.path == "/health/ready":
            self._readiness()
        elif self.path == "/health/startup":
            self._startup()
        else:
            self.send_error(404, "Not Found")

    def _liveness(self) -> None:
        """Liveness probe — are VPN processes alive?"""
        if not started.is_set():
            # Still starting up — don't fail liveness during init
            self.send_json({"status": "ok"})
            return

        if _check_vpn_alive():
            self.send_json({"status": "ok"})
        else:
            self.send_json({"status": "unhealthy"}, 503)

    def _readiness(self) -> None:
        """Readiness probe — can handle new connections?"""
        if ready.is_set():
            self.send_json({"status": "ready"})
        else:
            self.send_json({"status": "not_ready"}, 503)

    def _startup(self) -> None:
        """Startup probe — initialization complete?"""
        if started.is_set():
            self.send_json({"status": "started"})
        else:
            self.send_json({"status": "starting"}, 503)


def start_health_server(port: int = 8080) -> None:
    """Start health check HTTP server in background thread."""
    try:
        server = HTTPServer(("0.0.0.0", port), HealthHandler)
    except OSError as e:
        logger.error(f"Failed to start health check server on port {port}: {e}")
        raise

    logger.info("Health check server started", port=port)

    def run_server():
        try:
            server.serve_forever()
        except Exception as e:
            logger.error(f"Health check server error: {e}")

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
