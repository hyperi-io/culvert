#  Project:      hyperi-vpn
#  File:         test_health.py
#  Purpose:      Tests for health check server module
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import http.client
import json
import threading

import pytest
from lib.health import (
    HealthHandler,
    ready,
    started,
)


@pytest.fixture()
def health_server():
    """Start a health server on a random port for testing."""
    from http.server import HTTPServer

    server = HTTPServer(("127.0.0.1", 0), HealthHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


def _get(port: int, path: str) -> tuple[int, dict | str]:
    """Make GET request, return (status, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    try:
        return resp.status, json.loads(body)
    except json.JSONDecodeError:
        return resp.status, body


class TestHealthEndpoints:
    """Tests for health check HTTP endpoints."""

    def test_liveness_always_ok(self, health_server):
        """Liveness probe always returns 200."""
        status, body = _get(health_server, "/health/live")
        assert status == 200
        assert body["status"] == "ok"

    def test_readiness_503_when_not_ready(self, health_server):
        """Readiness returns 503 before ready event is set."""
        ready.clear()
        status, body = _get(health_server, "/health/ready")
        assert status == 503
        assert body["status"] == "not_ready"

    def test_readiness_200_when_ready(self, health_server):
        """Readiness returns 200 after ready event is set."""
        ready.set()
        status, body = _get(health_server, "/health/ready")
        assert status == 200
        assert body["status"] == "ready"
        ready.clear()

    def test_startup_503_when_not_started(self, health_server):
        """Startup returns 503 before started event is set."""
        started.clear()
        status, body = _get(health_server, "/health/startup")
        assert status == 503
        assert body["status"] == "starting"

    def test_startup_200_when_started(self, health_server):
        """Startup returns 200 after started event is set."""
        started.set()
        status, body = _get(health_server, "/health/startup")
        assert status == 200
        assert body["status"] == "started"
        started.clear()

    def test_404_on_unknown_path(self, health_server):
        """Unknown paths return 404."""
        status, _ = _get(health_server, "/unknown")
        assert status == 404

    def test_metrics_endpoint_returns_404(self, health_server):
        """Metrics endpoint moved to dedicated metrics server."""
        status, _ = _get(health_server, "/metrics")
        assert status == 404

    def test_readiness_transitions(self, health_server):
        """Ready flag toggles readiness response."""
        ready.clear()
        status1, _ = _get(health_server, "/health/ready")
        assert status1 == 503

        ready.set()
        status2, _ = _get(health_server, "/health/ready")
        assert status2 == 200

        ready.clear()
        status3, _ = _get(health_server, "/health/ready")
        assert status3 == 503
