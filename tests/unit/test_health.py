#  Project:      culvert
#  File:         test_health.py
#  Purpose:      Tests for the observability listener (health + metrics port)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import http.client
import json
from typing import Any

import pytest
from lib.health import health, start_observability


@pytest.fixture()
def obs_server():
    """Start the observability server on an ephemeral port, reset state."""
    health.set_started(False)
    health.set_ready(False)
    server = start_observability("127.0.0.1:0")
    _, port = server.bound_address
    yield port
    server.stop()
    health.set_started(False)
    health.set_ready(False)


def _get(port: int, path: str) -> tuple[int, Any]:
    """Make GET request, return (status, parsed-JSON-or-text body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    try:
        return resp.status, json.loads(body)
    except json.JSONDecodeError:
        return resp.status, body


class TestObservabilityEndpoints:
    """The single port serves probes on canonical routes AND aliases."""

    def test_liveness_ok_before_started(self, obs_server):
        """Liveness passes during init (VPN processes not yet expected)."""
        status, body = _get(obs_server, "/health/live")
        assert status == 200
        assert body["status"] == "alive"

    def test_liveness_canonical_healthz(self, obs_server):
        status, _ = _get(obs_server, "/healthz")
        assert status == 200

    def test_readiness_503_when_not_ready(self, obs_server):
        status, body = _get(obs_server, "/health/ready")
        assert status == 503
        assert body["status"] == "not_ready"

    def test_readiness_200_when_ready(self, obs_server):
        health.set_ready()
        status, body = _get(obs_server, "/readyz")
        assert status == 200
        assert body["status"] == "ready"

    def test_startup_503_when_not_started(self, obs_server):
        status, body = _get(obs_server, "/health/startup")
        assert status == 503
        assert body["status"] == "starting"

    def test_startup_200_when_started(self, obs_server):
        health.set_started()
        status, body = _get(obs_server, "/health/startup")
        assert status == 200
        assert body["status"] == "started"

    def test_404_on_unknown_path(self, obs_server):
        status, _ = _get(obs_server, "/unknown")
        assert status == 404

    def test_metrics_404_when_not_configured(self, obs_server):
        """Metrics are opt-in: no manager wired -> /metrics answers 404."""
        status, _ = _get(obs_server, "/metrics")
        assert status == 404

    def test_readiness_transitions(self, obs_server):
        status1, _ = _get(obs_server, "/health/ready")
        assert status1 == 503

        health.set_ready()
        status2, _ = _get(obs_server, "/health/ready")
        assert status2 == 200

        health.set_ready(False)
        status3, _ = _get(obs_server, "/health/ready")
        assert status3 == 503


class TestMetricsOnObservabilityPort:
    """A wired metrics object is served from the same port."""

    def test_metrics_served_when_configured(self):
        class FakeMetrics:
            def get_metrics(self):
                return b"vpn_up 1\n"

            def get_content_type(self):
                return "text/plain; version=0.0.4"

        server = start_observability("127.0.0.1:0", FakeMetrics())
        try:
            _, port = server.bound_address
            status, body = _get(port, "/metrics")
            assert status == 200
            assert "vpn_up 1" in body
        finally:
            server.stop()
