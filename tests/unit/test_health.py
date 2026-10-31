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

import lib.health as lib_health
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
    """The single port serves /livez, /readyz and /metrics - nothing else."""

    def test_liveness_ok_before_started(self, obs_server):
        """Liveness passes during init (VPN processes not yet expected)."""
        status, body = _get(obs_server, "/livez")
        assert status == 200
        assert body["status"] == "alive"

    def test_readiness_503_when_not_ready(self, obs_server):
        status, body = _get(obs_server, "/readyz")
        assert status == 503
        assert body["status"] == "not_ready"

    def test_readiness_200_when_ready(self, obs_server):
        health.set_ready()
        status, body = _get(obs_server, "/readyz")
        assert status == 200
        assert body["status"] == "ready"

    @pytest.mark.parametrize(
        "path",
        ["/healthz", "/health/live", "/health/ready", "/health/startup"],
    )
    def test_retired_paths_404(self, obs_server, path):
        """A retired probe path must 404, not quietly keep answering 200.

        An alias that still answers lets a chart probe a name the app no
        longer serves, and the mismatch stays invisible until something
        else breaks.
        """
        status, _ = _get(obs_server, path)
        assert status == 404

    def test_startup_state_readable_without_a_route(self, obs_server):
        """Startup has no endpoint of its own; the state lives on the manager."""
        assert health.is_started() is False
        health.set_started()
        assert health.is_started() is True

    def test_liveness_200_once_started_with_vpn_alive(self, obs_server, monkeypatch):
        """After set_started, liveness reflects the VPN process check."""
        monkeypatch.setattr(lib_health, "_check_vpn_alive", lambda: True)
        health.set_started()
        status, body = _get(obs_server, "/livez")
        assert status == 200
        assert body["status"] == "alive"

    def test_liveness_503_once_started_with_vpn_dead(self, obs_server, monkeypatch):
        """A dead VPN after startup must fail liveness so the pod restarts."""
        monkeypatch.setattr(lib_health, "_check_vpn_alive", lambda: False)
        health.set_started()
        status, body = _get(obs_server, "/livez")
        assert status == 503
        assert body["status"] == "not_alive"

    def test_404_on_unknown_path(self, obs_server):
        status, _ = _get(obs_server, "/unknown")
        assert status == 404

    def test_metrics_404_when_not_configured(self, obs_server):
        """Metrics are opt-in: no manager wired -> /metrics answers 404."""
        status, _ = _get(obs_server, "/metrics")
        assert status == 404

    def test_readiness_transitions(self, obs_server):
        status1, _ = _get(obs_server, "/readyz")
        assert status1 == 503

        health.set_ready()
        status2, _ = _get(obs_server, "/readyz")
        assert status2 == 200

        health.set_ready(False)
        status3, _ = _get(obs_server, "/readyz")
        assert status3 == 503


class TestChildSupervision:
    """One dead child fails liveness, however many others are still running."""

    CHILDREN = [
        "openvpn-udp",
        "openvpn-tcp",
        "openvpn-https",
        "stunnel",
        "wstunnel",
        "oauth2-udp",
    ]

    @pytest.fixture
    def supervised(self, manager, monkeypatch):
        """A manager holding one live child per name, wired into liveness."""
        monkeypatch.setattr(lib_health, "_children", manager)
        monkeypatch.setattr(lib_health, "_check_vpn_alive", lambda: True)
        for name in self.CHILDREN:
            manager.start(name, ["sleep", "30"], daemon=True)
        health.set_started()
        yield manager
        health.set_started(False)
        health.set_ready(False)

    def test_all_children_up_is_alive(self, supervised):
        assert lib_health._vpn_live() is True

    @pytest.mark.parametrize("dead", CHILDREN)
    def test_any_one_child_dying_fails_liveness(self, supervised, dead):
        supervised.processes[dead].kill()
        supervised.processes[dead].wait(timeout=10)
        assert lib_health._vpn_live() is False

    def test_a_child_that_never_started_fails_liveness(self, supervised):
        supervised.start("wstunnel", ["/nonexistent/binary/xyz123"], daemon=True)
        assert lib_health._vpn_live() is False

    def test_mark_serving_is_ready_only_with_every_child_up(self, supervised):
        assert lib_health.mark_serving(supervised) is True
        assert health.is_ready() is True

    def test_mark_serving_stays_not_ready_after_a_failed_start(self, supervised):
        health.set_ready(False)
        supervised.start("stunnel", ["/nonexistent/binary/xyz123"], daemon=True)
        assert lib_health.mark_serving(supervised) is False
        assert health.is_started() is True
        assert health.is_ready() is False


class TestVpnChecksWithoutTheirTools:
    """A host missing pgrep or iproute2 reads as VPN down, never an exception."""

    @pytest.mark.parametrize("check", ["_check_openvpn", "_check_wireguard"])
    def test_missing_binary_reads_as_down(self, monkeypatch, check):
        def missing(*_args: Any, **_kwargs: Any) -> None:
            raise FileNotFoundError(2, "No such file or directory")

        monkeypatch.setattr(lib_health.subprocess, "run", missing)
        assert getattr(lib_health, check)() is False


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
