#  Project:      culvert
#  File:         test_entrypoint_healthcheck.py
#  Purpose:      Tests for the entrypoint `healthcheck` command probe
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for entrypoint.py's `healthcheck` command.

Exercises the real probe (http.client.HTTPConnection against a local
listener) rather than mocking the HTTP call - no mocks for this surface.
"""

import contextlib
import http.server
import importlib
import socket
import threading

import pytest


@contextlib.contextmanager
def _livez_server(status: int = 200):
    """Serve a single /livez route on an ephemeral 127.0.0.1 port."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/livez":
                self.send_response(status)
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args) -> None:
            pass  # silence request logging during tests

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _free_closed_port() -> int:
    """Return a port with nothing listening on it (bind then release)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _run_healthcheck(monkeypatch, addr: str) -> int:
    """Invoke entrypoint.py's `healthcheck` command, return its exit code."""
    entrypoint = importlib.import_module("entrypoint")
    monkeypatch.setenv("CULVERT_METRICS_ADDR", addr)
    monkeypatch.setattr("sys.argv", ["entrypoint", "healthcheck"])
    with pytest.raises(SystemExit) as exc_info:
        entrypoint.main()
    code = exc_info.value.code
    assert isinstance(code, int), f"expected an int exit code, got {code!r}"
    return code


class TestEntrypointHealthcheck:
    """entrypoint.py `healthcheck` probes /livez on the observability port."""

    def test_200_exits_zero(self, monkeypatch, clean_env):
        with _livez_server(200) as port:
            code = _run_healthcheck(monkeypatch, f"127.0.0.1:{port}")
        assert code == 0

    def test_503_exits_one(self, monkeypatch, clean_env):
        with _livez_server(503) as port:
            code = _run_healthcheck(monkeypatch, f"127.0.0.1:{port}")
        assert code == 1

    def test_closed_port_exits_one(self, monkeypatch, clean_env):
        port = _free_closed_port()
        code = _run_healthcheck(monkeypatch, f"127.0.0.1:{port}")
        assert code == 1

    def test_non_numeric_port_exits_one(self, monkeypatch, clean_env):
        code = _run_healthcheck(monkeypatch, "127.0.0.1:not-a-port")
        assert code == 1

    def test_userinfo_authority_still_probes_localhost(self, monkeypatch, clean_env):
        """A 'user@host:port' CULVERT_METRICS_ADDR still only reaches localhost."""
        with _livez_server(200) as port:
            code = _run_healthcheck(monkeypatch, f"attacker@evil.example:{port}")
        assert code == 0
