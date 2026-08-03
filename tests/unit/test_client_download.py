#  Project:      culvert
#  File:         test_client_download.py
#  Purpose:      Test client download HTTP server
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for ClientDownloadHandler and BaseHandler.

Tests the HTTP server functionality for serving VPN client configs.
Uses real HTTP requests against a test server - no mocking of internals.
"""

import http.client
import socket
import ssl
import subprocess
import threading
from http.server import HTTPServer

import pytest
from lib.download import ClientDownloadHandler, start_client_download_server
from lib.health import BaseHandler


class TestBaseHandler:
    """Tests for BaseHandler shared utilities."""

    @pytest.fixture
    def handler_class(self):
        """Create a test handler class that exercises BaseHandler methods."""

        class TestHandler(BaseHandler):
            def do_GET(self):  # noqa: N802
                if self.path == "/json":
                    self.send_json({"status": "ok", "count": 42})
                elif self.path == "/json-error":
                    self.send_json({"error": "not found"}, status=404)
                elif self.path == "/text":
                    self.send_text("Hello, World!")
                elif self.path == "/html":
                    self.send_html("<h1>Test</h1>")
                elif self.path == "/html-error":
                    self.send_html("<h1>Error</h1>", status=500)
                else:
                    self.send_error(404)

        return TestHandler

    @pytest.fixture
    def test_server(self, handler_class):
        """Start a test HTTP server."""
        server = HTTPServer(("127.0.0.1", 0), handler_class)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield port
        server.shutdown()

    def test_send_json_success(self, test_server):
        """send_json() returns JSON with correct content-type."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/json")
        response = conn.getresponse()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/json"
        body = response.read().decode()
        assert '"status": "ok"' in body
        assert '"count": 42' in body
        conn.close()

    def test_send_json_with_status(self, test_server):
        """send_json() respects custom status code."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/json-error")
        response = conn.getresponse()

        assert response.status == 404
        assert response.getheader("Content-Type") == "application/json"
        conn.close()

    def test_send_text(self, test_server):
        """send_text() returns plain text."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/text")
        response = conn.getresponse()

        assert response.status == 200
        assert response.getheader("Content-Type") == "text/plain"
        assert response.read().decode() == "Hello, World!"
        conn.close()

    def test_send_html(self, test_server):
        """send_html() returns HTML with correct content-type."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/html")
        response = conn.getresponse()

        assert response.status == 200
        assert "text/html" in (response.getheader("Content-Type") or "")
        assert response.read().decode() == "<h1>Test</h1>"
        conn.close()

    def test_send_html_with_status(self, test_server):
        """send_html() respects custom status code."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/html-error")
        response = conn.getresponse()

        assert response.status == 500
        conn.close()


class TestClientDownloadHandler:
    """Tests for ClientDownloadHandler VPN config server."""

    @pytest.fixture
    def clients_dir(self, temp_dir):
        """Create a mock clients directory with test .ovpn files."""
        clients = temp_dir / "clients"
        clients.mkdir()

        # Create test .ovpn files
        (clients / "user1-udp.ovpn").write_text(
            "client\nremote vpn.example.com 1194 udp\n"
        )
        (clients / "user1-tcp.ovpn").write_text(
            "client\nremote vpn.example.com 443 tcp\n"
        )
        (clients / "user2-udp.ovpn").write_text(
            "client\nremote vpn.example.com 1194 udp\n"
        )

        return clients

    @pytest.fixture
    def test_server(self, clients_dir):
        """Start ClientDownloadHandler test server."""
        # Set class-level config
        ClientDownloadHandler.clients_dir = clients_dir

        server = HTTPServer(("127.0.0.1", 0), ClientDownloadHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield port
        server.shutdown()

    def test_list_clients_root(self, test_server):
        """GET / returns HTML file listing."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/")
        response = conn.getresponse()

        assert response.status == 200
        assert "text/html" in (response.getheader("Content-Type") or "")

        body = response.read().decode()
        assert "VPN Client Configurations" in body
        assert "user1-udp.ovpn" in body
        assert "user1-tcp.ovpn" in body
        assert "user2-udp.ovpn" in body
        conn.close()

    def test_list_clients_path(self, test_server):
        """GET /clients/ returns HTML file listing."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/")
        response = conn.getresponse()

        assert response.status == 200
        body = response.read().decode()
        assert "user1-udp.ovpn" in body
        conn.close()

    def test_download_client_file(self, test_server):
        """GET /clients/user1-udp.ovpn downloads the file."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/user1-udp.ovpn")
        response = conn.getresponse()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/octet-stream"
        assert "attachment" in (response.getheader("Content-Disposition") or "")
        assert "user1-udp.ovpn" in (response.getheader("Content-Disposition") or "")

        body = response.read().decode()
        assert "client" in body
        assert "remote vpn.example.com 1194 udp" in body
        conn.close()

    def test_download_nonexistent_file(self, test_server):
        """GET /clients/nonexistent.ovpn returns 404."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/nonexistent.ovpn")
        response = conn.getresponse()

        assert response.status == 404
        conn.close()

    def test_health_endpoint(self, test_server):
        """GET /health returns JSON status."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/health")
        response = conn.getresponse()

        assert response.status == 200
        assert response.getheader("Content-Type") == "application/json"
        body = response.read().decode()
        assert '"status": "ok"' in body
        conn.close()

    def test_404_unknown_path(self, test_server):
        """GET /unknown returns 404."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/unknown")
        response = conn.getresponse()

        assert response.status == 404
        conn.close()

    def test_path_traversal_dotdot(self, test_server):
        """Path traversal with .. is rejected."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/../../../etc/passwd")
        response = conn.getresponse()

        # Should be 400 (invalid filename) or 404
        assert response.status in (400, 404)
        conn.close()

    def test_path_traversal_encoded(self, test_server):
        """Path traversal attempts in filename are rejected."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/..%2F..%2Fetc%2Fpasswd.ovpn")
        response = conn.getresponse()

        # The handler checks for ".." in filename, should reject or 404
        assert response.status in (400, 404)
        conn.close()


class TestClientDownloadAuth:
    """Bearer-token auth: required when configured, /health exempt, fail-closed."""

    TOKEN = "test-token-xyz"

    @pytest.fixture
    def clients_dir(self, temp_dir):
        clients = temp_dir / "clients"
        clients.mkdir()
        (clients / "alice-udp-split.ovpn").write_text("client\n")
        return clients

    @pytest.fixture
    def test_server(self, clients_dir):
        ClientDownloadHandler.clients_dir = clients_dir
        ClientDownloadHandler.auth_token = self.TOKEN
        server = HTTPServer(("127.0.0.1", 0), ClientDownloadHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield port
        server.shutdown()
        # Reset class attr so other test classes run in no-auth mode.
        ClientDownloadHandler.auth_token = ""

    def test_listing_requires_token(self, test_server):
        """GET / without a token is rejected with 401."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/")
        assert conn.getresponse().status == 401
        conn.close()

    def test_download_requires_token(self, test_server):
        """Downloading a config without a token is rejected with 401."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/clients/alice-udp-split.ovpn")
        assert conn.getresponse().status == 401
        conn.close()

    def test_valid_token_allows_download(self, test_server):
        """A correct Bearer token grants access."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request(
            "GET",
            "/clients/alice-udp-split.ovpn",
            headers={"Authorization": f"Bearer {self.TOKEN}"},
        )
        assert conn.getresponse().status == 200
        conn.close()

    def test_wrong_token_rejected(self, test_server):
        """A wrong Bearer token is rejected with 401."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/", headers={"Authorization": "Bearer nope"})
        assert conn.getresponse().status == 401
        conn.close()

    def test_health_skips_auth(self, test_server):
        """/health stays reachable without a token (liveness probes)."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/health")
        assert conn.getresponse().status == 200
        conn.close()


class TestStartServerFailClosed:
    """The server refuses to start without an auth token."""

    def test_start_refuses_without_token(self, temp_dir):
        from lib.download import start_client_download_server

        with pytest.raises(ValueError, match="(?i)token"):
            start_client_download_server(0, temp_dir, auth_token="")


class TestClientDownloadHandlerEmptyDir:
    """Tests for ClientDownloadHandler with empty clients directory."""

    @pytest.fixture
    def empty_clients_dir(self, temp_dir):
        """Create an empty clients directory."""
        clients = temp_dir / "clients"
        clients.mkdir()
        return clients

    @pytest.fixture
    def test_server(self, empty_clients_dir):
        """Start ClientDownloadHandler with empty directory."""
        ClientDownloadHandler.clients_dir = empty_clients_dir

        server = HTTPServer(("127.0.0.1", 0), ClientDownloadHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield port
        server.shutdown()

    def test_empty_dir_message(self, test_server):
        """Empty clients directory shows helpful message."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/")
        response = conn.getresponse()

        assert response.status == 200
        body = response.read().decode()
        assert "No client configs available" in body
        conn.close()


class TestClientDownloadHandlerMissingDir:
    """Tests for ClientDownloadHandler with missing clients directory."""

    @pytest.fixture
    def test_server(self, temp_dir):
        """Start ClientDownloadHandler pointing to nonexistent directory."""
        ClientDownloadHandler.clients_dir = temp_dir / "nonexistent"

        server = HTTPServer(("127.0.0.1", 0), ClientDownloadHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        yield port
        server.shutdown()

    def test_missing_dir_error(self, test_server):
        """Missing clients directory returns error."""
        conn = http.client.HTTPConnection("127.0.0.1", test_server)
        conn.request("GET", "/")
        response = conn.getresponse()

        assert response.status == 503
        body = response.read().decode()
        assert "Clients directory not found" in body
        conn.close()


class TestDownloadServerTlsFloor:
    """The TLS listener must refuse anything below 1.3.

    Exercised through a real handshake rather than by reading the context back:
    what matters is what a client can actually negotiate. The negative case is
    the point - a 1.2-capped client has to be REFUSED, because without a stated
    floor PROTOCOL_TLS_SERVER inherits the platform OpenSSL's default and will
    serve .ovpn files, client private key included, over it.
    """

    @pytest.fixture
    def tls_server(self, temp_dir):
        """Start the real download server on a self-signed cert."""
        cert, key = temp_dir / "server.pem", temp_dir / "server.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        # Claim an ephemeral port and hand the number over: the server takes a
        # fixed port and returns nothing, so there is no way to learn one it
        # chose itself.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        clients = temp_dir / "tls-clients"
        clients.mkdir()
        start_client_download_server(
            port=port,
            clients_dir=clients,
            auth_token="test-token",
            tls_cert=str(cert),
            tls_key=str(key),
        )
        return port

    @staticmethod
    def _handshake(port: int, max_version: ssl.TLSVersion | None) -> str | None:
        """Negotiated TLS version, or None if the server refused."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if max_version is not None:
            ctx.maximum_version = max_version
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                    return tls.version()
        except ssl.SSLError:
            return None

    def test_tls12_client_is_refused(self, tls_server):
        """A client that cannot do 1.3 gets no connection at all."""
        assert self._handshake(tls_server, ssl.TLSVersion.TLSv1_2) is None, (
            "the server accepted TLS 1.2, so the download endpoint would hand"
            " client private keys over a connection weaker than the one the"
            " README promises"
        )

    def test_tls13_client_connects(self, tls_server):
        """The floor is a floor, not a wall - 1.3 still works."""
        assert self._handshake(tls_server, None) == "TLSv1.3"
