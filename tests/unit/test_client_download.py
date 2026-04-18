#  Project:      hyperi-vpn
#  File:         test_client_download.py
#  Purpose:      Test client download HTTP server
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for ClientDownloadHandler and BaseHandler.

Tests the HTTP server functionality for serving VPN client configs.
Uses real HTTP requests against a test server - no mocking of internals.
"""

import http.client
import threading
from http.server import HTTPServer

import pytest
from lib.download import ClientDownloadHandler
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
        assert "text/html" in response.getheader("Content-Type")
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
        assert "text/html" in response.getheader("Content-Type")

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
        assert "attachment" in response.getheader("Content-Disposition")
        assert "user1-udp.ovpn" in response.getheader("Content-Disposition")

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
