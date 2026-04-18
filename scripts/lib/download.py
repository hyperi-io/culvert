#  Project:      hyperi-vpn
#  File:         download.py
#  Purpose:      Client config download HTTPS server
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Client config download server for dfe-vpn.

Provides a simple web interface for employees to download their
VPN .ovpn configuration files.
"""

import threading
from datetime import datetime
from http.server import HTTPServer
from pathlib import Path

from hyperi_pylib.logger import logger

from lib.health import BaseHandler


class ClientDownloadHandler(BaseHandler):
    """HTTP handler for downloading client .ovpn files."""

    clients_dir: Path = Path("/etc/vpn/clients")

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        if self.path in ("/", "/clients", "/clients/"):
            self._list_clients()
        elif self.path.startswith("/clients/") and self.path.endswith(".ovpn"):
            self._download_client()
        elif self.path == "/health":
            self.send_json({"status": "ok"})
        else:
            self.send_error(404, "Not Found")

    def _list_clients(self) -> None:
        """List available client configs."""
        if not self.clients_dir.exists():
            self.send_html(
                self._render_error("Clients directory not found"),
                503,
            )
            return

        ovpn_files = sorted(self.clients_dir.glob("*.ovpn"))

        if not ovpn_files:
            self.send_html(self._render_error("No client configs available"))
            return

        self.send_html(self._render_file_list(ovpn_files))

    def _download_client(self) -> None:
        """Download a specific client config."""
        filename = self.path.split("/")[-1]

        # Security: prevent path traversal
        if ".." in filename or "/" in filename:
            self.send_error(400, "Invalid filename")
            return

        file_path = self.clients_dir / filename

        if not file_path.exists():
            self.send_error(404, "Client config not found")
            return

        client_ip = self.client_address[0]
        logger.info(
            f"Client config downloaded: {filename}",
            client_ip=client_ip,
        )

        self.send_file(file_path)

    def _render_file_list(self, files: list[Path]) -> str:
        """Render HTML file listing."""
        file_rows = ""
        for f in files:
            stat = f.stat()
            size_kb = stat.st_size / 1024
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            file_rows += f"""
            <tr>
                <td><a href="/clients/{f.name}" class="download-link">{f.name}</a></td>
                <td>{size_kb:.1f} KB</td>
                <td>{mtime}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>VPN Client Downloads</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f8f8;
            font-weight: 600;
        }}
        .download-link {{
            color: #0066cc;
            text-decoration: none;
            font-weight: 500;
        }}
        .download-link:hover {{
            text-decoration: underline;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #888;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VPN Client Configurations</h1>
        <p class="subtitle">Download your OpenVPN configuration file</p>
        <table>
            <thead>
                <tr>
                    <th>Configuration File</th>
                    <th>Size</th>
                    <th>Modified</th>
                </tr>
            </thead>
            <tbody>
                {file_rows}
            </tbody>
        </table>
        <div class="footer">
            <p>Import the .ovpn file into your OpenVPN client application.</p>
        </div>
    </div>
</body>
</html>"""

    def _render_error(self, message: str) -> str:
        """Render HTML error page."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>VPN Client Downloads</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .error {{
            color: #cc0000;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VPN Client Downloads</h1>
        <p class="error">{message}</p>
    </div>
</body>
</html>"""


def start_client_download_server(port: int, clients_dir: Path) -> None:
    """Start client download HTTP server in background thread."""
    ClientDownloadHandler.clients_dir = clients_dir

    try:
        server = HTTPServer(("0.0.0.0", port), ClientDownloadHandler)
    except OSError as e:
        logger.error(f"Failed to start client download server on port {port}: {e}")
        raise

    logger.info(
        "Client download server started",
        port=port,
        clients_dir=str(clients_dir),
    )

    def run_server():
        try:
            server.serve_forever()
        except Exception as e:
            logger.error(f"Client download server error: {e}")

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
