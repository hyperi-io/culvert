#  Project:      culvert
#  File:         wstunnel.py
#  Purpose:      wstunnel server startup for WireGuard DPI bypass
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
wstunnel DPI bypass for culvert WireGuard.

Tunnels WireGuard UDP over WebSocket/TLS on port 4443,
making traffic look like regular HTTPS.
"""

import subprocess

from scalo.logger import logger


def _build_wstunnel_command(cfg) -> list[str]:
    """Build the wstunnel server command for WireGuard DPI bypass.

    Serves WSS on the DPI-bypass port and restricts forwarding to the local
    WireGuard listener, so the tunnel can only reach wg, not arbitrary hosts.
    """
    return [
        "wstunnel",
        "server",
        f"wss://0.0.0.0:{cfg.wg_dpi_bypass_port}",
        "--restrict-to",
        f"127.0.0.1:{cfg.wg_port}",
        "--tls-certificate",
        cfg.stunnel_cert,
        "--tls-private-key",
        cfg.stunnel_key,
    ]


def start_wstunnel(cfg, proc_manager) -> subprocess.Popen | None:
    """Start the wstunnel server for WireGuard DPI bypass.

    Runs under ProcessManager supervision (daemon mode), which also routes
    its output to a log file instead of an undrained PIPE.
    """
    if not cfg.wg_dpi_bypass_enabled:
        return None

    logger.info(f"Starting wstunnel DPI bypass on port {cfg.wg_dpi_bypass_port}")
    return proc_manager.start("wstunnel", _build_wstunnel_command(cfg), daemon=True)
