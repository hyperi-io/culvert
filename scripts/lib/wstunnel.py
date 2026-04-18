#  Project:      hyperi-vpn
#  File:         wstunnel.py
#  Purpose:      wstunnel server startup for WireGuard DPI bypass
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
wstunnel DPI bypass for dfe-vpn WireGuard.

Tunnels WireGuard UDP over WebSocket/TLS on port 4443,
making traffic look like regular HTTPS.
"""

import subprocess

from hyperi_pylib.logger import logger


def start_wstunnel(cfg) -> subprocess.Popen | None:
    """Start wstunnel server for WireGuard DPI bypass."""
    if not cfg.wg_dpi_bypass_enabled:
        return None

    logger.info(f"Starting wstunnel DPI bypass on port {cfg.wg_dpi_bypass_port}")

    tls_cert = cfg.stunnel_cert
    tls_key = cfg.stunnel_key

    cmd = [
        "wstunnel",
        "server",
        f"wss://0.0.0.0:{cfg.wg_dpi_bypass_port}",
        "--restrict-to",
        f"127.0.0.1:{cfg.wg_port}",
        "--tls-certificate",
        tls_cert,
        "--tls-private-key",
        tls_key,
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    logger.info(f"wstunnel started (PID {process.pid})")
    return process
