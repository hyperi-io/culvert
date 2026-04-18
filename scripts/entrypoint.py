#!/usr/bin/env python3
#  Project:      hyperi-vpn
#  File:         entrypoint.py
#  Purpose:      Container entrypoint — thin orchestrator delegating to lib/ modules
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
DFE VPN Container Entrypoint.

Thin orchestrator that delegates to focused modules under lib/.
Handles container initialisation, PKI setup, and VPN server management.

Environment Variables:
    See README.md for full list of configuration options.
"""

import argparse
import os
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hyperi_pylib.logger import logger
from lib.config import Config
from lib.download import start_client_download_server
from lib.health import ready, set_protocol, start_health_server, started
from lib.metrics import start_metrics_server
from lib.network import setup_network
from lib.oauth2 import setup_oauth2, start_oauth2
from lib.openvpn import (
    auto_generate_clients,
    configure_server_https,
    configure_server_tcp,
    configure_server_udp,
    start_server,
)
from lib.pki import init_pki, start_crl_refresh
from lib.process import (
    ProcessManager,
    setup_directories,
    setup_log_rotation,
    setup_scripts,
)
from lib.stunnel import configure_stunnel
from lib.wireguard import setup_wireguard, start_wg_connection_monitor, start_wireguard
from lib.wstunnel import start_wstunnel


def run_server(cfg: Config) -> None:
    """Run the VPN server (main command)."""
    proc_manager = ProcessManager()
    proc_manager.config = cfg

    # Infrastructure setup
    setup_directories(cfg)
    setup_log_rotation()
    setup_network(cfg)

    # OpenVPN setup
    if cfg.protocol in ("openvpn", "both"):
        init_pki(cfg)
        configure_server_udp(cfg)
        configure_stunnel(cfg)
        configure_server_https(cfg)
        configure_server_tcp(cfg)
        setup_scripts(cfg)
        auto_generate_clients(cfg)
        setup_oauth2(cfg)
        start_oauth2(cfg)

    # WireGuard setup
    if cfg.protocol in ("wireguard", "both"):
        setup_wireguard(cfg)
        start_wireguard(cfg)
        wstunnel_proc = start_wstunnel(cfg)
        if wstunnel_proc:
            proc_manager.processes["wstunnel"] = wstunnel_proc
        start_wg_connection_monitor(cfg)

    # Background services
    set_protocol(cfg.protocol)

    if cfg.health_port > 0:
        start_health_server(cfg.health_port)

    if cfg.metrics_enabled and cfg.metrics_port > 0:
        start_metrics_server(
            cfg.metrics_port,
            cfg.max_clients,
            cfg.protocol,
            otel_enabled=cfg.otel_enabled,
            otel_endpoint=cfg.otel_endpoint,
            otel_protocol=cfg.otel_protocol,
            otel_insecure=cfg.otel_insecure,
        )

    if (
        cfg.crl_refresh_hours > 0
        and cfg.protocol in ("openvpn", "both")
        and cfg.pki_mode == "local"
    ):
        start_crl_refresh(cfg, proc_manager, cfg.crl_refresh_hours)

    if cfg.client_download_enabled:
        clients_dir = Path("/etc/vpn/clients")
        start_client_download_server(cfg.client_download_port, clients_dir)

    started.set()
    ready.set()

    # Start VPN processes (blocks)
    if cfg.protocol in ("openvpn", "both"):
        start_server(cfg, proc_manager)
    else:
        # WireGuard-only mode: kernel manages the interface, just wait
        logger.info("WireGuard-only mode -- waiting for signals")
        signal.pause()


def main() -> None:
    """Main entrypoint."""
    parser = argparse.ArgumentParser(description="DFE VPN Entrypoint")
    parser.add_argument(
        "command",
        nargs="?",
        default="server",
        choices=[
            "server",
            "init-pki-only",
            "generate-client",
            "revoke-client",
            "update-crl",
            "healthcheck",
            "shell",
        ],
        help="Command to run",
    )
    parser.add_argument("args", nargs="*", help="Command arguments")

    args = parser.parse_args()

    # Healthcheck runs without config loading (lightweight probe)
    if args.command == "healthcheck":
        import urllib.request

        try:
            health_port = os.environ.get("HYPERI_VPN_HEALTH_PORT", "8080")
            req = urllib.request.urlopen(
                f"http://localhost:{health_port}/health/live", timeout=3
            )
            sys.exit(0 if req.status == 200 else 1)
        except Exception:
            sys.exit(1)

    # Load and validate configuration
    cfg = Config.from_settings()

    if args.command == "server":
        run_server(cfg)

    elif args.command == "init-pki-only":
        setup_directories(cfg)
        init_pki(cfg)
        logger.info("PKI initialized. Exiting.")

    elif args.command == "generate-client":
        os.execvp(
            "/usr/local/bin/generate-client",
            ["/usr/local/bin/generate-client"] + args.args,
        )

    elif args.command == "revoke-client":
        os.execvp(
            "/usr/local/bin/revoke-client",
            ["/usr/local/bin/revoke-client"] + args.args,
        )

    elif args.command == "update-crl":
        os.execvp("/usr/local/bin/update-crl", ["/usr/local/bin/update-crl"])

    elif args.command == "shell":
        os.execvp("/bin/bash", ["/bin/bash"])


if __name__ == "__main__":
    main()
