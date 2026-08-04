#!/usr/bin/env python3
#  Project:      culvert
#  File:         entrypoint.py
#  Purpose:      Container entrypoint - thin orchestrator delegating to lib/ modules
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Culvert container entrypoint.

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

from lib.config import Config
from lib.download import start_client_download_server
from lib.health import health, set_protocol, start_observability
from lib.metrics import init_metrics
from lib.network import setup_forward_guards, setup_network, setup_routing_control
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
from scalo.logger import logger


def run_server(cfg: Config) -> None:
    """Run the VPN server (main command)."""
    proc_manager = ProcessManager()
    proc_manager.config = cfg

    # Infrastructure setup
    setup_directories(cfg)
    setup_log_rotation()
    setup_network(cfg)
    setup_routing_control(cfg)
    # LAST of the three: it inserts at FORWARD position 1, and it has to sit
    # above routing control's chain so a client cannot reach link-local through
    # an ACCEPT there.
    setup_forward_guards(cfg)

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
        start_oauth2(cfg, proc_manager)

    # WireGuard setup
    if cfg.protocol in ("wireguard", "both"):
        setup_wireguard(cfg)
        start_wireguard(cfg)
        start_wstunnel(cfg, proc_manager)
        start_wg_connection_monitor(cfg)

    # Observability: health always served; /metrics only when enabled
    set_protocol(cfg.protocol)

    metrics = None
    if cfg.metrics_enabled:
        # max_clients is resolved to an int in Config.__post_init__.
        assert cfg.max_clients is not None
        metrics = init_metrics(
            cfg.max_clients,
            cfg.protocol,
            otel_enabled=cfg.otel_enabled,
            otel_endpoint=cfg.otel_endpoint,
            otel_protocol=cfg.otel_protocol,
            otel_insecure=cfg.otel_insecure,
            pki_dir=str(cfg.pki_dir),
        )
    start_observability(cfg.metrics_addr, metrics)

    # Both PKI modes need this. External mode re-fetches rather than
    # regenerating, since the CA key that signs a CRL lives upstream.
    if cfg.crl_refresh_hours > 0 and cfg.protocol in ("openvpn", "both"):
        start_crl_refresh(cfg, proc_manager, cfg.crl_refresh_hours)

    if cfg.client_download_enabled:
        clients_dir = Path("/etc/vpn/clients")
        start_client_download_server(
            cfg.client_download_port,
            clients_dir,
            auth_token=cfg.client_download_token,
            bind=cfg.client_download_bind,
            tls_cert=cfg.client_download_tls_cert,
            tls_key=cfg.client_download_tls_key,
        )

    # Start VPN processes (blocks). start_server flips started/ready once
    # its listeners are launched; in WireGuard-only mode the kernel
    # interface is already up, so flip here before waiting.
    if cfg.protocol in ("openvpn", "both"):
        start_server(cfg, proc_manager)
    else:
        logger.info("WireGuard-only mode -- waiting for signals")
        health.set_started()
        health.set_ready()
        signal.pause()


def main() -> None:
    """Main entrypoint."""
    parser = argparse.ArgumentParser(description="Culvert entrypoint")
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
            # Probe the observability port (health + metrics share it).
            # int() keeps the URL authority fixed to localhost: a raw env
            # string could smuggle '@host' into the authority; a
            # non-numeric value just fails the probe via ValueError.
            addr = os.environ.get("CULVERT_METRICS_ADDR", "0.0.0.0:9090")
            health_port = int(addr.rsplit(":", 1)[-1]) if ":" in addr else 9090
            # Scheme, host, and (cast) port are fixed, so no file:// or
            # off-host reach is possible.
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            req = urllib.request.urlopen(
                f"http://localhost:{health_port}/livez", timeout=3
            )
            sys.exit(0 if req.status == 200 else 1)
        except Exception:
            sys.exit(1)

    # Load and validate configuration
    cfg = Config.from_settings()

    if args.command == "server":
        cfg.validate()
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
