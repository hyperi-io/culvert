#  Project:      hyperi-vpn
#  File:         stunnel.py
#  Purpose:      stunnel TLS wrapper configuration for HTTPS DPI bypass
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
stunnel configuration for dfe-vpn.

Generates stunnel config to terminate TLS on port 443 and forward
to OpenVPN on an internal port, making VPN traffic indistinguishable
from regular HTTPS.
"""

import os
from pathlib import Path

from hyperi_pylib.logger import logger

from lib.openvpn import generate_config


def configure_stunnel(cfg) -> None:
    """Configure stunnel for HTTPS tunneling."""
    if not cfg.https_enabled:
        return

    logger.info(
        f"Configuring stunnel"
        f" (TLS:{cfg.https_port}"
        f" -> OpenVPN:{cfg.https_internal_port})..."
    )

    template = cfg.server_https_conf.parent / "stunnel-server.conf.template"
    if not template.exists():
        logger.warning("stunnel template not found, skipping")
        return

    if not Path(cfg.stunnel_cert).exists():
        logger.warning(f"stunnel cert not found: {cfg.stunnel_cert}")
        logger.warning(
            "HTTPS tunnel will not work - mount TLS certs to /etc/vpn/oauth2-tls/"
        )
        return

    if not Path(cfg.stunnel_key).exists():
        logger.warning(f"stunnel key not found: {cfg.stunnel_key}")
        return

    variables = {
        "STUNNEL_CERT_PATH": cfg.stunnel_cert,
        "STUNNEL_KEY_PATH": cfg.stunnel_key,
        "OPENVPN_HTTPS_INTERNAL_PORT": cfg.https_internal_port,
    }

    generate_config(template, cfg.stunnel_conf, variables)

    # Create stunnel log file with proper permissions
    # (stunnel runs as nobody)
    stunnel_log = cfg.log_dir / "stunnel.log"
    stunnel_log.touch(exist_ok=True)
    os.chmod(stunnel_log, 0o666)

    logger.info(
        f"stunnel configured: port {cfg.https_port}"
        f" -> localhost:{cfg.https_internal_port}"
    )
