#  Project:      hyperi-vpn
#  File:         network.py
#  Purpose:      Network setup: iptables, IP forwarding, CIDR utilities
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Network configuration for dfe-vpn container.

Handles iptables NAT rules, IP forwarding, and CIDR utilities.
"""

import ipaddress

from hyperi_pylib.logger import logger

from lib.process import run


def setup_network(cfg) -> None:
    """Configure iptables and IP forwarding."""
    logger.info("Configuring network (iptables, forwarding)...")

    # IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() == "1":
                logger.info("IP forwarding already enabled on host")
            else:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                logger.info("IP forwarding enabled")
    except OSError:
        logger.warning(
            "Cannot enable IP forwarding - ensure host has net.ipv4.ip_forward=1"
        )

    # Detect outbound interface
    result = run(
        "ip route get 1.1.1.1 | awk '{print $5; exit}'",
        capture=True,
    )
    iface = result.stdout.strip() or "eth0"

    # NAT rules
    if cfg.udp_enabled:
        run(
            f"iptables -t nat -A POSTROUTING"
            f" -s {cfg.udp_network}/24 -o {iface} -j MASQUERADE",
            check=False,
        )
        logger.info("UDP NAT rule added")

    if cfg.https_enabled:
        run(
            f"iptables -t nat -A POSTROUTING"
            f" -s {cfg.https_network}/24 -o {iface} -j MASQUERADE",
            check=False,
        )
        logger.info("HTTPS NAT rule added")

    if cfg.tcp_enabled:
        run(
            f"iptables -t nat -A POSTROUTING"
            f" -s {cfg.tcp_network}/24 -o {iface} -j MASQUERADE",
            check=False,
        )
        logger.info("TCP NAT rule added")

    logger.info(f"Network configured (NAT via {iface})")


def cidr_to_netmask(prefix: int) -> str:
    """Convert CIDR prefix to netmask."""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
