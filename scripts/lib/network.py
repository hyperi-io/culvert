#  Project:      culvert
#  File:         network.py
#  Purpose:      Network setup: iptables, IP forwarding, CIDR utilities
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Network configuration for culvert container.

Handles iptables NAT rules, IP forwarding, and CIDR utilities.
"""

import ipaddress
import subprocess

from scalo.logger import logger

from lib.process import run


class FirewallError(RuntimeError):
    """A required iptables rule could not be installed."""


def _add_rule(rule: str, purpose: str) -> None:
    """Install an iptables rule, refusing to continue if it does not land.

    These rules are not advisory. Routing control is what enforces client
    isolation, the egress allow-list and the downstream-admin gate; the NAT
    rules are what let a client reach anything at all. A rule that fails to
    install silently removes the behaviour the operator asked for, so this
    raises: the container exits rather than serving clients while reporting a
    control it only appears to have.

    Callers use it for -A and -I. -N and -D are expected to fail (chain already
    present, rule not present) and stay tolerant.
    """
    try:
        run(f"iptables {rule}")
    except subprocess.CalledProcessError as exc:
        raise FirewallError(
            f"iptables {rule} failed (exit {exc.returncode}); this rule"
            f" implements {purpose}, so refusing to start without it."
        ) from exc


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

    # NAT rules - prefix length derived from the configured netmask so the
    # masqueraded range always matches what OpenVPN hands out.
    listeners = [
        (cfg.udp_enabled, "UDP", cfg.udp_network, cfg.udp_netmask),
        (cfg.https_enabled, "HTTPS", cfg.https_network, cfg.https_netmask),
        (cfg.tcp_enabled, "TCP", cfg.tcp_network, cfg.tcp_netmask),
    ]
    for enabled, name, network, netmask in listeners:
        if not enabled:
            continue
        prefix = _prefixlen(network, netmask)
        _add_rule(
            f"-t nat -A POSTROUTING -s {network}/{prefix} -o {iface} -j MASQUERADE",
            f"NAT for the {name} tunnel subnet",
        )
        logger.info(f"{name} NAT rule added")

    # WireGuard needs the same rule. Its subnet is already a CIDR, and wg-quick
    # adds no NAT of its own unless the operator supplies a PostUp - so without
    # this a WireGuard client completes its handshake and then reaches nothing
    # off the server, which looks like a client problem and is not.
    if cfg.protocol in ("wireguard", "both"):
        _add_rule(
            f"-t nat -A POSTROUTING -s {cfg.wg_network} -o {iface} -j MASQUERADE",
            "NAT for the WireGuard subnet",
        )
        logger.info("WireGuard NAT rule added")

    logger.info(f"Network configured (NAT via {iface})")


def _vpn_interfaces(cfg) -> list[str]:
    """Kernel interfaces carrying client tunnels for the active protocol."""
    ifaces = []
    if cfg.protocol in ("openvpn", "both"):
        ifaces.append("tun+")
    if cfg.protocol in ("wireguard", "both"):
        ifaces.append("wg0")
    return ifaces


def _csv_cidrs(raw: str) -> list[str]:
    return [c.strip() for c in raw.split(",") if c.strip()]


def setup_routing_control(cfg) -> None:
    """Install the opt-in FORWARD filtering chain (CULVERT_FWD).

    Semantics when CULVERT_ROUTING_CONTROL_ENABLED=true:
    - replies to established flows always pass (conntrack), so a client
      reaching out still gets its answers;
    - client-to-client traffic is dropped unless client_isolation is
      switched off;
    - nothing outside may INITIATE into the tunnels except sources in
      downstream_admin_cidrs (the edge-fleet reverse-admin path);
    - when allowed_destinations is set, clients may only initiate to
      those CIDRs.

    All rules live in a dedicated chain rebuilt on each start, so
    restarts do not stack duplicates.
    """
    if not cfg.routing_control_enabled:
        return

    logger.info("Configuring routing control (FORWARD filtering)...")
    ifaces = _vpn_interfaces(cfg)
    if not ifaces:
        logger.warning("Routing control enabled but no VPN interfaces resolved")
        return

    # Detach FORWARD from the chain BEFORE flushing it. On a restart the jump
    # from the previous run survives, and a flushed chain that is still jumped
    # falls straight through to the FORWARD policy - so a failure part-way
    # through the rebuild below would leave traffic unfiltered. Detached first,
    # a failure leaves nothing in the forwarding path at all.
    run("iptables -D FORWARD -j CULVERT_FWD", check=False)

    # Build CULVERT_FWD fully, then jump FORWARD at it LAST - so there is never
    # a window where the chain is jumped-but-empty (packets escaping to the
    # FORWARD policy). IPv4 only: the tunnels carry only IPv4, and the server
    # enables only net.ipv4.ip_forward, so ip6tables is deliberately not set up.
    run("iptables -N CULVERT_FWD", check=False)
    run("iptables -F CULVERT_FWD", check=False)

    # Client-to-client FIRST, above the conntrack accept, so cross-tunnel
    # traffic is decided by state-independent rules (a RELATED packet from a
    # conntrack helper cannot slip between clients). Denied by default;
    # CULVERT_CLIENT_ISOLATION=false permits it - the explicit ACCEPT is needed
    # so the default-deny into tunnels below does not drop it anyway.
    verdict = "DROP" if cfg.client_isolation else "ACCEPT"
    for in_if in ifaces:
        for out_if in ifaces:
            _add_rule(
                f"-A CULVERT_FWD -i {in_if} -o {out_if} -j {verdict}",
                "client isolation",
            )
    if cfg.client_isolation:
        logger.info("Client-to-client isolation enforced")
    else:
        logger.info("Client-to-client permitted (isolation disabled)")

    # Replies to established flows pass.
    _add_rule(
        "-A CULVERT_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "replies to established flows",
    )

    # Downstream admin holes, then default-deny unsolicited into tunnels
    admin_cidrs = _csv_cidrs(cfg.downstream_admin_cidrs)
    for cidr in admin_cidrs:
        for out_if in ifaces:
            _add_rule(
                f"-A CULVERT_FWD -o {out_if} -s {cidr} -j ACCEPT",
                "the downstream-admin gate",
            )
        # setup_network MASQUERADEs all VPN-subnet egress. That would rewrite a
        # client's REPLY to an admin-initiated connection to the server's own
        # address, so the admin sees an answer from the wrong source and the
        # exchange never completes. Exclude the admin-bound REPLY from NAT so
        # the client's real tunnel address is kept. Scoped to ESTABLISHED,
        # RELATED: a client INITIATING to the admin CIDR is still masqueraded,
        # so its tunnel IP is not exposed.
        ct = "-m conntrack --ctstate ESTABLISHED,RELATED"
        run(f"iptables -t nat -D POSTROUTING {ct} -d {cidr} -j RETURN", check=False)
        _add_rule(
            f"-t nat -I POSTROUTING 1 {ct} -d {cidr} -j RETURN",
            "keeping the real tunnel source on reverse-admin replies",
        )
    for out_if in ifaces:
        _add_rule(
            f"-A CULVERT_FWD -o {out_if} -j DROP",
            "default-deny of unsolicited traffic into the tunnels",
        )
    if admin_cidrs:
        logger.info(f"Downstream admin access allowed from {len(admin_cidrs)} CIDR(s)")
    else:
        logger.info("Unsolicited inbound to tunnels: denied (no admin CIDRs)")

    # Egress allow-list (unrestricted when empty)
    allowed = _csv_cidrs(cfg.allowed_destinations)
    if allowed:
        for cidr in allowed:
            for in_if in ifaces:
                _add_rule(
                    f"-A CULVERT_FWD -i {in_if} -d {cidr} -j ACCEPT",
                    "the egress allow-list",
                )
        for in_if in ifaces:
            _add_rule(
                f"-A CULVERT_FWD -i {in_if} -j DROP",
                "the egress allow-list's terminal deny",
            )
        logger.info(f"Client egress restricted to {len(allowed)} CIDR(s)")

    # Chain is fully populated - now point FORWARD at it.
    _add_rule("-I FORWARD 1 -j CULVERT_FWD", "routing control itself")
    logger.info("Routing control configured")


def cidr_to_netmask(prefix: int) -> str:
    """Convert CIDR prefix to netmask."""
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _prefixlen(network: str, netmask: str) -> int:
    """CIDR prefix length for a network/netmask pair."""
    return ipaddress.IPv4Network(f"{network}/{netmask}", strict=False).prefixlen
