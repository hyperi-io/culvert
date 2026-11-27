#  Project:      culvert
#  File:         network.py
#  Purpose:      Network setup: iptables, IP forwarding, CIDR utilities
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Network configuration for culvert container.

Handles iptables NAT rules, IP forwarding, and CIDR utilities.
"""

import ipaddress
import re
import subprocess
from dataclasses import dataclass

from scalo.logger import logger

from lib.process import run


class FirewallError(RuntimeError):
    """A required iptables rule could not be installed."""


def _iptables(*args: str, check: bool = True) -> None:
    """Run iptables with args as its argv."""
    run(["iptables", *args], check=check)


def _add_rule(rule: list[str], purpose: str) -> None:
    """Install an iptables rule, refusing to continue if it does not land.

    These rules are not advisory. Routing control is what enforces client
    isolation, the egress allow-list and the downstream-admin gate, and the NAT
    rules are what let a client reach anything at all. A rule that fails to
    install silently removes the behaviour the operator asked for, so this
    raises: the container exits rather than serving clients while reporting a
    control it only appears to have.

    Callers use it for -A and -I. -N and -D are expected to fail (chain already
    present, rule not present) and stay tolerant.
    """
    try:
        _iptables(*rule)
    except subprocess.CalledProcessError as exc:
        raise FirewallError(
            f"iptables {' '.join(rule)} failed (exit {exc.returncode}). This rule"
            f" implements {purpose}, so refusing to start without it."
        ) from exc


# One allowed_destinations entry: a CIDR, optionally narrowed to PORT/PROTO.
_DESTINATION = re.compile(
    r"(?P<cidr>[^:/\s]+(?:/\d{1,2})?)(?::(?P<port>\d{1,5})/(?P<protocol>tcp|udp))?"
)


@dataclass(frozen=True, slots=True)
class Destination:
    """Where a client may initiate to: a CIDR, and optionally one port on it.

    Attributes:
        cidr: The IPv4 network, normalised.
        port: The destination port, or None for every port and protocol.
        protocol: tcp or udp when port is set, else None.

    """

    cidr: str
    port: int | None = None
    protocol: str | None = None

    def match(self) -> list[str]:
        """Return the iptables match arguments for this destination."""
        args = ["-d", self.cidr]
        if self.port is not None and self.protocol is not None:
            args += ["-p", self.protocol, "--dport", str(self.port)]
        return args


def parse_destination(entry: str) -> Destination:
    """Parse one allowed_destinations entry: CIDR, or CIDR:PORT/PROTO.

    Raises:
        ValueError: The entry is not one of those forms, the CIDR is not IPv4,
            or the port is outside 1-65535.

    """
    text = entry.strip()
    found = _DESTINATION.fullmatch(text)
    if found is None:
        raise ValueError(
            f"'{text}' is not CIDR or CIDR:PORT/PROTO (e.g. 10.20.0.0/16:8080/tcp)"
        )
    try:
        network = ipaddress.IPv4Network(found["cidr"], strict=False)
    except ValueError as exc:
        raise ValueError(f"'{text}' does not start with an IPv4 CIDR") from exc
    if found["port"] is None:
        return Destination(str(network))
    port = int(found["port"])
    if not 1 <= port <= 65535:
        raise ValueError(f"'{text}' has port {port}, outside 1-65535")
    return Destination(str(network), port, found["protocol"])


def parse_destinations(raw: str) -> list[Destination]:
    """Parse a comma-separated allowed_destinations value, empty entries dropped."""
    return [parse_destination(entry) for entry in _csv_cidrs(raw)]


def _outbound_interface(fallback: str = "eth0") -> str:
    """Return the interface the default route leaves by, or fallback."""
    try:
        result = run(["ip", "route", "get", "1.1.1.1"], check=False, capture=True)
    except FileNotFoundError:
        return fallback
    words = (result.stdout or "").split()
    if "dev" in words[:-1]:
        return words[words.index("dev") + 1]
    return fallback


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

    iface = _outbound_interface()

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
            ["-t", "nat", "-A", "POSTROUTING", "-s", f"{network}/{prefix}"]
            + ["-o", iface, "-j", "MASQUERADE"],
            f"NAT for the {name} tunnel subnet",
        )
        logger.info(f"{name} NAT rule added")

    # WireGuard needs the same rule. Its subnet is already a CIDR, and wg-quick
    # adds no NAT of its own unless the operator supplies a PostUp - so without
    # this a WireGuard client completes its handshake and then reaches nothing
    # off the server, which looks like a client problem and is not.
    if cfg.protocol in ("wireguard", "both"):
        _add_rule(
            ["-t", "nat", "-A", "POSTROUTING", "-s", cfg.wg_network]
            + ["-o", iface, "-j", "MASQUERADE"],
            "NAT for the WireGuard subnet",
        )
        logger.info("WireGuard NAT rule added")

    # The tunnel MTU sits well below the 1500 of the networks on either side, so
    # a peer deriving its MSS from its own link advertises more than the tunnel
    # can carry. Oversized segments are dropped rather than fragmented, so the
    # connection establishes and then stalls on its first full-size packet.
    _add_rule(
        ["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST"]
        + ["SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        "MSS clamping so forwarded TCP fits the tunnel MTU",
    )
    logger.info("TCP MSS clamping rule added")

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
      reaching out still gets its answers.
    - client-to-client traffic is dropped unless client_isolation is
      switched off.
    - nothing outside may INITIATE into the tunnels except sources in
      downstream_admin_cidrs (the edge-fleet reverse-admin path).
    - when allowed_destinations is set, clients may only initiate to
      those CIDRs, or to the one port an entry names on its CIDR.

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
    _iptables("-D", "FORWARD", "-j", "CULVERT_FWD", check=False)

    # Build CULVERT_FWD fully, then jump FORWARD at it LAST - so there is never
    # a window where the chain is jumped-but-empty (packets escaping to the
    # FORWARD policy). IPv4 only: the tunnels carry only IPv4, and the server
    # enables only net.ipv4.ip_forward, so ip6tables is deliberately not set up.
    _iptables("-N", "CULVERT_FWD", check=False)
    _iptables("-F", "CULVERT_FWD", check=False)

    # Client-to-client FIRST, above the conntrack accept, so cross-tunnel
    # traffic is decided by state-independent rules (a RELATED packet from a
    # conntrack helper cannot slip between clients). Denied by default, and
    # CULVERT_CLIENT_ISOLATION=false permits it - the explicit ACCEPT is needed
    # so the default-deny into tunnels below does not drop it anyway.
    verdict = "DROP" if cfg.client_isolation else "ACCEPT"
    for in_if in ifaces:
        for out_if in ifaces:
            _add_rule(
                ["-A", "CULVERT_FWD", "-i", in_if, "-o", out_if, "-j", verdict],
                "client isolation",
            )
    if cfg.client_isolation:
        logger.info("Client-to-client isolation enforced")
    else:
        logger.info("Client-to-client permitted (isolation disabled)")

    # Replies to established flows pass.
    established = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"]
    _add_rule(
        ["-A", "CULVERT_FWD", *established, "-j", "ACCEPT"],
        "replies to established flows",
    )

    # Downstream admin holes, then default-deny unsolicited into tunnels
    admin_cidrs = _csv_cidrs(cfg.downstream_admin_cidrs)
    for cidr in admin_cidrs:
        for out_if in ifaces:
            _add_rule(
                ["-A", "CULVERT_FWD", "-o", out_if, "-s", cidr, "-j", "ACCEPT"],
                "the downstream-admin gate",
            )
        # setup_network MASQUERADEs all VPN-subnet egress. That would rewrite a
        # client's REPLY to an admin-initiated connection to the server's own
        # address, so the admin sees an answer from the wrong source and the
        # exchange never completes. Exclude the admin-bound REPLY from NAT so
        # the client's real tunnel address is kept. Scoped to ESTABLISHED,
        # RELATED: a client INITIATING to the admin CIDR is still masqueraded,
        # so its tunnel IP is not exposed.
        nat_return = [*established, "-d", cidr, "-j", "RETURN"]
        _iptables("-t", "nat", "-D", "POSTROUTING", *nat_return, check=False)
        _add_rule(
            ["-t", "nat", "-I", "POSTROUTING", "1", *nat_return],
            "keeping the real tunnel source on reverse-admin replies",
        )
    for out_if in ifaces:
        _add_rule(
            ["-A", "CULVERT_FWD", "-o", out_if, "-j", "DROP"],
            "default-deny of unsolicited traffic into the tunnels",
        )
    if admin_cidrs:
        logger.info(f"Downstream admin access allowed from {len(admin_cidrs)} CIDR(s)")
    else:
        logger.info("Unsolicited inbound to tunnels: denied (no admin CIDRs)")

    # Egress allow-list (unrestricted when empty)
    allowed = parse_destinations(cfg.allowed_destinations)
    if allowed:
        for destination in allowed:
            for in_if in ifaces:
                _add_rule(
                    ["-A", "CULVERT_FWD", "-i", in_if, *destination.match()]
                    + ["-j", "ACCEPT"],
                    "the egress allow-list",
                )
        for in_if in ifaces:
            _add_rule(
                ["-A", "CULVERT_FWD", "-i", in_if, "-j", "DROP"],
                "the egress allow-list's terminal deny",
            )
        logger.info(f"Client egress restricted to {len(allowed)} destination(s)")

    # Chain is fully populated - now point FORWARD at it.
    _add_rule(["-I", "FORWARD", "1", "-j", "CULVERT_FWD"], "routing control itself")
    logger.info("Routing control configured")


LINK_LOCAL = "169.254.0.0/16"


def setup_forward_guards(cfg) -> None:
    """Drop forwarded client traffic to link-local addresses.

    On any cloud instance 169.254.169.254 is the metadata service. A client that
    adds a route for it down the tunnel has its packet forwarded and masqueraded
    by the server, and gets the HOST's instance credentials back - a VPN account
    turned into cloud credentials. Link-local is not routable beyond the link, so
    there is nothing legitimate being denied.

    This is deliberately NOT part of routing control: that is opt-in, and this
    has to hold on the default configuration. Scoped to FORWARD, so the server's
    own access to the metadata service is untouched - external PKI on AWS
    authenticates with exactly those instance credentials.

    MUST be called AFTER setup_routing_control. Both insert at FORWARD position
    1, so whichever runs last is evaluated first, and this one has to be.
    """
    if not cfg.block_link_local:
        logger.warning(
            "CULVERT_BLOCK_LINK_LOCAL is off - clients can reach"
            f" {LINK_LOCAL}, which on a cloud instance includes the metadata"
            " service and this host's credentials"
        )
        return

    ifaces = _vpn_interfaces(cfg)
    if not ifaces:
        return

    _iptables("-D", "FORWARD", "-j", "CULVERT_GUARD", check=False)
    _iptables("-N", "CULVERT_GUARD", check=False)
    _iptables("-F", "CULVERT_GUARD", check=False)
    for in_if in ifaces:
        _add_rule(
            ["-A", "CULVERT_GUARD", "-i", in_if, "-d", LINK_LOCAL, "-j", "DROP"],
            "the link-local guard, which stops clients reaching cloud metadata",
        )
    _add_rule(["-I", "FORWARD", "1", "-j", "CULVERT_GUARD"], "the link-local guard")
    logger.info(f"Link-local guard installed ({LINK_LOCAL} unreachable by clients)")


def _prefixlen(network: str, netmask: str) -> int:
    """CIDR prefix length for a network/netmask pair."""
    return ipaddress.IPv4Network(f"{network}/{netmask}", strict=False).prefixlen
