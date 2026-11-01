#  Project:      culvert
#  File:         wireguard.py
#  Purpose:      WireGuard key management, IP allocation, config generation,
#                and lifecycle
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""WireGuard management for culvert.

Merges key management, IP allocation, config generation, and
interface lifecycle into a single module.
"""

import fcntl
import ipaddress
import json
import re
import subprocess
import sys
from collections import deque
from contextlib import contextmanager
from pathlib import Path

from scalo.logger import logger

from lib.process import write_file_atomic, write_secret


@contextmanager
def _exclusive(lock_path: Path):
    """Hold an exclusive flock on lock_path, across processes."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _alloc_lock(wg_dir: Path):
    """Serialise read-modify-write of allocations.json across processes.

    Concurrent generate-client / revoke-client runs would otherwise race and
    double-allocate an IP or clobber the peer list.
    """
    return _exclusive(wg_dir / "allocations.lock")


def peer_lifecycle_lock(pki_dir: Path):
    """Serialise a whole issue, revoke or server-config rebuild across processes.

    Hold it from the first read of peers and allocations to the live sync. An
    issuer that read a peer just before a revoke would otherwise write the
    revoked key back into wg0.conf and the running interface.
    """
    return _exclusive(pki_dir / "wireguard" / "lifecycle.lock")


# ---------------------------------------------------------------------------
# Device slots
# ---------------------------------------------------------------------------
#
# WireGuard keeps one endpoint per peer, so two devices sharing a key cannot
# both be connected: the server answers whichever handshook last. Concurrent
# use of one client identity is therefore several independent peers, each with
# its own keypair and tunnel IP, grouped under the client's name.


def peer_id(client_name: str, slot: int) -> str:
    """Peer identity for one of a client's device slots.

    Slot 1 keeps the bare client name, so peers, IP allocations and configs
    issued before slots existed stay valid. Later slots take a dotted suffix,
    which no client name can collide with - validate_client_name permits only
    [a-zA-Z0-9_-].
    """
    return client_name if slot == 1 else f"{client_name}.{slot}"


def peer_ids(client_name: str, slots: int) -> list[str]:
    """Peer identities for every slot a client is issued."""
    return [peer_id(client_name, n) for n in range(1, slots + 1)]


def slot_infix(slot: int) -> str:
    """Filename infix separating a client's slots (slot 1 is unsuffixed)."""
    return "" if slot == 1 else str(slot)


# wg-quick and the Android app name the interface after the config file, and
# Linux caps an interface name at 15 characters, so the client name is the
# directory rather than part of the file name.
WG_QUICK_NAME = re.compile(r"[a-zA-Z0-9_=+.-]{1,15}")


def client_config_name(
    client_name: str, slot: int, mode: str, https: bool = False
) -> str:
    """Path, under the clients directory, of one slot's split or full config.

    Raises:
        ValueError: The file name would not be a valid interface name, which
            happens over HTTPS from slot 10.
    """
    tunnel = "-https" if https else ""
    stem = f"wg{slot_infix(slot)}{tunnel}-{mode}"
    if not WG_QUICK_NAME.fullmatch(stem):
        raise ValueError(
            f"WireGuard config {stem}.conf is too long for an interface name,"
            " which wg-quick and the Android app derive from it (15 characters)"
        )
    return f"{client_name}/{stem}.conf"


def client_config_names(client_name: str, slot: int, https: bool) -> list[str]:
    """Paths of every config one slot is issued."""
    variants = (False, True) if https else (False,)
    return [
        client_config_name(client_name, slot, mode, https=tunnelled)
        for tunnelled in variants
        for mode in ("split", "full")
    ]


def existing_peer_ids(pki_dir: Path, client_name: str) -> list[str]:
    """Every peer identity currently on disk for a client, slot order.

    Revocation reads this rather than the configured slot count: lowering the
    count must not orphan peers that are still in the server config.
    """
    peers_dir = pki_dir / "wireguard" / "peers"
    if not peers_dir.exists():
        return []

    found = []
    if (peers_dir / f"{client_name}.pub").exists():
        found.append((1, client_name))
    for pub in peers_dir.glob(f"{client_name}.*.pub"):
        suffix = pub.name[len(client_name) + 1 : -len(".pub")]
        if suffix.isdigit():
            found.append((int(suffix), pub.name[: -len(".pub")]))
    return [name for _, name in sorted(found)]


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def generate_server_keys(pki_dir: Path) -> tuple[str, str]:
    """Generate server keypair if not exists. Returns (private_key, public_key)."""
    wg_dir = pki_dir / "wireguard"
    priv_path = wg_dir / "server_private.key"
    pub_path = wg_dir / "server_public.key"

    if priv_path.exists() and pub_path.exists():
        logger.info("WireGuard server keys exist, reusing")
        return (
            priv_path.read_text().strip(),
            pub_path.read_text().strip(),
        )

    wg_dir.mkdir(parents=True, exist_ok=True)
    (wg_dir / "peers").mkdir(exist_ok=True)

    private = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public = (
        subprocess.check_output(["wg", "pubkey"], input=private.encode())
        .decode()
        .strip()
    )

    write_secret(priv_path, private + "\n")
    pub_path.write_text(public + "\n")

    logger.info("Generated WireGuard server keypair")
    return private, public


def generate_client_keys() -> tuple[str, str]:
    """Generate a client keypair. Returns (private_key, public_key)."""
    private = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public = (
        subprocess.check_output(["wg", "pubkey"], input=private.encode())
        .decode()
        .strip()
    )
    return private, public


def load_or_generate_client_keys(
    pki_dir: Path, client_name: str, rotate: bool = False
) -> tuple[str, str]:
    """Return a client's keypair, reusing the stored one by default.

    WireGuard keys have no expiry, so a client's identity is retained across
    config regenerations and container restarts: the private key is persisted
    at pki/wireguard/peers/<name>.key (0600, like the OpenVPN client keys) and
    reused. It is minted only when absent, or when rotate forces a fresh one.

    Retaining it is the whole point -- generating a new keypair changes the
    server's accepted peer, which silently breaks every config already handed
    to that client. Returns (private_key, public_key).
    """
    peers_dir = pki_dir / "wireguard" / "peers"
    key_path = peers_dir / f"{client_name}.key"
    pub_path = peers_dir / f"{client_name}.pub"

    if not rotate and key_path.exists():
        private = key_path.read_text().strip()
        public = (
            subprocess.check_output(["wg", "pubkey"], input=private.encode())
            .decode()
            .strip()
        )
        # Rewrite the .pub from the private key so a missing or stale public
        # half self-heals rather than desyncing from the peer.
        pub_path.write_text(public + "\n")
        logger.info("WireGuard client key exists, reusing", client=client_name)
        return private, public

    peers_dir.mkdir(parents=True, exist_ok=True)
    private, public = generate_client_keys()
    write_secret(key_path, private + "\n")
    pub_path.write_text(public + "\n")
    logger.info(
        "Generated WireGuard client keypair", client=client_name, rotated=rotate
    )
    return private, public


# ---------------------------------------------------------------------------
# IP allocation
# ---------------------------------------------------------------------------


def _write_allocations(alloc_file: Path, allocations: dict[str, str]) -> None:
    """Replace allocations.json whole, so a failed write leaves the old one."""
    data = (json.dumps(allocations, indent=2) + "\n").encode()
    write_file_atomic(alloc_file, data, 0o644)


def allocate_peer_ip(pki_dir: Path, network: str, client_name: str) -> str:
    """Allocate next available IP for a WireGuard peer."""
    alloc_file = pki_dir / "wireguard" / "allocations.json"
    net = ipaddress.ip_network(network, strict=False)

    with _alloc_lock(alloc_file.parent):
        allocations: dict[str, str] = {}
        if alloc_file.exists():
            allocations = json.loads(alloc_file.read_text())

        # A name already allocated keeps its IP (idempotent re-runs).
        if client_name in allocations:
            return allocations[client_name]

        used_ips = set(allocations.values())
        used_ips.add(str(net.network_address + 1))  # .1 reserved for server

        for host in net.hosts():
            ip_str = str(host)
            if ip_str not in used_ips:
                allocations[client_name] = ip_str
                _write_allocations(alloc_file, allocations)
                return ip_str

    raise RuntimeError(f"No available IPs in {network}")


def deallocate_peer_ip(pki_dir: Path, client_name: str) -> str | None:
    """Remove a peer's IP allocation. Returns the freed IP or None."""
    alloc_file = pki_dir / "wireguard" / "allocations.json"
    if not alloc_file.exists():
        return None

    with _alloc_lock(alloc_file.parent):
        allocations: dict[str, str] = json.loads(alloc_file.read_text())
        ip = allocations.pop(client_name, None)
        if ip:
            _write_allocations(alloc_file, allocations)
    return ip


# ---------------------------------------------------------------------------
# Kernel module check & subnet validation
# ---------------------------------------------------------------------------


def check_kernel_module() -> bool:
    """Check if WireGuard kernel module is available on the host."""
    if Path("/sys/module/wireguard").exists():
        return True
    try:
        subprocess.run(
            ["ip", "link", "add", "wg-test", "type", "wireguard"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["ip", "link", "del", "wg-test"],
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError, FileNotFoundError:
        return False


def validate_subnets_no_overlap(
    subnets: list[tuple[str, str]],
) -> list[str]:
    """Check that named subnets don't overlap. Returns list of error messages."""
    errors = []
    networks = []
    for name, cidr in subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            networks.append((name, net))
        except ValueError as e:
            errors.append(f"Invalid subnet for {name}: {cidr} ({e})")

    for i, (name_a, net_a) in enumerate(networks):
        for name_b, net_b in networks[i + 1 :]:
            if net_a.overlaps(net_b):
                errors.append(
                    f"Subnet overlap: {name_a} ({net_a}) overlaps {name_b} ({net_b})"
                )
    return errors


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------


def generate_server_config(
    private_key: str,
    network: str,
    listen_port: int,
    mtu: int,
    peers_dir: Path,
    alloc_file: Path,
    post_up: str = "",
    post_down: str = "",
) -> str:
    """Generate a WireGuard server configuration (wg0.conf)."""
    net = ipaddress.ip_network(network, strict=False)
    server_ip = str(net.network_address + 1)
    prefix_len = net.prefixlen

    lines = [
        "[Interface]",
        f"Address = {server_ip}/{prefix_len}",
        f"ListenPort = {listen_port}",
        f"PrivateKey = {private_key}",
        f"MTU = {mtu}",
    ]

    if post_up:
        lines.append(f"PostUp = {post_up}")
    if post_down:
        lines.append(f"PostDown = {post_down}")

    allocations: dict[str, str] = {}
    if alloc_file.exists():
        allocations = json.loads(alloc_file.read_text())

    for client_name, client_ip in sorted(allocations.items()):
        pub_key_file = peers_dir / f"{client_name}.pub"
        if not pub_key_file.exists():
            logger.warning(
                "Skipping peer, no public key file",
                client=client_name,
                path=str(pub_key_file),
            )
            continue

        public_key = pub_key_file.read_text().strip()
        lines.append("")
        lines.append(f"# {client_name}")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {public_key}")
        lines.append(f"AllowedIPs = {client_ip}/32")

    lines.append("")
    return "\n".join(lines)


def build_dns_line(dns_servers: list[str], dns_domain: str = "") -> str:
    """Assemble the `DNS =` value from resolvers and an optional search domain.

    Entries are stripped, empties dropped and duplicates removed in order.
    Without that, a deployment setting DNS1 and DNS2 to the same resolver emits
    it twice, and clearing DNS2 emits a trailing comma that wg-quick rejects.

    A leading `~` is stripped from the domain. It is systemd-resolved's routing
    prefix, but wg-quick hands this line to resolvconf, where a distro with a
    partial resolvconf stub drops the setting silently. The routing domain is
    emitted through PostUp in the Linux variant instead.
    """
    seen: list[str] = []
    for server in dns_servers:
        entry = server.strip()
        if entry and entry not in seen:
            seen.append(entry)

    domain = dns_domain.strip().lstrip("~")
    if domain and domain not in seen:
        seen.append(domain)

    return ", ".join(seen)


def split_allowed_ips(push_routes: str, wg_network: str) -> str:
    """Return a split-tunnel client's AllowedIPs: the pushed routes, then the tunnel.

    Args:
        push_routes: Comma-separated CIDRs, as CULVERT_PUSH_ROUTES carries them.
        wg_network: The WireGuard tunnel network.

    Returns:
        The `AllowedIPs =` value, empty route entries dropped.

    """
    routes = [route.strip() for route in push_routes.split(",") if route.strip()]
    return ", ".join([*routes, wg_network])


def generate_client_config(
    client_private_key: str | None,
    client_ip: str,
    server_public_key: str,
    server_endpoint: str,
    server_port: int,
    dns_servers: list[str],
    dns_domain: str = "",
    mtu: int = 1420,
    persistent_keepalive: int = 25,
    allowed_ips: str = "0.0.0.0/0, ::/0",
) -> str:
    """Generate a WireGuard client configuration file."""
    private_key_value = client_private_key or "YOUR_PRIVATE_KEY_HERE"

    dns_line = build_dns_line(dns_servers, dns_domain)

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key_value}",
        f"Address = {client_ip}/32",
        f"DNS = {dns_line}",
        f"MTU = {mtu}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"Endpoint = {server_endpoint}:{server_port}",
        f"AllowedIPs = {allowed_ips}",
    ]

    if persistent_keepalive > 0:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")

    lines.append("")
    return "\n".join(lines)


# wg-quick's fwmark for a full tunnel, which it routes outside wg0. It takes the
# next free table number when 51820 is in use, which a client host rarely has.
WG_QUICK_FWMARK = 51820


def generate_https_tunnel_client_config(
    client_private_key: str | None,
    client_ip: str,
    server_public_key: str,
    server_endpoint: str,
    server_port: int,
    dns_servers: list[str],
    dns_domain: str = "",
    mtu: int = 1420,
    persistent_keepalive: int = 25,
    allowed_ips: str = "0.0.0.0/0, ::/0",
    wstunnel_port: int = 443,
    tls_server_name: str = "",
) -> str:
    """Generate a WireGuard client config that runs over HTTPS via wstunnel.

    ``tls_server_name`` is the name on the server's certificate. When the
    dialled endpoint is not that name -- an IP literal, or an external address
    that differs from the certificate CN -- it is passed as the SNI override so
    verification still has a name to match.
    """
    private_key_value = client_private_key or "YOUR_PRIVATE_KEY_HERE"

    dns_line = build_dns_line(dns_servers, dns_domain)

    # wstunnel accepts any certificate unless verification is asked for.
    tls_flags = " --tls-verify-certificate"
    if tls_server_name and tls_server_name != server_endpoint:
        tls_flags += f" --tls-sni-override {tls_server_name}"

    # A full tunnel would carry wstunnel's own connection to the server inside
    # the tunnel it carries, so the full variant marks it to bypass wg0.
    full_tunnel = "0.0.0.0/0" in allowed_ips
    if full_tunnel:
        tls_flags += f" --socket-so-mark {WG_QUICK_FWMARK}"

    header = [
        "# WireGuard over HTTPS (wstunnel required)",
        "#",
        "# Start wstunnel before activating this WireGuard config:",
        f"#   wstunnel client"
        f" -L udp://127.0.0.1:51820:127.0.0.1:{server_port}"
        f"{tls_flags}"
        f" wss://{server_endpoint}:{wstunnel_port}",
        "#",
        "# The WireGuard Endpoint below connects to the local wstunnel listener.",
        "# wstunnel carries the UDP tunnel inside WebSocket/TLS, so it travels",
        "# as ordinary HTTPS on a web port.",
    ]
    if full_tunnel:
        header += [
            "#",
            "# --socket-so-mark keeps wstunnel's connection out of this tunnel. It",
            "# is Linux only and needs root. Elsewhere, drop it and route",
            f"# {server_endpoint} through your normal gateway instead.",
        ]
    header.append("")

    body = [
        "[Interface]",
        f"PrivateKey = {private_key_value}",
        f"Address = {client_ip}/32",
        f"DNS = {dns_line}",
        f"MTU = {mtu}",
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        "Endpoint = 127.0.0.1:51820",
        f"AllowedIPs = {allowed_ips}",
    ]

    if persistent_keepalive > 0:
        body.append(f"PersistentKeepalive = {persistent_keepalive}")

    body.append("")
    return "\n".join(header + body)


# ---------------------------------------------------------------------------
# Interface lifecycle (used by entrypoint)
# ---------------------------------------------------------------------------


def setup_wireguard(cfg) -> None:
    """Set up WireGuard interface and configuration."""
    logger.info("Setting up WireGuard")

    if not check_kernel_module():
        logger.error(
            "WireGuard kernel module not available."
            " Run 'modprobe wireguard' on the host."
        )
        sys.exit(1)

    peers_dir = cfg.pki_dir / "wireguard" / "peers"
    alloc_file = cfg.pki_dir / "wireguard" / "allocations.json"

    with peer_lifecycle_lock(cfg.pki_dir):
        server_priv, server_pub = generate_server_keys(cfg.pki_dir)
        logger.info(f"WireGuard server public key: {server_pub}")

        config_content = generate_server_config(
            private_key=server_priv,
            network=cfg.wg_network,
            listen_port=cfg.wg_port,
            mtu=cfg.wg_mtu,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
            post_up=cfg.wg_post_up,
            post_down=cfg.wg_post_down,
        )

        # wg0.conf embeds the server private key - 0600 from creation.
        write_secret(cfg.wg_conf, config_content)
    logger.info(f"WireGuard config written to {cfg.wg_conf}")


class WireGuardSyncError(RuntimeError):
    """The running wg0 interface refused the new peer list and kept the old one."""


def sync_running_interface(conf_path: Path) -> bool:
    """Apply a changed wg0.conf to the live interface.

    The kernel holds the peer list, not the file, so writing a new peer into
    wg0.conf does nothing by itself - a freshly issued client would fail to
    connect, with no error anywhere, until the container was restarted.

    Returns False when there is no interface to sync, which is the normal case
    for issuing a config before the server has started. A missing `wg` binary
    is the same case: there is no WireGuard here to sync.

    Raises:
        WireGuardSyncError: The interface is up and did not take the new peers,
            so it still accepts whatever keys it held before.
    """
    try:
        shown = subprocess.run(["wg", "show", "wg0"], capture_output=True)
    except FileNotFoundError:
        logger.info("wg is not installed - no WireGuard interface to sync")
        return False
    if shown.returncode != 0:
        logger.info("WireGuard interface wg0 is not up - nothing to sync")
        return False

    stripped = subprocess.run(
        ["wg-quick", "strip", str(conf_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if stripped.returncode != 0:
        raise WireGuardSyncError(
            f"could not read {conf_path}: {stripped.stderr.strip()}"
        )

    # syncconf takes a path, and the stripped form still carries the server
    # private key, so it goes to a 0600 file beside the config and is removed.
    tmp_path = conf_path.with_suffix(".syncconf")
    write_secret(tmp_path, stripped.stdout)
    try:
        result = subprocess.run(
            ["wg", "syncconf", "wg0", str(tmp_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    if result.returncode != 0:
        raise WireGuardSyncError(
            f"wg0 refused the new peer list: {result.stderr.strip()}"
        )
    logger.info("Applied peer list to the running wg0 interface")
    return True


def start_wireguard(cfg) -> None:
    """Start the WireGuard interface using wg-quick."""
    logger.info(f"Starting WireGuard on port {cfg.wg_port}")
    result = subprocess.run(
        ["wg-quick", "up", str(cfg.wg_conf)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        logger.error(f"Failed to start WireGuard: {result.stderr}")
        sys.exit(1)
    logger.info("WireGuard interface wg0 is up")


# ---------------------------------------------------------------------------
# Connection monitoring (polling loop)
# ---------------------------------------------------------------------------


def _build_pubkey_to_name(pki_dir: Path) -> dict[str, str]:
    """Build a mapping from public key to peer name."""
    peers_dir = pki_dir / "wireguard" / "peers"
    mapping: dict[str, str] = {}
    if not peers_dir.exists():
        return mapping
    for pub_file in peers_dir.glob("*.pub"):
        name = pub_file.stem
        pubkey = pub_file.read_text().strip()
        mapping[pubkey] = name
    return mapping


class EndpointFlapDetector:
    """Spot two devices sharing one WireGuard key from the peer's endpoint.

    WireGuard keeps one endpoint per peer and updates it to whichever device
    sent the last authenticated packet. A roaming client moves from one
    address to another and stays there. Devices sharing a key take turns, so
    the endpoint comes back to an address it left. That return, inside
    ``window`` seconds, is the flap.
    """

    def __init__(self, window: float = 600.0, announce_every: float = 600.0):
        """Flag a return within ``window`` seconds, at most once per ``announce_every``."""
        self.window = window
        self.announce_every = announce_every
        self._last: dict[str, str] = {}
        self._seen: dict[str, deque[tuple[float, str]]] = {}
        self._announced: dict[str, float] = {}

    def observe(self, peer: str, endpoint: str, now: float) -> dict | None:
        """Record ``peer`` at ``endpoint``.

        Returns None unless the endpoint has just returned to an address seen
        within the window, then ``{"endpoints": [...], "announce": bool}``.
        ``announce`` is False while a log line for this peer is still fresh,
        so a steady flap logs once per ``announce_every`` but counts every time.
        """
        if self._last.get(peer) == endpoint:
            return None
        history = self._seen.setdefault(peer, deque())
        while history and now - history[0][0] > self.window:
            history.popleft()
        earlier = {addr for _, addr in history}
        self._last[peer] = endpoint
        history.append((now, endpoint))
        if endpoint not in earlier:
            return None
        last_announced = self._announced.get(peer)
        announce = last_announced is None or now - last_announced >= self.announce_every
        if announce:
            self._announced[peer] = now
        return {"endpoints": sorted(earlier | {endpoint}), "announce": announce}

    def forget_missing(self, peers: set[str]) -> None:
        """Drop state for peers no longer reported by the interface."""
        for state in (self._last, self._seen, self._announced):
            for peer in set(state) - peers:
                del state[peer]


# A peer with no handshake for this long is disconnected. WireGuard rekeys every
# 2 minutes while traffic flows.
PEER_ACTIVE_SECONDS = 180


def start_wg_connection_monitor(cfg, interval: int = 15) -> None:
    """Start background thread that polls WireGuard for connection events.

    Detects peer connect/disconnect by monitoring handshake timestamps.
    A peer is "connected" when it has a recent handshake (within 3 minutes).
    """
    import threading
    import time

    from lib.metrics import (
        parse_wg_endpoints,
        parse_wg_handshakes,
        parse_wg_transfer,
        record_endpoint_flap,
    )

    def _poll_loop():
        pubkey_names = _build_pubkey_to_name(cfg.pki_dir)
        connected_peers: set[str] = set()
        flaps = EndpointFlapDetector()

        while True:
            time.sleep(interval)

            try:
                # Get handshakes
                hs_result = subprocess.run(
                    ["wg", "show", "wg0", "latest-handshakes"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                if hs_result.returncode != 0:
                    continue

                handshakes = parse_wg_handshakes(hs_result.stdout)
                now = int(time.time())

                # Get transfer stats
                tx_result = subprocess.run(
                    ["wg", "show", "wg0", "transfer"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                transfers = {}
                if tx_result.returncode == 0:
                    transfers = parse_wg_transfer(tx_result.stdout)

                ep_result = subprocess.run(
                    ["wg", "show", "wg0", "endpoints"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                endpoints = {}
                if ep_result.returncode == 0:
                    endpoints = parse_wg_endpoints(ep_result.stdout)

                # Refresh name mapping periodically (new peers may be added)
                pubkey_names = _build_pubkey_to_name(cfg.pki_dir)

                current_connected: set[str] = set()

                flaps.forget_missing(set(endpoints))
                for pubkey, endpoint in endpoints.items():
                    flap = flaps.observe(pubkey, endpoint, time.monotonic())
                    if flap is None:
                        continue
                    name = pubkey_names.get(pubkey, pubkey[:8])
                    record_endpoint_flap(name)
                    if flap["announce"]:
                        logger.warning(
                            "WireGuard peer endpoint is flapping between "
                            "addresses, two devices may share this key",
                            peer=name,
                            endpoints=flap["endpoints"],
                        )

                for pubkey, hs in handshakes.items():
                    if hs.timestamp == 0:
                        continue
                    age = now - hs.timestamp
                    name = pubkey_names.get(pubkey, pubkey[:8])

                    if age <= PEER_ACTIVE_SECONDS:
                        current_connected.add(pubkey)

                        if pubkey not in connected_peers:
                            # New connection
                            tx = transfers.get(pubkey)
                            logger.info(
                                "WireGuard peer connected",
                                peer=name,
                                handshake_age=age,
                                rx=tx.rx if tx else 0,
                                tx=tx.tx if tx else 0,
                            )

                # Detect disconnects
                for pubkey in connected_peers - current_connected:
                    name = pubkey_names.get(pubkey, pubkey[:8])
                    tx = transfers.get(pubkey)
                    logger.info(
                        "WireGuard peer disconnected",
                        peer=name,
                        rx=tx.rx if tx else 0,
                        tx=tx.tx if tx else 0,
                    )

                connected_peers = current_connected

            except Exception as e:
                logger.warning(
                    "WireGuard monitor error",
                    error=str(e),
                )

    thread = threading.Thread(target=_poll_loop, daemon=True)
    thread.start()
    logger.info(
        "WireGuard connection monitor started",
        interval=interval,
    )
