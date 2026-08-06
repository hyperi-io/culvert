#  Project:      culvert
#  File:         wireguard.py
#  Purpose:      WireGuard key management, IP allocation, config generation,
#                and lifecycle
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
WireGuard management for culvert.

Merges key management, IP allocation, config generation, and
interface lifecycle into a single module.
"""

import fcntl
import ipaddress
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

from scalo.logger import logger

from lib.process import write_secret


@contextmanager
def _alloc_lock(wg_dir: Path):
    """Serialise read-modify-write of allocations.json across processes.

    Concurrent generate-client / revoke-client runs would otherwise race and
    double-allocate an IP or clobber the peer list.
    """
    wg_dir.mkdir(parents=True, exist_ok=True)
    lock_path = wg_dir / "allocations.lock"
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


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
                alloc_file.write_text(json.dumps(allocations, indent=2) + "\n")
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
            alloc_file.write_text(json.dumps(allocations, indent=2) + "\n")
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
    except (subprocess.CalledProcessError, FileNotFoundError):
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

    dns_line = ", ".join(dns_servers)
    if dns_domain:
        dns_line = f"{dns_line}, {dns_domain}"

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
) -> str:
    """Generate a WireGuard client config that runs over HTTPS via wstunnel."""
    private_key_value = client_private_key or "YOUR_PRIVATE_KEY_HERE"

    dns_line = ", ".join(dns_servers)
    if dns_domain:
        dns_line = f"{dns_line}, {dns_domain}"

    header = [
        "# WireGuard over HTTPS (wstunnel required)",
        "#",
        "# Start wstunnel before activating this WireGuard config:",
        f"#   wstunnel client"
        f" -L udp://127.0.0.1:51820:127.0.0.1:{server_port}"
        f" wss://{server_endpoint}:{wstunnel_port}",
        "#",
        "# The WireGuard Endpoint below connects to the local wstunnel listener.",
        "# wstunnel carries the UDP tunnel inside WebSocket/TLS, so it travels",
        "# as ordinary HTTPS on a web port.",
        "",
    ]

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

    server_priv, server_pub = generate_server_keys(cfg.pki_dir)
    logger.info(f"WireGuard server public key: {server_pub}")

    peers_dir = cfg.pki_dir / "wireguard" / "peers"
    alloc_file = cfg.pki_dir / "wireguard" / "allocations.json"

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


def sync_running_interface(conf_path: Path) -> bool:
    """Apply a changed wg0.conf to the live interface.

    The kernel holds the peer list, not the file, so writing a new peer into
    wg0.conf does nothing by itself - a freshly issued client would fail to
    connect, with no error anywhere, until the container was restarted.

    Returns False when there is no interface to sync, which is the normal case
    for issuing a config before the server has started.
    """
    if subprocess.run(["wg", "show", "wg0"], capture_output=True).returncode != 0:
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
        logger.warning(f"Could not read {conf_path}: {stripped.stderr.strip()}")
        return False

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
        logger.warning(f"Could not apply peers to wg0: {result.stderr.strip()}")
        return False
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


def start_wg_connection_monitor(cfg, interval: int = 15) -> None:
    """Start background thread that polls WireGuard for connection events.

    Detects peer connect/disconnect by monitoring handshake timestamps.
    A peer is "connected" when it has a recent handshake (within 3 minutes).
    """
    import threading
    import time

    from lib.metrics import parse_wg_handshakes, parse_wg_transfer

    stale_threshold = 180  # 3 minutes without handshake = disconnected

    def _poll_loop():
        pubkey_names = _build_pubkey_to_name(cfg.pki_dir)
        connected_peers: set[str] = set()

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

                # Refresh name mapping periodically (new peers may be added)
                pubkey_names = _build_pubkey_to_name(cfg.pki_dir)

                current_connected: set[str] = set()

                for pubkey, hs in handshakes.items():
                    if hs.timestamp == 0:
                        continue
                    age = now - hs.timestamp
                    name = pubkey_names.get(pubkey, pubkey[:8])

                    if age <= stale_threshold:
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
