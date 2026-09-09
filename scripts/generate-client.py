#!/usr/bin/env python3
#  Project:      culvert
#  File:         generate-client.py
#  Purpose:      Generate VPN client certificates and configurations
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Generate OpenVPN and WireGuard client configurations.

Each run issues material for ONE named client: its own certificate and its
own tls-crypt-v2 key, so a client can be revoked individually. Pass --name
per user or per device; with OIDC SSO enabled, a live IdP login is required
on top of the certificate.

Tuned for OpenVPN 2.7+ with DCO, and for 4G/mobile links.

Usage: generate-client [options]

Without --name the client name derives from the server CN:
  vpn.example.com -> vpn-example-com

Outputs vary by --protocol flag:
  openvpn:   6 .ovpn files (3 listeners x 2 tunnel modes)
  wireguard: 2-4 .conf files PER DEVICE SLOT (split/full, plus the
             HTTPS-tunnelled pair when WireGuard-over-HTTPS is enabled)
  all:       both sets of files

A client identity carries CULVERT_SHARED_CLIENT_SLOTS concurrent connections by
default. OpenVPN allows that on one certificate; WireGuard cannot share a key,
so it gets one independent peer per slot.
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

# Allow importing lib/ modules from scripts directory (container and dev paths)
for _scripts_path in ["/etc/vpn/scripts", str(Path(__file__).parent)]:
    if _scripts_path not in sys.path:
        sys.path.insert(0, _scripts_path)

from lib.process import write_secret  # noqa: E402
from scalo.logger import logger  # noqa: E402

# ===============================================================================
# Configuration
# ===============================================================================


class Config:
    """Client generation configuration.

    Wraps lib.config.Config (CULVERT_* cascade) and adds output_dir +
    dns_servers convenience fields used only by generate-client.
    """

    def __init__(self):
        from lib.config import Config as VpnConfig

        vpn = VpnConfig.from_settings()
        self._vpn = vpn
        self.pki_dir = vpn.pki_dir
        self.output_dir = Path(os.environ.get("OUTPUT_DIR", "/etc/vpn/clients"))
        self.server_cn = vpn.server_cn
        self.client_endpoint = vpn.client_endpoint
        self.udp_port = vpn.udp_port
        self.tcp_port = vpn.tcp_port
        self.https_port = vpn.https_port
        self.key_type = vpn.key_type
        self.key_size = vpn.key_size
        self.cert_expire_days = vpn.cert_expire_days

        # WireGuard. wg_conf and the PostUp/PostDown hooks are needed because
        # issuing a client rewrites the server's own config: writing it anywhere
        # but wg_conf leaves the running server unaware of the peer, and dropping
        # the hooks would silently discard the operator's own firewall rules.
        self.wg_network = vpn.wg_network
        self.wg_port = vpn.wg_port
        self.wg_mtu = vpn.wg_mtu
        self.wg_conf = vpn.wg_conf
        self.wg_post_up = vpn.wg_post_up
        self.wg_post_down = vpn.wg_post_down
        self.wg_persistent_keepalive = vpn.wg_persistent_keepalive
        self.wg_https_tunnel_enabled = vpn.wg_https_tunnel_enabled
        self.wg_https_tunnel_port = vpn.wg_https_tunnel_port

        # Concurrent connections per client identity. Config already forces the
        # slot count to 1 when sharing is opted out.
        self.allow_shared_clients = vpn.allow_shared_clients
        self.shared_client_slots = vpn.shared_client_slots

        # DNS/routing
        self.dns_servers = [vpn.dns1, vpn.dns2]
        self.dns_domain = vpn.dns_domain
        self.push_routes = vpn.push_routes
        self.full_tunnel = vpn.full_tunnel

    def validate(self) -> None:
        """Validate the underlying CULVERT_* settings, exiting on error."""
        self._vpn.validate()


# ===============================================================================
# Validation
# ===============================================================================


def validate_client_name(name: str) -> bool:
    """Validate client name contains only safe characters."""
    if not name:
        return False
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))


def validate_wg_pubkey(key: str) -> bool:
    """Validate WireGuard public key shape (32 bytes base64, 44 chars).

    The key is written into peer files and interpolated into wg0.conf,
    so reject anything that is not a plain single-line key.
    """
    return bool(re.match(r"^[A-Za-z0-9+/]{43}=$", key))


def validate_proxy(proxy: str) -> bool:
    """Validate proxy format (host:port)."""
    return bool(re.match(r"^[a-zA-Z0-9._-]+:[0-9]+$", proxy))


# ===============================================================================
# Certificate Generation
# ===============================================================================


def generate_certificate(
    client_name: str,
    cert_days: int,
    pki_dir: Path,
    key_type: str = "ec",
    key_size: str = "secp384r1",
) -> None:
    """Generate client certificate using easy-rsa."""
    logger.info("Generating client certificate...", client=client_name, days=cert_days)

    env = os.environ.copy()
    env.update(
        {
            "EASYRSA": "/usr/share/easy-rsa",
            "EASYRSA_PKI": str(pki_dir),
            "EASYRSA_BATCH": "1",
            "EASYRSA_CERT_EXPIRE": str(cert_days),
            "EASYRSA_REQ_CN": client_name,
        }
    )
    # Match the CA/server algorithm (easy-rsa would otherwise fall back
    # to its RSA default for client keys).
    if key_type == "ec":
        env.update({"EASYRSA_ALGO": "ec", "EASYRSA_CURVE": key_size})
    else:
        env.update({"EASYRSA_ALGO": "rsa", "EASYRSA_KEY_SIZE": key_size})

    # Generate request and sign
    subprocess.run(
        ["./easyrsa", "gen-req", client_name, "nopass"],
        cwd="/usr/share/easy-rsa",
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["./easyrsa", "sign-req", "client", client_name],
        cwd="/usr/share/easy-rsa",
        env=env,
        check=True,
        capture_output=True,
    )

    # Generate tls-crypt-v2 client key
    logger.info("Generating tls-crypt-v2 client key...")
    subprocess.run(
        [
            "openvpn",
            "--tls-crypt-v2",
            str(pki_dir / "tc.key"),
            "--genkey",
            "tls-crypt-v2-client",
            str(pki_dir / "private" / f"{client_name}-tc.key"),
        ],
        check=True,
        capture_output=True,
    )

    logger.info("Certificate generated successfully", client=client_name)


# ===============================================================================
# .ovpn Configuration Generation
# ===============================================================================


def generate_ovpn_config(
    client_name: str,
    tunnel_mode: str,
    output_path: Path,
    protocol: str,
    cfg: Config,
    additional_routes: str = "",
    proxy_server: str = "",
    proxy_auth: bool = False,
) -> None:
    """Generate a single .ovpn configuration file."""

    # Determine remote line based on protocol
    stunnel_config = None
    if protocol == "udp":
        remote_line = f"remote {cfg.client_endpoint} {cfg.udp_port} udp"
        proto_desc = f"UDP {cfg.udp_port}"
    elif protocol == "tcp":
        remote_line = f"remote {cfg.client_endpoint} {cfg.tcp_port} tcp"
        proto_desc = f"TCP {cfg.tcp_port}"
    elif protocol == "tcp-https":
        # HTTPS tunnel via stunnel - connect to local stunnel on 1195
        # stunnel handles the TLS connection to server:443
        remote_line = "remote 127.0.0.1 1195 tcp"
        proto_desc = f"TCP {cfg.https_port} (HTTPS tunnel via stunnel)"

        # The proxy belongs HERE, in stunnel, not in the OpenVPN config.
        # OpenVPN's own remote is loopback, so an http-proxy directive there
        # would ask the corporate proxy to CONNECT to 127.0.0.1 - which it
        # refuses. stunnel is the process that actually reaches the server, so
        # it is the one that has to speak to the proxy.
        if proxy_server:
            proxy_host, proxy_port = proxy_server.split(":")
            stunnel_target = f"""connect = {proxy_host}:{proxy_port}

# Reach the server THROUGH the proxy: stunnel opens the TCP connection to the
# proxy and asks it to CONNECT onwards to the real endpoint. Corporate proxies
# generally only permit CONNECT to 443, which is exactly the port the HTTPS
# listener uses - that is the whole point of tunnelling over it.
protocol = connect
protocolHost = {cfg.client_endpoint}:{cfg.https_port}"""
            if proxy_auth:
                stunnel_target += """
protocolAuthentication = basic
protocolUsername = CHANGE_ME
protocolPassword = CHANGE_ME"""
            else:
                stunnel_target += """

# Add proxy authentication if needed - uncomment and fill in:
# protocolAuthentication = basic
# protocolUsername = your-username
# protocolPassword = your-password"""
        else:
            stunnel_target = f"connect = {cfg.client_endpoint}:{cfg.https_port}"

        stunnel_name = (
            f"{client_name}-proxy-stunnel.conf"
            if proxy_server
            else (f"{client_name}-stunnel.conf")
        )
        stunnel_config = f"""# Culvert stunnel Client Configuration
# Run: stunnel {stunnel_name}
# Then connect with OpenVPN

# Foreground mode
foreground = yes

# TLS 1.3 only
sslVersionMin = TLSv1.3

# Client mode
client = yes

[openvpn-https]
accept = 127.0.0.1:1195
{stunnel_target}

# Verify server certificate
verifyChain = yes
CApath = /etc/ssl/certs
checkHost = {cfg.server_cn}
"""
    else:
        raise ValueError(f"Unknown protocol: {protocol}")

    mode_desc = f"{tunnel_mode} tunnel"
    if protocol == "tcp-https":
        mode_desc += " (HTTPS)"

    # Proxy configuration. Note what is NOT here: an http-proxy directive.
    # OpenVPN connects to the local stunnel, and stunnel is what talks to the
    # proxy - see the stunnel config built above. Putting it here instead makes
    # OpenVPN ask the proxy to CONNECT to 127.0.0.1, which cannot work.
    proxy_section = ""
    if proxy_server:
        mode_desc = f"{tunnel_mode} tunnel (PROXY MODE)"
        proto_desc = f"TCP {cfg.https_port} via proxy {proxy_server}"
        proxy_section = f"""
#===============================================================================
# PROXY MODE
#===============================================================================
# Egress goes through {proxy_server}. Start stunnel with
# {client_name}-proxy-stunnel.conf FIRST - it holds the proxy settings and does
# the CONNECT to {cfg.client_endpoint}:{cfg.https_port}. This file only ever talks to
# stunnel on loopback."""

    logger.info(
        f"Creating config: {output_path.name}", protocol=proto_desc, mode=tunnel_mode
    )

    # Read certificate files
    ca_cert = (cfg.pki_dir / "ca.crt").read_text()
    client_key = (cfg.pki_dir / "private" / f"{client_name}.key").read_text()
    tc_key = (cfg.pki_dir / "private" / f"{client_name}-tc.key").read_text()

    # Extract just the certificate (not the full chain info)
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cfg.pki_dir / "issued" / f"{client_name}.crt")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    client_cert = result.stdout

    # Build tunnel mode section
    if tunnel_mode == "full":
        tunnel_section = """\
#===============================================================================
# Full Tunnel Mode - ALL traffic through VPN
#===============================================================================
redirect-gateway def1 bypass-dhcp

# WINDOWS ONLY: stops applications querying a DNS server outside the tunnel.
# Uncomment on Windows. Leave it commented everywhere else - OpenVPN 2.7 on
# Linux and macOS does not know the option and refuses to start.
#block-outside-dns
"""
    else:
        tunnel_section = """\
#===============================================================================
# Split Tunnel Mode - Only VPN network routes through VPN
#===============================================================================
# Routes are pushed by server
# Additional routes can be specified at generation time
"""
        if additional_routes:
            tunnel_section += "\n# Additional routes (specified at generation time)\n"
            for route in additional_routes.split(","):
                route = route.strip()
                if route:
                    tunnel_section += f"route {route}\n"

    # Generate timestamp
    timestamp = datetime.now(UTC).isoformat()

    # Build config
    config = f"""# Culvert Client Configuration
# Compatible with OpenVPN Connect (iOS, Android, Windows, macOS)
#
# Client: {client_name}
# Mode: {mode_desc}
# Protocol: {proto_desc}
# Server: {cfg.client_endpoint}
# Generated: {timestamp}
#
# Recommended client: OpenVPN Connect (https://openvpn.net/client/)

client
dev tun

#===============================================================================
# Server Connection
#===============================================================================
{remote_line}
{proxy_section}

#===============================================================================
# Connection Settings
#===============================================================================
nobind

#===============================================================================
# CNSA 2.0 Security (TLS 1.3, AEAD ciphers)
#===============================================================================
tls-version-min 1.3
cipher AES-256-GCM
auth SHA384
remote-cert-tls server
verify-x509-name {cfg.server_cn} name

#===============================================================================
# MTU Optimization
#===============================================================================
tun-mtu 1400

#===============================================================================
# Security Hardening
#===============================================================================
# Compression disabled (VORACLE vulnerability)

#===============================================================================
# Logging
#===============================================================================
verb 3

{tunnel_section}
#===============================================================================
# Embedded Certificates (no external files needed)
#===============================================================================
<ca>
{ca_cert}</ca>

<cert>
{client_cert}</cert>

<key>
{client_key}</key>

<tls-crypt-v2>
{tc_key}</tls-crypt-v2>
"""

    # Write config
    write_secret(output_path, config)

    # Write stunnel config if HTTPS tunnel. The proxy variant gets its own
    # name: both are built from the same tcp-https branch, and proxy configs
    # are generated second, so a shared name means --proxy silently destroys
    # the direct-HTTPS stunnel config the same run just wrote.
    if stunnel_config:
        suffix = "-proxy-stunnel.conf" if proxy_server else "-stunnel.conf"
        stunnel_path = output_path.parent / f"{client_name}{suffix}"
        write_secret(stunnel_path, stunnel_config)
        logger.info(f"  stunnel config: {stunnel_path}")


# ===============================================================================
# WireGuard Configuration Generation
# ===============================================================================


def _bundle_client_zip(client_name: str, output_dir: Path) -> Path | None:
    """Zip a single client's generated files into <name>.zip (0600).

    Per client, never one archive of every client: a shared archive would
    package one client's private keys with another's. Returns the zip path, or
    None when the client has no files. The .zip itself is excluded so repeated
    runs do not nest.
    """
    import zipfile

    members = sorted(
        p
        for p in output_dir.glob(f"{client_name}-*")
        if p.is_file() and p.suffix != ".zip"
    )
    if not members:
        return None

    zip_path = output_dir / f"{client_name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member in members:
            zf.write(member, member.name)
    zip_path.chmod(0o600)
    logger.info("Bundled client configs", zip=str(zip_path), files=len(members))
    return zip_path


def generate_wireguard_configs(
    client_name: str,
    cfg: Config,
    pubkeys: list[str] | None = None,
    rotate: bool = False,
) -> None:
    """Generate WireGuard client configuration files.

    Issues cfg.shared_client_slots peers for the client, each with its own
    keypair and tunnel IP, so the identity can carry that many concurrent
    connections. Each slot gets split and full tunnel configs, plus the
    HTTPS-tunnelled variants when WireGuard-over-HTTPS is enabled.

    Supplied pubkeys select client-side key generation (no private key embedded
    in the config) and set the slot count, one key per slot. Otherwise each
    slot's keypair is retained across runs and rotated only when rotate is set.
    """
    from lib import wireguard

    wg_dir = cfg.pki_dir / "wireguard"
    peers_dir = wg_dir / "peers"
    peers_dir.mkdir(parents=True, exist_ok=True)

    # Generate or load server keys
    server_private, server_public = wireguard.generate_server_keys(cfg.pki_dir)

    slots = len(pubkeys) if pubkeys else cfg.shared_client_slots
    if slots > 1:
        logger.info(
            "Issuing concurrent WireGuard device slots",
            client=client_name,
            slots=slots,
        )

    # Lowering the slot count does not retire the peers already issued above it:
    # they keep their key and their allocation, so the server still accepts them.
    # Reissuing must not delete a credential, so say so instead of doing it.
    surplus = wireguard.existing_peer_ids(cfg.pki_dir, client_name)[slots:]
    if surplus:
        logger.warning(
            "Client still has WireGuard peers above the configured slot count;"
            " they remain able to connect until revoked",
            client=client_name,
            slots=slots,
            surplus=", ".join(surplus),
            revoke=f"revoke-client --protocol wireguard {client_name}",
        )

    # Build AllowedIPs for split tunnel
    split_allowed_ips_parts = []
    if cfg.push_routes:
        for route in cfg.push_routes.split(","):
            route = route.strip()
            if route:
                split_allowed_ips_parts.append(route)
    # Include the WireGuard network itself
    split_allowed_ips_parts.append(cfg.wg_network)
    split_allowed_ips = ", ".join(split_allowed_ips_parts)
    full_allowed_ips = "0.0.0.0/0, ::/0"

    # Generate client configs
    configs_to_write: list[tuple[str, str]] = []

    for slot in range(1, slots + 1):
        peer = wireguard.peer_id(client_name, slot)
        infix = wireguard.slot_infix(slot)

        # Each slot needs its own tunnel IP: two devices sharing one address
        # would be indistinguishable to the server's routing table.
        client_ip = wireguard.allocate_peer_ip(cfg.pki_dir, cfg.wg_network, peer)
        logger.info("Allocated WireGuard IP", peer=peer, ip=client_ip)

        # Reuse the slot's keypair by default; mint only when it does not exist
        # yet or rotate is requested. Regenerating it changes the server's
        # accepted peer and silently breaks configs already issued to that slot.
        if pubkeys:
            client_private = None
            client_public = pubkeys[slot - 1]
            (peers_dir / f"{peer}.pub").write_text(client_public + "\n")
            logger.info(
                "Using provided client public key (client-side key generation)",
                peer=peer,
            )
        else:
            client_private, _ = wireguard.load_or_generate_client_keys(
                cfg.pki_dir, peer, rotate=rotate
            )

        # Everything the four variants share. Held in one place so a tunnel mode
        # cannot silently drift from the others -- they differ only in the
        # routes they claim, and the HTTPS pair in the port wstunnel listens on.
        peer_config = {
            "client_private_key": client_private,
            "client_ip": client_ip,
            "server_public_key": server_public,
            "server_endpoint": cfg.client_endpoint,
            "server_port": cfg.wg_port,
            "dns_servers": cfg.dns_servers,
            "dns_domain": cfg.dns_domain,
            "mtu": cfg.wg_mtu,
            "persistent_keepalive": cfg.wg_persistent_keepalive,
        }

        for mode, allowed_ips in (
            ("split", split_allowed_ips),
            ("full", full_allowed_ips),
        ):
            configs_to_write.append(
                (
                    f"{client_name}-wg{infix}-{mode}.conf",
                    wireguard.generate_client_config(
                        **peer_config, allowed_ips=allowed_ips
                    ),
                )
            )

            # HTTPS-tunnelled variant (WireGuard inside WebSocket/TLS)
            if cfg.wg_https_tunnel_enabled:
                configs_to_write.append(
                    (
                        f"{client_name}-wg{infix}-https-{mode}.conf",
                        wireguard.generate_https_tunnel_client_config(
                            **peer_config,
                            allowed_ips=allowed_ips,
                            wstunnel_port=cfg.wg_https_tunnel_port,
                            tls_server_name=cfg.server_cn,
                        ),
                    )
                )

    # Write all config files
    for filename, content in configs_to_write:
        out_path = cfg.output_dir / filename
        write_secret(out_path, content)
        logger.info(f"Created WireGuard config: {out_path}")

    # Regenerate the server config with the new peer, at the path the server
    # itself uses, and push the peer list into the running interface. Written
    # anywhere else it is a file nothing reads, and left unsynced the client
    # cannot connect until the container restarts.
    alloc_file = wg_dir / "allocations.json"
    server_conf = wireguard.generate_server_config(
        private_key=server_private,
        network=cfg.wg_network,
        listen_port=cfg.wg_port,
        mtu=cfg.wg_mtu,
        peers_dir=peers_dir,
        alloc_file=alloc_file,
        post_up=cfg.wg_post_up,
        post_down=cfg.wg_post_down,
    )
    write_secret(cfg.wg_conf, server_conf)
    logger.info("Regenerated WireGuard server config", path=str(cfg.wg_conf))
    wireguard.sync_running_interface(cfg.wg_conf)


# ===============================================================================
# Main
# ===============================================================================


def main() -> None:
    cfg = Config()

    # Unvalidated, a bad setting reaches a client file and fails only on
    # someone else's machine.
    cfg.validate()

    default_name = cfg.server_cn.replace(".", "-")

    parser = argparse.ArgumentParser(
        description="Generate VPN client configurations (OpenVPN and/or WireGuard)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
OpenVPN output files (6 total - 3 listeners x 2 tunnel modes):
  {{name}}-udp-split.ovpn   - UDP, split tunnel (fastest)
  {{name}}-udp-full.ovpn    - UDP, full tunnel
  {{name}}-tcp-split.ovpn   - TCP {cfg.tcp_port}, split tunnel (proxy fallback)
  {{name}}-tcp-full.ovpn    - TCP {cfg.tcp_port}, full tunnel
  {{name}}-https-split.ovpn - TCP {cfg.https_port} over TLS, split tunnel
  {{name}}-https-full.ovpn  - TCP {cfg.https_port} over TLS, full tunnel

WireGuard output files, PER DEVICE SLOT (2-4 per slot):
  {{name}}-wg-split.conf     - Split tunnel
  {{name}}-wg-full.conf      - Full tunnel
  {{name}}-wg-https-split.conf - Over HTTPS, split tunnel (if enabled)
  {{name}}-wg-https-full.conf  - Over HTTPS, full tunnel (if enabled)

Slots 2+ carry the slot number ({{name}}-wg2-split.conf, ...). Each slot is an
independent peer with its own key and tunnel IP, which is what lets one client
identity hold {cfg.shared_client_slots} concurrent WireGuard connections.
Set CULVERT_ALLOW_SHARED_CLIENTS=false for one exclusive connection per client.

Protocol Configuration (from environment):
  Server CN:  {cfg.server_cn}
  UDP port:   {cfg.udp_port}
  TCP port:   {cfg.tcp_port}
  HTTPS port: {cfg.https_port}
  WG port:    {cfg.wg_port}
  WG network: {cfg.wg_network}

Examples:
  generate-client                              # Both protocols, default name
  generate-client --protocol openvpn           # OpenVPN only
  generate-client --protocol wireguard         # WireGuard only
  generate-client --protocol wireguard --pubkey <base64key>
  generate-client --routes 10.1.0.0/16,192.168.1.0/24
  generate-client --proxy proxy.corp.com:8080
  generate-client --name custom-vpn            # Override name (rare)
""",
    )
    parser.add_argument("--name", help=f"Client/file name (default: {default_name})")
    parser.add_argument(
        "--output", help=f"Output directory (default: {cfg.output_dir})"
    )
    parser.add_argument(
        "--protocol",
        choices=["openvpn", "wireguard", "all"],
        default="all",
        help="VPN protocol to generate configs for (default: all)",
    )
    parser.add_argument(
        "--pubkey",
        action="append",
        metavar="KEY",
        help=(
            "WireGuard client public key (client-side key generation mode)."
            " Repeat once per concurrent device slot; overrides"
            " CULVERT_SHARED_CLIENT_SLOTS."
        ),
    )
    parser.add_argument(
        "--routes", help="Additional routes for split tunnel (comma-separated)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help=(
            "Client certificate validity in days (default: CULVERT_CERT_EXPIRE_DAYS)"
        ),
    )
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="Regenerate configs only (skip cert creation)",
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help=(
            "Mint a fresh WireGuard client keypair, replacing the retained one."
            " Invalidates the client's existing WireGuard configs."
        ),
    )
    parser.add_argument("--proxy", help="HTTP CONNECT proxy (HOST:PORT)")
    parser.add_argument(
        "--proxy-auth", action="store_true", help="Add proxy auth placeholder"
    )

    args = parser.parse_args()

    # Apply arguments
    client_name = args.name or default_name
    if args.output:
        cfg.output_dir = Path(args.output)
    additional_routes = args.routes or ""

    generate_openvpn = args.protocol in ("openvpn", "all")
    generate_wg = args.protocol in ("wireguard", "all")

    # Validate
    if not validate_client_name(client_name):
        logger.error(
            f"Invalid client name '{client_name}'. "
            "Use only alphanumeric, dash, underscore."
        )
        sys.exit(1)

    if args.proxy and not validate_proxy(args.proxy):
        logger.error("Invalid proxy format. Use HOST:PORT (e.g., proxy.corp.com:8080)")
        sys.exit(1)

    if args.pubkey and not generate_wg:
        logger.error("--pubkey is only valid with --protocol wireguard or all")
        sys.exit(1)

    for key in args.pubkey or []:
        if not validate_wg_pubkey(key):
            logger.error(
                "Invalid WireGuard public key: expected 44-char base64"
                f" (wg pubkey output), got '{key}'"
            )
            sys.exit(1)

    if args.pubkey and len(set(args.pubkey)) != len(args.pubkey):
        logger.error(
            "Duplicate --pubkey values: each device slot needs its own keypair,"
            " or the slots cannot be connected at the same time"
        )
        sys.exit(1)

    if args.pubkey and len(args.pubkey) > 1 and not cfg.allow_shared_clients:
        logger.error(
            f"{len(args.pubkey)} --pubkey values given but"
            " CULVERT_ALLOW_SHARED_CLIENTS=false, which allows one slot per client"
        )
        sys.exit(1)

    # An unset --days falls back to the configured cert lifetime, so a
    # deployment with a long CULVERT_CERT_EXPIRE_DAYS issues clients to match.
    cert_days = args.days if args.days is not None else cfg.cert_expire_days

    logger.info(f"Generating client: {client_name}")
    logger.info(f"  Protocol: {args.protocol}")
    if generate_openvpn:
        logger.info(f"  Certificate validity: {cert_days} days")
        logger.info(f"  UDP port: {cfg.udp_port}")
        logger.info(f"  TCP port: {cfg.tcp_port}")
    if generate_wg:
        logger.info(f"  WireGuard port: {cfg.wg_port}")
        logger.info(f"  WireGuard network: {cfg.wg_network}")
    if args.proxy:
        logger.info(f"  HTTP Proxy: {args.proxy}")

    # Create output directory
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    # ---- OpenVPN ----
    if generate_openvpn:
        # Check PKI
        if not (cfg.pki_dir / "ca.crt").exists():
            logger.error("PKI not initialized. Start the server first.")
            sys.exit(1)

        # Handle certificate
        cert_path = cfg.pki_dir / "issued" / f"{client_name}.crt"
        if args.config_only:
            if not cert_path.exists():
                logger.error(
                    f"Config-only mode but certificate doesn't exist: {client_name}"
                )
                sys.exit(1)
            logger.info("Config-only mode: using existing certificate")
        else:
            if cert_path.exists():
                logger.warning(f"Client certificate already exists: {client_name}")
                logger.error(
                    "Use revoke-client to revoke first, "
                    "or use --config-only to regenerate configs"
                )
                sys.exit(1)
            generate_certificate(
                client_name,
                cert_days,
                cfg.pki_dir,
                key_type=cfg.key_type,
                key_size=cfg.key_size,
            )

        # Generate 6 config files: 3 protocols x 2 tunnel modes
        configs = [
            ("udp", "split", additional_routes),
            ("udp", "full", ""),
            ("tcp", "split", additional_routes),
            ("tcp", "full", ""),
            ("tcp-https", "split", additional_routes),
            ("tcp-https", "full", ""),
        ]

        # Map protocol to filename suffix
        proto_names = {"udp": "udp", "tcp": "tcp", "tcp-https": "https"}

        for protocol, mode, routes in configs:
            proto_name = proto_names[protocol]
            output_path = cfg.output_dir / f"{client_name}-{proto_name}-{mode}.ovpn"
            generate_ovpn_config(
                client_name,
                mode,
                output_path,
                protocol,
                cfg,
                additional_routes=routes,
            )

        # Generate proxy configs if specified
        if args.proxy:
            for mode, routes in [("split", additional_routes), ("full", "")]:
                output_path = cfg.output_dir / f"{client_name}-proxy-{mode}.ovpn"
                generate_ovpn_config(
                    client_name,
                    mode,
                    output_path,
                    "tcp-https",
                    cfg,
                    additional_routes=routes,
                    proxy_server=args.proxy,
                    proxy_auth=args.proxy_auth,
                )

    # ---- WireGuard ----
    if generate_wg:
        generate_wireguard_configs(
            client_name=client_name,
            cfg=cfg,
            pubkeys=args.pubkey,
            rotate=args.rotate,
        )

    # Copy vpn-client-setup.md to output directory
    setup_doc_src = Path("/etc/vpn/docs/vpn-client-setup.md")
    setup_doc_dst = cfg.output_dir / "vpn-client-setup.md"
    if setup_doc_src.exists():
        import shutil

        shutil.copy2(setup_doc_src, setup_doc_dst)
        logger.info(f"  Documentation: {setup_doc_dst}")

    # Bundle this client's files into <name>.zip for easy hand-off. Per client,
    # not one archive of every client, so one client's private keys are never
    # packaged alongside another's. Regenerated each run so it tracks the
    # current configs.
    _bundle_client_zip(client_name, cfg.output_dir)

    # Summary
    logger.info("")
    if args.config_only:
        logger.info("Configuration files regenerated successfully!")
    else:
        logger.info("Client configuration generated successfully!")

    if generate_openvpn:
        if not args.config_only:
            logger.info("")
            logger.info("OpenVPN certificate files:")
            logger.info(f"  Certificate:  {cfg.pki_dir}/issued/{client_name}.crt")
            logger.info(f"  Private key:  {cfg.pki_dir}/private/{client_name}.key")
            logger.info(f"  TLS key:      {cfg.pki_dir}/private/{client_name}-tc.key")

        logger.info("")
        logger.info("OpenVPN configuration files (6 total):")
        logger.info("")
        logger.info(f"  UDP {cfg.udp_port} (fastest, use first):")
        logger.info(f"    {cfg.output_dir}/{client_name}-udp-split.ovpn")
        logger.info(f"    {cfg.output_dir}/{client_name}-udp-full.ovpn")
        logger.info("")
        logger.info(f"  TCP {cfg.tcp_port} (fallback when UDP blocked):")
        logger.info(f"    {cfg.output_dir}/{client_name}-tcp-split.ovpn")
        logger.info(f"    {cfg.output_dir}/{client_name}-tcp-full.ovpn")
        logger.info("")
        logger.info(f"  TCP {cfg.https_port} over TLS (networks that only pass HTTPS):")
        logger.info(f"    {cfg.output_dir}/{client_name}-https-split.ovpn")
        logger.info(f"    {cfg.output_dir}/{client_name}-https-full.ovpn")

        if args.proxy:
            logger.info("")
            logger.info(f"  Proxy configs (via {args.proxy}):")
            logger.info(f"    {cfg.output_dir}/{client_name}-proxy-split.ovpn")
            logger.info(f"    {cfg.output_dir}/{client_name}-proxy-full.ovpn")

    if generate_wg:
        from lib import wireguard

        slots = len(args.pubkey) if args.pubkey else cfg.shared_client_slots
        wg_dir = cfg.pki_dir / "wireguard"

        logger.info("")
        logger.info(f"WireGuard configuration files ({slots} device slot(s)):")
        for slot in range(1, slots + 1):
            infix = wireguard.slot_infix(slot)
            logger.info(f"    {cfg.output_dir}/{client_name}-wg{infix}-split.conf")
            logger.info(f"    {cfg.output_dir}/{client_name}-wg{infix}-full.conf")
            if cfg.wg_https_tunnel_enabled:
                logger.info(
                    f"    {cfg.output_dir}/{client_name}-wg{infix}-https-split.conf"
                )
                logger.info(
                    f"    {cfg.output_dir}/{client_name}-wg{infix}-https-full.conf"
                )
        logger.info("")
        logger.info("WireGuard peer keys:")
        for peer in wireguard.peer_ids(client_name, slots):
            logger.info(f"    {wg_dir}/peers/{peer}.pub")
        if slots > 1:
            logger.info("")
            logger.info(
                "Each slot is a separate device: give one config per device, and"
                " never the same slot to two, or they cannot connect at once."
            )

    logger.info("")
    logger.info("Usage:")
    if generate_openvpn:
        logger.info("  1. Try UDP first (fastest, lowest latency)")
        logger.info(f"  2. If UDP blocked, try TCP on port {cfg.tcp_port}")
        logger.info(f"  3. If still blocked, try over TLS (TCP {cfg.https_port})")
        logger.info("  4. Split = VPN routes only, Full = all traffic through VPN")
    if generate_wg:
        logger.info("  WireGuard: Import .conf into WireGuard client app")
        if cfg.wg_https_tunnel_enabled:
            logger.info(
                "  Over HTTPS: run wstunnel first, then activate the -wg-https- config"
            )


if __name__ == "__main__":
    main()
