#!/usr/bin/env python3
#  Project:      culvert
#  File:         revoke-client.py
#  Purpose:      Revoke VPN client certificates and update CRL
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Revoke OpenVPN and/or WireGuard client configurations.

Usage: revoke-client [--protocol openvpn|wireguard|all] <client-name>

This will:
  OpenVPN:
    1. Revoke the client certificate
    2. Update the CRL
    3. Remove client files (keys, configs)
  WireGuard:
    1. Remove live peer from wg0 interface (if running)
    2. Delete peer public key file
    3. Deallocate IP from allocations.json
    4. Regenerate wg0.conf without the removed peer
"""

import argparse
import os
import subprocess
import sys
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

EASYRSA = Path("/usr/share/easy-rsa")

# Lazy-loaded from CULVERT_* config cascade (populated in main)
PKI_DIR = Path("/etc/vpn/pki")
OUTPUT_DIR = Path("/etc/vpn/clients")


# ===============================================================================
# Client Functions
# ===============================================================================


def list_clients() -> list[str]:
    """List available client certificates."""
    clients = []
    issued_dir = PKI_DIR / "issued"
    if issued_dir.exists():
        for crt_file in issued_dir.glob("*.crt"):
            client_name = crt_file.stem
            if client_name != "server":
                clients.append(client_name)
    return sorted(clients)


def revoke_client(client_name: str, missing_ok: bool = False) -> bool:
    """Revoke a client certificate.

    Returns True when a certificate was revoked. With missing_ok (the
    --protocol all path) a missing certificate is a skip, not an abort,
    so a WireGuard-only client still gets its peer revoked.
    """
    cert_path = PKI_DIR / "issued" / f"{client_name}.crt"

    if not cert_path.exists():
        if missing_ok:
            logger.warning(
                f"No OpenVPN certificate for {client_name}, skipping OpenVPN revocation"
            )
            return False
        logger.error(f"Client certificate not found: {client_name}")
        logger.info("Available clients:")
        clients = list_clients()
        if clients:
            for c in clients:
                print(f"  {c}")
        else:
            print("  (none)")
        sys.exit(1)

    logger.warning(f"Revoking client: {client_name}")
    logger.warning("This action cannot be undone!")
    print("")

    # Set up environment for easy-rsa
    env = os.environ.copy()
    env.update(
        {
            "EASYRSA": str(EASYRSA),
            "EASYRSA_PKI": str(PKI_DIR),
            "EASYRSA_BATCH": "1",
        }
    )

    # Revoke certificate
    logger.info("Revoking certificate...")
    result = subprocess.run(
        ["./easyrsa", "revoke", client_name],
        cwd=EASYRSA,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error(f"Failed to revoke certificate: {result.stderr}")
        sys.exit(1)

    # Update CRL
    logger.info("Updating CRL...")
    result = subprocess.run(
        ["./easyrsa", "gen-crl"],
        cwd=EASYRSA,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error(f"Failed to update CRL: {result.stderr}")
        sys.exit(1)

    # Remove client files
    logger.info("Removing client files...")
    files_to_remove = [
        PKI_DIR / "private" / f"{client_name}.key",
        PKI_DIR / "private" / f"{client_name}-tc.key",
        PKI_DIR / "reqs" / f"{client_name}.req",
    ]

    # Remove .ovpn files
    for ovpn_file in OUTPUT_DIR.glob(f"{client_name}-*.ovpn"):
        files_to_remove.append(ovpn_file)

    removed = 0
    for f in files_to_remove:
        if f.exists():
            f.unlink()
            removed += 1
            logger.info(f"  Removed: {f}")

    logger.info(f"OpenVPN client {client_name} has been revoked", files_removed=removed)
    logger.info("")
    logger.info("Note: Connected clients will be disconnected when they next")
    logger.info("attempt to reconnect and the server verifies against the CRL.")
    return True


# ===============================================================================
# WireGuard Revocation
# ===============================================================================


def revoke_wireguard_client(client_name: str) -> bool:
    """Revoke a WireGuard client by removing its peer and deallocating its IP.

    Returns True when a peer was revoked, False when none existed.
    """
    from lib import wireguard

    wg_dir = PKI_DIR / "wireguard"
    peers_dir = wg_dir / "peers"
    pub_key_path = peers_dir / f"{client_name}.pub"

    if not pub_key_path.exists():
        logger.warning(
            f"WireGuard peer key not found: {client_name}",
            path=str(pub_key_path),
        )
        return False

    public_key = pub_key_path.read_text().strip()
    logger.info(f"Revoking WireGuard peer: {client_name}")

    # Remove live peer from wg0 interface (if running)
    try:
        subprocess.run(
            ["wg", "set", "wg0", "peer", public_key, "remove"],
            check=True,
            capture_output=True,
        )
        logger.info("Removed live peer from wg0 interface")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.info("wg0 interface not active, skipping live peer removal")

    # Delete peer public key file
    pub_key_path.unlink()
    logger.info(f"  Removed: {pub_key_path}")

    # Deallocate IP
    freed_ip = wireguard.deallocate_peer_ip(PKI_DIR, client_name)
    if freed_ip:
        logger.info(f"  Deallocated IP: {freed_ip}")
    else:
        logger.warning("No IP allocation found for client", client=client_name)

    # Remove WireGuard config files from output directory
    removed = 0
    for wg_conf in OUTPUT_DIR.glob(f"{client_name}-wg*.conf"):
        wg_conf.unlink()
        removed += 1
        logger.info(f"  Removed: {wg_conf}")

    # Regenerate wg0.conf without the removed peer
    priv_path = wg_dir / "server_private.key"
    if priv_path.exists():
        from lib.config import Config as VpnConfig

        vcfg = VpnConfig.from_settings()
        alloc_file = wg_dir / "allocations.json"

        server_private = priv_path.read_text().strip()
        server_conf = wireguard.generate_server_config(
            private_key=server_private,
            network=vcfg.wg_network,
            listen_port=vcfg.wg_port,
            mtu=vcfg.wg_mtu,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )
        wg0_path = wg_dir / "wg0.conf"
        write_secret(wg0_path, server_conf)
        logger.info("Regenerated WireGuard server config without revoked peer")

    logger.info(
        f"WireGuard client {client_name} has been revoked",
        files_removed=removed + 1,
    )
    return True


# ===============================================================================
# Main
# ===============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Revoke VPN client certificate and/or WireGuard peer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This will:
  OpenVPN:
    1. Revoke the client certificate
    2. Update the CRL
    3. Remove client files (keys, configs)
  WireGuard:
    1. Remove live peer from wg0 interface
    2. Delete peer public key and config files
    3. Deallocate IP and regenerate server config

Examples:
  revoke-client alice
  revoke-client --protocol wireguard alice
  revoke-client --list
""",
    )
    parser.add_argument("client_name", nargs="?", help="Client name to revoke")
    parser.add_argument(
        "--list", "-l", action="store_true", help="List available clients"
    )
    parser.add_argument(
        "--protocol",
        choices=["openvpn", "wireguard", "all"],
        default="all",
        help="VPN protocol to revoke (default: all)",
    )

    args = parser.parse_args()

    # Load config from CULVERT_* cascade
    global PKI_DIR, OUTPUT_DIR
    from lib.config import Config as VpnConfig

    vpn_cfg = VpnConfig.from_settings()
    PKI_DIR = vpn_cfg.pki_dir
    OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/etc/vpn/clients"))

    if args.list:
        logger.info("Available clients:")
        clients = list_clients()
        if clients:
            for c in clients:
                print(f"  {c}")
        else:
            print("  (none)")
        return

    if not args.client_name:
        parser.print_help()
        sys.exit(1)

    if args.protocol == "all":
        ovpn_revoked = revoke_client(args.client_name, missing_ok=True)
        wg_revoked = revoke_wireguard_client(args.client_name)
        if not (ovpn_revoked or wg_revoked):
            logger.error(
                f"No OpenVPN certificate or WireGuard peer found: {args.client_name}"
            )
            sys.exit(1)
    elif args.protocol == "openvpn":
        revoke_client(args.client_name)
    elif not revoke_wireguard_client(args.client_name):
        sys.exit(1)


if __name__ == "__main__":
    main()
