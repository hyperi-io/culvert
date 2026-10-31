#!/usr/bin/env python3
#  Project:      culvert
#  File:         revoke-client.py
#  Purpose:      Revoke VPN client certificates and update CRL
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Revoke OpenVPN and/or WireGuard client configurations.

Usage: revoke-client [--protocol openvpn|wireguard|all] <client-name>

This will:
  OpenVPN:
    1. Revoke the client certificate
    2. Update the CRL
    3. Remove client files (keys, .ovpn and stunnel configs)
  WireGuard (for every device slot the client holds):
    1. Remove live peer from wg0 interface (if running)
    2. Delete peer key files and config files
    3. Deallocate IP from allocations.json
    4. Regenerate wg0.conf without the removed peers
  Either way, <client-name>.zip is rebuilt from the configs the client still
  holds, or removed when it holds none.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

# Allow importing lib/ modules from scripts directory (container and dev paths)
for _scripts_path in ["/etc/vpn/scripts", str(Path(__file__).parent)]:
    if _scripts_path not in sys.path:
        sys.path.insert(0, _scripts_path)

import scalo.logger  # noqa: E402
from lib.clients import (  # noqa: E402
    bundle_zip,
    client_files,
    openvpn_files,
    owned_files,
    wireguard_files,
)
from lib.management import (  # noqa: E402
    PASSWORD_FILE,
    RUN_DIR,
    kill_client_sessions,
)
from lib.pki import (  # noqa: E402
    EASYRSA_DIR,
    regenerate_local_crl,
    validate_client_name,
)
from lib.process import write_secret  # noqa: E402
from scalo.logger import logger  # noqa: E402

# ===============================================================================
# Configuration
# ===============================================================================

# Lazy-loaded from CULVERT_* config cascade (populated in main)
PKI_DIR = Path("/etc/vpn/pki")
OUTPUT_DIR = Path("/etc/vpn/clients")


class RevocationError(RuntimeError):
    """Revocation could not be completed, so the client still has access."""


def _wg_interface_up() -> bool:
    """Return True when a wg0 interface exists to remove a peer from.

    A missing `wg` binary means there is no WireGuard here at all, which is the
    same situation as no interface: nothing live to revoke.
    """
    try:
        result = subprocess.run(["wg", "show", "wg0"], capture_output=True, check=False)
    except FileNotFoundError:
        return False
    return result.returncode == 0


# ===============================================================================
# Client Functions
# ===============================================================================


def _rebundle_zip(client_name: str) -> None:
    """Rebuild the client's zip from what it still holds, so no revoked key stays."""
    remaining = owned_files(
        OUTPUT_DIR, client_name, client_files(OUTPUT_DIR, client_name)
    )
    bundle_zip(OUTPUT_DIR, client_name, remaining)


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


def revoke_client(client_name: str, crl_days: int, missing_ok: bool = False) -> bool:
    """Revoke a client certificate and regenerate the CRL for crl_days.

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
            "EASYRSA": str(EASYRSA_DIR),
            "EASYRSA_PKI": str(PKI_DIR),
            "EASYRSA_BATCH": "1",
        }
    )

    # Revoke certificate
    logger.info("Revoking certificate...")
    result = subprocess.run(
        ["./easyrsa", "revoke", client_name],
        cwd=EASYRSA_DIR,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        logger.error(f"Failed to revoke certificate: {result.stderr}")
        sys.exit(1)

    # Update CRL
    logger.info("Updating CRL...")
    # The failure, with Easy-RSA's stderr, is logged by the library.
    if not regenerate_local_crl(SimpleNamespace(pki_dir=PKI_DIR, crl_days=crl_days)):
        sys.exit(1)

    # The CRL stops the next handshake. A session already up carries on until it
    # renegotiates, so end it now.
    kill_client_sessions(client_name, RUN_DIR, PASSWORD_FILE)

    # Remove client files
    logger.info("Removing client files...")
    files_to_remove = [
        PKI_DIR / "private" / f"{client_name}.key",
        PKI_DIR / "private" / f"{client_name}-tc.key",
        PKI_DIR / "reqs" / f"{client_name}.req",
    ]

    # Exact filenames only: a "<name>-*" glob for foo also takes foo-bar's configs.
    files_to_remove.extend(
        owned_files(OUTPUT_DIR, client_name, openvpn_files(OUTPUT_DIR, client_name))
    )

    removed = 0
    for f in files_to_remove:
        if f.exists():
            f.unlink()
            removed += 1
            logger.info(f"  Removed: {f}")
    _rebundle_zip(client_name)

    logger.info(f"OpenVPN client {client_name} has been revoked", files_removed=removed)
    return True


# ===============================================================================
# WireGuard Revocation
# ===============================================================================


def _revoke_wireguard_peer(peer: str, peers_dir: Path) -> None:
    """Remove one peer: live interface first, then its key files and IP.

    Raises RevocationError when the live removal is refused, so a peer whose
    tunnel is still up is never reported as revoked.
    """
    from lib import wireguard

    pub_key_path = peers_dir / f"{peer}.pub"
    public_key = pub_key_path.read_text().strip()
    logger.info(f"Revoking WireGuard peer: {peer}")

    # Remove the peer from the running interface. The kernel holds the peer
    # list, so until this lands the revoked client keeps its tunnel.
    #
    # "interface not up" and "removal refused" are reported separately on
    # purpose. Treating every failure as the former - which is what catching
    # CalledProcessError alongside FileNotFoundError did - meant a refused
    # removal was logged as an inactive interface and the function still
    # reported the client revoked, while its tunnel kept working.
    if not _wg_interface_up():
        logger.info("wg0 is not up - no live peer to remove")
    else:
        removal = subprocess.run(
            ["wg", "set", "wg0", "peer", public_key, "remove"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if removal.returncode != 0:
            raise RevocationError(
                f"could not remove {peer} from the running wg0 interface"
                f" (exit {removal.returncode}): {removal.stderr.strip()}."
                " The client's tunnel is still live, so nothing has been"
                " revoked - refusing to report otherwise."
            )
        logger.info("Removed live peer from wg0 interface")

    # Delete peer public key file and the retained private key, so a later
    # generate-client mints a fresh identity rather than reusing this one.
    pub_key_path.unlink()
    logger.info(f"  Removed: {pub_key_path}")
    priv_key_path = peers_dir / f"{peer}.key"
    if priv_key_path.exists():
        priv_key_path.unlink()
        logger.info(f"  Removed: {priv_key_path}")

    # Deallocate IP
    freed_ip = wireguard.deallocate_peer_ip(PKI_DIR, peer)
    if freed_ip:
        logger.info(f"  Deallocated IP: {freed_ip}")
    else:
        logger.warning("No IP allocation found for peer", peer=peer)


def revoke_wireguard_client(client_name: str) -> bool:
    """Revoke a WireGuard client: every device slot it holds.

    Slots are read from disk rather than from the configured slot count, so
    lowering CULVERT_SHARED_CLIENT_SLOTS cannot strand a peer that still has
    access. Returns True when a peer was revoked, False when none existed.
    """
    from lib import wireguard

    wg_dir = PKI_DIR / "wireguard"
    peers_dir = wg_dir / "peers"

    peers = wireguard.existing_peer_ids(PKI_DIR, client_name)
    if not peers:
        logger.warning(
            f"WireGuard peer key not found: {client_name}",
            path=str(peers_dir / f"{client_name}.pub"),
        )
        return False

    if len(peers) > 1:
        logger.info(
            "Revoking every device slot for client",
            client=client_name,
            slots=len(peers),
        )

    for peer in peers:
        _revoke_wireguard_peer(peer, peers_dir)

    # Exact filenames only: "<name>-wg*" also matches a client named "<name>-wg-x".
    removed = 0
    for wg_conf in wireguard_files(OUTPUT_DIR, client_name):
        wg_conf.unlink()
        removed += 1
        logger.info(f"  Removed: {wg_conf}")
    _rebundle_zip(client_name)

    # Regenerate the server config without the removed peer, at the path the
    # server actually reads. Writing it under the PKI directory instead left the
    # revoked peer in the file the server loads, so a container restart brought
    # the peer back - a revocation that silently expired. The PostUp/PostDown
    # hooks go back in too, or the next wg-quick up drops the operator's rules.
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
            post_up=vcfg.wg_post_up,
            post_down=vcfg.wg_post_down,
        )
        write_secret(vcfg.wg_conf, server_conf)
        logger.info(
            "Regenerated WireGuard server config without revoked peer",
            path=str(vcfg.wg_conf),
        )
    else:
        logger.warning(
            "No WireGuard server private key found, so the server config was not"
            " regenerated - the peer is removed from the live interface but"
            " would return if the server config were rebuilt from these files",
            path=str(priv_path),
        )

    logger.info(
        f"WireGuard client {client_name} has been revoked",
        slots=len(peers),
        files_removed=removed + len(peers),
    )
    return True


# ===============================================================================
# Main
# ===============================================================================


def main() -> None:
    """Revoke a client's certificate and/or WireGuard peer from the CLI args."""
    # culvert emits no spans, so no OTLP span exporter is started.
    scalo.logger.setup(otel_tracing=False)

    parser = argparse.ArgumentParser(
        description="Revoke VPN client certificate and/or WireGuard peer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This will:
  OpenVPN:
    1. Revoke the client certificate
    2. Update the CRL
    3. Remove client files (keys, .ovpn and stunnel configs)
  WireGuard (every device slot the client holds):
    1. Remove live peers from wg0 interface
    2. Delete peer public keys and config files
    3. Deallocate IPs and regenerate server config
  Either way, <client>.zip is rebuilt from what the client still holds, or
  removed when it holds nothing.

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

    if not validate_client_name(args.client_name):
        logger.error(
            f"Invalid client name '{args.client_name}'. "
            "Use only alphanumeric, dash, underscore."
        )
        sys.exit(1)

    try:
        if args.protocol == "all":
            ovpn_revoked = revoke_client(
                args.client_name, vpn_cfg.crl_days, missing_ok=True
            )
            wg_revoked = revoke_wireguard_client(args.client_name)
            if not (ovpn_revoked or wg_revoked):
                logger.error(
                    f"No OpenVPN certificate or WireGuard peer found:"
                    f" {args.client_name}"
                )
                sys.exit(1)
        elif args.protocol == "openvpn":
            revoke_client(args.client_name, vpn_cfg.crl_days)
        elif not revoke_wireguard_client(args.client_name):
            sys.exit(1)
    except RevocationError as exc:
        # A non-zero exit with the reason named, not a traceback: the operator
        # needs to know the client still has access and why.
        logger.error(f"Revocation FAILED for {args.client_name}: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
