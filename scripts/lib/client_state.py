#  Project:      culvert
#  File:         client_state.py
#  Purpose:      Track and report stale issued client configurations
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Persist the server settings used to issue static client configs.

The registry contains no credentials. It records, per client and protocol, the
server-side settings embedded in the client's last issued files. Clients
without a record stay UNKNOWN: absence of evidence is never reported as CURRENT.
"""

import fcntl
import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from lib import wireguard

_REGISTRY = "client-config-state.json"
_LOCK = "client-config-state.lock"
_VERSION = 1

# The server's own certificate sits in issued/ beside the clients' certificates.
_SERVER_CERT = "server"


@dataclass(frozen=True, slots=True)
class ClientState:
    """One operator-facing issued-client status row.

    Attributes:
        client: The client name.
        status: CURRENT, STALE or UNKNOWN.
        reasons: The changed or unrecorded settings, as protocol.field.

    """

    client: str
    status: str
    reasons: tuple[str, ...]


def _sha256(path: Path) -> str | None:
    """Return the hex SHA-256 of a file, or None when it does not exist."""
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stripped_text(path: Path) -> str | None:
    """Return a file's stripped content, or None when it does not exist."""
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8").strip()


def current_protocol_state(cfg) -> dict[str, dict[str, object]]:
    """Return the server-side settings each protocol embeds in a client's files.

    Per-run arguments such as --routes and --proxy are the operator's choice at
    issue time and are not compared. OpenVPN DNS is pushed live by the server,
    so it is not embedded either.

    Args:
        cfg: generate-client's Config, or anything carrying the same fields.

    Returns:
        A mapping of protocol to the settings its files carry.

    """
    https_tunnel = None
    if cfg.wg_https_tunnel_enabled:
        https_tunnel = {"port": cfg.wg_https_tunnel_port, "server_cn": cfg.server_cn}

    return {
        "openvpn": {
            "endpoint": cfg.client_endpoint,
            "server_cn": cfg.server_cn,
            "udp_port": cfg.udp_port,
            "tcp_port": cfg.tcp_port,
            "https_port": cfg.https_port,
            "ca": _sha256(cfg.pki_dir / "ca.crt"),
        },
        "wireguard": {
            "endpoint": cfg.client_endpoint,
            "port": cfg.wg_port,
            "server_key": _stripped_text(
                cfg.pki_dir / "wireguard" / "server_public.key"
            ),
            "dns": wireguard.build_dns_line(cfg.dns_servers, cfg.dns_domain),
            "mtu": cfg.wg_mtu,
            "keepalive": cfg.wg_persistent_keepalive,
            "split_routes": wireguard.split_allowed_ips(
                cfg.push_routes, cfg.wg_network
            ),
            "https_tunnel": https_tunnel,
        },
    }


@contextmanager
def _registry_lock(pki_dir: Path) -> Iterator[None]:
    """Serialise registry read-modify-write operations."""
    pki_dir.mkdir(parents=True, exist_ok=True)
    with open(pki_dir / _LOCK, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _read_clients(path: Path) -> dict[str, object]:
    """Return the registry's per-client records, empty when there is no registry.

    Raises:
        ValueError: The registry is not valid JSON or not this version's shape.

    """
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != _VERSION:
        raise ValueError(f"Unsupported or malformed client state registry: {path}")
    clients = data.get("clients")
    if not isinstance(clients, dict):
        raise ValueError(f"Unsupported or malformed client state registry: {path}")
    return clients


def record_client_state(
    pki_dir: Path,
    client_name: str,
    protocol_state: dict[str, dict[str, object]],
) -> None:
    """Record successfully issued protocols without erasing the others.

    Args:
        pki_dir: The PKI directory holding the registry.
        client_name: The client just issued.
        protocol_state: The settings of each protocol that was issued.

    Raises:
        ValueError: The registry or the client's entry in it is malformed.
        OSError: The registry could not be read or written.

    """
    registry_path = pki_dir / _REGISTRY
    with _registry_lock(pki_dir):
        clients = _read_clients(registry_path)
        prior = clients.get(client_name, {})
        if not isinstance(prior, dict):
            raise ValueError(f"Malformed client entry in registry: {client_name}")
        clients[client_name] = {**prior, **protocol_state}

        temporary = registry_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {"version": _VERSION, "clients": clients}, indent=2, sort_keys=True
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, registry_path)


def _known_clients(pki_dir: Path) -> dict[str, set[str]]:
    """Return every issued client and the protocols it holds credentials for."""
    known: dict[str, set[str]] = {}
    issued = pki_dir / "issued"
    if issued.exists():
        for certificate in issued.glob("*.crt"):
            if certificate.stem != _SERVER_CERT:
                known.setdefault(certificate.stem, set()).add("openvpn")

    peers = pki_dir / "wireguard" / "peers"
    if peers.exists():
        for public_key in peers.glob("*.pub"):
            peer = public_key.stem
            base, separator, slot = peer.rpartition(".")
            client = base if separator and slot.isdigit() else peer
            known.setdefault(client, set()).add("wireguard")
    return known


def _compare(
    protocol: str, recorded: object, current: dict[str, object]
) -> tuple[list[str], list[str]]:
    """Return (changed, unrecorded) protocol.field names for one protocol."""
    if not isinstance(recorded, dict):
        return [], [f"{protocol}: no issuance record"]
    changed: list[str] = []
    unrecorded: list[str] = []
    for field, value in current.items():
        if field not in recorded:
            unrecorded.append(f"{protocol}.{field}: not recorded")
        elif recorded[field] != value:
            changed.append(f"{protocol}.{field}")
    return changed, unrecorded


def inspect_client_states(
    pki_dir: Path,
    current_state: dict[str, dict[str, object]],
) -> list[ClientState]:
    """Compare issued clients with today's settings.

    Args:
        pki_dir: The PKI directory holding the certificates, peers and registry.
        current_state: What current_protocol_state returns for today's config.

    Returns:
        One row per issued client, sorted by name.

    Raises:
        ValueError: The registry is malformed.

    """
    clients = _read_clients(pki_dir / _REGISTRY)
    rows: list[ClientState] = []

    for client, protocols in sorted(_known_clients(pki_dir).items()):
        issued = clients.get(client)
        if not isinstance(issued, dict):
            rows.append(ClientState(client, "UNKNOWN", ("no issuance record",)))
            continue

        changed: list[str] = []
        unrecorded: list[str] = []
        for protocol in sorted(protocols):
            protocol_changed, protocol_unrecorded = _compare(
                protocol, issued.get(protocol), current_state[protocol]
            )
            changed += protocol_changed
            unrecorded += protocol_unrecorded

        if changed:
            rows.append(ClientState(client, "STALE", tuple(changed + unrecorded)))
        elif unrecorded:
            rows.append(ClientState(client, "UNKNOWN", tuple(unrecorded)))
        else:
            rows.append(ClientState(client, "CURRENT", ()))
    return rows
