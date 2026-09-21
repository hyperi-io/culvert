#  Project:      culvert
#  File:         client_state.py
#  Purpose:      Track and report stale issued client configurations
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Persist the material settings used to issue static client configs.

The registry contains no credentials. It records only the endpoint, DNS shape,
and WireGuard MTU that were embedded in a client's last issued files. Legacy
clients without a record stay UNKNOWN: absence of evidence is never reported as
CURRENT.
"""

import fcntl
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_REGISTRY = "client-config-state.json"
_LOCK = "client-config-state.lock"
_VERSION = 1


@dataclass(frozen=True)
class ClientState:
    """One operator-facing issued-client status row."""

    client: str
    status: str
    reasons: tuple[str, ...]


def _dns_value(servers: list[str], domain: str) -> list[str]:
    """Canonicalise DNS exactly as the generated WireGuard line does."""
    values: list[str] = []
    for value in servers:
        value = value.strip()
        if value and value not in values:
            values.append(value)
    domain = domain.strip().lstrip("~")
    if domain and domain not in values:
        values.append(domain)
    return values


def current_protocol_state(
    *,
    client_endpoint: str,
    dns_servers: list[str],
    dns_domain: str,
    wg_mtu: int,
) -> dict[str, dict[str, object]]:
    """Build the material settings embedded by each client protocol."""
    dns = _dns_value(dns_servers, dns_domain)
    return {
        # OpenVPN receives DNS from the live server, so it is not embedded in
        # the static client file. The dialled endpoint is.
        "openvpn": {"endpoint": client_endpoint},
        "wireguard": {
            "endpoint": client_endpoint,
            "dns": dns,
            "mtu": wg_mtu,
        },
    }


@contextmanager
def _registry_lock(pki_dir: Path) -> Iterator[None]:
    """Serialise registry read-modify-write operations."""
    pki_dir.mkdir(parents=True, exist_ok=True)
    with open(pki_dir / _LOCK, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _read_registry(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"version": _VERSION, "clients": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != _VERSION or not isinstance(data.get("clients"), dict):
        raise ValueError(f"Unsupported or malformed client state registry: {path}")
    return data


def record_client_state(
    pki_dir: Path,
    client_name: str,
    protocol_state: dict[str, dict[str, object]],
) -> None:
    """Record successfully issued protocols without erasing the others."""
    registry_path = pki_dir / _REGISTRY
    with _registry_lock(pki_dir):
        registry = _read_registry(registry_path)
        clients = registry["clients"]
        assert isinstance(clients, dict)
        prior = clients.get(client_name, {})
        if not isinstance(prior, dict):
            raise ValueError(f"Malformed client entry in registry: {client_name}")
        clients[client_name] = {**prior, **protocol_state}

        temporary = registry_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.chmod(0o600)
        os.replace(temporary, registry_path)
        registry_path.chmod(0o600)


def _known_clients(pki_dir: Path) -> dict[str, set[str]]:
    known: dict[str, set[str]] = {}
    issued = pki_dir / "issued"
    if issued.exists():
        for certificate in issued.glob("*.crt"):
            known.setdefault(certificate.stem, set()).add("openvpn")

    peers = pki_dir / "wireguard" / "peers"
    if peers.exists():
        for public_key in peers.glob("*.pub"):
            peer = public_key.stem
            base, separator, slot = peer.rpartition(".")
            client = base if separator and slot.isdigit() else peer
            known.setdefault(client, set()).add("wireguard")
    return known


def inspect_client_states(
    pki_dir: Path,
    current_state: dict[str, dict[str, object]],
) -> list[ClientState]:
    """Compare issued clients with today's material generation settings."""
    registry = _read_registry(pki_dir / _REGISTRY)
    clients = registry["clients"]
    assert isinstance(clients, dict)
    rows: list[ClientState] = []

    for client, protocols in sorted(_known_clients(pki_dir).items()):
        issued = clients.get(client)
        if not isinstance(issued, dict):
            rows.append(ClientState(client, "UNKNOWN", ("no issuance record",)))
            continue

        differences: list[str] = []
        missing: list[str] = []
        for protocol in sorted(protocols):
            recorded = issued.get(protocol)
            current = current_state.get(protocol)
            if not isinstance(recorded, dict) or not isinstance(current, dict):
                missing.append(f"{protocol}: no issuance record")
                continue
            for field in ("endpoint", "dns", "mtu"):
                if field not in current:
                    continue
                if recorded.get(field) != current[field]:
                    differences.append(f"{protocol}.{field}")

        if differences:
            rows.append(ClientState(client, "STALE", tuple(differences + missing)))
        elif missing:
            rows.append(ClientState(client, "UNKNOWN", tuple(missing)))
        else:
            rows.append(ClientState(client, "CURRENT", ()))
    return rows
