#  Project:      culvert
#  File:         clients.py
#  Purpose:      The files generate-client writes for one client
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""The files generate-client writes for one client in the clients directory.

A client name may contain "-", so one name can prefix another: "alice" and
"alice-laptop". A "<name>-*" glob for alice also returns alice-laptop's configs,
private keys included. Each file is matched instead on the exact suffix
generate-client writes after "<name>-", so one client's files are never bundled
with, or deleted alongside, another client's.

One filename is ambiguous by construction: "<name>-proxy-stunnel.conf" is also
the direct stunnel config of a client named "<name>-proxy". generate-client
refuses to issue such a name (collides_with_proxy_stunnel). A client issued
before that check can still hold the shared file, and owned_files keeps it while
the other client still has configs of its own. Stunnel configs carry no key
material.
"""

import glob
import os
import re
import zipfile
from pathlib import Path

from scalo.logger import logger

# generate-client --proxy appends this to the client name, before "-stunnel.conf".
PROXY_SUFFIX = "-proxy"

# The six listener x mode configs, the --proxy pair, and their stunnel configs.
_OPENVPN_SUFFIX = re.compile(
    r"(?:udp|tcp|https|proxy)-(?:split|full)\.ovpn|(?:proxy-)?stunnel\.conf"
)

# Slot 1 carries no number and later slots start at 2, as wireguard.slot_infix.
_WIREGUARD_SUFFIX = re.compile(
    r"wg(?:[2-9]|[1-9][0-9]+)?(?:-https)?-(?:split|full)\.conf"
)


def _matching(
    output_dir: Path, client_name: str, suffix: re.Pattern[str]
) -> list[Path]:
    """Return the files in output_dir named "<client_name>-<suffix>"."""
    prefix = f"{client_name}-"
    return sorted(
        path
        for path in output_dir.glob(f"{glob.escape(prefix)}*")
        if suffix.fullmatch(path.name[len(prefix) :]) and path.is_file()
    )


def openvpn_files(output_dir: Path, client_name: str) -> list[Path]:
    """Return the client's .ovpn and stunnel configs in output_dir.

    Args:
        output_dir: The directory generate-client writes client configs to.
        client_name: The client, already checked by validate_client_name.

    Returns:
        The matching files, sorted. Empty when there are none or the
        directory does not exist.

    """
    return _matching(output_dir, client_name, _OPENVPN_SUFFIX)


def wireguard_files(output_dir: Path, client_name: str) -> list[Path]:
    """Return the client's WireGuard configs in output_dir, for every slot.

    Args:
        output_dir: The directory generate-client writes client configs to.
        client_name: The client, already checked by validate_client_name.

    Returns:
        The matching files, sorted. Empty when there are none or the
        directory does not exist.

    """
    return _matching(output_dir, client_name, _WIREGUARD_SUFFIX)


def client_files(output_dir: Path, client_name: str) -> list[Path]:
    """Return every config generate-client wrote for the client in output_dir.

    Args:
        output_dir: The directory generate-client writes client configs to.
        client_name: The client, already checked by validate_client_name.

    Returns:
        The OpenVPN, stunnel and WireGuard configs, sorted.

    """
    return sorted(
        [
            *openvpn_files(output_dir, client_name),
            *wireguard_files(output_dir, client_name),
        ]
    )


def collides_with_proxy_stunnel(client_name: str) -> bool:
    """Return whether client_name would share another client's stunnel config file.

    A client named "<x>-proxy" writes "<x>-proxy-stunnel.conf", the file that
    generate-client --proxy writes for client "<x>". The match ignores case
    because the clients directory is normally a host bind mount, and on a
    case-insensitive host "x-PROXY-stunnel.conf" and "x-proxy-stunnel.conf" are
    one file.

    Args:
        client_name: The client about to be issued, already checked by
            validate_client_name.

    Returns:
        True when the name ends in "-proxy".

    """
    return client_name.lower().endswith(PROXY_SUFFIX)


def _other_writer(path: Path, client_name: str) -> str | None:
    """Return the other client that writes the same filename, or None."""
    if path.name == f"{client_name}{PROXY_SUFFIX}-stunnel.conf":
        return f"{client_name}{PROXY_SUFFIX}"
    if path.name == f"{client_name}-stunnel.conf" and client_name.endswith(
        PROXY_SUFFIX
    ):
        return client_name.removesuffix(PROXY_SUFFIX)
    return None


def owned_files(output_dir: Path, client_name: str, files: list[Path]) -> list[Path]:
    """Drop the files another client also writes while it has configs of its own.

    Revocation removes what this returns, so a file shared by construction
    stays for the client still using it.

    Args:
        output_dir: The directory generate-client writes client configs to.
        client_name: The client the files were matched for.
        files: Files already matched for client_name.

    Returns:
        The files that belong to client_name alone, in their given order.

    """
    owned = []
    for path in files:
        other = _other_writer(path, client_name)
        if other and any(p != path for p in client_files(output_dir, other)):
            logger.info("Kept a config another client also uses", path=str(path))
            continue
        owned.append(path)
    return owned


def bundle_zip(output_dir: Path, client_name: str, members: list[Path]) -> Path | None:
    """Write members to <client_name>.zip with mode 0600, or remove the zip.

    The zip carries private keys, so it is created 0600 rather than chmodded
    after the write, and removed when there is nothing left to put in it.

    Args:
        output_dir: The directory generate-client writes client configs to.
        client_name: The client the zip is named for.
        members: The client's files to bundle.

    Returns:
        The zip path, or None when members is empty and the zip was removed.

    """
    zip_path = output_dir / f"{client_name}.zip"
    if not members:
        if zip_path.exists():
            zip_path.unlink()
            logger.info("Removed client zip", zip=str(zip_path))
        return None

    fd = os.open(zip_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as handle:
        with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
            for member in members:
                archive.write(member, member.name)
    logger.info("Bundled client configs", zip=str(zip_path), files=len(members))
    return zip_path
