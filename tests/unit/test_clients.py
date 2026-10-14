#  Project:      culvert
#  File:         test_clients.py
#  Purpose:      Tests for matching a client's files in the clients directory
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Which files in the clients directory belong to which client.

A client name may contain "-", so "alice" prefixes "alice-laptop", "alice-udp"
and "alice-wg2". Each of those clients must keep its own files, because the
OpenVPN and WireGuard configs embed that client's private keys.
"""

from pathlib import Path

import pytest
from lib.clients import client_files, openvpn_files, wireguard_files

OPENVPN_SUFFIXES = [
    f"{proto}-{mode}.ovpn"
    for proto in ("udp", "tcp", "https", "proxy")
    for mode in ("split", "full")
] + ["stunnel.conf", "proxy-stunnel.conf"]

WIREGUARD_SUFFIXES = [
    f"wg{slot}{https}-{mode}.conf"
    for slot in ("", "2", "10")
    for https in ("", "-https")
    for mode in ("split", "full")
]


def _issue(directory: Path, client: str) -> list[str]:
    """Write every file generate-client can produce for client; return the names."""
    names = [f"{client}-{suffix}" for suffix in OPENVPN_SUFFIXES + WIREGUARD_SUFFIXES]
    for name in names:
        (directory / name).write_text(f"{client} key", encoding="utf-8")
    return sorted(names)


def _names(paths: list[Path]) -> list[str]:
    return [path.name for path in paths]


class TestOwnFiles:
    """Every file generate-client writes for a client is found, and nothing else."""

    def test_every_generated_file_is_found(self, tmp_path):
        expected = _issue(tmp_path, "alice")
        assert _names(client_files(tmp_path, "alice")) == expected

    def test_protocols_split_by_file(self, tmp_path):
        _issue(tmp_path, "alice")
        assert all(
            name.endswith((".ovpn", "stunnel.conf"))
            for name in _names(openvpn_files(tmp_path, "alice"))
        )
        assert all(
            name.startswith("alice-wg")
            for name in _names(wireguard_files(tmp_path, "alice"))
        )

    @pytest.mark.parametrize(
        "name",
        [
            "alice.zip",
            "vpn-client-setup.md",
            "alice-notes.txt",
            "alice-wg1-split.conf",
            "alice-wg0-split.conf",
            "alice-udp-split.ovpn.bak",
        ],
    )
    def test_files_generate_client_does_not_write_are_ignored(self, tmp_path, name):
        (tmp_path / name).write_text("x", encoding="utf-8")
        assert client_files(tmp_path, "alice") == []

    def test_a_missing_directory_has_no_files(self, tmp_path):
        assert client_files(tmp_path / "absent", "alice") == []


class TestPrefixedNames:
    """A client whose name extends another's keeps every one of its files."""

    @pytest.mark.parametrize(
        "other",
        [
            "alice-laptop",
            "alice-udp",
            "alice-https",
            "alice-stunnel",
            "alice-wg",
            "alice-wg2",
            "alice-wg-phone",
        ],
    )
    def test_files_stay_with_their_own_client(self, tmp_path, other):
        alice = _issue(tmp_path, "alice")
        theirs = _issue(tmp_path, other)

        assert _names(client_files(tmp_path, "alice")) == alice
        assert _names(client_files(tmp_path, other)) == theirs

    def test_proxy_stunnel_name_is_the_only_shared_one(self, tmp_path):
        """Both clients write alice-proxy-stunnel.conf.

        It is alice's proxy stunnel config and alice-proxy's direct one. Stunnel
        configs carry no key material, and every config with a key stays with
        its own client.
        """
        alice = set(_issue(tmp_path, "alice"))
        theirs = set(_issue(tmp_path, "alice-proxy"))

        assert set(_names(client_files(tmp_path, "alice"))) == alice
        assert set(_names(client_files(tmp_path, "alice-proxy"))) == theirs
        assert alice & theirs == {"alice-proxy-stunnel.conf"}
