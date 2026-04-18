#  Project:      hyperi-vpn
#  File:         test_wireguard_keys.py
#  Purpose:      Unit tests for WireGuard key management and IP allocation
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import json
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from lib.wireguard import (
    allocate_peer_ip,
    deallocate_peer_ip,
    generate_server_keys,
    validate_subnets_no_overlap,
)

FAKE_PRIVATE = "cFakePrivateKeyBase64EncodedValue000000000000="
FAKE_PUBLIC = "cFakePublicKeyBase64EncodedValueX000000000000="


@pytest.fixture()
def pki_dir(tmp_path: Path) -> Path:
    """Provide a temporary PKI directory."""
    pki = tmp_path / "pki"
    pki.mkdir()
    return pki


class TestGenerateServerKeys:
    """Tests for generate_server_keys."""

    def test_creates_keys_when_missing(self, pki_dir: Path) -> None:
        """Keys are generated and written to disk with correct permissions."""
        with patch("lib.wireguard.subprocess.check_output") as mock_co:
            mock_co.side_effect = [
                FAKE_PRIVATE.encode(),
                FAKE_PUBLIC.encode(),
            ]
            private, public = generate_server_keys(pki_dir)

        assert private == FAKE_PRIVATE
        assert public == FAKE_PUBLIC

        priv_path = pki_dir / "wireguard" / "server_private.key"
        pub_path = pki_dir / "wireguard" / "server_public.key"
        assert priv_path.exists()
        assert pub_path.exists()
        assert priv_path.read_text().strip() == FAKE_PRIVATE
        assert pub_path.read_text().strip() == FAKE_PUBLIC

        # Private key should have 0600 permissions
        mode = priv_path.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_creates_peers_directory(self, pki_dir: Path) -> None:
        """Peers subdirectory is created alongside keys."""
        with patch("lib.wireguard.subprocess.check_output") as mock_co:
            mock_co.side_effect = [
                FAKE_PRIVATE.encode(),
                FAKE_PUBLIC.encode(),
            ]
            generate_server_keys(pki_dir)

        peers_dir = pki_dir / "wireguard" / "peers"
        assert peers_dir.is_dir()

    def test_reuses_existing_keys(self, pki_dir: Path) -> None:
        """Existing keys are read from disk, not regenerated."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)
        (wg_dir / "server_private.key").write_text(FAKE_PRIVATE + "\n")
        (wg_dir / "server_public.key").write_text(FAKE_PUBLIC + "\n")

        with patch("lib.wireguard.subprocess.check_output") as mock_co:
            private, public = generate_server_keys(pki_dir)
            mock_co.assert_not_called()

        assert private == FAKE_PRIVATE
        assert public == FAKE_PUBLIC


class TestAllocatePeerIp:
    """Tests for allocate_peer_ip."""

    def test_assigns_first_ip_at_dot_2(self, pki_dir: Path) -> None:
        """First client gets .2 since .1 is reserved for the server."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        ip = allocate_peer_ip(pki_dir, "10.8.0.0/24", "alice")
        assert ip == "10.8.0.2"

    def test_assigns_sequential_ips(self, pki_dir: Path) -> None:
        """Multiple clients get sequential addresses."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        ip1 = allocate_peer_ip(pki_dir, "10.8.0.0/24", "alice")
        ip2 = allocate_peer_ip(pki_dir, "10.8.0.0/24", "bob")
        ip3 = allocate_peer_ip(pki_dir, "10.8.0.0/24", "charlie")

        assert ip1 == "10.8.0.2"
        assert ip2 == "10.8.0.3"
        assert ip3 == "10.8.0.4"

    def test_skips_server_ip(self, pki_dir: Path) -> None:
        """The .1 address is never allocated to a client."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        # Allocate all IPs in a /30 (only .1, .2 are hosts)
        ip = allocate_peer_ip(pki_dir, "10.8.0.0/30", "alice")
        assert ip == "10.8.0.2"

    def test_raises_when_exhausted(self, pki_dir: Path) -> None:
        """RuntimeError raised when no IPs remain."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        # /30 has hosts .1 and .2 only; .1 is server
        allocate_peer_ip(pki_dir, "10.8.0.0/30", "alice")

        with pytest.raises(RuntimeError, match="No available IPs"):
            allocate_peer_ip(pki_dir, "10.8.0.0/30", "bob")

    def test_persists_allocations_to_json(self, pki_dir: Path) -> None:
        """Allocations are written to allocations.json."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        allocate_peer_ip(pki_dir, "10.8.0.0/24", "alice")

        alloc_file = wg_dir / "allocations.json"
        assert alloc_file.exists()
        data = json.loads(alloc_file.read_text())
        assert data["alice"] == "10.8.0.2"


class TestDeallocatePeerIp:
    """Tests for deallocate_peer_ip."""

    def test_frees_allocated_ip(self, pki_dir: Path) -> None:
        """Deallocated IP is removed from the allocations file."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        allocate_peer_ip(pki_dir, "10.8.0.0/24", "alice")
        allocate_peer_ip(pki_dir, "10.8.0.0/24", "bob")

        freed = deallocate_peer_ip(pki_dir, "alice")
        assert freed == "10.8.0.2"

        data = json.loads((wg_dir / "allocations.json").read_text())
        assert "alice" not in data
        assert "bob" in data

    def test_freed_ip_is_reused(self, pki_dir: Path) -> None:
        """A deallocated IP can be reassigned to a new client."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)

        allocate_peer_ip(pki_dir, "10.8.0.0/24", "alice")
        allocate_peer_ip(pki_dir, "10.8.0.0/24", "bob")
        deallocate_peer_ip(pki_dir, "alice")

        ip = allocate_peer_ip(pki_dir, "10.8.0.0/24", "charlie")
        assert ip == "10.8.0.2"

    def test_returns_none_for_unknown_client(self, pki_dir: Path) -> None:
        """Deallocating an unknown client returns None."""
        wg_dir = pki_dir / "wireguard"
        wg_dir.mkdir(parents=True)
        alloc_file = wg_dir / "allocations.json"
        alloc_file.write_text("{}\n")

        result = deallocate_peer_ip(pki_dir, "nonexistent")
        assert result is None

    def test_returns_none_when_no_file(self, pki_dir: Path) -> None:
        """Deallocating when no allocations file exists returns None."""
        result = deallocate_peer_ip(pki_dir, "anyone")
        assert result is None


class TestValidateSubnetsNoOverlap:
    """Tests for validate_subnets_no_overlap."""

    def test_no_overlap(self) -> None:
        """Non-overlapping subnets produce no errors."""
        subnets = [
            ("vpn", "10.8.0.0/24"),
            ("mgmt", "10.9.0.0/24"),
        ]
        errors = validate_subnets_no_overlap(subnets)
        assert errors == []

    def test_detects_overlap(self) -> None:
        """Overlapping subnets produce an error message."""
        subnets = [
            ("vpn", "10.8.0.0/24"),
            ("other", "10.8.0.0/25"),
        ]
        errors = validate_subnets_no_overlap(subnets)
        assert len(errors) == 1
        assert "overlap" in errors[0].lower()
        assert "vpn" in errors[0]
        assert "other" in errors[0]

    def test_detects_invalid_subnet(self) -> None:
        """Invalid CIDR notation produces an error message."""
        subnets = [
            ("bad", "not-a-cidr"),
            ("good", "10.0.0.0/24"),
        ]
        errors = validate_subnets_no_overlap(subnets)
        assert len(errors) == 1
        assert "Invalid subnet" in errors[0]
        assert "bad" in errors[0]

    def test_multiple_overlaps(self) -> None:
        """Multiple overlapping pairs each produce an error."""
        subnets = [
            ("a", "10.0.0.0/16"),
            ("b", "10.0.1.0/24"),
            ("c", "10.0.2.0/24"),
        ]
        errors = validate_subnets_no_overlap(subnets)
        assert len(errors) == 2
