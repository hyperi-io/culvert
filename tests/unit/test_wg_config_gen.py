#  Project:      culvert
#  File:         test_wg_config_gen.py
#  Purpose:      Unit tests for WireGuard configuration file generation
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from lib.wireguard import (
    generate_client_config,
    generate_https_tunnel_client_config,
    generate_server_config,
)

FAKE_SERVER_PRIV = "sServerPrivateKeyBase64000000000000000000000="
FAKE_SERVER_PUB = "sServerPublicKeyBase640000000000000000000000="
FAKE_CLIENT_PRIV = "cClientPrivateKeyBase64000000000000000000000="


@pytest.fixture()
def wg_peers(tmp_path: Path) -> tuple[Path, Path]:
    """Create peers directory and allocations file for testing."""
    peers_dir = tmp_path / "peers"
    peers_dir.mkdir()
    alloc_file = tmp_path / "allocations.json"
    return peers_dir, alloc_file


class TestGenerateServerConfig:
    """Tests for generate_server_config."""

    def test_interface_fields(self, wg_peers: tuple[Path, Path]) -> None:
        """Server config contains correct [Interface] section fields."""
        peers_dir, alloc_file = wg_peers
        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.0.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )

        assert "[Interface]" in config
        assert f"PrivateKey = {FAKE_SERVER_PRIV}" in config
        assert "Address = 10.8.0.1/24" in config
        assert "ListenPort = 51820" in config
        assert "MTU = 1420" in config

    def test_includes_peers_from_allocations(self, wg_peers: tuple[Path, Path]) -> None:
        """Server config generates [Peer] sections from allocations + pub keys."""
        peers_dir, alloc_file = wg_peers

        # Set up allocations and peer public keys
        allocations = {"alice": "10.8.0.2", "bob": "10.8.0.3"}
        alloc_file.write_text(json.dumps(allocations) + "\n")
        (peers_dir / "alice.pub").write_text(
            "AlicePublicKeyBase64000000000000000000000000=\n"
        )
        (peers_dir / "bob.pub").write_text(
            "BobPublicKeyBase640000000000000000000000000000=\n"
        )

        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.0.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )

        assert "# alice" in config
        assert "# bob" in config
        assert "[Peer]" in config
        assert "AllowedIPs = 10.8.0.2/32" in config
        assert "AllowedIPs = 10.8.0.3/32" in config
        assert "AlicePublicKeyBase64000000000000000000000000=" in config
        assert "BobPublicKeyBase640000000000000000000000000000=" in config

    def test_skips_peer_without_pubkey(self, wg_peers: tuple[Path, Path]) -> None:
        """Peers without a .pub file in the peers directory are skipped."""
        peers_dir, alloc_file = wg_peers

        allocations = {"alice": "10.8.0.2", "no_key": "10.8.0.3"}
        alloc_file.write_text(json.dumps(allocations) + "\n")
        (peers_dir / "alice.pub").write_text("AlicePubKey=\n")

        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.0.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )

        assert "# alice" in config
        assert "no_key" not in config

    def test_custom_post_up_down(self, wg_peers: tuple[Path, Path]) -> None:
        """PostUp and PostDown lines appear when provided."""
        peers_dir, alloc_file = wg_peers
        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.0.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
            post_up="iptables -A FORWARD -i wg0 -j ACCEPT",
            post_down="iptables -D FORWARD -i wg0 -j ACCEPT",
        )

        assert "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT" in config
        assert "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT" in config

    def test_no_post_up_down_by_default(self, wg_peers: tuple[Path, Path]) -> None:
        """PostUp and PostDown lines are absent when not provided."""
        peers_dir, alloc_file = wg_peers
        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.0.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )

        assert "PostUp" not in config
        assert "PostDown" not in config


class TestGenerateClientConfig:
    """Tests for generate_client_config."""

    def test_full_tunnel_allowed_ips(self) -> None:
        """Full tunnel config routes all traffic through VPN."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            allowed_ips="0.0.0.0/0, ::/0",
        )

        assert "AllowedIPs = 0.0.0.0/0, ::/0" in config

    def test_split_tunnel_allowed_ips(self) -> None:
        """Split tunnel config routes only VPN subnet."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            allowed_ips="10.8.0.0/24, 192.168.1.0/24",
        )

        assert "AllowedIPs = 10.8.0.0/24, 192.168.1.0/24" in config

    def test_dns_domain_appended(self) -> None:
        """DNS domain is appended to the DNS line when provided."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1", "1.1.1.1"],
            dns_domain="corp.example.com",
        )

        assert "DNS = 10.8.0.1, 1.1.1.1, corp.example.com" in config

    def test_no_dns_domain(self) -> None:
        """DNS line has only servers when no domain is specified."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "DNS = 10.8.0.1" in config
        assert "DNS = 10.8.0.1," not in config

    def test_pubkey_mode_placeholder(self) -> None:
        """When private key is None, placeholder text is used."""
        config = generate_client_config(
            client_private_key=None,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "PrivateKey = YOUR_PRIVATE_KEY_HERE" in config

    def test_persistent_keepalive_included(self) -> None:
        """PersistentKeepalive line appears with a non-zero value."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            persistent_keepalive=25,
        )

        assert "PersistentKeepalive = 25" in config

    def test_persistent_keepalive_omitted_when_zero(self) -> None:
        """PersistentKeepalive line is omitted when set to 0."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            persistent_keepalive=0,
        )

        assert "PersistentKeepalive" not in config

    def test_endpoint_format(self) -> None:
        """Endpoint line has correct host:port format."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "Endpoint = vpn.example.com:51820" in config

    def test_client_address_format(self) -> None:
        """Client address uses /32 prefix."""
        config = generate_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.5",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "Address = 10.8.0.5/32" in config


class TestGenerateHttpsTunnelClientConfig:
    """Tests for generate_https_tunnel_client_config."""

    def test_endpoint_is_localhost(self) -> None:
        """HTTPS-tunnel config uses 127.0.0.1:51820 as endpoint for wstunnel."""
        config = generate_https_tunnel_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "Endpoint = 127.0.0.1:51820" in config
        assert "vpn.example.com:51820" not in config.split("\n[")[1]

    def test_wstunnel_instructions_in_comments(self) -> None:
        """HTTPS-tunnel config has wstunnel instructions as comments at the top."""
        config = generate_https_tunnel_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "# WireGuard over HTTPS" in config
        assert "wstunnel client" in config
        assert "wss://vpn.example.com" in config

    def test_wstunnel_port_in_command(self) -> None:
        """The wstunnel command uses the specified wstunnel port."""
        config = generate_https_tunnel_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            wstunnel_port=8443,
        )

        assert "wss://vpn.example.com:8443" in config

    def test_https_config_has_interface_and_peer(self) -> None:
        """HTTPS-tunnel config still contains valid [Interface] and [Peer] sections."""
        config = generate_https_tunnel_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "[Interface]" in config
        assert "[Peer]" in config
        assert f"PrivateKey = {FAKE_CLIENT_PRIV}" in config
        assert f"PublicKey = {FAKE_SERVER_PUB}" in config

    def test_https_config_pubkey_mode(self) -> None:
        """HTTPS-tunnel config uses placeholder when private key is None."""
        config = generate_https_tunnel_client_config(
            client_private_key=None,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
        )

        assert "PrivateKey = YOUR_PRIVATE_KEY_HERE" in config

    def test_https_config_dns_domain(self) -> None:
        """HTTPS-tunnel config appends DNS domain when provided."""
        config = generate_https_tunnel_client_config(
            client_private_key=FAKE_CLIENT_PRIV,
            client_ip="10.8.0.2",
            server_public_key=FAKE_SERVER_PUB,
            server_endpoint="vpn.example.com",
            server_port=51820,
            dns_servers=["10.8.0.1"],
            dns_domain="corp.example.com",
        )

        assert "DNS = 10.8.0.1, corp.example.com" in config


class TestGenerateClientConfigWrapper:
    """generate-client's own Config wrapper, which is easy to leave incomplete.

    It copies selected fields off lib.config.Config rather than subclassing it,
    so a field the script uses but never copies shows up only as an
    AttributeError at the moment someone issues a client.
    """

    @staticmethod
    def _wrapper_class():
        import importlib.util

        path = Path(__file__).resolve().parents[2] / "scripts" / "generate-client.py"
        spec = importlib.util.spec_from_file_location("generate_client_script", path)
        assert spec is not None and spec.loader is not None, f"cannot load {path}"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.Config

    def test_carries_every_field_the_wireguard_path_uses(self) -> None:
        """Issuing a WireGuard client rewrites AND reloads the server config."""
        cfg = self._wrapper_class()()
        for field in (
            "wg_conf",
            "wg_post_up",
            "wg_post_down",
            "wg_network",
            "wg_port",
            "wg_mtu",
        ):
            assert hasattr(cfg, field), (
                f"generate-client's Config wrapper does not copy {field}, so"
                " generate_wireguard_configs raises AttributeError"
            )


class TestBundleClientZip:
    """generate-client bundles each client's files into <name>.zip."""

    @staticmethod
    def _module():
        import importlib.util

        path = Path(__file__).resolve().parents[2] / "scripts" / "generate-client.py"
        spec = importlib.util.spec_from_file_location("generate_client_script", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_bundles_only_this_clients_files(self, tmp_path: Path) -> None:
        """The zip holds alice's files and none of bob's."""
        import stat
        import zipfile

        (tmp_path / "alice-udp-split.ovpn").write_text("a1")
        (tmp_path / "alice-wg-split.conf").write_text("a2")
        (tmp_path / "bob-udp-split.ovpn").write_text("b1")

        zip_path = self._module()._bundle_client_zip("alice", tmp_path)

        assert zip_path == tmp_path / "alice.zip"
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
        assert names == {"alice-udp-split.ovpn", "alice-wg-split.conf"}
        assert stat.S_IMODE(zip_path.stat().st_mode) == 0o600

    def test_excludes_existing_zip_and_returns_none_when_empty(
        self, tmp_path: Path
    ) -> None:
        """A prior <name>.zip is never nested, and no files means no zip."""
        (tmp_path / "carol.zip").write_text("stale")
        assert self._module()._bundle_client_zip("carol", tmp_path) is None
