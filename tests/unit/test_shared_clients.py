#  Project:      culvert
#  File:         test_shared_clients.py
#  Purpose:      Unit tests for shared client connections (allow-shared default
#                and the cascade opt-out) across OpenVPN and WireGuard
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for concurrent connections on one client identity.

A client identity is expected to carry more than one connection at a time.
The two protocols reach that differently and both are covered here: OpenVPN
through ``duplicate-cn``, WireGuard through independent device-slot peers.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from lib.config import Config
from lib.openvpn import _common_variables, _duplicate_cn_directive, generate_config
from lib.wireguard import (
    allocate_peer_ip,
    existing_peer_ids,
    generate_server_config,
    peer_id,
    peer_ids,
    slot_infix,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "config"

FAKE_SERVER_PRIV = "sServerPrivateKeyBase64000000000000000000000="

# Every server template carries the directive, so the opt-out has to reach all
# three: an operator who disabled sharing on UDP but still shared it on the TCP
# fallback would have no exclusivity at all.
SERVER_TEMPLATES = (
    "server.conf.template",
    "server-tcp.conf.template",
    "server-https.conf.template",
)


class TestSharedClientConfig:
    """The cascade fields and their opt-out."""

    def test_shared_by_default(self, clean_env):
        """Sharing is on, with room for two concurrent connections."""
        cfg = Config.from_settings()
        assert cfg.allow_shared_clients is True
        assert cfg.shared_client_slots == 2

    def test_opt_out_via_cascade(self, clean_env, monkeypatch):
        """CULVERT_ALLOW_SHARED_CLIENTS=false turns sharing off."""
        monkeypatch.setenv("CULVERT_ALLOW_SHARED_CLIENTS", "false")
        cfg = Config.from_settings()
        assert cfg.allow_shared_clients is False

    def test_opt_out_forces_a_single_slot(self, clean_env, monkeypatch):
        """A leftover slot count must not keep issuing extra peers.

        Without this the opt-out would still hand every client two WireGuard
        peers, which is exactly the sharing it was set to prevent.
        """
        monkeypatch.setenv("CULVERT_ALLOW_SHARED_CLIENTS", "false")
        monkeypatch.setenv("CULVERT_SHARED_CLIENT_SLOTS", "4")
        cfg = Config.from_settings()
        assert cfg.shared_client_slots == 1

    def test_slot_count_is_overridable(self, clean_env, monkeypatch):
        """A deployment can raise the number of concurrent devices."""
        monkeypatch.setenv("CULVERT_SHARED_CLIENT_SLOTS", "5")
        cfg = Config.from_settings()
        assert cfg.shared_client_slots == 5

    def test_zero_slots_is_a_validation_error(self, clean_env, monkeypatch):
        """Zero slots would issue a client nothing at all."""
        monkeypatch.setenv("CULVERT_SHARED_CLIENT_SLOTS", "0")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_zero_slots_still_errors_with_sharing_off(self, clean_env, monkeypatch):
        """The opt-out clamp must not launder an invalid count into a valid one.

        Clamping every count to 1 would turn a rejected 0 into an accepted 1,
        so the operator's mistake would ship as a working config.
        """
        monkeypatch.setenv("CULVERT_ALLOW_SHARED_CLIENTS", "false")
        monkeypatch.setenv("CULVERT_SHARED_CLIENT_SLOTS", "0")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        assert cfg.shared_client_slots == 0
        with pytest.raises(SystemExit):
            cfg.validate()

    @staticmethod
    def _captured_warnings(monkeypatch) -> list[str]:
        """Collect lib.config's warning lines.

        The project logs through loguru, which does not reach pytest's caplog,
        so asserting on caplog here would pass whether or not anything warned.
        """
        import lib.config

        captured: list[str] = []
        monkeypatch.setattr(
            lib.config.logger, "warning", lambda msg, *a, **k: captured.append(str(msg))
        )
        return captured

    def test_default_slots_do_not_warn(self, clean_env, monkeypatch):
        """A warning every stock deployment emits is one nobody reads."""
        monkeypatch.setenv("CULVERT_PROTOCOL", "wireguard")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        captured = self._captured_warnings(monkeypatch)
        cfg.validate()
        assert not [w for w in captured if "SHARED_CLIENT_SLOTS" in w], captured

    def test_raised_slots_report_the_pool_cost(self, clean_env, monkeypatch):
        """Raising the count above the default shrinks the address pool."""
        monkeypatch.setenv("CULVERT_PROTOCOL", "wireguard")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_SHARED_CLIENT_SLOTS", "5")
        monkeypatch.setenv("CULVERT_WG_NETWORK", "10.8.3.0/24")
        cfg = Config.from_settings()
        captured = self._captured_warnings(monkeypatch)
        cfg.validate()

        # 256 addresses less network, server and broadcast, split five ways.
        pool = [w for w in captured if "SHARED_CLIENT_SLOTS" in w]
        assert len(pool) == 1, captured
        assert "50 WireGuard clients" in pool[0]
        assert "instead of 253" in pool[0]


class TestOpenVpnDuplicateCn:
    """OpenVPN shares one certificate across sessions via duplicate-cn."""

    def test_directive_present_when_shared(self):
        cfg = Config(allow_shared_clients=True)
        assert _duplicate_cn_directive(cfg) == "duplicate-cn"

    def test_directive_names_the_opt_out_when_disabled(self):
        """The generated config says why the directive is gone."""
        cfg = Config(allow_shared_clients=False)
        rendered = _duplicate_cn_directive(cfg)
        assert not rendered.startswith("duplicate-cn")
        assert rendered.startswith("#")
        assert "CULVERT_ALLOW_SHARED_CLIENTS" in rendered

    def test_common_variables_carries_it(self):
        """Every listener's render picks the directive up from one place."""
        assert _common_variables(Config())["OPENVPN_DUPLICATE_CN"] == "duplicate-cn"

    @pytest.mark.parametrize("template_name", SERVER_TEMPLATES)
    def test_rendered_template_shares_by_default(
        self, tmp_path: Path, template_name: str
    ):
        """The real template renders an active duplicate-cn line."""
        out = tmp_path / "server.conf"
        generate_config(TEMPLATE_DIR / template_name, out, _common_variables(Config()))
        directives = [
            line.strip()
            for line in out.read_text().splitlines()
            if line.strip() == "duplicate-cn"
        ]
        assert directives == ["duplicate-cn"], (
            f"{template_name} did not render an active duplicate-cn line, so one"
            " certificate cannot hold two concurrent OpenVPN sessions"
        )

    @pytest.mark.parametrize("template_name", SERVER_TEMPLATES)
    def test_rendered_template_honours_the_opt_out(
        self, tmp_path: Path, template_name: str
    ):
        """Opting out leaves no active duplicate-cn line in any listener."""
        out = tmp_path / "server.conf"
        variables = _common_variables(Config(allow_shared_clients=False))
        generate_config(TEMPLATE_DIR / template_name, out, variables)
        active = [
            line
            for line in out.read_text().splitlines()
            if line.strip() == "duplicate-cn"
        ]
        assert active == [], (
            f"{template_name} still enables duplicate-cn with sharing opted out"
        )

    @pytest.mark.parametrize("template_name", SERVER_TEMPLATES)
    def test_no_unsubstituted_placeholder(self, tmp_path: Path, template_name: str):
        """A missed substitution would make OpenVPN refuse to start."""
        out = tmp_path / "server.conf"
        generate_config(TEMPLATE_DIR / template_name, out, _common_variables(Config()))
        assert "${OPENVPN_DUPLICATE_CN}" not in out.read_text()


class TestWireGuardSlotIdentity:
    """Slot naming, which existing deployments depend on not changing."""

    def test_first_slot_keeps_the_bare_client_name(self):
        """Peers and configs issued before slots existed stay valid."""
        assert peer_id("alice", 1) == "alice"
        assert slot_infix(1) == ""

    def test_later_slots_take_a_dotted_suffix(self):
        """A dot cannot collide with a client name (only [a-zA-Z0-9_-])."""
        assert peer_id("alice", 2) == "alice.2"
        assert peer_id("alice", 3) == "alice.3"
        assert slot_infix(2) == "2"

    def test_peer_ids_covers_every_slot(self):
        assert peer_ids("alice", 3) == ["alice", "alice.2", "alice.3"]

    def test_existing_peer_ids_finds_every_slot_on_disk(self, tmp_path: Path):
        """Revocation reads disk, not the configured count."""
        peers = tmp_path / "wireguard" / "peers"
        peers.mkdir(parents=True)
        for name in ("alice", "alice.2", "alice.3"):
            (peers / f"{name}.pub").write_text("k\n")

        assert existing_peer_ids(tmp_path, "alice") == ["alice", "alice.2", "alice.3"]

    def test_existing_peer_ids_ignores_other_clients(self, tmp_path: Path):
        """Revoking alice must not sweep up a differently named client."""
        peers = tmp_path / "wireguard" / "peers"
        peers.mkdir(parents=True)
        for name in ("alice", "alice.2", "alice-laptop", "bob"):
            (peers / f"{name}.pub").write_text("k\n")

        assert existing_peer_ids(tmp_path, "alice") == ["alice", "alice.2"]

    def test_existing_peer_ids_when_client_is_unknown(self, tmp_path: Path):
        (tmp_path / "wireguard" / "peers").mkdir(parents=True)
        assert existing_peer_ids(tmp_path, "nobody") == []


class TestWireGuardConcurrentSlots:
    """Two slots must be independently connectable at the same time."""

    def test_each_slot_gets_its_own_ip(self, tmp_path: Path):
        """Two devices on one address are indistinguishable to the server."""
        (tmp_path / "wireguard").mkdir(parents=True)
        first = allocate_peer_ip(tmp_path, "10.8.3.0/24", peer_id("alice", 1))
        second = allocate_peer_ip(tmp_path, "10.8.3.0/24", peer_id("alice", 2))

        assert first != second
        assert first == "10.8.3.2"
        assert second == "10.8.3.3"

    def test_slot_allocation_is_idempotent(self, tmp_path: Path):
        """Re-issuing a client must not shuffle a live device onto a new IP."""
        (tmp_path / "wireguard").mkdir(parents=True)
        allocate_peer_ip(tmp_path, "10.8.3.0/24", "alice")
        allocate_peer_ip(tmp_path, "10.8.3.0/24", "alice.2")

        assert allocate_peer_ip(tmp_path, "10.8.3.0/24", "alice") == "10.8.3.2"
        assert allocate_peer_ip(tmp_path, "10.8.3.0/24", "alice.2") == "10.8.3.3"

    def test_server_config_carries_a_peer_per_slot(self, tmp_path: Path):
        """The server accepts both of one client's devices concurrently.

        Two [Peer] blocks with distinct keys and distinct AllowedIPs is what
        makes the connections concurrent rather than one evicting the other.
        """
        peers_dir = tmp_path / "peers"
        peers_dir.mkdir()
        alloc_file = tmp_path / "allocations.json"
        alloc_file.write_text(
            json.dumps({"alice": "10.8.3.2", "alice.2": "10.8.3.3"}) + "\n"
        )
        (peers_dir / "alice.pub").write_text(
            "AliceSlot1PublicKey000000000000000000000000=\n"
        )
        (peers_dir / "alice.2.pub").write_text(
            "AliceSlot2PublicKey000000000000000000000000=\n"
        )

        config = generate_server_config(
            private_key=FAKE_SERVER_PRIV,
            network="10.8.3.0/24",
            listen_port=51820,
            mtu=1420,
            peers_dir=peers_dir,
            alloc_file=alloc_file,
        )

        assert config.count("[Peer]") == 2
        assert "# alice" in config
        assert "# alice.2" in config
        assert "AliceSlot1PublicKey000000000000000000000000=" in config
        assert "AliceSlot2PublicKey000000000000000000000000=" in config
        assert "AllowedIPs = 10.8.3.2/32" in config
        assert "AllowedIPs = 10.8.3.3/32" in config
