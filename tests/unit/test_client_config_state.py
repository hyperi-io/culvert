#  Project:      culvert
#  File:         test_client_config_state.py
#  Purpose:      Tests for the issued-client freshness registry and report
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Issued-client state must make stale static configs observable.

A client reported CURRENT holds files carrying every server-side setting
generate-client would write today. Anything the record cannot vouch for is
UNKNOWN, never CURRENT.
"""

import json
import stat
from importlib import util
from pathlib import Path
from types import SimpleNamespace

import pytest
from lib.client_state import (
    current_protocol_state,
    inspect_client_states,
    record_client_state,
)


def _generate_client_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "generate-client.py"
    spec = util.spec_from_file_location("generate_client_state_report", path)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cfg(pki_dir: Path, **overrides) -> SimpleNamespace:
    """The generate-client Config fields current_protocol_state reads."""
    fields = {
        "pki_dir": pki_dir,
        "client_endpoint": "vpn.example.com",
        "server_cn": "vpn.example.com",
        "udp_port": 1194,
        "tcp_port": 1194,
        "https_port": 443,
        "wg_port": 51820,
        "wg_mtu": 1420,
        "dns_servers": ["10.8.0.1", "1.1.1.1"],
        "dns_domain": "corp.example.com",
        "wg_persistent_keepalive": 25,
        "push_routes": "10.1.0.0/16",
        "wg_network": "10.8.3.0/24",
        "wg_https_tunnel_enabled": False,
        "wg_https_tunnel_port": 4443,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _current(pki_dir: Path, **overrides) -> dict[str, dict[str, object]]:
    return current_protocol_state(_cfg(pki_dir, **overrides))


def _known_client(pki_dir: Path, name: str) -> None:
    issued = pki_dir / "issued"
    issued.mkdir(parents=True, exist_ok=True)
    (issued / f"{name}.crt").write_text("certificate", encoding="utf-8")


def _known_wireguard_client(pki_dir: Path, name: str) -> None:
    peers = pki_dir / "wireguard" / "peers"
    peers.mkdir(parents=True, exist_ok=True)
    (peers / f"{name}.pub").write_text("key", encoding="utf-8")


def _both_protocols(pki_dir: Path, name: str = "alice") -> None:
    _known_client(pki_dir, name)
    _known_wireguard_client(pki_dir, name)


@pytest.fixture
def pki(tmp_path: Path) -> Path:
    """A PKI directory with a CA and a WireGuard server key to fingerprint."""
    (tmp_path / "wireguard").mkdir()
    (tmp_path / "ca.crt").write_text("ca one", encoding="utf-8")
    (tmp_path / "wireguard" / "server_public.key").write_text(
        "ServerKeyOne=\n", encoding="utf-8"
    )
    return tmp_path


class TestIssuedClientState:
    def test_the_server_certificate_is_not_a_client(self, pki: Path) -> None:
        _known_client(pki, "server")
        _known_client(pki, "alice")
        record_client_state(pki, "alice", _current(pki))

        rows = inspect_client_states(pki, _current(pki))

        assert [(row.client, row.status) for row in rows] == [("alice", "CURRENT")]

    def test_matching_issue_record_is_current(self, pki: Path) -> None:
        _known_client(pki, "alice")
        record_client_state(pki, "alice", _current(pki))

        rows = inspect_client_states(pki, _current(pki))

        assert [(row.client, row.status, row.reasons) for row in rows] == [
            ("alice", "CURRENT", ())
        ]

    def test_reports_every_material_change_by_protocol(self, pki: Path) -> None:
        _both_protocols(pki)
        record_client_state(pki, "alice", _current(pki))

        changed = _current(
            pki,
            client_endpoint="203.0.113.10",
            dns_servers=["9.9.9.9", ""],
            dns_domain="new.example.com",
            wg_mtu=1280,
        )
        [row] = inspect_client_states(pki, changed)

        assert row.status == "STALE"
        assert row.reasons == (
            "openvpn.endpoint",
            "wireguard.endpoint",
            "wireguard.dns",
            "wireguard.mtu",
        )

    @pytest.mark.parametrize(
        ("override", "reason"),
        [
            ({"udp_port": 1195}, "openvpn.udp_port"),
            ({"tcp_port": 8443}, "openvpn.tcp_port"),
            ({"https_port": 8443}, "openvpn.https_port"),
            ({"server_cn": "vpn2.example.com"}, "openvpn.server_cn"),
            ({"wg_port": 51821}, "wireguard.port"),
            ({"wg_persistent_keepalive": 0}, "wireguard.keepalive"),
            ({"push_routes": "10.1.0.0/16,10.2.0.0/16"}, "wireguard.split_routes"),
            ({"wg_network": "10.9.0.0/24"}, "wireguard.split_routes"),
            ({"wg_https_tunnel_enabled": True}, "wireguard.https_tunnel"),
        ],
    )
    def test_every_server_setting_a_file_embeds_is_compared(
        self, pki: Path, override: dict, reason: str
    ) -> None:
        _both_protocols(pki)
        record_client_state(pki, "alice", _current(pki))

        [row] = inspect_client_states(pki, _current(pki, **override))

        assert row.status == "STALE"
        assert reason in row.reasons

    def test_a_replaced_ca_makes_openvpn_stale(self, pki: Path) -> None:
        _known_client(pki, "alice")
        record_client_state(pki, "alice", _current(pki))
        (pki / "ca.crt").write_text("ca two", encoding="utf-8")

        [row] = inspect_client_states(pki, _current(pki))

        assert row.reasons == ("openvpn.ca",)

    def test_a_replaced_server_key_makes_wireguard_stale(self, pki: Path) -> None:
        _known_wireguard_client(pki, "alice")
        record_client_state(pki, "alice", _current(pki))
        (pki / "wireguard" / "server_public.key").write_text("ServerKeyTwo=\n")

        [row] = inspect_client_states(pki, _current(pki))

        assert row.reasons == ("wireguard.server_key",)

    def test_client_without_a_record_is_unknown_not_current(self, pki: Path) -> None:
        _known_client(pki, "legacy")

        [row] = inspect_client_states(pki, _current(pki))

        assert row.client == "legacy"
        assert row.status == "UNKNOWN"
        assert row.reasons == ("no issuance record",)

    def test_a_setting_the_record_predates_is_unknown(self, pki: Path) -> None:
        _known_client(pki, "alice")
        older = _current(pki)
        del older["openvpn"]["ca"]
        record_client_state(pki, "alice", older)

        [row] = inspect_client_states(pki, _current(pki))

        assert row.status == "UNKNOWN"
        assert row.reasons == ("openvpn.ca: not recorded",)

    def test_partial_reissue_preserves_the_other_protocol_record(
        self, pki: Path
    ) -> None:
        _both_protocols(pki)
        record_client_state(pki, "alice", _current(pki))
        moved = _current(pki, client_endpoint="new.example.com")
        record_client_state(pki, "alice", {"openvpn": moved["openvpn"]})

        [row] = inspect_client_states(pki, moved)

        assert row.status == "STALE"
        assert row.reasons == ("wireguard.endpoint",)

    def test_wireguard_slots_are_one_client_identity(self, pki: Path) -> None:
        peers = pki / "wireguard" / "peers"
        peers.mkdir()
        (peers / "alice.pub").write_text("key", encoding="utf-8")
        (peers / "alice.2.pub").write_text("key", encoding="utf-8")
        record_client_state(pki, "alice", {"wireguard": _current(pki)["wireguard"]})

        rows = inspect_client_states(pki, _current(pki))

        assert [row.client for row in rows] == ["alice"]

    def test_registry_is_private_and_holds_no_key(self, pki: Path) -> None:
        record_client_state(pki, "alice", _current(pki))

        registry = pki / "client-config-state.json"

        assert stat.S_IMODE(registry.stat().st_mode) == 0o600
        assert "ca one" not in registry.read_text(encoding="utf-8")

    def test_a_malformed_registry_is_refused(self, pki: Path) -> None:
        (pki / "client-config-state.json").write_text("[]", encoding="utf-8")
        with pytest.raises(ValueError, match="malformed"):
            inspect_client_states(pki, _current(pki))


class TestOperatorReport:
    def test_names_stale_fields_and_returns_nonzero_signal(
        self, pki: Path, capsys
    ) -> None:
        _both_protocols(pki)
        record_client_state(pki, "alice", _current(pki))
        cfg = _cfg(
            pki,
            client_endpoint="new.example.com",
            dns_servers=["9.9.9.9", ""],
            dns_domain="new.example.com",
            wg_mtu=1280,
        )

        all_current = _generate_client_module()._report_client_states(cfg)

        assert all_current is False
        assert capsys.readouterr().out == (
            "STALE alice: openvpn.endpoint, wireguard.endpoint, "
            "wireguard.dns, wireguard.mtu\n"
        )

    def test_no_clients_is_successful_and_explicit(self, pki: Path, capsys) -> None:
        all_current = _generate_client_module()._report_client_states(_cfg(pki))

        assert all_current is True
        assert capsys.readouterr().out == "No issued clients found.\n"

    def test_a_malformed_registry_is_a_failure_not_a_traceback(self, pki: Path) -> None:
        (pki / "client-config-state.json").write_text("not json", encoding="utf-8")

        assert _generate_client_module()._report_client_states(_cfg(pki)) is False

    def test_recording_one_completed_protocol_does_not_bless_the_other(
        self, pki: Path
    ) -> None:
        _both_protocols(pki)
        record_client_state(pki, "alice", _current(pki))
        cfg = _cfg(pki, client_endpoint="new.example.com")

        _generate_client_module()._record_generated_protocol(cfg, "alice", "openvpn")
        [row] = inspect_client_states(pki, current_protocol_state(cfg))

        assert row.status == "STALE"
        assert row.reasons == ("wireguard.endpoint",)

    def test_an_unwritable_registry_does_not_fail_the_issue(self, pki: Path) -> None:
        """The configs are already written; losing the record costs only the report."""
        registry = pki / "client-config-state.json"
        registry.write_text(json.dumps({"version": 99}), encoding="utf-8")

        _generate_client_module()._record_generated_protocol(
            _cfg(pki), "alice", "openvpn"
        )

        assert json.loads(registry.read_text(encoding="utf-8")) == {"version": 99}
