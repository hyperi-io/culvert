"""Issued-client state must make stale static configs observable."""

import stat
from importlib import util
from pathlib import Path
from types import SimpleNamespace

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


def _current(
    *, endpoint: str = "vpn.example.com", mtu: int = 1420
) -> dict[str, dict[str, object]]:
    return current_protocol_state(
        client_endpoint=endpoint,
        dns_servers=["10.8.0.1", "1.1.1.1"],
        dns_domain="corp.example.com",
        wg_mtu=mtu,
    )


def _known_client(pki_dir: Path, name: str) -> None:
    issued = pki_dir / "issued"
    issued.mkdir(parents=True, exist_ok=True)
    (issued / f"{name}.crt").write_text("certificate", encoding="utf-8")


def _known_wireguard_client(pki_dir: Path, name: str) -> None:
    peers = pki_dir / "wireguard" / "peers"
    peers.mkdir(parents=True, exist_ok=True)
    (peers / f"{name}.pub").write_text("key", encoding="utf-8")


class TestIssuedClientState:
    def test_matching_issue_record_is_current(self, tmp_path: Path) -> None:
        _known_client(tmp_path, "alice")
        record_client_state(tmp_path, "alice", _current())

        rows = inspect_client_states(tmp_path, _current())

        assert [(row.client, row.status, row.reasons) for row in rows] == [
            ("alice", "CURRENT", ())
        ]

    def test_reports_every_material_change_by_protocol(self, tmp_path: Path) -> None:
        _known_client(tmp_path, "alice")
        _known_wireguard_client(tmp_path, "alice")
        record_client_state(tmp_path, "alice", _current())

        changed = current_protocol_state(
            client_endpoint="203.0.113.10",
            dns_servers=["9.9.9.9", ""],
            dns_domain="new.example.com",
            wg_mtu=1280,
        )
        [row] = inspect_client_states(tmp_path, changed)

        assert row.status == "STALE"
        assert row.reasons == (
            "openvpn.endpoint",
            "wireguard.endpoint",
            "wireguard.dns",
            "wireguard.mtu",
        )

    def test_client_without_a_record_is_unknown_not_current(
        self, tmp_path: Path
    ) -> None:
        _known_client(tmp_path, "legacy")

        [row] = inspect_client_states(tmp_path, _current())

        assert row.client == "legacy"
        assert row.status == "UNKNOWN"
        assert row.reasons == ("no issuance record",)

    def test_partial_reissue_preserves_the_other_protocol_record(
        self, tmp_path: Path
    ) -> None:
        _known_client(tmp_path, "alice")
        _known_wireguard_client(tmp_path, "alice")
        original = _current()
        record_client_state(tmp_path, "alice", original)
        record_client_state(
            tmp_path,
            "alice",
            {"openvpn": _current(endpoint="new.example.com")["openvpn"]},
        )

        [row] = inspect_client_states(tmp_path, _current(endpoint="new.example.com"))

        assert row.status == "STALE"
        assert row.reasons == ("wireguard.endpoint",)

    def test_wireguard_slots_are_one_client_identity(self, tmp_path: Path) -> None:
        peers = tmp_path / "wireguard" / "peers"
        peers.mkdir(parents=True)
        (peers / "alice.pub").write_text("key", encoding="utf-8")
        (peers / "alice.2.pub").write_text("key", encoding="utf-8")
        record_client_state(tmp_path, "alice", {"wireguard": _current()["wireguard"]})

        rows = inspect_client_states(tmp_path, _current())

        assert [row.client for row in rows] == ["alice"]

    def test_registry_is_private(self, tmp_path: Path) -> None:
        record_client_state(tmp_path, "alice", _current())

        registry = tmp_path / "client-config-state.json"

        assert stat.S_IMODE(registry.stat().st_mode) == 0o600


class TestOperatorReport:
    def test_names_stale_fields_and_returns_nonzero_signal(
        self, tmp_path: Path, capsys
    ) -> None:
        _known_client(tmp_path, "alice")
        _known_wireguard_client(tmp_path, "alice")
        record_client_state(tmp_path, "alice", _current())
        cfg = SimpleNamespace(
            pki_dir=tmp_path,
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

    def test_no_clients_is_successful_and_explicit(
        self, tmp_path: Path, capsys
    ) -> None:
        cfg = SimpleNamespace(
            pki_dir=tmp_path,
            client_endpoint="vpn.example.com",
            dns_servers=["1.1.1.1", ""],
            dns_domain="",
            wg_mtu=1420,
        )

        all_current = _generate_client_module()._report_client_states(cfg)

        assert all_current is True
        assert capsys.readouterr().out == "No issued clients found.\n"

    def test_recording_one_completed_protocol_does_not_bless_the_other(
        self, tmp_path: Path
    ) -> None:
        _known_client(tmp_path, "alice")
        _known_wireguard_client(tmp_path, "alice")
        record_client_state(tmp_path, "alice", _current())
        cfg = SimpleNamespace(
            pki_dir=tmp_path,
            client_endpoint="new.example.com",
            dns_servers=["10.8.0.1", "1.1.1.1"],
            dns_domain="corp.example.com",
            wg_mtu=1420,
        )

        _generate_client_module()._record_generated_protocol(cfg, "alice", "openvpn")
        [row] = inspect_client_states(tmp_path, _current(endpoint="new.example.com"))

        assert row.status == "STALE"
        assert row.reasons == ("wireguard.endpoint",)
