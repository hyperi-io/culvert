#  Project:      culvert
#  File:         test_revoke.py
#  Purpose:      Tests that revocation cannot report success it did not achieve
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Revocation must never report a client revoked while it still has access.

Two ways that used to happen, both covered here:

- the live peer removal failing was caught alongside "wg is not installed" and
  logged as an inactive interface, after which the function returned True;
- the regenerated server config was written under the PKI directory rather than
  the path the server reads, so a restart brought the revoked peer back.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "revoke-client.py"


def _module():
    """Load revoke-client.py, whose filename is not a valid module name."""
    spec = importlib.util.spec_from_file_location("revoke_client_script", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def revoke(tmp_path, monkeypatch):
    """revoke-client with its PKI and output directories pointed at tmp_path."""
    module = _module()
    pki = tmp_path / "pki"
    (pki / "wireguard" / "peers").mkdir(parents=True)
    (tmp_path / "clients").mkdir()
    monkeypatch.setattr(module, "PKI_DIR", pki)
    monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path / "clients")
    return module


def _add_peer(revoke, name: str = "alice") -> Path:
    """Create the peer public key file that marks a client as existing."""
    path = revoke.PKI_DIR / "wireguard" / "peers" / f"{name}.pub"
    path.write_text("fakepublickey=\n", encoding="utf-8")
    return path


class TestLivePeerRemoval:
    """The kernel holds the peer list, so this is what ends a live tunnel."""

    def test_missing_peer_returns_false(self, revoke):
        assert revoke.revoke_wireguard_client("nobody") is False

    def test_absent_interface_is_not_a_failure(self, revoke, monkeypatch):
        """No wg0 means nothing live to remove - revocation still proceeds."""
        _add_peer(revoke)
        monkeypatch.setattr(revoke, "_wg_interface_up", lambda: False)
        assert revoke.revoke_wireguard_client("alice") is True

    def test_refused_removal_raises_instead_of_reporting_success(
        self, revoke, monkeypatch
    ):
        """A live interface that refuses the removal must abort.

        This is the fail-open case: the client's tunnel is still up, so
        reporting it revoked tells the operator access is gone when it is not.
        """
        _add_peer(revoke)
        monkeypatch.setattr(revoke, "_wg_interface_up", lambda: True)
        monkeypatch.setattr(
            revoke.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess(
                a[0] if a else [], 1, "", "Unable to modify interface: Access denied"
            ),
        )
        with pytest.raises(revoke.RevocationError, match="still live"):
            revoke.revoke_wireguard_client("alice")

    def test_peer_file_survives_a_refused_removal(self, revoke, monkeypatch):
        """Aborting must not leave the PKI half-dismantled.

        Deleting the peer file while the live peer remains would make the client
        invisible to a retry while its tunnel kept working.
        """
        peer = _add_peer(revoke)
        monkeypatch.setattr(revoke, "_wg_interface_up", lambda: True)
        monkeypatch.setattr(
            revoke.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "denied"),
        )
        with pytest.raises(revoke.RevocationError):
            revoke.revoke_wireguard_client("alice")
        assert peer.exists(), (
            "the peer key was deleted despite the live removal failing, so a"
            " retry can no longer find the client it needs to revoke"
        )


class TestRevocationPersists:
    """A revocation that a restart undoes is not a revocation."""

    def test_server_config_is_written_where_the_server_reads_it(
        self, revoke, tmp_path, monkeypatch
    ):
        """The regenerated config must land on cfg.wg_conf.

        Writing it under the PKI directory instead left the revoked peer in the
        file the server loads, so the peer came back on the next restart -
        silently, because the revoke itself reported success.
        """
        import lib.config

        _add_peer(revoke)
        monkeypatch.setattr(revoke, "_wg_interface_up", lambda: False)

        wg_dir = revoke.PKI_DIR / "wireguard"
        (wg_dir / "server_private.key").write_text("privkey=\n", encoding="utf-8")

        server_conf_path = tmp_path / "server" / "wg0.conf"
        server_conf_path.parent.mkdir()
        real_from_settings = lib.config.Config.from_settings

        def fake_from_settings(*args, **kwargs):
            cfg = real_from_settings(*args, **kwargs)
            cfg.wg_conf = server_conf_path
            return cfg

        monkeypatch.setattr(
            lib.config.Config, "from_settings", staticmethod(fake_from_settings)
        )

        assert revoke.revoke_wireguard_client("alice") is True
        assert server_conf_path.exists(), (
            "the server config the running server reads was not rewritten, so a"
            " restart restores the revoked peer"
        )
        assert not (wg_dir / "wg0.conf").exists(), (
            "the config was written under the PKI directory, which nothing reads"
        )


class TestInterfaceDetection:
    """ "wg is not installed" and "wg0 refused the change" are different faults."""

    def test_missing_wg_binary_reads_as_no_interface(self, revoke, monkeypatch):
        def boom(*a, **kw):
            raise FileNotFoundError("wg")

        monkeypatch.setattr(revoke.subprocess, "run", boom)
        assert revoke._wg_interface_up() is False

    def test_nonzero_wg_show_reads_as_no_interface(self, revoke, monkeypatch):
        monkeypatch.setattr(
            revoke.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess([], 1),
        )
        assert revoke._wg_interface_up() is False

    def test_zero_wg_show_reads_as_up(self, revoke, monkeypatch):
        monkeypatch.setattr(
            revoke.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess([], 0),
        )
        assert revoke._wg_interface_up() is True


class TestClientNameValidation:
    """A client name reaches PKI_DIR / "issued" / f"{name}.crt" unescaped."""

    def test_rejects_path_traversal(self, revoke):
        assert revoke.validate_client_name("../ca") is False

    def test_rejects_path_separator(self, revoke):
        assert revoke.validate_client_name("sub/name") is False

    def test_accepts_safe_name(self, revoke):
        assert revoke.validate_client_name("alice-2") is True

    def test_main_refuses_before_touching_pki(self, revoke, monkeypatch):
        """main() must reject an unsafe name before any revoke_* call runs."""

        def boom(*a, **kw):
            raise AssertionError("revocation attempted with an unvalidated name")

        monkeypatch.setattr(revoke, "revoke_client", boom)
        monkeypatch.setattr(revoke, "revoke_wireguard_client", boom)
        monkeypatch.setattr("sys.argv", ["revoke-client", "../ca"])

        with pytest.raises(SystemExit) as exc_info:
            revoke.main()
        assert exc_info.value.code == 1


class Cli:
    """revoke-client's main(), plus the paths a test inspects afterwards."""

    def __init__(self, module, pki: Path, clients: Path, server_conf: Path, mp):
        self.module = module
        self.pki = pki
        self.clients = clients
        self.server_conf = server_conf
        self._monkeypatch = mp

    def __call__(self, *args: str) -> None:
        self._monkeypatch.setattr("sys.argv", ["revoke-client", *args])
        self.module.main()


@pytest.fixture
def cli(revoke, tmp_path, clean_env, monkeypatch):
    """Run revoke-client's main() with its config cascade pointed at tmp_path."""
    import lib.config

    pki = revoke.PKI_DIR
    clients = tmp_path / "clients"
    server_conf = tmp_path / "server" / "wg0.conf"
    server_conf.parent.mkdir()
    real_from_settings = lib.config.Config.from_settings

    def from_settings(*args, **kwargs):
        cfg = real_from_settings(*args, **kwargs)
        cfg.pki_dir = pki
        cfg.wg_conf = server_conf
        return cfg

    monkeypatch.setattr(lib.config.Config, "from_settings", staticmethod(from_settings))
    monkeypatch.setenv("OUTPUT_DIR", str(clients))
    monkeypatch.setattr(revoke, "_wg_interface_up", lambda: False)
    return Cli(revoke, pki, clients, server_conf, monkeypatch)


class TestListing:
    """--list names every issued client, never the server's own certificate."""

    def test_lists_clients_without_the_server(self, cli, capsys):
        issued = cli.pki / "issued"
        issued.mkdir()
        for name in ("server", "bob", "alice"):
            (issued / f"{name}.crt").write_text("cert", encoding="utf-8")

        cli("--list")
        assert capsys.readouterr().out.split() == ["alice", "bob"]

    def test_says_none_when_nothing_is_issued(self, cli, capsys):
        cli("--list")
        assert capsys.readouterr().out.split() == ["(none)"]


class TestMainRefusals:
    """Every path that revokes nothing exits non-zero."""

    def test_no_client_name_prints_usage(self, cli, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli()
        assert exc_info.value.code == 1
        assert "usage:" in capsys.readouterr().out

    def test_openvpn_unknown_client_lists_the_known_ones(self, cli, capsys):
        issued = cli.pki / "issued"
        issued.mkdir()
        (issued / "bob.crt").write_text("cert", encoding="utf-8")
        with pytest.raises(SystemExit) as exc_info:
            cli("--protocol", "openvpn", "alice")
        assert exc_info.value.code == 1
        assert capsys.readouterr().out.split() == ["bob"]

    def test_all_protocols_with_nothing_found_exits(self, cli):
        with pytest.raises(SystemExit) as exc_info:
            cli("alice")
        assert exc_info.value.code == 1

    def test_wireguard_unknown_client_exits(self, cli):
        with pytest.raises(SystemExit) as exc_info:
            cli("--protocol", "wireguard", "alice")
        assert exc_info.value.code == 1

    def test_refused_live_removal_exits_non_zero(self, cli, revoke, monkeypatch):
        """The operator must learn the client still has access."""
        _add_peer(revoke)
        monkeypatch.setattr(revoke, "_wg_interface_up", lambda: True)
        monkeypatch.setattr(
            revoke.subprocess,
            "run",
            lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "denied"),
        )
        with pytest.raises(SystemExit) as exc_info:
            cli("--protocol", "wireguard", "alice")
        assert exc_info.value.code == 1


class TestWireGuardRevocationScope:
    """Revoking a client removes every slot it holds and nothing of anyone else's."""

    def test_every_slot_and_its_files_go_and_other_clients_stay(self, cli, revoke):
        import json

        peers = cli.pki / "wireguard" / "peers"
        for peer, key in (
            ("alice", "AliceKey1="),
            ("alice.2", "AliceKey2="),
            ("bob", "BobKey="),
        ):
            (peers / f"{peer}.pub").write_text(key + "\n", encoding="utf-8")
            (peers / f"{peer}.key").write_text("private\n", encoding="utf-8")
        allocations = cli.pki / "wireguard" / "allocations.json"
        allocations.write_text(
            json.dumps({"alice": "10.8.3.2", "alice.2": "10.8.3.3", "bob": "10.8.3.4"})
        )
        (cli.pki / "wireguard" / "server_private.key").write_text("ServerPriv=\n")
        for name in ("alice-wg-split.conf", "alice-wg2-full.conf", "bob-wg-split.conf"):
            (cli.clients / name).write_text("config", encoding="utf-8")

        cli("--protocol", "wireguard", "alice")

        assert sorted(p.name for p in peers.iterdir()) == ["bob.key", "bob.pub"]
        assert json.loads(allocations.read_text()) == {"bob": "10.8.3.4"}
        assert [p.name for p in cli.clients.iterdir()] == ["bob-wg-split.conf"]
        server = cli.server_conf.read_text(encoding="utf-8")
        assert "PublicKey = BobKey=" in server
        assert "AliceKey" not in server

    def test_revocation_without_a_server_key_still_removes_the_peer(self, cli, revoke):
        """No server key means no config to rebuild; the peer still goes."""
        peer = _add_peer(revoke)
        cli("--protocol", "wireguard", "alice")
        assert not peer.exists()
        assert not cli.server_conf.exists()
