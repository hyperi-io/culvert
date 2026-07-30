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
