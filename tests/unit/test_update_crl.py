#  Project:      culvert
#  File:         test_update_crl.py
#  Purpose:      Tests for update-crl's preconditions and CRL expiry report
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""update-crl refuses to run without a CA, refreshes the CRL and reports it.

Easy-RSA is not on a CI runner, so local regeneration runs against the
`easyrsa` stand-in from conftest, whose CRL is a record of how it was invoked.
External PKI fetches through scalo's real file provider.
"""

import importlib.util
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "update-crl.py"


@pytest.fixture
def update_crl(tmp_path, clean_env, monkeypatch):
    """update-crl with its PKI directory pointed at tmp_path."""
    spec = importlib.util.spec_from_file_location("update_crl_script", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PKI_DIR", tmp_path / "pki")
    return module


class TestPreconditions:
    """Without a CA there is nothing to sign a CRL with."""

    def test_missing_pki_directory_exits(self, update_crl):
        with pytest.raises(SystemExit) as exc_info:
            update_crl.main()
        assert exc_info.value.code == 1

    def test_missing_ca_exits(self, update_crl):
        update_crl.PKI_DIR.mkdir()
        with pytest.raises(SystemExit) as exc_info:
            update_crl.main()
        assert exc_info.value.code == 1


class TestRegeneration:
    """update-crl regenerates through lib.pki, the code the refresh loop runs."""

    @staticmethod
    def _pki_with_ca(pki_dir: Path) -> Path:
        pki_dir.mkdir()
        (pki_dir / "ca.crt").write_text("CA\n", encoding="utf-8")
        return pki_dir

    def test_produces_the_same_crl_as_the_library(self, update_crl, easyrsa):
        from lib.pki import regenerate_local_crl

        pki = self._pki_with_ca(update_crl.PKI_DIR)
        crl = pki / "crl.pem"

        update_crl.main()
        from_command = crl.read_text(encoding="utf-8")
        crl.unlink()
        cfg = SimpleNamespace(pki_dir=pki, crl_days=180)
        assert regenerate_local_crl(cfg) is True
        assert crl.read_text(encoding="utf-8") == from_command

        # 180 is the default when CULVERT_CRL_DAYS is unset.
        assert json.loads(from_command) == {
            "argv": ["gen-crl"],
            "cwd": str(easyrsa.resolve()),
            "easyrsa": str(easyrsa),
            "pki": str(pki),
            "batch": "1",
            "crl_days": "180",
        }

    def test_the_configured_lifetime_reaches_easy_rsa(
        self, update_crl, easyrsa, monkeypatch
    ):
        """update-crl runs in its own process, so only the config can carry it."""
        monkeypatch.setenv("CULVERT_CRL_DAYS", "30")
        pki = self._pki_with_ca(update_crl.PKI_DIR)
        update_crl.main()
        record = json.loads((pki / "crl.pem").read_text(encoding="utf-8"))
        assert record["crl_days"] == "30"

    def test_a_new_crl_is_readable_by_openvpn(self, update_crl, easyrsa):
        """OpenVPN reads the CRL after dropping to nobody."""
        pki = self._pki_with_ca(update_crl.PKI_DIR)
        update_crl.main()
        assert stat.S_IMODE((pki / "crl.pem").stat().st_mode) == 0o644

    def test_a_failed_regeneration_exits_1_and_says_why(
        self, update_crl, easyrsa, monkeypatch
    ):
        import lib.pki

        errors: list[str] = []
        monkeypatch.setattr(
            lib.pki.logger, "error", lambda msg, *a, **k: errors.append(str(msg))
        )
        monkeypatch.setenv("FAKE_EASYRSA_FAIL", "gen-crl")
        pki = self._pki_with_ca(update_crl.PKI_DIR)
        with pytest.raises(SystemExit) as exc_info:
            update_crl.main()
        assert exc_info.value.code == 1
        assert not (pki / "crl.pem").exists()
        assert any("gen-crl failed" in e for e in errors), errors


class TestCrlExpiryReport:
    """The expiry is read back from the CRL itself, by openssl."""

    def test_reports_the_next_update(self, update_crl, write_crl):
        update_crl.PKI_DIR.mkdir()
        next_update = datetime(2031, 5, 4, 3, 2, 1, tzinfo=UTC)
        write_crl(update_crl.PKI_DIR / "crl.pem", next_update)
        assert update_crl.get_crl_expiry() == "May  4 03:02:01 2031 GMT"

    def test_reports_a_crl_that_has_already_expired(self, update_crl, write_crl):
        update_crl.PKI_DIR.mkdir()
        write_crl(update_crl.PKI_DIR / "crl.pem", datetime.now(UTC) - timedelta(days=2))
        assert update_crl.get_crl_expiry().endswith(" GMT")

    def test_no_crl_reads_as_not_applicable(self, update_crl):
        update_crl.PKI_DIR.mkdir()
        assert update_crl.get_crl_expiry() == "N/A"

    def test_unreadable_crl_reads_as_unknown(self, update_crl):
        update_crl.PKI_DIR.mkdir()
        (update_crl.PKI_DIR / "crl.pem").write_text("not a crl\n", encoding="utf-8")
        assert update_crl.get_crl_expiry() == "unknown"


class TestExternalPki:
    """External PKI has no CA key here, so update-crl fetches the CRL instead."""

    @pytest.fixture
    def external(self, update_crl, monkeypatch, issue_cert, write_crl, tmp_path):
        """A server on external PKI whose provider is a directory of real files."""
        ca = issue_cert("culvert-test-ca", is_ca=True)
        source = tmp_path / "source"
        source.mkdir()
        write_crl(source / "crl.pem", datetime.now(UTC) + timedelta(days=30), issuer=ca)
        pki = update_crl.PKI_DIR
        pki.mkdir()
        (pki / "ca.crt").write_bytes(ca.cert_pem)
        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("CULVERT_SECRETS_CRL_PATH", str(source / "crl.pem"))
        return source, pki

    def test_the_crl_is_fetched_not_regenerated(self, update_crl, external, easyrsa):
        source, pki = external
        update_crl.main()
        assert (pki / "crl.pem").read_bytes() == (source / "crl.pem").read_bytes()
        assert stat.S_IMODE((pki / "crl.pem").stat().st_mode) == 0o644

    def test_no_new_revocation_leaves_the_server_running(
        self, update_crl, monkeypatch, external, server, easyrsa
    ):
        """A reload drops every client, so it happens only for a new revocation."""
        proc, marker = server
        monkeypatch.setattr(update_crl, "SERVER_PID", proc.pid)
        update_crl.main()
        assert not marker.exists()
        assert proc.poll() is None

    def test_no_crl_path_exits_1(self, update_crl, external, monkeypatch, easyrsa):
        _, pki = external
        monkeypatch.delenv("CULVERT_SECRETS_CRL_PATH")
        with pytest.raises(SystemExit) as exc_info:
            update_crl.main()
        assert exc_info.value.code == 1
        assert not (pki / "crl.pem").exists()

    def test_a_crl_from_another_ca_is_refused(
        self, update_crl, external, issue_cert, write_crl, easyrsa
    ):
        """OpenVPN refuses every client against a CRL its CA did not sign."""
        source, pki = external
        other = issue_cert("someone-else", is_ca=True)
        write_crl(
            source / "crl.pem", datetime.now(UTC) + timedelta(days=9), issuer=other
        )
        with pytest.raises(SystemExit) as exc_info:
            update_crl.main()
        assert exc_info.value.code == 1
        assert not (pki / "crl.pem").exists()


# A stand-in server: argv ends like the image's PID 1, and SIGHUP writes a marker.
_SERVER = """
import signal, sys, time
from pathlib import Path
signal.signal(signal.SIGHUP, lambda *_: Path(sys.argv[1]).write_text("hup"))
print("ready", flush=True)
time.sleep(30)
"""


@pytest.fixture
def server(tmp_path):
    """A real process named like culvert's entrypoint, which records a SIGHUP."""
    import subprocess
    import sys

    marker = tmp_path / "hup"
    proc = subprocess.Popen(
        [sys.executable, "-c", _SERVER, str(marker), "/entrypoint.py", "server"],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "ready"
    yield proc, marker
    proc.kill()
    proc.wait()


def _wait_for(path: Path) -> bool:
    import time

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return False


class TestReloadOnNewRevocations:
    """A CRL that revokes a live session's certificate ends it, as the refresh loop does."""

    def test_the_culvert_server_is_reloaded(self, update_crl, server):
        proc, marker = server
        assert update_crl.reload_server(proc.pid) is True
        assert _wait_for(marker)

    def test_any_other_process_is_left_alone(self, update_crl, tmp_path):
        import subprocess

        other = subprocess.Popen(["sleep", "30"])
        try:
            assert update_crl.reload_server(other.pid) is False
            assert other.poll() is None
        finally:
            other.kill()
            other.wait()

    def test_a_missing_pid_is_not_the_server(self, update_crl, tmp_path):
        assert update_crl.reload_server(4242, proc=tmp_path) is False

    def test_an_external_crl_with_a_new_revocation_reloads(
        self, update_crl, monkeypatch, issue_cert, write_crl, tmp_path, server, easyrsa
    ):
        proc, marker = server
        ca = issue_cert("culvert-test-ca", is_ca=True)
        source = tmp_path / "source"
        source.mkdir()
        expiry = datetime.now(UTC) + timedelta(days=30)
        write_crl(source / "crl.pem", expiry, issuer=ca, revoked=[4242])
        pki = update_crl.PKI_DIR
        pki.mkdir()
        (pki / "ca.crt").write_bytes(ca.cert_pem)
        write_crl(pki / "crl.pem", expiry, issuer=ca)
        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("CULVERT_SECRETS_CRL_PATH", str(source / "crl.pem"))
        monkeypatch.setattr(update_crl, "SERVER_PID", proc.pid)

        update_crl.main()

        assert (pki / "crl.pem").read_bytes() == (source / "crl.pem").read_bytes()
        assert _wait_for(marker), "the server was not reloaded for the new revocation"
