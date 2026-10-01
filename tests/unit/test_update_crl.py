#  Project:      culvert
#  File:         test_update_crl.py
#  Purpose:      Tests for update-crl's preconditions and CRL expiry report
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""update-crl refuses to run without a CA, regenerates and reports the CRL.

Easy-RSA is not on a CI runner, so regeneration runs against the `easyrsa`
stand-in from conftest, whose CRL is a record of how it was invoked.
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
