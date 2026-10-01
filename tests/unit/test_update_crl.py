#  Project:      culvert
#  File:         test_update_crl.py
#  Purpose:      Tests for update-crl's preconditions and CRL expiry report
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""update-crl refuses to run without a CA and reports the CRL it leaves behind.

Regenerating the CRL itself needs Easy-RSA, which is not on a CI runner; the
container tier covers that. These tests cover what happens either side of it.
"""

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "update-crl.py"


@pytest.fixture
def update_crl(tmp_path, monkeypatch):
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
