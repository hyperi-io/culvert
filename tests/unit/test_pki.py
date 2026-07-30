#  Project:      culvert
#  File:         test_pki.py
#  Purpose:      Tests for PKI module (local + external modes)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import stat

import pytest

# ---------------------------------------------------------------------------
# Existing tests (local mode validation)
# ---------------------------------------------------------------------------


def test_external_pki_file_fallback(tmp_path):
    """External PKI with no provider validates convention paths exist."""
    from lib.pki import validate_external_pki_files

    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    (pki_dir / "ca.crt").write_text("CA")
    (pki_dir / "issued").mkdir()
    (pki_dir / "issued" / "server.crt").write_text("CERT")
    (pki_dir / "private").mkdir()
    (pki_dir / "private" / "server.key").write_text("KEY")
    (pki_dir / "crl.pem").write_text("CRL")
    validate_external_pki_files(pki_dir)  # Should not raise


def test_external_pki_file_fallback_missing(tmp_path):
    """External PKI file fallback fails if certs missing."""
    from lib.pki import validate_external_pki_files

    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    with pytest.raises(SystemExit):
        validate_external_pki_files(pki_dir)


def test_external_pki_partial_files(tmp_path):
    """External PKI fails if only some files present."""
    from lib.pki import validate_external_pki_files

    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    (pki_dir / "ca.crt").write_text("CA")
    with pytest.raises(SystemExit):
        validate_external_pki_files(pki_dir)


# ---------------------------------------------------------------------------
# PEM validation
# ---------------------------------------------------------------------------


class TestValidatePem:
    """Tests for PEM content validation."""

    def test_valid_pem_cert(self):
        from lib.pki import _validate_pem

        data = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
        assert _validate_pem(data, "test") is True

    def test_valid_pem_key(self):
        from lib.pki import _validate_pem

        data = b"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n"
        assert _validate_pem(data, "test") is True

    def test_invalid_pem(self):
        from lib.pki import _validate_pem

        assert _validate_pem(b"not a certificate", "test") is False

    def test_empty_data(self):
        from lib.pki import _validate_pem

        assert _validate_pem(b"", "test") is False

    def test_pem_with_leading_whitespace(self):
        from lib.pki import _validate_pem

        data = b"  \n-----BEGIN CERTIFICATE-----\ndata\n"
        assert _validate_pem(data, "test") is True


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------


class TestCreateManager:
    """Tests for the SecretsManager factory."""

    def test_file_manager(self, clean_env, monkeypatch):
        import asyncio

        from lib.config import Config
        from lib.pki import create_manager

        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        cfg = Config.from_settings()
        manager = create_manager(cfg)
        try:
            assert type(manager).__name__ == "SecretsManager"
            # File provider is registered and healthy out of the box
            assert manager.health_check_sync().get("file") is True
        finally:
            asyncio.run(manager.close())

    def test_unknown_provider_exits(self, clean_env, monkeypatch):
        from lib.config import Config
        from lib.pki import create_manager

        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "gcp")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            create_manager(cfg)


# ---------------------------------------------------------------------------
# External PKI fetch (using real FileProvider + temp files)
# ---------------------------------------------------------------------------

FAKE_CA = "-----BEGIN CERTIFICATE-----\nFAKE_CA\n-----END CERTIFICATE-----\n"
FAKE_CERT = "-----BEGIN CERTIFICATE-----\nFAKE_CERT\n-----END CERTIFICATE-----\n"
FAKE_KEY = "-----BEGIN PRIVATE KEY-----\nFAKE_KEY\n-----END PRIVATE KEY-----\n"
FAKE_CRL = "-----BEGIN X509 CRL-----\nFAKE_CRL\n-----END X509 CRL-----\n"


class TestFetchExternalPki:
    """Tests for external PKI fetch with resilience."""

    @pytest.fixture
    def pki_env(self, tmp_path, clean_env, monkeypatch):
        """Set up temp PKI dir and source cert files for FileProvider."""
        from lib.config import Config

        # Source certs (what FileProvider reads)
        src = tmp_path / "source"
        src.mkdir()
        (src / "ca.crt").write_text(FAKE_CA)
        (src / "server.crt").write_text(FAKE_CERT)
        (src / "server.key").write_text(FAKE_KEY)
        (src / "crl.pem").write_text(FAKE_CRL)

        # PKI dest dir
        pki = tmp_path / "pki"
        pki.mkdir()
        (pki / "issued").mkdir()
        (pki / "private").mkdir()

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("CULVERT_SECRETS_CA_CERT_PATH", str(src / "ca.crt"))
        monkeypatch.setenv(
            "CULVERT_SECRETS_SERVER_CERT_PATH",
            str(src / "server.crt"),
        )
        monkeypatch.setenv(
            "CULVERT_SECRETS_SERVER_KEY_PATH",
            str(src / "server.key"),
        )
        monkeypatch.setenv("CULVERT_SECRETS_CRL_PATH", str(src / "crl.pem"))

        cfg = Config.from_settings()
        cfg.pki_dir = pki

        return cfg, pki, src

    def test_fetches_all_certs(self, pki_env):
        """FileProvider fetches and writes all 4 cert files."""
        from lib.pki import fetch_external_pki

        cfg, pki, _ = pki_env

        result = fetch_external_pki(cfg)
        assert result is True
        assert (pki / "ca.crt").exists()
        assert (pki / "issued" / "server.crt").exists()
        assert (pki / "private" / "server.key").exists()
        assert (pki / "crl.pem").exists()

    def test_server_key_has_600_perms(self, pki_env):
        """Server private key written with 0600 permissions."""
        from lib.pki import fetch_external_pki

        cfg, pki, _ = pki_env

        fetch_external_pki(cfg)
        mode = (pki / "private" / "server.key").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_ca_cert_has_644_perms(self, pki_env):
        """CA cert written with 0644 permissions."""
        from lib.pki import fetch_external_pki

        cfg, pki, _ = pki_env

        fetch_external_pki(cfg)
        mode = (pki / "ca.crt").stat().st_mode
        assert stat.S_IMODE(mode) == 0o644

    def test_crl_optional(self, pki_env):
        """Empty CRL path succeeds without CRL."""
        from lib.pki import fetch_external_pki

        cfg, pki, _ = pki_env
        cfg.secrets_crl_path = ""

        result = fetch_external_pki(cfg)
        assert result is True
        assert not (pki / "crl.pem").exists()

    def test_fallback_to_local_certs(self, pki_env):
        """Provider fails but local certs exist - init_pki succeeds."""
        from lib.pki import init_pki

        cfg, pki, _ = pki_env

        # Pre-populate local certs + tc.key (avoids openvpn call)
        (pki / "ca.crt").write_text(FAKE_CA)
        (pki / "issued" / "server.crt").write_text(FAKE_CERT)
        (pki / "private" / "server.key").write_text(FAKE_KEY)
        (pki / "tc.key").write_text("TC_KEY")

        # Point to nonexistent source (provider will fail)
        cfg.secrets_ca_cert_path = "/nonexistent/ca.crt"
        cfg.secrets_server_cert_path = "/nonexistent/server.crt"
        cfg.secrets_server_key_path = "/nonexistent/server.key"

        # Should not exit - falls back to local certs
        init_pki(cfg)
        assert "FAKE_CA" in (pki / "ca.crt").read_text()

    def test_no_local_no_provider_exits(self, pki_env):
        """Provider fails AND no local certs - init_pki exits."""
        from lib.pki import init_pki

        cfg, pki, _ = pki_env

        # Point to nonexistent source
        cfg.secrets_ca_cert_path = "/nonexistent/ca.crt"
        cfg.secrets_server_cert_path = "/nonexistent/server.crt"
        cfg.secrets_server_key_path = "/nonexistent/server.key"
        cfg.secrets_crl_path = ""

        with pytest.raises(SystemExit):
            init_pki(cfg)

    def test_invalid_pem_not_written(self, pki_env):
        """Invalid PEM doesn't overwrite good local file."""
        from lib.pki import fetch_external_pki

        cfg, pki, src = pki_env

        # Pre-populate a good local CA cert
        (pki / "ca.crt").write_text(FAKE_CA)

        # Make source CA cert invalid PEM
        (src / "ca.crt").write_text("not valid PEM content")

        result = fetch_external_pki(cfg)
        assert result is False
        # Good local file preserved
        assert "FAKE_CA" in (pki / "ca.crt").read_text()
