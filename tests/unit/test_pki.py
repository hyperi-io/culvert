#  Project:      culvert
#  File:         test_pki.py
#  Purpose:      Tests for PKI module (local + external modes)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

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

    def test_pem_after_a_certificate_text_dump(self):
        """Easy-RSA's own issued/server.crt looks exactly like this."""
        from lib.pki import _validate_pem

        data = (
            b"Certificate:\n    Data:\n        Version: 3 (0x2)\n"
            b"        Serial Number: 1 (0x1)\n"
            b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
        )
        assert _validate_pem(data, "server certificate") is True


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


class TestCrlRefresh:
    """The CRL has to keep moving, in BOTH PKI modes.

    External PKI used to be excluded outright: the CRL was fetched once at
    startup and never again, so a certificate revoked at the upstream CA kept
    working until someone restarted the container - with the configured refresh
    interval logged as though it were doing something.
    """

    @pytest.fixture
    def crl_env(self, tmp_path, clean_env, monkeypatch):
        """External-PKI config backed by real files, as the fetch tests use."""
        from lib.config import Config

        src = tmp_path / "source"
        src.mkdir()
        (src / "ca.crt").write_text(FAKE_CA)
        (src / "server.crt").write_text(FAKE_CERT)
        (src / "server.key").write_text(FAKE_KEY)
        (src / "crl.pem").write_text(FAKE_CRL)

        pki = tmp_path / "pki"
        pki.mkdir()
        (pki / "issued").mkdir()
        (pki / "private").mkdir()

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("CULVERT_SECRETS_CA_CERT_PATH", str(src / "ca.crt"))
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_CERT_PATH", str(src / "server.crt"))
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_KEY_PATH", str(src / "server.key"))
        monkeypatch.setenv("CULVERT_SECRETS_CRL_PATH", str(src / "crl.pem"))

        cfg = Config.from_settings()
        cfg.pki_dir = pki
        return cfg, pki, src

    def test_external_mode_refetches(self, crl_env):
        """External mode gets the re-fetcher, not the local regenerator."""
        from lib.pki import crl_refresher, refetch_external_crl

        cfg, _, _ = crl_env
        refresh, how = crl_refresher(cfg)
        assert refresh is refetch_external_crl
        assert "provider" in how

    def test_local_mode_regenerates(self, crl_env):
        """Local mode still regenerates from its own CA."""
        from lib.pki import _regenerate_local_crl, crl_refresher

        cfg, _, _ = crl_env
        cfg.pki_mode = "local"
        refresh, how = crl_refresher(cfg)
        assert refresh is _regenerate_local_crl
        assert "local CA" in how

    def test_external_without_crl_path_has_no_refresher(self, crl_env):
        """Nothing to re-fetch, and it must say so rather than pretend."""
        from lib.pki import crl_refresher

        cfg, _, _ = crl_env
        cfg.secrets_crl_path = ""
        assert crl_refresher(cfg) is None

    def test_refetch_picks_up_an_upstream_change(self, crl_env):
        """A CRL updated at the provider reaches disk without a restart."""
        from lib.pki import refetch_external_crl

        cfg, pki, src = crl_env
        (pki / "crl.pem").write_text(FAKE_CRL)

        updated = FAKE_CRL.replace("FAKE_CRL", "FAKE_CRL_REVOKED_ALICE")
        (src / "crl.pem").write_text(updated)

        assert refetch_external_crl(cfg) is True
        assert "FAKE_CRL_REVOKED_ALICE" in (pki / "crl.pem").read_text()

    def test_refetch_keeps_the_existing_crl_when_unreachable(self, crl_env):
        """A provider that cannot be read must not blank the CRL on disk.

        Losing the CRL fails OPEN - OpenVPN would accept every revoked
        certificate - so a stale CRL is strictly better than none.
        """
        from lib.pki import refetch_external_crl

        cfg, pki, _ = crl_env
        (pki / "crl.pem").write_text(FAKE_CRL)
        cfg.secrets_crl_path = "/nonexistent/crl.pem"

        assert refetch_external_crl(cfg) is False
        assert "FAKE_CRL" in (pki / "crl.pem").read_text()


class TestCrlExpiry:
    """The CRL's remaining life has to be observable.

    A refresh that fails is survivable while there is life left, and an
    outage once nextUpdate passes - so "did the refresh work" is the wrong
    question to alert on. Nothing measured the margin, which is how a
    refresh that had never once succeeded went unnoticed until the CRL
    aged out and OpenVPN began refusing every client.
    """

    def test_reports_remaining_life(self, tmp_path, write_crl):
        """A CRL good for another 30 days reports about 30 days."""
        from lib.pki import crl_seconds_until_expiry

        write_crl(
            tmp_path / "crl.pem",
            datetime.now(UTC) + timedelta(days=30),
        )

        remaining = crl_seconds_until_expiry(tmp_path)
        assert remaining is not None
        assert 29.9 < remaining / 86400 < 30.1

    def test_goes_negative_once_expired(self, tmp_path, write_crl):
        """An expired CRL reports negative, not None and not zero.

        This is the state that refuses every client, so it has to be
        distinguishable from "no CRL" and from "expires today".
        """
        from lib.pki import crl_seconds_until_expiry

        write_crl(
            tmp_path / "crl.pem",
            datetime.now(UTC) - timedelta(days=3),
        )

        remaining = crl_seconds_until_expiry(tmp_path)
        assert remaining is not None
        assert -3.1 < remaining / 86400 < -2.9

    def test_survives_a_single_digit_day(self, tmp_path, write_crl):
        """openssl pads a single-digit day to two columns ("Aug  4")."""
        from lib.pki import crl_seconds_until_expiry

        # A day-of-month under 10, whatever today is.
        target = datetime.now(UTC) + timedelta(days=30)
        while target.day > 9:
            target += timedelta(days=1)
        write_crl(tmp_path / "crl.pem", target)

        remaining = crl_seconds_until_expiry(tmp_path)
        assert remaining is not None
        assert remaining > 0

    def test_none_when_there_is_no_crl(self, tmp_path):
        """No CRL is not an expiry of zero."""
        from lib.pki import crl_seconds_until_expiry

        assert crl_seconds_until_expiry(tmp_path) is None

    def test_none_when_the_crl_is_unreadable(self, tmp_path):
        """Garbage in the CRL file must not crash the refresh loop."""
        from lib.pki import crl_seconds_until_expiry

        (tmp_path / "crl.pem").write_text("not a CRL")
        assert crl_seconds_until_expiry(tmp_path) is None

    @pytest.fixture
    def local_cfg(self, tmp_path, clean_env, monkeypatch):
        """Local-PKI config pointed at a real, empty PKI dir."""
        from lib.config import Config

        pki = tmp_path / "pki"
        pki.mkdir()
        monkeypatch.setenv("CULVERT_PKI_MODE", "local")

        cfg = Config.from_settings()
        cfg.pki_dir = pki
        return cfg, pki

    def test_log_reports_the_margin(self, local_cfg, write_crl):
        """log_crl_expiry hands back the margin it logged."""
        from lib.pki import log_crl_expiry

        cfg, pki = local_cfg
        write_crl(
            pki / "crl.pem",
            datetime.now(UTC) + timedelta(days=45),
        )

        remaining = log_crl_expiry(cfg)
        assert remaining is not None
        assert 44.9 < remaining / 86400 < 45.1

    def test_log_tolerates_a_missing_crl(self, local_cfg):
        """Nothing to report is not a crash."""
        from lib.pki import log_crl_expiry

        cfg, _ = local_cfg
        assert log_crl_expiry(cfg) is None


class TestLocalPkiNeverDestroysKeyMaterial:
    """`init_pki_local` must never issue `easyrsa init-pki`, in any spelling.

    That command removes the PKI directory before recreating it, and 3.2.x
    gives no way to opt out. Two ways it hurts: the directory is a volume
    mount, so the removal fails and the container will not start, and where it
    could succeed it takes the CA with it. This function is reached with a
    HALF-built PKI too, since `init_pki` skips it only when the CA, the server
    certificate and the tls-crypt key are ALL present - so a CA that lost its
    tls-crypt key lands here.

    Asserted on the commands actually issued, because that is where the damage
    would be done. All init-pki creates is three directories we make ourselves.
    """

    @pytest.fixture
    def local_cfg(self, tmp_path, clean_env, monkeypatch):
        from lib.config import Config

        monkeypatch.setenv("CULVERT_PKI_MODE", "local")
        cfg = Config.from_settings()
        cfg.pki_dir = tmp_path / "pki"
        return cfg

    @staticmethod
    def _run_init(monkeypatch, cfg) -> list[str]:
        """Run init_pki_local with easy-rsa stubbed out; return its commands."""
        import lib.pki as pki_mod

        # The easy-rsa install path is hardcoded and absent off-container, so
        # the function would exit before reaching the decision under test.
        real_exists = Path.exists
        monkeypatch.setattr(
            Path,
            "exists",
            lambda self: (
                True if str(self) == "/usr/share/easy-rsa" else real_exists(self)
            ),
        )

        # With easy-rsa stubbed nothing is actually written, so the trailing
        # permission pass has no files to chmod. Not what is under test.
        monkeypatch.setattr(Path, "chmod", lambda self, mode: None)

        commands: list[str] = []
        monkeypatch.setattr(pki_mod, "run", lambda cmd, **kw: commands.append(cmd))
        monkeypatch.setattr(pki_mod, "generate_tc_key", lambda *a, **kw: None)
        pki_mod.init_pki_local(cfg)
        return commands

    def test_init_pki_is_never_issued_on_a_fresh_directory(
        self, local_cfg, monkeypatch
    ):
        """Not even the first start may call it - the mount cannot be removed."""
        commands = self._run_init(monkeypatch, local_cfg)
        assert not any("init-pki" in c for c in commands), (
            "init-pki was issued. easy-rsa 3.2.x removes the PKI directory"
            " first, which fails outright on a volume mount and stops the"
            f" container starting: {commands}"
        )

    def test_init_pki_is_never_issued_over_an_existing_ca(self, local_cfg, monkeypatch):
        """A CA present means there is something to lose."""
        local_cfg.pki_dir.mkdir(parents=True)
        (local_cfg.pki_dir / "ca.crt").write_text("CA")

        commands = self._run_init(monkeypatch, local_cfg)
        assert not any("init-pki" in c for c in commands), (
            "init-pki ran over an existing CA. Where the removal succeeds that"
            f" revokes every client the CA ever signed: {commands}"
        )

    def test_the_ca_is_still_built(self, local_cfg, monkeypatch):
        """Dropping init-pki must not stop the PKI being created.

        build-ca needs the three directories, which we now make ourselves.
        """
        commands = self._run_init(monkeypatch, local_cfg)
        assert any("build-ca" in c for c in commands), f"no CA was built: {commands}"
        for name in ("issued", "private", "reqs"):
            assert (local_cfg.pki_dir / name).is_dir(), (
                f"{name}/ was not created, so build-ca has nothing to write into"
            )
