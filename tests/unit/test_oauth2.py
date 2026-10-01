#  Project:      culvert
#  File:         test_oauth2.py
#  Purpose:      Tests for lib/oauth2.py process supervision
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for lib/oauth2.py."""

import lib.oauth2 as oauth2
import pytest
from lib.config import Config

SERVER_CN = "vpn.example.test"


class FakeProcessManager:
    """Records start() calls the way ProcessManager would track processes."""

    def __init__(self):
        self.processes = {}
        self.started = {}

    def start(self, name, cmd, daemon=False):
        self.started[name] = cmd
        self.processes[name] = object()
        return self.processes[name]


class TestStartOAuth2Supervision:
    """start_oauth2 must register each instance with the ProcessManager."""

    def test_registers_one_process_per_enabled_listener(self, monkeypatch):
        monkeypatch.setattr(oauth2.Path, "mkdir", lambda self, *a, **k: None)
        monkeypatch.setattr(oauth2.Path, "exists", lambda self: True)

        cfg = Config()
        cfg.udp_enabled = True
        cfg.oauth2_udp_enabled = True
        cfg.tcp_enabled = True
        cfg.oauth2_tcp_enabled = True
        cfg.https_enabled = False
        cfg.oauth2_https_enabled = False

        pm = FakeProcessManager()
        oauth2.start_oauth2(cfg, pm)

        assert pm.started["oauth2-udp"][:2] == ["openvpn-auth-oauth2", "--config"]
        assert "config-udp.yaml" in pm.started["oauth2-udp"][2]
        assert pm.started["oauth2-tcp"][:2] == ["openvpn-auth-oauth2", "--config"]
        assert "config-tcp.yaml" in pm.started["oauth2-tcp"][2]
        # HTTPS listener disabled -> no instance registered.
        assert "oauth2-https" not in pm.started

    def test_stale_config_for_disabled_listener_is_not_started(self, monkeypatch):
        """A config file left over for a now-disabled OAuth2 listener is ignored."""
        # Every config-*.yaml exists on disk (stale from a previous run)...
        monkeypatch.setattr(oauth2.Path, "mkdir", lambda self, *a, **k: None)
        monkeypatch.setattr(oauth2.Path, "exists", lambda self: True)

        cfg = Config()
        cfg.udp_enabled = True
        cfg.oauth2_udp_enabled = True
        # ...but TCP transport is up with OAuth2 turned OFF.
        cfg.tcp_enabled = True
        cfg.oauth2_tcp_enabled = False
        cfg.https_enabled = False
        cfg.oauth2_https_enabled = False

        pm = FakeProcessManager()
        oauth2.start_oauth2(cfg, pm)

        assert "oauth2-udp" in pm.started
        assert "oauth2-tcp" not in pm.started  # disabled despite stale config

    def test_no_oauth2_enabled_starts_nothing(self, monkeypatch):
        monkeypatch.setattr(oauth2.Path, "mkdir", lambda self, *a, **k: None)
        monkeypatch.setattr(oauth2.Path, "exists", lambda self: True)

        cfg = Config()
        cfg.oauth2_udp_enabled = False
        cfg.oauth2_tcp_enabled = False
        cfg.oauth2_https_enabled = False

        pm = FakeProcessManager()
        oauth2.start_oauth2(cfg, pm)
        assert pm.started == {}


class TestOAuth2ConfigSchema:
    """The generated config must load under openvpn-auth-oauth2's strict schema."""

    def test_emits_only_keys_the_pinned_release_accepts(self):
        """An unknown key stops the binary at startup, and CI never runs it."""
        cfg = Config()
        cfg.server_cn = "vpn.example.test"
        cfg.oauth2_issuer = "https://idp.example.test"
        cfg.oauth2_client_id = "culvert"
        cfg.oauth2_client_secret = "client-secret"
        cfg.oauth2_tls_cert = "/etc/vpn/oauth2-tls/fullchain.pem"
        cfg.oauth2_tls_key = "/etc/vpn/oauth2-tls/privkey.pem"
        cfg.oauth2_template = "/etc/vpn/oauth2-template.html"
        cfg.oauth2_validate_groups = "vpn-users, admins"

        config = oauth2._oauth2_config(
            cfg, 9000, "/run/vpn/management-udp.sock", "h" * 32, "m" * 32
        )

        assert {section: sorted(body) for section, body in config.items()} == {
            "http": [
                "assets-path",
                "baseurl",
                "cert",
                "key",
                "listen",
                "secret",
                "template",
                "tls",
            ],
            "oauth2": ["client", "issuer", "scopes", "validate"],
            "openvpn": ["addr", "password"],
            "log": ["level"],
        }
        assert sorted(config["oauth2"]["client"]) == ["id", "secret"]
        assert config["oauth2"]["validate"] == {"groups": ["vpn-users", "admins"]}
        assert config["openvpn"]["addr"] == "unix:///run/vpn/management-udp.sock"


def _capture(monkeypatch, level: str) -> list[str]:
    """Collect lib.oauth2's log lines at one level; loguru does not reach caplog."""
    captured: list[str] = []
    monkeypatch.setattr(
        oauth2.logger, level, lambda msg, *a, **k: captured.append(str(msg))
    )
    return captured


class TestTlsCertificateCoversServerName:
    """The OIDC callback is served on the server name, so the cert must cover it."""

    @pytest.fixture
    def cert_file(self, tmp_path, issue_cert):
        """Write a real certificate and return its path."""

        def _write(common_name, **kwargs):
            path = tmp_path / "oauth2-tls.pem"
            path.write_bytes(issue_cert(common_name, **kwargs).cert_pem)
            return str(path)

        return _write

    @pytest.mark.parametrize(
        ("common_name", "sans"),
        [
            pytest.param(SERVER_CN, (), id="exact-cn"),
            pytest.param("other.example.test", (SERVER_CN,), id="exact-san"),
            pytest.param("*.example.test", (), id="wildcard-cn"),
            pytest.param("other.example.test", ("*.example.test",), id="wildcard-san"),
        ],
    )
    def test_accepts_a_certificate_covering_the_name(
        self, cert_file, monkeypatch, common_name, sans
    ):
        errors = _capture(monkeypatch, "error")
        oauth2.validate_oauth2_tls_cert(cert_file(common_name, sans=sans), SERVER_CN)
        assert errors == []

    @pytest.mark.parametrize(
        ("common_name", "sans"),
        [
            pytest.param("other.example.test", ("another.example.test",), id="other"),
            pytest.param("*.other.test", ("*.other.test",), id="other-wildcard"),
            # A wildcard covers one label, so it cannot reach a deeper name.
            pytest.param("*.test", ("*.test",), id="wildcard-too-shallow"),
        ],
    )
    def test_refuses_a_certificate_for_another_name(self, cert_file, common_name, sans):
        with pytest.raises(SystemExit) as exc_info:
            oauth2.validate_oauth2_tls_cert(
                cert_file(common_name, sans=sans), SERVER_CN
            )
        assert exc_info.value.code == 1

    def test_refuses_a_missing_certificate(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            oauth2.validate_oauth2_tls_cert(str(tmp_path / "absent.pem"), SERVER_CN)
        assert exc_info.value.code == 1

    def test_refuses_an_expired_certificate(self, cert_file):
        with pytest.raises(SystemExit) as exc_info:
            oauth2.validate_oauth2_tls_cert(
                cert_file(SERVER_CN, valid_days=-1), SERVER_CN
            )
        assert exc_info.value.code == 1

    def test_warns_inside_the_30_day_window(self, cert_file, monkeypatch):
        warnings = _capture(monkeypatch, "warning")
        oauth2.validate_oauth2_tls_cert(cert_file(SERVER_CN, valid_days=10), SERVER_CN)
        assert warnings == ["OAuth2 TLS certificate expires within 30 days"]

    def test_no_warning_with_time_to_spare(self, cert_file, monkeypatch):
        warnings = _capture(monkeypatch, "warning")
        oauth2.validate_oauth2_tls_cert(cert_file(SERVER_CN, valid_days=90), SERVER_CN)
        assert warnings == []


class TestManagementInterface:
    """OAuth2 drives OpenVPN through the management socket of its own listener."""

    MANAGEMENT_UDP = (
        "management /run/vpn/management-udp.sock unix /etc/vpn/management.pwd"
    )

    def test_replaces_stale_directives_on_oauth2_listeners_only(self, tmp_path):
        udp = tmp_path / "server.conf"
        udp.write_text(
            "port 1194\n"
            "management /old.sock unix /old.pwd\n"
            "management-hold\n"
            "auth-user-pass-optional\n"
            "verb 3\n"
        )
        tcp = tmp_path / "server-tcp.conf"
        tcp.write_text("port 1194\nverb 3\n")
        cfg = Config(
            udp_enabled=True,
            oauth2_udp_enabled=True,
            tcp_enabled=True,
            oauth2_tcp_enabled=False,
            server_conf=udp,
            server_tcp_conf=tcp,
        )

        oauth2._configure_oauth2_management(cfg, "management-password")

        lines = udp.read_text().splitlines()
        assert [line for line in lines if line.startswith("management")] == [
            self.MANAGEMENT_UDP,
            "management-client-auth",
        ]
        assert lines.count("auth-user-pass-optional") == 1
        assert "verb 3" in lines
        assert tcp.read_text() == "port 1194\nverb 3\n"

    def test_listener_without_a_config_is_skipped(self, tmp_path):
        cfg = Config(
            udp_enabled=False,
            https_enabled=True,
            oauth2_https_enabled=True,
            server_https_conf=tmp_path / "server-https.conf",
        )
        oauth2._configure_oauth2_management(cfg, "management-password")
        assert not cfg.server_https_conf.exists()

    def test_setup_is_a_no_op_without_oauth2(self, monkeypatch):
        """Certificate-only authentication generates nothing."""
        cfg = Config()
        infos = _capture(monkeypatch, "info")
        oauth2.setup_oauth2(cfg)
        assert infos == [
            "OIDC SSO disabled on all listeners (certificate-only authentication)"
        ]
