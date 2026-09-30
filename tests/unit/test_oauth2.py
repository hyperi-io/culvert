#  Project:      culvert
#  File:         test_oauth2.py
#  Purpose:      Tests for lib/oauth2.py process supervision
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for lib/oauth2.py."""

import lib.oauth2 as oauth2
from lib.config import Config


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
