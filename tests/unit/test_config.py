#  Project:      hyperi-vpn
#  File:         test_config.py
#  Purpose:      Tests for lib/config.py Config.from_settings()
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for Config.from_settings() using HYPERI_VPN_* env prefix."""

from lib.config import Config


class TestConfigDefaults:
    """Config.from_settings() with no env vars produces sane defaults."""

    def test_default_server_cn_empty(self, clean_env):
        """server_cn has no default — must be explicitly configured."""
        cfg = Config.from_settings()
        assert cfg.server_cn == ""

    def test_default_ca_cn_generic(self, clean_env):
        """With no org_name, ca_cn derives to generic 'VPN CA'."""
        cfg = Config.from_settings()
        assert cfg.ca_cn == "VPN CA"

    def test_ca_cn_derived_from_org_name(self, clean_env, monkeypatch):
        """org_name='Acme' → ca_cn='Acme VPN CA'."""
        monkeypatch.setenv("HYPERI_VPN_ORG_NAME", "Acme")
        cfg = Config.from_settings()
        assert cfg.ca_cn == "Acme VPN CA"

    def test_explicit_ca_cn_wins_over_derivation(self, clean_env, monkeypatch):
        """Explicit ca_cn overrides org_name derivation."""
        monkeypatch.setenv("HYPERI_VPN_ORG_NAME", "Acme")
        monkeypatch.setenv("HYPERI_VPN_CA_CN", "Custom Name CA")
        cfg = Config.from_settings()
        assert cfg.ca_cn == "Custom Name CA"

    def test_default_stunnel_cert_empty(self, clean_env):
        """stunnel_cert has no default."""
        cfg = Config.from_settings()
        assert cfg.stunnel_cert == ""

    def test_default_stunnel_key_empty(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.stunnel_key == ""

    def test_default_protocol(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.protocol == "openvpn"

    def test_default_pki_mode(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.pki_mode == "local"

    def test_default_key_type(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.key_type == "ec"

    def test_default_key_size(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.key_size == "secp384r1"

    def test_default_udp_enabled(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.udp_enabled is True

    def test_default_udp_port(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.udp_port == 1194

    def test_default_dns(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.dns1 == "1.1.1.1"
        assert cfg.dns2 == "1.0.0.1"

    def test_default_wg_port(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.wg_port == 51820

    def test_default_metrics_disabled(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.metrics_enabled is False

    def test_default_otel_disabled(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.otel_enabled is False

    def test_default_health_port(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.health_port == 8080

    def test_default_secrets_provider_empty(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.secrets_provider == ""

    def test_default_oauth2_disabled(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.oauth2_enabled is False


class TestConfigEnvOverride:
    """Config.from_settings() reads HYPERI_VPN_* env vars."""

    def test_server_cn_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.test.io")
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.test.io"

    def test_protocol_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_PROTOCOL", "both")
        cfg = Config.from_settings()
        assert cfg.protocol == "both"

    def test_udp_port_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_UDP_PORT", "11940")
        cfg = Config.from_settings()
        assert cfg.udp_port == 11940

    def test_dns_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_DNS1", "8.8.8.8")
        monkeypatch.setenv("HYPERI_VPN_DNS2", "8.8.4.4")
        cfg = Config.from_settings()
        assert cfg.dns1 == "8.8.8.8"
        assert cfg.dns2 == "8.8.4.4"

    def test_bool_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_METRICS_ENABLED", "true")
        cfg = Config.from_settings()
        assert cfg.metrics_enabled is True

    def test_wg_network_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_WG_NETWORK", "10.100.0.0/16")
        cfg = Config.from_settings()
        assert cfg.wg_network == "10.100.0.0/16"

    def test_otel_fields(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_OTEL_ENABLED", "true")
        monkeypatch.setenv("HYPERI_VPN_OTEL_ENDPOINT", "localhost:4317")
        monkeypatch.setenv("HYPERI_VPN_OTEL_PROTOCOL", "http")
        cfg = Config.from_settings()
        assert cfg.otel_enabled is True
        assert cfg.otel_endpoint == "localhost:4317"
        assert cfg.otel_protocol == "http"

    def test_secrets_provider_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_SECRETS_PROVIDER", "openbao")
        monkeypatch.setenv(
            "HYPERI_VPN_SECRETS_OPENBAO_ADDRESS",
            "https://bao.example.com:8200",
        )
        cfg = Config.from_settings()
        assert cfg.secrets_provider == "openbao"
        assert cfg.secrets_openbao_address == "https://bao.example.com:8200"


class TestConfigNetworkProfiles:
    """Network profile drives performance tuning defaults."""

    def test_default_profile_buffers(self, clean_env):
        """Default profile uses 0 buffers (OS auto-tuning)."""
        cfg = Config.from_settings()
        assert cfg.sndbuf == 0
        assert cfg.rcvbuf == 0

    def test_default_profile_mtu(self, clean_env):
        """Default profile uses 1500 MTU."""
        cfg = Config.from_settings()
        assert cfg.tun_mtu == 1500
        assert cfg.mssfix == 1450

    def test_wireless_profile_buffers(self, clean_env, monkeypatch):
        """Wireless profile uses larger buffers."""
        monkeypatch.setenv("HYPERI_VPN_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.sndbuf == 393216
        assert cfg.rcvbuf == 393216

    def test_wireless_profile_mtu(self, clean_env, monkeypatch):
        """Wireless profile uses smaller MTU."""
        monkeypatch.setenv("HYPERI_VPN_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.tun_mtu == 1400
        assert cfg.mssfix == 1400

    def test_mobile_profile_same_as_wireless(self, clean_env, monkeypatch):
        """Mobile profile uses same settings as wireless."""
        monkeypatch.setenv("HYPERI_VPN_NETWORK_PROFILE", "mobile")
        cfg = Config.from_settings()
        assert cfg.sndbuf == 393216
        assert cfg.tun_mtu == 1400

    def test_wireless_keepalive(self, clean_env, monkeypatch):
        """Wireless profile uses longer keepalive intervals."""
        monkeypatch.setenv("HYPERI_VPN_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.keepalive_ping == 30
        assert cfg.keepalive_timeout == 120


class TestConfigOAuth2Inheritance:
    """Per-listener OAuth2 inherits from global setting."""

    def test_global_enables_all(self, clean_env, monkeypatch):
        """Global OAUTH2_ENABLED enables all listeners."""
        monkeypatch.setenv("HYPERI_VPN_OAUTH2_ENABLED", "true")
        cfg = Config.from_settings()
        assert cfg.oauth2_udp_enabled is True
        assert cfg.oauth2_tcp_enabled is True
        assert cfg.oauth2_https_enabled is True

    def test_per_listener_override(self, clean_env, monkeypatch):
        """Per-listener OAuth2 can override global."""
        monkeypatch.setenv("HYPERI_VPN_OAUTH2_ENABLED", "true")
        monkeypatch.setenv("HYPERI_VPN_OAUTH2_UDP_ENABLED", "false")
        cfg = Config.from_settings()
        assert cfg.oauth2_udp_enabled is False
        assert cfg.oauth2_tcp_enabled is True
        assert cfg.oauth2_https_enabled is True

    def test_all_disabled_by_default(self, clean_env):
        """All listeners disabled when global OAuth2 not set."""
        cfg = Config.from_settings()
        assert cfg.oauth2_udp_enabled is False
        assert cfg.oauth2_tcp_enabled is False
        assert cfg.oauth2_https_enabled is False


class TestConfigMaxClients:
    """max_clients: None = auto-detect, explicit int kept."""

    def test_max_clients_auto_when_unset(self, clean_env):
        cfg = Config.from_settings()
        # When not set, max_clients starts as None then
        # __post_init__ auto-calculates to an int >= 10
        assert isinstance(cfg.max_clients, int)
        assert cfg.max_clients >= 10

    def test_max_clients_explicit(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_MAX_CLIENTS", "50")
        cfg = Config.from_settings()
        assert cfg.max_clients == 50

    def test_max_clients_auto_string(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_MAX_CLIENTS", "auto")
        cfg = Config.from_settings()
        # 'auto' parsed to None, then __post_init__ calculates
        assert isinstance(cfg.max_clients, int)
        assert cfg.max_clients >= 10


class TestExternalPKIValidation:
    """Tests for external PKI config validation."""

    def test_external_mode_requires_provider(self, clean_env, monkeypatch):
        """External PKI without secrets_provider fails."""
        import pytest

        monkeypatch.setenv("HYPERI_VPN_PKI_MODE", "external")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_mode_requires_cert_paths(self, clean_env, monkeypatch):
        """External PKI without cert paths fails."""
        import pytest

        monkeypatch.setenv("HYPERI_VPN_PKI_MODE", "external")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_PROVIDER", "file")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_mode_file_valid(self, clean_env, monkeypatch):
        """External PKI with file provider and all paths passes."""
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("HYPERI_VPN_HTTPS_ENABLED", "false")
        monkeypatch.setenv("HYPERI_VPN_PKI_MODE", "external")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_CA_CERT_PATH", "/certs/ca.crt")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_CERT_PATH", "/certs/server.crt")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_KEY_PATH", "/certs/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # Should not raise

    def test_external_openbao_requires_address(self, clean_env, monkeypatch):
        """OpenBao provider without address fails."""
        import pytest

        monkeypatch.setenv("HYPERI_VPN_PKI_MODE", "external")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_PROVIDER", "openbao")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_CA_CERT_PATH", "x")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_CERT_PATH", "x")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_KEY_PATH", "x")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_invalid_provider(self, clean_env, monkeypatch):
        """Unknown provider value fails."""
        import pytest

        monkeypatch.setenv("HYPERI_VPN_PKI_MODE", "external")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_PROVIDER", "gcp")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_CA_CERT_PATH", "x")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_CERT_PATH", "x")
        monkeypatch.setenv("HYPERI_VPN_SECRETS_SERVER_KEY_PATH", "x")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()


class TestProfileLoader:
    """Tests for HYPERI_VPN_PROFILE loading."""

    def test_no_profile_uses_defaults(self, clean_env):
        """With no profile set, generic defaults apply."""
        cfg = Config.from_settings()
        assert cfg.server_cn == ""  # new generic default

    def test_profile_absolute_path_loads(self, clean_env, monkeypatch, tmp_path):
        """Profile at absolute path overrides defaults."""
        profile = tmp_path / "site.yaml"
        profile.write_text("server_cn: vpn.my-org.example\n")
        monkeypatch.setenv("HYPERI_VPN_PROFILE", str(profile))
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.my-org.example"

    def test_env_var_overrides_profile(self, clean_env, monkeypatch, tmp_path):
        """Explicit env var wins over profile value."""
        profile = tmp_path / "site.yaml"
        profile.write_text("server_cn: from-profile.example\n")
        monkeypatch.setenv("HYPERI_VPN_PROFILE", str(profile))
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "from-env.example")
        cfg = Config.from_settings()
        assert cfg.server_cn == "from-env.example"

    def test_missing_profile_exits(self, clean_env, monkeypatch):
        """Non-existent profile path exits with clear error."""
        import pytest

        monkeypatch.setenv(
            "HYPERI_VPN_PROFILE",
            "/nonexistent/profile.yaml",
        )
        with pytest.raises(SystemExit):
            Config.from_settings()

    def test_profile_unknown_key_ignored(self, clean_env, monkeypatch, tmp_path):
        """Unknown keys in profile silently ignored (Dynaconf)."""
        profile = tmp_path / "site.yaml"
        profile.write_text(
            "server_cn: vpn.example.com\nunknown_field: should_not_crash\n"
        )
        monkeypatch.setenv("HYPERI_VPN_PROFILE", str(profile))
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.example.com"


class TestStunnelValidation:
    """HTTPS listener requires stunnel cert/key."""

    def test_https_without_stunnel_fails(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("HYPERI_VPN_HTTPS_ENABLED", "true")
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_https_with_stunnel_passes(self, clean_env, monkeypatch):
        monkeypatch.setenv("HYPERI_VPN_HTTPS_ENABLED", "true")
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv(
            "HYPERI_VPN_STUNNEL_CERT",
            "/path/to/fullchain.pem",
        )
        monkeypatch.setenv("HYPERI_VPN_STUNNEL_KEY", "/path/to/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_https_disabled_no_stunnel_ok(self, clean_env, monkeypatch):
        """If HTTPS listener is disabled, empty stunnel paths OK."""
        monkeypatch.setenv("HYPERI_VPN_HTTPS_ENABLED", "false")
        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise


class TestDfeProfile:
    """Regression lock: profiles/dfe.yaml must reproduce DFE config."""

    def test_dfe_profile_values(self, clean_env, monkeypatch):
        """Loading profiles/dfe.yaml produces pre-refactor DFE config."""
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        dfe_yaml = project_root / "profiles" / "dfe.yaml"
        monkeypatch.setenv("HYPERI_VPN_PROFILE", str(dfe_yaml))

        cfg = Config.from_settings()

        assert cfg.org_name == "DFE"
        assert cfg.server_cn == "vpn.hyperi.io"
        assert cfg.ca_cn == "DFE VPN CA"
        assert cfg.stunnel_cert == ("/etc/vpn/oauth2-tls/hyperi-wildcard-fullchain.pem")
        assert cfg.stunnel_key == ("/etc/vpn/oauth2-tls/hyperi-wildcard.key")
        assert cfg.push_routes == "10.66.0.0/16,10.42.0.0/16"
        assert cfg.dns_domain == "devex.hyperi.io"


class TestValidatorErrorPrefix:
    """Validator error messages must use HYPERI_VPN_ prefix."""

    def test_invalid_port_error_uses_new_prefix(self, clean_env, monkeypatch):
        """Validator errors use HYPERI_VPN_ prefix, not DFE_VPN_."""
        import io

        import pytest
        from hyperi_pylib.logger import logger

        monkeypatch.setenv("HYPERI_VPN_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("HYPERI_VPN_HTTPS_ENABLED", "false")
        monkeypatch.setenv("HYPERI_VPN_UDP_PORT", "99999")

        sink = io.StringIO()
        sink_id = logger.add(sink, level="ERROR")
        try:
            cfg = Config.from_settings()
            with pytest.raises(SystemExit):
                cfg.validate()
            output = sink.getvalue()
        finally:
            logger.remove(sink_id)

        assert "HYPERI_VPN_UDP_PORT" in output
        assert "DFE_VPN_" not in output
