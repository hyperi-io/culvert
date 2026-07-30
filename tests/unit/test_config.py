#  Project:      culvert
#  File:         test_config.py
#  Purpose:      Tests for lib/config.py Config.from_settings()
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Unit tests for Config.from_settings() using CULVERT_* env prefix."""

from lib.config import Config


class TestConfigDefaults:
    """Config.from_settings() with no env vars produces sane defaults."""

    def test_default_server_cn_empty(self, clean_env):
        """server_cn has no default - must be explicitly configured."""
        cfg = Config.from_settings()
        assert cfg.server_cn == ""

    def test_default_ca_cn_generic(self, clean_env):
        """With no org_name, ca_cn derives to generic 'VPN CA'."""
        cfg = Config.from_settings()
        assert cfg.ca_cn == "VPN CA"

    def test_ca_cn_derived_from_org_name(self, clean_env, monkeypatch):
        """org_name='Acme' -> ca_cn='Acme VPN CA'."""
        monkeypatch.setenv("CULVERT_ORG_NAME", "Acme")
        cfg = Config.from_settings()
        assert cfg.ca_cn == "Acme VPN CA"

    def test_explicit_ca_cn_wins_over_derivation(self, clean_env, monkeypatch):
        """Explicit ca_cn overrides org_name derivation."""
        monkeypatch.setenv("CULVERT_ORG_NAME", "Acme")
        monkeypatch.setenv("CULVERT_CA_CN", "Custom Name CA")
        cfg = Config.from_settings()
        assert cfg.ca_cn == "Custom Name CA"

    def test_empty_ca_cn_still_derives_from_org_name(self, clean_env, monkeypatch):
        """An empty ca_cn must not defeat the org_name derivation.

        docker-compose.yaml passes CULVERT_CA_CN through as an empty string so
        an operator can rely on CULVERT_ORG_NAME alone. If empty were treated
        as "set", the documented ORG_NAME behaviour would silently do nothing.
        """
        monkeypatch.setenv("CULVERT_ORG_NAME", "Acme")
        monkeypatch.setenv("CULVERT_CA_CN", "")
        cfg = Config.from_settings()
        assert cfg.ca_cn == "Acme VPN CA"

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

    def test_default_tcp_disabled(self, clean_env):
        """Default is OpenVPN UDP-only; TCP is opt-in."""
        cfg = Config.from_settings()
        assert cfg.tcp_enabled is False

    def test_default_https_disabled(self, clean_env):
        """HTTPS/stunnel listener is opt-in."""
        cfg = Config.from_settings()
        assert cfg.https_enabled is False

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

    def test_default_metrics_addr(self, clean_env):
        """One observability listener on the conventional 9090 bind."""
        cfg = Config.from_settings()
        assert cfg.metrics_addr == "0.0.0.0:9090"

    def test_default_secrets_provider_empty(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.secrets_provider == ""

    def test_default_oauth2_disabled(self, clean_env):
        cfg = Config.from_settings()
        assert cfg.oauth2_enabled is False


class TestConfigEnvOverride:
    """Config.from_settings() reads CULVERT_* env vars."""

    def test_server_cn_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.test.io")
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.test.io"

    def test_protocol_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_PROTOCOL", "both")
        cfg = Config.from_settings()
        assert cfg.protocol == "both"

    def test_udp_port_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_UDP_PORT", "11940")
        cfg = Config.from_settings()
        assert cfg.udp_port == 11940

    def test_dns_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_DNS1", "8.8.8.8")
        monkeypatch.setenv("CULVERT_DNS2", "8.8.4.4")
        cfg = Config.from_settings()
        assert cfg.dns1 == "8.8.8.8"
        assert cfg.dns2 == "8.8.4.4"

    def test_bool_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_METRICS_ENABLED", "true")
        cfg = Config.from_settings()
        assert cfg.metrics_enabled is True

    def test_wg_network_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_WG_NETWORK", "10.100.0.0/16")
        cfg = Config.from_settings()
        assert cfg.wg_network == "10.100.0.0/16"

    def test_otel_fields(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_OTEL_ENABLED", "true")
        monkeypatch.setenv("CULVERT_OTEL_ENDPOINT", "localhost:4317")
        monkeypatch.setenv("CULVERT_OTEL_PROTOCOL", "http")
        cfg = Config.from_settings()
        assert cfg.otel_enabled is True
        assert cfg.otel_endpoint == "localhost:4317"
        assert cfg.otel_protocol == "http"

    def test_secrets_provider_override(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "openbao")
        monkeypatch.setenv(
            "CULVERT_SECRETS_OPENBAO_ADDRESS",
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
        monkeypatch.setenv("CULVERT_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.sndbuf == 393216
        assert cfg.rcvbuf == 393216

    def test_wireless_profile_mtu(self, clean_env, monkeypatch):
        """Wireless profile uses smaller MTU."""
        monkeypatch.setenv("CULVERT_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.tun_mtu == 1400
        assert cfg.mssfix == 1400

    def test_mobile_profile_same_as_wireless(self, clean_env, monkeypatch):
        """Mobile profile uses same settings as wireless."""
        monkeypatch.setenv("CULVERT_NETWORK_PROFILE", "mobile")
        cfg = Config.from_settings()
        assert cfg.sndbuf == 393216
        assert cfg.tun_mtu == 1400

    def test_wireless_keepalive(self, clean_env, monkeypatch):
        """Wireless profile uses longer keepalive intervals."""
        monkeypatch.setenv("CULVERT_NETWORK_PROFILE", "wireless")
        cfg = Config.from_settings()
        assert cfg.keepalive_ping == 30
        assert cfg.keepalive_timeout == 120


class TestConfigOAuth2Inheritance:
    """Per-listener OAuth2 inherits from global setting."""

    def test_global_enables_all(self, clean_env, monkeypatch):
        """Global CULVERT_OAUTH2_ENABLED enables all listeners."""
        monkeypatch.setenv("CULVERT_OAUTH2_ENABLED", "true")
        cfg = Config.from_settings()
        assert cfg.oauth2_udp_enabled is True
        assert cfg.oauth2_tcp_enabled is True
        assert cfg.oauth2_https_enabled is True

    def test_per_listener_override(self, clean_env, monkeypatch):
        """Per-listener OAuth2 can override global."""
        monkeypatch.setenv("CULVERT_OAUTH2_ENABLED", "true")
        monkeypatch.setenv("CULVERT_OAUTH2_UDP_ENABLED", "false")
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
        monkeypatch.setenv("CULVERT_MAX_CLIENTS", "50")
        cfg = Config.from_settings()
        assert cfg.max_clients == 50

    def test_max_clients_auto_string(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_MAX_CLIENTS", "auto")
        cfg = Config.from_settings()
        # 'auto' parsed to None, then __post_init__ calculates
        assert isinstance(cfg.max_clients, int)
        assert cfg.max_clients >= 10


class TestExternalPKIValidation:
    """Tests for external PKI config validation."""

    def test_external_mode_requires_provider(self, clean_env, monkeypatch):
        """External PKI without secrets_provider fails."""
        import pytest

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_mode_requires_cert_paths(self, clean_env, monkeypatch):
        """External PKI without cert paths fails."""
        import pytest

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_mode_file_valid(self, clean_env, monkeypatch):
        """External PKI with file provider and all paths passes."""
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "false")
        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "file")
        monkeypatch.setenv("CULVERT_SECRETS_CA_CERT_PATH", "/certs/ca.crt")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_CERT_PATH", "/certs/server.crt")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_KEY_PATH", "/certs/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # Should not raise

    def test_external_openbao_requires_address(self, clean_env, monkeypatch):
        """OpenBao provider without address fails."""
        import pytest

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "openbao")
        monkeypatch.setenv("CULVERT_SECRETS_CA_CERT_PATH", "x")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_CERT_PATH", "x")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_KEY_PATH", "x")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_external_invalid_provider(self, clean_env, monkeypatch):
        """Unknown provider value fails."""
        import pytest

        monkeypatch.setenv("CULVERT_PKI_MODE", "external")
        monkeypatch.setenv("CULVERT_SECRETS_PROVIDER", "gcp")
        monkeypatch.setenv("CULVERT_SECRETS_CA_CERT_PATH", "x")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_CERT_PATH", "x")
        monkeypatch.setenv("CULVERT_SECRETS_SERVER_KEY_PATH", "x")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()


class TestProfileLoader:
    """Tests for CULVERT_PROFILE loading."""

    def test_no_profile_uses_defaults(self, clean_env):
        """With no profile set, generic defaults apply."""
        cfg = Config.from_settings()
        assert cfg.server_cn == ""  # new generic default

    def test_profile_absolute_path_loads(self, clean_env, monkeypatch, tmp_path):
        """Profile at absolute path overrides defaults."""
        profile = tmp_path / "site.yaml"
        profile.write_text("server_cn: vpn.my-org.example\n")
        monkeypatch.setenv("CULVERT_PROFILE", str(profile))
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.my-org.example"

    def test_env_var_overrides_profile(self, clean_env, monkeypatch, tmp_path):
        """Explicit env var wins over profile value."""
        profile = tmp_path / "site.yaml"
        profile.write_text("server_cn: from-profile.example\n")
        monkeypatch.setenv("CULVERT_PROFILE", str(profile))
        monkeypatch.setenv("CULVERT_SERVER_CN", "from-env.example")
        cfg = Config.from_settings()
        assert cfg.server_cn == "from-env.example"

    def test_missing_profile_exits(self, clean_env, monkeypatch):
        """Non-existent profile path exits with clear error."""
        import pytest

        monkeypatch.setenv(
            "CULVERT_PROFILE",
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
        monkeypatch.setenv("CULVERT_PROFILE", str(profile))
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.example.com"

    def test_profile_relative_path_loads(self, clean_env, monkeypatch, tmp_path):
        """A RELATIVE profile path resolves against cwd and its values load.

        Regression: get_config() rebases a relative path onto its own
        config_dir and silently drops it. config.py must resolve to
        absolute first so a relative CULVERT_PROFILE actually applies.
        """
        (tmp_path / "site.yaml").write_text("server_cn: vpn.rel.example\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CULVERT_PROFILE", "site.yaml")
        cfg = Config.from_settings()
        assert cfg.server_cn == "vpn.rel.example"


class TestShippedProfiles:
    """Regression lock: every shipped opinionated profile loads + validates."""

    def _load(self, monkeypatch, name, extra_env=None):
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        monkeypatch.setenv(
            "CULVERT_PROFILE", str(project_root / "profiles" / f"{name}.yaml")
        )
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        for k, v in (extra_env or {}).items():
            monkeypatch.setenv(k, v)
        cfg = Config.from_settings()
        cfg.validate()
        return cfg

    def test_home(self, clean_env, monkeypatch):
        cfg = self._load(monkeypatch, "home")
        assert cfg.protocol == "openvpn"
        assert cfg.full_tunnel is False
        assert cfg.push_routes == "192.168.1.0/24"

    def test_corporate(self, clean_env, monkeypatch):
        cfg = self._load(
            monkeypatch,
            "corporate",
            {
                "CULVERT_OAUTH2_ISSUER": "https://issuer.example.com",
                "CULVERT_OAUTH2_CLIENT_ID": "id",
                "CULVERT_OAUTH2_CLIENT_SECRET": "sec",
                "CULVERT_OAUTH2_TLS_CERT": "/etc/hosts",
                "CULVERT_OAUTH2_TLS_KEY": "/etc/hosts",
            },
        )
        assert cfg.tcp_enabled is True
        assert cfg.oauth2_enabled is True
        assert cfg.oauth2_validate_groups == "vpn-users"

    def test_travel(self, clean_env, monkeypatch):
        cfg = self._load(
            monkeypatch,
            "travel",
            {
                "CULVERT_STUNNEL_CERT": "/etc/hosts",
                "CULVERT_STUNNEL_KEY": "/etc/hosts",
            },
        )
        assert cfg.protocol == "both"
        assert cfg.https_enabled is True
        assert cfg.wg_dpi_bypass_enabled is True
        assert cfg.network_profile == "wireless"

    def test_edge_fleet(self, clean_env, monkeypatch):
        cfg = self._load(monkeypatch, "edge-fleet")
        assert cfg.routing_control_enabled is True
        assert cfg.client_isolation is True
        assert cfg.udp_network == "100.64.0.0"
        assert cfg.allowed_destinations == "10.20.0.0/16"
        assert cfg.downstream_admin_cidrs == "10.10.0.0/16"
        assert cfg.log_mode == "stdout"


class TestStunnelValidation:
    """HTTPS listener requires stunnel cert/key."""

    def test_https_without_stunnel_fails(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_https_with_stunnel_passes(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv(
            "CULVERT_STUNNEL_CERT",
            "/path/to/fullchain.pem",
        )
        monkeypatch.setenv("CULVERT_STUNNEL_KEY", "/path/to/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_https_disabled_no_stunnel_ok(self, clean_env, monkeypatch):
        """If HTTPS listener is disabled, empty stunnel paths OK."""
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "false")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_wg_dpi_without_stunnel_fails(self, clean_env, monkeypatch):
        """wstunnel serves WSS with the stunnel cert pair - require it."""
        import pytest

        monkeypatch.setenv("CULVERT_PROTOCOL", "wireguard")
        monkeypatch.setenv("CULVERT_WG_DPI_BYPASS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_wg_dpi_with_stunnel_passes(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_PROTOCOL", "wireguard")
        monkeypatch.setenv("CULVERT_WG_DPI_BYPASS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_STUNNEL_CERT", "/path/to/fullchain.pem")
        monkeypatch.setenv("CULVERT_STUNNEL_KEY", "/path/to/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_wg_dpi_openvpn_only_no_stunnel_ok(self, clean_env, monkeypatch):
        """DPI-bypass flag is inert when WireGuard is not running."""
        monkeypatch.setenv("CULVERT_PROTOCOL", "openvpn")
        monkeypatch.setenv("CULVERT_WG_DPI_BYPASS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_wg_dpi_protocol_both_without_stunnel_fails(self, clean_env, monkeypatch):
        """protocol=both with WG DPI bypass still requires the cert pair."""
        import pytest

        monkeypatch.setenv("CULVERT_PROTOCOL", "both")
        monkeypatch.setenv("CULVERT_WG_DPI_BYPASS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()


class TestClientDownloadValidation:
    """Client download server requires the bearer token at validate() time."""

    def test_enabled_without_token_fails(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_CLIENT_DOWNLOAD_ENABLED", "true")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_enabled_with_token_passes(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_CLIENT_DOWNLOAD_ENABLED", "true")
        monkeypatch.setenv("CULVERT_CLIENT_DOWNLOAD_TOKEN", "e2e-token")
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_disabled_without_token_ok(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise


class TestExampleProfile:
    """Regression lock: the shipped profiles/example.yaml loads cleanly."""

    def test_example_profile_values(self, clean_env, monkeypatch):
        """Loading profiles/example.yaml applies its placeholder defaults."""
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        example_yaml = project_root / "profiles" / "example.yaml"
        monkeypatch.setenv("CULVERT_PROFILE", str(example_yaml))

        cfg = Config.from_settings()

        assert cfg.org_name == "Example Org"
        assert cfg.server_cn == "vpn.example.com"
        assert cfg.ca_cn == "Example Org VPN CA"
        assert cfg.stunnel_cert == "/etc/vpn/oauth2-tls/fullchain.pem"
        assert cfg.stunnel_key == "/etc/vpn/oauth2-tls/privkey.key"
        assert cfg.push_routes == "10.0.0.0/24,10.0.1.0/24"
        assert cfg.dns_domain == "internal.example.com"


class TestProtocolAwareValidation:
    """server_cn is required for OpenVPN but advisory for WireGuard-only."""

    def test_wireguard_only_without_server_cn_is_valid(self, clean_env, monkeypatch):
        """A WireGuard-only server does not require CULVERT_SERVER_CN."""
        monkeypatch.setenv("CULVERT_PROTOCOL", "wireguard")
        cfg = Config.from_settings()
        cfg.validate()  # should not raise

    def test_openvpn_without_server_cn_fails(self, clean_env, monkeypatch):
        """OpenVPN still requires a valid server CN."""
        import pytest

        monkeypatch.setenv("CULVERT_PROTOCOL", "openvpn")
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "false")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_validate_detects_subnet_overlap(self, clean_env, monkeypatch):
        """protocol=both with overlapping OpenVPN/WG subnets fails validation.

        Also proves the lib.wireguard import in validate() resolves (it was
        previously a bare `from wireguard import` that raised ImportError and
        silently skipped the overlap check).
        """
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_PROTOCOL", "both")
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "false")
        monkeypatch.setenv("CULVERT_TCP_ENABLED", "false")
        monkeypatch.setenv("CULVERT_UDP_NETWORK", "192.168.50.0")
        monkeypatch.setenv("CULVERT_WG_NETWORK", "192.168.50.0/24")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_all_listeners_enabled_no_collision(self, clean_env, monkeypatch):
        """Opting into every listener at once passes with default subnets.

        Guarantees the simple UDP-only default scales up cleanly: enabling
        UDP + TCP + HTTPS + WireGuard + the WG bypass together must not
        collide on the shipped default subnets.
        """
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_PROTOCOL", "both")
        monkeypatch.setenv("CULVERT_UDP_ENABLED", "true")
        monkeypatch.setenv("CULVERT_TCP_ENABLED", "true")
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_WG_DPI_BYPASS_ENABLED", "true")
        monkeypatch.setenv("CULVERT_STUNNEL_CERT", "/etc/vpn/tls/fullchain.pem")
        monkeypatch.setenv("CULVERT_STUNNEL_KEY", "/etc/vpn/tls/server.key")
        cfg = Config.from_settings()
        cfg.validate()  # default subnets are distinct -> no collision

    def test_overlap_caught_without_wireguard(self, clean_env, monkeypatch):
        """Overlapping OpenVPN listener subnets fail even when WG is off.

        The overlap guard runs for any multi-listener combination, not only
        protocol=both.
        """
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_PROTOCOL", "openvpn")
        monkeypatch.setenv("CULVERT_TCP_ENABLED", "true")
        monkeypatch.setenv("CULVERT_UDP_NETWORK", "192.168.77.0")
        monkeypatch.setenv("CULVERT_TCP_NETWORK", "192.168.77.0")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()


class TestValidatorErrorPrefix:
    """Validator error messages must use CULVERT_ prefix."""

    def test_invalid_port_error_uses_new_prefix(self, clean_env, monkeypatch):
        """Validator errors use CULVERT_ prefix, not DFE_VPN_."""
        import io

        import pytest
        from scalo.logger import logger

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_HTTPS_ENABLED", "false")
        monkeypatch.setenv("CULVERT_UDP_PORT", "99999")

        sink = io.StringIO()
        sink_id = logger.add(sink, level="ERROR")
        try:
            cfg = Config.from_settings()
            with pytest.raises(SystemExit):
                cfg.validate()
            output = sink.getvalue()
        finally:
            logger.remove(sink_id)

        assert "CULVERT_UDP_PORT" in output
        assert "DFE_VPN_" not in output
        assert "HYPERI_VPN_" not in output


class TestRoutingControlConfig:
    """Routing-control fields: defaults, validation, warning path."""

    def test_defaults(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        cfg = Config.from_settings()
        assert cfg.routing_control_enabled is False
        assert cfg.client_isolation is True
        assert cfg.allowed_destinations == ""
        assert cfg.downstream_admin_cidrs == ""

    def test_invalid_admin_cidr_fails_validation(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_ROUTING_CONTROL_ENABLED", "true")
        monkeypatch.setenv("CULVERT_DOWNSTREAM_ADMIN_CIDRS", "10.0.0.0/33")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_invalid_allowed_destination_fails_validation(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_ROUTING_CONTROL_ENABLED", "true")
        monkeypatch.setenv("CULVERT_ALLOWED_DESTINATIONS", "not-a-cidr")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_cidrs_without_switch_is_warning_not_error(self, clean_env, monkeypatch):
        """Valid CIDRs with the switch off pass validation (warn only)."""
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_DOWNSTREAM_ADMIN_CIDRS", "10.10.0.0/16")
        cfg = Config.from_settings()
        cfg.validate()

    def test_valid_lists_pass(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_ROUTING_CONTROL_ENABLED", "true")
        monkeypatch.setenv("CULVERT_CLIENT_ISOLATION", "false")
        monkeypatch.setenv("CULVERT_ALLOWED_DESTINATIONS", "100.96.0.0/16,10.20.0.0/24")
        monkeypatch.setenv("CULVERT_DOWNSTREAM_ADMIN_CIDRS", "10.10.0.0/16")
        cfg = Config.from_settings()
        cfg.validate()
        assert cfg.client_isolation is False


class TestNetmaskValidation:
    """Malformed netmasks fail validation, not iptables setup at runtime."""

    def test_bad_netmask_fails(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_UDP_NETMASK", "255.255.0")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_noncontiguous_netmask_fails(self, clean_env, monkeypatch):
        import pytest

        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_UDP_NETMASK", "255.0.255.0")
        cfg = Config.from_settings()
        with pytest.raises(SystemExit):
            cfg.validate()

    def test_valid_netmask_passes(self, clean_env, monkeypatch):
        monkeypatch.setenv("CULVERT_SERVER_CN", "vpn.example.com")
        monkeypatch.setenv("CULVERT_UDP_NETMASK", "255.255.0.0")
        cfg = Config.from_settings()
        cfg.validate()
