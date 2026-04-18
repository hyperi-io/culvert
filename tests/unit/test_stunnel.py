#  Project:      hyperi-vpn
#  File:         test_stunnel.py
#  Purpose:      Tests for stunnel configuration module
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

from dataclasses import dataclass, field
from pathlib import Path

from lib.stunnel import configure_stunnel


@dataclass
class FakeStunnelCfg:
    https_enabled: bool = True
    https_port: int = 443
    https_internal_port: int = 1195
    stunnel_cert: str = ""
    stunnel_key: str = ""
    stunnel_conf: Path = field(default_factory=lambda: Path("/tmp/stunnel.conf"))
    server_https_conf: Path = field(default_factory=lambda: Path("/tmp/server"))
    log_dir: Path = field(default_factory=lambda: Path("/tmp/log"))


class TestConfigureStunnel:
    """Tests for stunnel configuration generation."""

    def test_skipped_when_https_disabled(self, tmp_path):
        """No config generated when HTTPS is disabled."""
        cfg = FakeStunnelCfg(https_enabled=False)
        cfg.stunnel_conf = tmp_path / "stunnel.conf"
        configure_stunnel(cfg)
        assert not cfg.stunnel_conf.exists()

    def test_skipped_when_template_missing(self, tmp_path):
        """No config if template doesn't exist."""
        cfg = FakeStunnelCfg()
        cfg.server_https_conf = tmp_path / "server" / "server-https.conf"
        cfg.stunnel_conf = tmp_path / "stunnel.conf"
        (tmp_path / "server").mkdir()
        configure_stunnel(cfg)
        assert not cfg.stunnel_conf.exists()

    def test_skipped_when_cert_missing(self, tmp_path):
        """No config if TLS cert doesn't exist."""
        server_dir = tmp_path / "server"
        server_dir.mkdir()
        # Create template
        template = server_dir / "stunnel-server.conf.template"
        template.write_text(
            "cert = ${STUNNEL_CERT_PATH}\n"
            "key = ${STUNNEL_KEY_PATH}\n"
            "connect = 127.0.0.1:${OPENVPN_HTTPS_INTERNAL_PORT}\n"
        )

        cfg = FakeStunnelCfg()
        cfg.server_https_conf = server_dir / "server-https.conf"
        cfg.stunnel_conf = tmp_path / "stunnel.conf"
        cfg.stunnel_cert = str(tmp_path / "nonexistent.pem")
        cfg.stunnel_key = str(tmp_path / "nonexistent.key")

        configure_stunnel(cfg)
        assert not cfg.stunnel_conf.exists()

    def test_generates_config_with_valid_certs(self, tmp_path):
        """Config is generated when certs exist."""
        server_dir = tmp_path / "server"
        server_dir.mkdir()
        log_dir = tmp_path / "log"
        log_dir.mkdir()

        template = server_dir / "stunnel-server.conf.template"
        template.write_text(
            "cert = ${STUNNEL_CERT_PATH}\n"
            "key = ${STUNNEL_KEY_PATH}\n"
            "connect = 127.0.0.1:${OPENVPN_HTTPS_INTERNAL_PORT}\n"
        )

        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("CERT")
        key_file.write_text("KEY")

        cfg = FakeStunnelCfg()
        cfg.server_https_conf = server_dir / "server-https.conf"
        cfg.stunnel_conf = tmp_path / "stunnel.conf"
        cfg.stunnel_cert = str(cert_file)
        cfg.stunnel_key = str(key_file)
        cfg.log_dir = log_dir

        configure_stunnel(cfg)

        assert cfg.stunnel_conf.exists()
        content = cfg.stunnel_conf.read_text()
        assert str(cert_file) in content
        assert str(key_file) in content
        assert "1195" in content
        # Log file should be created
        assert (log_dir / "stunnel.log").exists()
