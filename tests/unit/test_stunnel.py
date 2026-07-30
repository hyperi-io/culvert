#  Project:      culvert
#  File:         test_stunnel.py
#  Purpose:      Tests for stunnel configuration module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from lib.stunnel import configure_stunnel

REPO_ROOT = Path(__file__).resolve().parents[2]


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
        # Log file created at 0640 (matches the logrotate target) even on
        # the non-root path where the nobody:nogroup chown fails
        stunnel_log = log_dir / "stunnel.log"
        assert stunnel_log.exists()
        import stat

        assert stat.S_IMODE(stunnel_log.stat().st_mode) == 0o640


class TestRealStunnelTemplate:
    """Render the SHIPPED template, not a synthetic stand-in.

    The tests above prove the substitution machinery works. These prove the
    template we actually ship produces a config that terminates TLS on the web
    port and hands off to OpenVPN on localhost - the whole VPN-over-HTTPS path.
    A broken shipped template would sail past a synthetic fixture.
    """

    def _render(self, tmp_path, https_port=443, internal_port=1195):
        template = REPO_ROOT / "config" / "stunnel-server.conf.template"
        assert template.exists(), f"shipped template missing at {template}"

        server_dir = tmp_path / "server"
        server_dir.mkdir()
        shutil.copy(template, server_dir / "stunnel-server.conf.template")

        log_dir = tmp_path / "log"
        log_dir.mkdir()
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_text("CERT")
        key_file.write_text("KEY")

        cfg = FakeStunnelCfg()
        cfg.https_port = https_port
        cfg.https_internal_port = internal_port
        cfg.server_https_conf = server_dir / "server-https.conf"
        cfg.stunnel_conf = tmp_path / "stunnel.conf"
        cfg.stunnel_cert = str(cert_file)
        cfg.stunnel_key = str(key_file)
        cfg.log_dir = log_dir

        configure_stunnel(cfg)
        assert cfg.stunnel_conf.exists()
        return cfg.stunnel_conf.read_text(), cert_file, key_file

    def test_no_unsubstituted_variables_remain(self, tmp_path):
        """An unsubstituted ${VAR} would make stunnel fail at startup."""
        content, _, _ = self._render(tmp_path)
        leftovers = re.findall(r"\$\{[A-Z_]+\}", content)
        assert not leftovers, f"template left variables unsubstituted: {leftovers}"

    def test_accepts_on_the_configured_https_port(self, tmp_path):
        """The TLS listener must bind the port the operator configured."""
        content, _, _ = self._render(tmp_path, https_port=8443)
        assert re.search(r"(?m)^\s*accept\s*=\s*(?:[\d.]+:)?8443\s*$", content), (
            f"no accept on 8443 in the rendered config:\n{content}"
        )

    def test_forwards_to_openvpn_on_localhost_only(self, tmp_path):
        """Decrypted traffic must go to loopback, never a routable address."""
        content, _, _ = self._render(tmp_path, internal_port=1196)
        match = re.search(r"(?m)^\s*connect\s*=\s*(\S+)\s*$", content)
        assert match, f"no connect directive in:\n{content}"
        assert match.group(1) == "127.0.0.1:1196", (
            f"expected connect = 127.0.0.1:1196, got {match.group(1)}"
        )

    def test_wires_the_configured_cert_and_key(self, tmp_path):
        """Without both, stunnel cannot present a certificate at all."""
        content, cert_file, key_file = self._render(tmp_path)
        assert re.search(
            rf"(?m)^\s*cert\s*=\s*{re.escape(str(cert_file))}\s*$", content
        )
        assert re.search(rf"(?m)^\s*key\s*=\s*{re.escape(str(key_file))}\s*$", content)

    def test_requires_tls_13(self, tmp_path):
        """The listener must not negotiate below TLS 1.3."""
        content, _, _ = self._render(tmp_path)
        assert "TLSv1.3" in content, (
            f"shipped template does not pin TLS 1.3:\n{content}"
        )
