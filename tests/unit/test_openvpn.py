#  Project:      culvert
#  File:         test_openvpn.py
#  Purpose:      Tests for OpenVPN config generation module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

from dataclasses import dataclass
from pathlib import Path

import lib.openvpn as openvpn_mod
import pytest
from lib.config import Config
from lib.openvpn import (
    _apply_common_options,
    _strip_timestamps,
    configure_server_https,
    configure_server_tcp,
    configure_server_udp,
    generate_config,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_TEMPLATES = (
    "server.conf.template",
    "server-tcp.conf.template",
    "server-https.conf.template",
)


class TestShippedServerTemplates:
    """Assertions against the templates that actually ship in the image."""

    @pytest.mark.parametrize("name", SERVER_TEMPLATES)
    def test_no_windows_only_option_is_pushed(self, name):
        """block-outside-dns is fatal to a non-Windows OpenVPN 2.7 client.

        An option the client does not recognise in a PUSH_REPLY aborts the whole
        option import, so pushing this to everyone means no Linux or macOS client
        on a current OpenVPN can bring the tunnel up at all. It belongs in the
        client config, commented, where a Windows user can enable it.
        """
        text = (REPO_ROOT / "config" / name).read_text(encoding="utf-8")
        pushes = [
            line
            for line in text.splitlines()
            if line.strip().startswith("push ") and "block-outside-dns" in line
        ]
        assert not pushes, f"{name} pushes a Windows-only option: {pushes}"

    @pytest.mark.parametrize("name", SERVER_TEMPLATES)
    def test_external_scripts_are_not_permitted(self, name):
        """script-security 2 lets OpenVPN run scripts; nothing here needs it.

        Culvert ships no client-connect hooks, so enabling it by default only
        widens what the server process is allowed to execute. An operator who
        mounts their own hooks uncomments it along with the hook lines.
        """
        text = (REPO_ROOT / "config" / name).read_text(encoding="utf-8")
        active = [
            line
            for line in text.splitlines()
            if line.strip().startswith("script-security")
        ]
        assert not active, f"{name} enables external scripts: {active}"

    def test_https_listener_binds_loopback_only(self):
        """The stunnel-fronted listener must not be reachable directly.

        stunnel terminates TLS and connects to 127.0.0.1, so loopback is all this
        instance needs. Without an explicit `local`, OpenVPN binds every
        interface - and on Kubernetes that publishes a plain TCP listener on the
        pod IP, reachable by any pod, which skips the TLS wrap the listener
        exists to travel inside.
        """
        text = (REPO_ROOT / "config" / "server-https.conf.template").read_text(
            encoding="utf-8"
        )
        directives = [
            line.strip()
            for line in text.splitlines()
            if line.strip().startswith("local ")
        ]
        assert directives == ["local 127.0.0.1"], (
            f"server-https.conf.template must bind loopback only, found: {directives}"
        )


class TestGenerateConfig:
    """Tests for template-based config generation."""

    def test_substitutes_variables(self, tmp_path):
        """Variables are replaced in template."""
        template = tmp_path / "tmpl.conf"
        template.write_text("port ${PORT}\nnetwork ${NETWORK}\n")
        output = tmp_path / "out.conf"

        generate_config(template, output, {"PORT": "1194", "NETWORK": "10.0.0.0"})

        content = output.read_text()
        assert "port 1194" in content
        assert "network 10.0.0.0" in content

    def test_missing_template_does_not_create_output(self, tmp_path):
        """If template doesn't exist, output is not created."""
        output = tmp_path / "out.conf"
        generate_config(tmp_path / "nonexistent.conf", output, {})
        assert not output.exists()

    def test_integer_variables_converted(self, tmp_path):
        """Integer values are stringified."""
        template = tmp_path / "tmpl.conf"
        template.write_text("mtu ${MTU}\n")
        output = tmp_path / "out.conf"

        generate_config(template, output, {"MTU": 1500})

        assert "mtu 1500" in output.read_text()

    def test_unmatched_variables_kept(self, tmp_path):
        """Variables not in the dict stay as-is."""
        template = tmp_path / "tmpl.conf"
        template.write_text("${KNOWN} ${UNKNOWN}\n")
        output = tmp_path / "out.conf"

        generate_config(template, output, {"KNOWN": "yes"})

        content = output.read_text()
        assert "yes" in content
        assert "${UNKNOWN}" in content

    def test_empty_variables_dict(self, tmp_path):
        """Empty variables dict produces exact template copy."""
        template = tmp_path / "tmpl.conf"
        template.write_text("static content\n")
        output = tmp_path / "out.conf"

        generate_config(template, output, {})
        assert output.read_text() == "static content\n"


class TestApplyCommonOptions:
    """Tests for DNS, routes, full tunnel config injection."""

    @dataclass
    class FakeCfg:
        dns_domain: str = ""
        push_routes: str = ""
        full_tunnel: bool = False

    def test_no_options_no_change(self):
        """No options set leaves content unchanged."""
        cfg = self.FakeCfg()
        content = _apply_common_options("base\n", cfg)
        assert content == "base\n"

    def test_dns_domain_pushed(self):
        """DNS domain adds dhcp-option push."""
        cfg = self.FakeCfg(dns_domain="example.com")
        content = _apply_common_options("", cfg)
        assert 'push "dhcp-option DOMAIN example.com"' in content

    def test_push_routes_added(self):
        """CIDR routes are converted to push route directives."""
        cfg = self.FakeCfg(push_routes="10.0.0.0/24,172.16.0.0/16")
        content = _apply_common_options("", cfg)
        assert 'push "route 10.0.0.0 255.255.255.0"' in content
        assert 'push "route 172.16.0.0 255.255.0.0"' in content

    def test_full_tunnel_adds_redirect(self):
        """Full tunnel adds redirect-gateway directive."""
        cfg = self.FakeCfg(full_tunnel=True)
        content = _apply_common_options("", cfg)
        assert 'push "redirect-gateway def1 bypass-dhcp"' in content

    def test_all_options_combined(self):
        """All options work together."""
        cfg = self.FakeCfg(
            dns_domain="corp.io",
            push_routes="10.0.0.0/8",
            full_tunnel=True,
        )
        content = _apply_common_options("base\n", cfg)
        assert "dhcp-option DOMAIN corp.io" in content
        assert 'push "route 10.0.0.0 255.0.0.0"' in content
        assert "redirect-gateway def1 bypass-dhcp" in content

    def test_push_routes_without_cidr_skipped(self):
        """Routes without / separator are skipped."""
        cfg = self.FakeCfg(push_routes="invalid,10.0.0.0/24")
        content = _apply_common_options("", cfg)
        assert "invalid" not in content
        assert "10.0.0.0" in content

    def test_multiple_routes_comma_separated(self):
        """Multiple comma-separated routes all added."""
        cfg = self.FakeCfg(push_routes="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
        content = _apply_common_options("", cfg)
        lines_with_route = [line for line in content.split("\n") if "push" in line]
        assert len(lines_with_route) == 3


class TestStripTimestamps:
    """Tests for config comparison timestamp stripping."""

    def test_strips_date_comments(self):
        """Lines with dates in comments are removed."""
        content = (
            "# Generated: 2026-04-01\n"
            "remote vpn.example.com 1194\n"
            "# Culvert v2.0.0\n"
            "proto udp\n"
        )
        result = _strip_timestamps(content)
        assert "Generated" not in result
        assert "Culvert" not in result
        assert "remote vpn.example.com 1194" in result
        assert "proto udp" in result

    def test_preserves_non_date_comments(self):
        """Regular comments without dates are kept."""
        content = "# This is a normal comment\nline2\n"
        result = _strip_timestamps(content)
        assert "normal comment" in result

    def test_empty_content(self):
        """Empty content returns empty string."""
        assert _strip_timestamps("") == ""

    def test_no_timestamps_unchanged(self):
        """Content without timestamps is unchanged."""
        content = "remote vpn.example.com\nproto udp\n"
        assert _strip_timestamps(content) == content


class TestConfigGenerationTempFile:
    """Config generation must rename within the destination filesystem."""

    def test_temp_file_created_beside_destination(self, tmp_path, monkeypatch):
        """NamedTemporaryFile gets dir=<dest parent> so rename never crosses fs."""
        server_dir = tmp_path / "etc-vpn-server"
        server_dir.mkdir()
        (server_dir / "server.conf.template").write_text(
            "port ${OPENVPN_UDP_PORT}\nlog-append /var/log/vpn/openvpn.log\n"
        )

        cfg = Config()
        cfg.server_conf = server_dir / "server.conf"
        cfg.udp_enabled = True

        captured = {}
        real_ntf = openvpn_mod.tempfile.NamedTemporaryFile

        def spy(*args, **kwargs):
            captured["dir"] = kwargs.get("dir")
            return real_ntf(*args, **kwargs)

        monkeypatch.setattr(openvpn_mod.tempfile, "NamedTemporaryFile", spy)

        configure_server_udp(cfg)

        assert captured["dir"] == server_dir
        assert cfg.server_conf.exists()
        assert "port 1194" in cfg.server_conf.read_text()


# Listener name -> (configure function, template, Config field naming its output).
LISTENERS = {
    "udp": (configure_server_udp, "server.conf.template", "server_conf"),
    "tcp": (configure_server_tcp, "server-tcp.conf.template", "server_tcp_conf"),
    "https": (
        configure_server_https,
        "server-https.conf.template",
        "server_https_conf",
    ),
}


class TestShippedListenerRender:
    """Each listener rendered from the template the image ships."""

    @pytest.fixture
    def server_dir(self, tmp_path):
        """A server directory holding copies of the shipped templates."""
        server = tmp_path / "server"
        server.mkdir()
        for _, template, _ in LISTENERS.values():
            (server / template).write_text(
                (REPO_ROOT / "config" / template).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        return server

    @staticmethod
    def _cfg(server_dir, **overrides):
        cfg = Config(
            udp_enabled=True,
            tcp_enabled=True,
            https_enabled=True,
            server_conf=server_dir / "server.conf",
            server_tcp_conf=server_dir / "server-tcp.conf",
            server_https_conf=server_dir / "server-https.conf",
        )
        for name, value in overrides.items():
            setattr(cfg, name, value)
        return cfg

    @staticmethod
    def _render(listener, cfg):
        configure, _, field = LISTENERS[listener]
        configure(cfg)
        return getattr(cfg, field).read_text(encoding="utf-8")

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_every_placeholder_is_substituted(self, server_dir, listener):
        """OpenVPN refuses a config that still carries a ${...} placeholder."""
        rendered = self._render(listener, self._cfg(server_dir))
        assert "${" not in rendered

    def test_each_listener_binds_its_own_port(self, server_dir):
        cfg = self._cfg(
            server_dir, udp_port=11940, tcp_port=11941, https_internal_port=11942
        )
        assert "port 11940" in self._render("udp", cfg)
        assert "port 11941" in self._render("tcp", cfg)
        assert "port 11942" in self._render("https", cfg)

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_stdout_log_mode_reaches_every_listener(self, server_dir, listener):
        """A listener still logging to a file hides its failure inside the pod."""
        rendered = self._render(listener, self._cfg(server_dir, log_mode="stdout"))
        active = [
            line for line in rendered.splitlines() if line.startswith("log-append")
        ]
        assert active == [], f"{listener} still logs to a file: {active}"

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_file_log_mode_keeps_each_listeners_own_log(self, server_dir, listener):
        rendered = self._render(listener, self._cfg(server_dir, log_mode="file"))
        assert "\nlog-append /var/log/vpn/openvpn" in rendered

    def test_both_log_mode_adds_a_file_log_when_the_template_has_none(self, tmp_path):
        server = tmp_path / "server"
        server.mkdir()
        (server / "server.conf.template").write_text("port ${OPENVPN_UDP_PORT}\n")
        cfg = Config(
            server_conf=server / "server.conf",
            log_mode="both",
            log_dir=tmp_path / "log",
        )
        configure_server_udp(cfg)
        assert f"log-append {tmp_path / 'log'}/openvpn.log" in (
            cfg.server_conf.read_text(encoding="utf-8")
        )

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_common_options_reach_every_listener(self, server_dir, listener):
        cfg = self._cfg(
            server_dir,
            dns_domain="corp.example.test",
            push_routes="10.20.0.0/16",
            full_tunnel=True,
        )
        rendered = self._render(listener, cfg)
        assert 'push "dhcp-option DOMAIN corp.example.test"' in rendered
        assert 'push "route 10.20.0.0 255.255.0.0"' in rendered
        assert 'push "redirect-gateway def1 bypass-dhcp"' in rendered

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_disabled_listener_writes_nothing(self, server_dir, listener):
        cfg = self._cfg(
            server_dir, udp_enabled=False, tcp_enabled=False, https_enabled=False
        )
        configure, _, field = LISTENERS[listener]
        configure(cfg)
        assert not getattr(cfg, field).exists()

    @pytest.mark.parametrize("listener", sorted(LISTENERS))
    def test_missing_template_writes_nothing(self, tmp_path, listener):
        empty = tmp_path / "empty"
        empty.mkdir()
        cfg = self._cfg(empty)
        configure, _, field = LISTENERS[listener]
        configure(cfg)
        assert not getattr(cfg, field).exists()
        assert list(empty.iterdir()) == [], "a temp file was left behind"
