#  Project:      culvert
#  File:         test_wstunnel.py
#  Purpose:      Tests for wstunnel WireGuard-over-HTTPS module
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

from dataclasses import dataclass

from lib.process import ProcessManager
from lib.wstunnel import _build_wstunnel_command, start_wstunnel


@dataclass
class FakeWstunnelCfg:
    wg_https_tunnel_enabled: bool = True
    wg_https_tunnel_port: int = 4443
    wg_port: int = 51820
    stunnel_cert: str = "/etc/vpn/pki/stunnel.pem"
    stunnel_key: str = "/etc/vpn/pki/stunnel.key"


class TestStartWstunnel:
    """start_wstunnel side-effect gate."""

    def test_returns_none_when_disabled(self):
        """No process is started when the HTTPS tunnel is disabled."""
        cfg = FakeWstunnelCfg(wg_https_tunnel_enabled=False)
        assert start_wstunnel(cfg, ProcessManager()) is None


class TestBuildWstunnelCommand:
    """Command construction for the wstunnel server."""

    def test_serves_wss_on_https_tunnel_port(self):
        """The server listens with WSS on the configured HTTPS-tunnel port."""
        cmd = _build_wstunnel_command(FakeWstunnelCfg(wg_https_tunnel_port=8443))
        assert cmd[:2] == ["wstunnel", "server"]
        assert "wss://0.0.0.0:8443" in cmd

    def test_restricts_forwarding_to_local_wireguard(self):
        """Forwarding is restricted to the local WireGuard listener only."""
        cmd = _build_wstunnel_command(FakeWstunnelCfg(wg_port=51900))
        restrict_idx = cmd.index("--restrict-to")
        assert cmd[restrict_idx + 1] == "127.0.0.1:51900"

    def test_wires_tls_cert_and_key(self):
        """The TLS certificate and key paths are passed through."""
        cfg = FakeWstunnelCfg(stunnel_cert="/c/cert.pem", stunnel_key="/c/key.pem")
        cmd = _build_wstunnel_command(cfg)
        assert cmd[cmd.index("--tls-certificate") + 1] == "/c/cert.pem"
        assert cmd[cmd.index("--tls-private-key") + 1] == "/c/key.pem"
