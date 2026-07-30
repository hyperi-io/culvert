#  Project:      culvert
#  File:         test_https_tunnel.py
#  Purpose:      E2E tests for VPN over HTTPS on a network that blocks the rest
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for running the VPN over HTTPS.

The other connectivity modules prove each listener works on an open network.
These prove the claim that actually sells the HTTPS-tunnelled listeners: that
they still work when every plain VPN port is blocked and only a web port gets
out. The client blocks its own egress to UDP 1194, TCP 1194 and UDP 51820, so
the only route to the server is TLS on 443 (stunnel) or 4443 (wstunnel).

Each test first asserts the block is genuinely in force. Without that, a
passing result would prove nothing - the traffic could simply have taken the
plain path.
"""

import pytest
from helpers import (
    TARGET_RESPONSE,
    block_plain_vpn_ports,
    connect_openvpn,
    connect_openvpn_https,
    connect_wireguard_https_tunnel,
    curl_target,
    disconnect_openvpn,
    disconnect_openvpn_https,
    disconnect_wireguard_https_tunnel,
    docker_exec,
    get_openvpn_log,
    has_wireguard_module,
    tcp_port_reachable,
    tls_handshake,
    unblock_plain_vpn_ports,
    wait_for_tunnel,
)

CLIENT_NAME = "e2e-client"

pytestmark = pytest.mark.usefixtures("compose_stack")


@pytest.fixture
def plain_ports_blocked():
    """Block the client's egress to every plain VPN listener."""
    block_plain_vpn_ports()
    try:
        yield
    finally:
        unblock_plain_vpn_ports()


@pytest.mark.e2e
class TestWebPortsSpeakTLS:
    """The listeners on the web ports must present real TLS."""

    def test_https_listener_completes_tls_handshake(self):
        """stunnel on 443 must terminate TLS, not just accept bytes."""
        report = tls_handshake(443)
        assert "CONNECTION ESTABLISHED" in report, (
            f"No TLS handshake on 443. openssl said:\n{report}"
        )
        assert "TLSv1.3" in report, f"Expected TLS 1.3 on 443, got:\n{report}"

    def test_wstunnel_listener_completes_tls_handshake(self):
        """wstunnel on 4443 must serve WSS, so TLS must terminate there too."""
        report = tls_handshake(4443)
        assert "CONNECTION ESTABLISHED" in report, (
            f"No TLS handshake on 4443. openssl said:\n{report}"
        )


@pytest.mark.e2e
class TestPlainPortsBlockIsReal:
    """Guard the guard: prove the block works before relying on it."""

    def test_web_port_open_and_plain_port_closed(self, plain_ports_blocked):
        """TCP 1194 must be unreachable while 443 stays reachable."""
        assert not tcp_port_reachable(1194), (
            "TCP 1194 is still reachable, so the egress block did not take"
            " effect and the HTTPS tests below would prove nothing"
        )
        assert tcp_port_reachable(443), (
            "TCP 443 is unreachable, so the block is too broad"
        )

    def test_plain_openvpn_cannot_connect_when_blocked(self, plain_ports_blocked):
        """The plain UDP listener must fail while blocked."""
        connect_openvpn(f"{CLIENT_NAME}-udp-split.ovpn")
        try:
            with pytest.raises(TimeoutError):
                wait_for_tunnel("tun0", timeout=20)
        finally:
            disconnect_openvpn()


@pytest.mark.e2e
class TestOpenVPNOverHTTPS:
    """OpenVPN reaches the target with only 443 open."""

    def test_connects_and_reaches_target_when_plain_blocked(self, plain_ports_blocked):
        """The whole point: a working tunnel over nothing but a web port."""
        connect_openvpn_https(
            f"{CLIENT_NAME}-https-split.ovpn",
            f"{CLIENT_NAME}-stunnel.conf",
        )
        try:
            ip = wait_for_tunnel("tun0", timeout=40)
            assert ip.startswith("10.8.2."), (
                f"Expected an IP from the HTTPS listener's 10.8.2.0/24, got {ip}"
            )

            body = curl_target()
            assert body == TARGET_RESPONSE, (
                f"Expected '{TARGET_RESPONSE}', got '{body}'."
                f" OpenVPN log:\n{get_openvpn_log()}"
            )
        finally:
            disconnect_openvpn_https()

    def test_traffic_actually_traverses_stunnel(self, plain_ports_blocked):
        """The client's stunnel must hold an established session to 443.

        Confirms the path really is client -> stunnel -> 443 rather than the
        tunnel having come up some other way.
        """
        connect_openvpn_https(
            f"{CLIENT_NAME}-https-split.ovpn",
            f"{CLIENT_NAME}-stunnel.conf",
        )
        try:
            wait_for_tunnel("tun0", timeout=40)
            result = docker_exec(
                "e2e-vpn-client",
                "ss -tnp state established '( dport = :443 )'",
                check=False,
            )
            assert "443" in result.stdout, (
                "No established connection to port 443 while the tunnel was up."
                f" ss said:\n{result.stdout}\n{result.stderr}"
            )
        finally:
            disconnect_openvpn_https()


@pytest.mark.e2e
class TestWireGuardOverHTTPS:
    """WireGuard reaches the target with only 4443 open."""

    @pytest.fixture(autouse=True)
    def _require_wireguard(self):
        if not has_wireguard_module():
            pytest.skip("WireGuard kernel module unavailable on this host")

    def test_connects_and_reaches_target_when_plain_blocked(self, plain_ports_blocked):
        """WireGuard over WebSocket/TLS with UDP 51820 blocked."""
        config_name = f"{CLIENT_NAME}-wg-https-split.conf"
        connect_wireguard_https_tunnel(config_name)
        try:
            body = curl_target()
            assert body == TARGET_RESPONSE, (
                f"Expected '{TARGET_RESPONSE}', got '{body}' with UDP 51820"
                " blocked - WireGuard over HTTPS did not carry the traffic"
            )
        finally:
            disconnect_wireguard_https_tunnel(config_name)
