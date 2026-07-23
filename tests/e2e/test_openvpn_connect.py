#  Project:      culvert
#  File:         test_openvpn_connect.py
#  Purpose:      E2E tests for OpenVPN connectivity (UDP, TCP, HTTPS)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for OpenVPN connectivity (UDP, TCP, HTTPS)."""

import pytest
from helpers import (
    TARGET_RESPONSE,
    connect_openvpn,
    curl_target,
    disconnect_openvpn,
    docker_exec,
    get_openvpn_log,
    wait_for_tunnel,
)

# The connectivity stack is shared across this module's tests.
pytestmark = pytest.mark.usefixtures("compose_stack")


@pytest.mark.e2e
class TestNoTunnel:
    """Verify target is unreachable without VPN."""

    def test_target_unreachable_without_vpn(self):
        """Client cannot reach target on internal network directly."""
        result = curl_target(timeout=3)
        assert result is None, (
            f"Target should be unreachable without VPN, but got: {result}"
        )


@pytest.mark.e2e
class TestOpenVPNUDP:
    """OpenVPN UDP connectivity."""

    def test_connect_and_reach_target(self, openvpn_udp_connection):
        """Client connects via UDP and reaches target through tunnel."""
        ip = wait_for_tunnel("tun0", timeout=30)
        assert ip.startswith("10.8.0."), f"Expected IP in 10.8.0.0/24, got {ip}"

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )

    def test_target_unreachable_after_disconnect(self):
        """After connect+disconnect, target is unreachable again."""
        connect_openvpn("e2e-client-udp-split.ovpn")
        try:
            wait_for_tunnel("tun0", timeout=30)
        finally:
            disconnect_openvpn()

        result = curl_target(timeout=3)
        assert result is None, "Target should be unreachable after disconnect"


@pytest.mark.e2e
class TestOpenVPNTCP:
    """OpenVPN TCP connectivity."""

    def test_connect_and_reach_target(self, openvpn_tcp_connection):
        """Client connects via TCP and reaches target through tunnel."""
        ip = wait_for_tunnel("tun0", timeout=30)
        assert ip.startswith("10.8.1."), f"Expected IP in 10.8.1.0/24, got {ip}"

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )


@pytest.mark.e2e
class TestOpenVPNHTTPS:
    """OpenVPN HTTPS (stunnel) connectivity."""

    @pytest.fixture(autouse=True)
    def _check_stunnel_config(self):
        """Skip if stunnel client config was not generated."""
        result = docker_exec(
            "e2e-vpn-client",
            "test -f /etc/vpn/clients/e2e-client-stunnel.conf",
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("stunnel config not generated")

    def test_connect_and_reach_target(self, openvpn_https_connection):
        """Client connects via HTTPS tunnel and reaches target."""
        ip = wait_for_tunnel("tun0", timeout=30)
        assert ip.startswith("10.8.2."), f"Expected IP in 10.8.2.0/24, got {ip}"

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )
