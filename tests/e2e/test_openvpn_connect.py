#  Project:      culvert
#  File:         test_openvpn_connect.py
#  Purpose:      E2E tests for OpenVPN connectivity (UDP, TCP, HTTPS)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for OpenVPN connectivity (UDP, TCP, HTTPS)."""

import pytest
from conftest import CLIENT_NAME
from helpers import (
    CLIENT_CONTAINER,
    TARGET_RESPONSE,
    assert_tunnel_mode,
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
        assert_tunnel_mode("tun0", "split")

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )

    def test_full_tunnel_connect_and_reach_target(self, openvpn_udp_full_connection):
        """The full-tunnel config: same reachability, but via a default route.

        Split and full route by different means - a pushed prefix versus
        redirect-gateway - so a fault in one is invisible from the other. This
        pair is also what would have caught the block-outside-dns push, which
        only breaks a full tunnel.
        """
        ip = wait_for_tunnel("tun0", timeout=30)
        assert ip.startswith("10.8.0."), f"Expected IP in 10.8.0.0/24, got {ip}"
        assert_tunnel_mode("tun0", "full")

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )

    def test_target_unreachable_after_disconnect(self):
        """After connect+disconnect, target is unreachable again."""
        connect_openvpn(f"{CLIENT_NAME}-udp-split.ovpn")
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
    def _require_stunnel_config(self):
        """Fail, not skip, if the stunnel client config is missing.

        Skipping here would let a broken config generator turn the whole HTTPS
        path green - the listener is opted in by this stack, so the config not
        being there is a defect, not an unmet precondition.
        """
        stunnel_conf = f"{CLIENT_NAME}-stunnel.conf"
        result = docker_exec(
            CLIENT_CONTAINER,
            f"test -f /etc/vpn/clients/{stunnel_conf}",
            check=False,
        )
        assert result.returncode == 0, (
            f"{stunnel_conf} was not generated, so the HTTPS listener"
            " cannot be tested. generate-client should have produced it."
        )

    def test_connect_and_reach_target(self, openvpn_https_connection):
        """Client connects via HTTPS tunnel and reaches target."""
        ip = wait_for_tunnel("tun0", timeout=30)
        assert ip.startswith("10.8.2."), f"Expected IP in 10.8.2.0/24, got {ip}"

        body = curl_target()
        assert body == TARGET_RESPONSE, (
            f"Expected '{TARGET_RESPONSE}', got '{body}'. "
            f"OpenVPN log:\n{get_openvpn_log()}"
        )
