#  Project:      culvert
#  File:         test_wireguard_connect.py
#  Purpose:      E2E tests for WireGuard connectivity
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for WireGuard connectivity."""

import pytest
from conftest import CLIENT_NAME
from helpers import (
    CLIENT_CONTAINER,
    TARGET_RESPONSE,
    assert_tunnel_mode,
    curl_target,
    docker_exec,
    has_wireguard_module,
    wait_for_tunnel,
)

# The connectivity stack is shared across this module's tests.
pytestmark = pytest.mark.usefixtures("compose_stack")

_wg_available = None


def wireguard_available() -> bool:
    """Lazy check for WireGuard kernel module."""
    global _wg_available  # noqa: PLW0603
    if _wg_available is None:
        _wg_available = has_wireguard_module()
    return _wg_available


@pytest.mark.e2e
@pytest.mark.skipif(
    "not wireguard_available()",
    reason="WireGuard kernel module not available",
)
class TestWireGuard:
    """WireGuard connectivity."""

    def test_connect_and_reach_target(self, wireguard_connection):
        """Client connects via WireGuard and reaches target."""
        ip = wait_for_tunnel("wg0", timeout=15)
        assert ip.startswith("10.8.3."), f"Expected IP in 10.8.3.0/24, got {ip}"
        assert_tunnel_mode("wg0", "split")

        body = curl_target()
        assert body == TARGET_RESPONSE, f"Expected '{TARGET_RESPONSE}', got '{body}'"

    def test_full_tunnel_connect_and_reach_target(self, wireguard_full_connection):
        """The full-tunnel config, which wg-quick routes a different way.

        Split gets a plain route for the pushed prefixes; full gets an fwmark and
        a policy rule, which is also the path that needs
        net.ipv4.conf.all.src_valid_mark - requested on the client in the compose
        file, because wg-quick's own attempt to set it fails inside a container.
        """
        ip = wait_for_tunnel("wg0", timeout=15)
        assert ip.startswith("10.8.3."), f"Expected IP in 10.8.3.0/24, got {ip}"

        mark = docker_exec(
            CLIENT_CONTAINER,
            "cat /proc/sys/net/ipv4/conf/all/src_valid_mark",
            check=False,
        ).stdout.strip()
        assert mark == "1", (
            "net.ipv4.conf.all.src_valid_mark is not 1 in the client container,"
            " so rp_filter may drop the tunnel's return traffic and a failure"
            " here would say nothing about the server"
        )
        assert_tunnel_mode("wg0", "full")

        body = curl_target()
        assert body == TARGET_RESPONSE, f"Expected '{TARGET_RESPONSE}', got '{body}'"


@pytest.mark.e2e
@pytest.mark.skipif(
    "not wireguard_available()",
    reason="WireGuard kernel module not available",
)
class TestWireGuardOverHTTPSOpenNetwork:
    """WireGuard over HTTPS (wstunnel)."""

    @pytest.fixture(autouse=True)
    def _require_https_tunnel_config(self):
        """Skip if HTTPS-tunnel client config was not generated."""
        result = docker_exec(
            CLIENT_CONTAINER,
            f"test -f /etc/vpn/clients/{CLIENT_NAME}-wg-https-split.conf",
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("WireGuard-over-HTTPS config not generated")

    def test_connect_and_reach_target(self, wireguard_https_tunnel_connection):
        """Client connects via WireGuard over HTTPS and reaches target."""
        ip = wait_for_tunnel("wg0", timeout=15)
        assert ip.startswith("10.8.3."), f"Expected IP in 10.8.3.0/24, got {ip}"

        body = curl_target()
        assert body == TARGET_RESPONSE, f"Expected '{TARGET_RESPONSE}', got '{body}'"
