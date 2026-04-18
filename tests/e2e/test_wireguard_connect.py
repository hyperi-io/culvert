#  Project:      hyperi-vpn
#  File:         test_wireguard_connect.py
#  Purpose:      E2E tests for WireGuard connectivity
#  Language:     Python
#
#  License:      FSL-1.1-ALv2
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for WireGuard connectivity."""

import pytest
from helpers import (
    TARGET_RESPONSE,
    curl_target,
    docker_exec,
    has_wireguard_module,
    wait_for_tunnel,
)

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
        assert ip.startswith("192.168.200."), (
            f"Expected IP in 192.168.200.0/24, got {ip}"
        )

        body = curl_target()
        assert body == TARGET_RESPONSE, f"Expected '{TARGET_RESPONSE}', got '{body}'"


@pytest.mark.e2e
@pytest.mark.skipif(
    "not wireguard_available()",
    reason="WireGuard kernel module not available",
)
class TestWireGuardDPIBypass:
    """WireGuard DPI bypass (wstunnel) connectivity."""

    @pytest.fixture(autouse=True)
    def _check_dpi_config(self):
        """Skip if DPI bypass client config was not generated."""
        result = docker_exec(
            "e2e-vpn-client",
            "test -f /etc/vpn/clients/e2e-client-wg-dpi-split.conf",
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("WireGuard DPI bypass config not generated")

    def test_connect_and_reach_target(self, wireguard_dpi_connection):
        """Client connects via WireGuard DPI bypass and reaches target."""
        ip = wait_for_tunnel("wg0", timeout=15)
        assert ip.startswith("192.168.200."), (
            f"Expected IP in 192.168.200.0/24, got {ip}"
        )

        body = curl_target()
        assert body == TARGET_RESPONSE, f"Expected '{TARGET_RESPONSE}', got '{body}'"
