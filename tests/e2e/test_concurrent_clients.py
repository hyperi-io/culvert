#  Project:      culvert
#  File:         test_concurrent_clients.py
#  Purpose:      E2E tests for two concurrent connections on one client identity
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for shared client connections.

Two client hosts connect at the same time under a single issued identity and
both must carry traffic. A single-host test cannot show this: the failure mode
is one connection EVICTING the other, which looks identical to success when
only one end is ever up.
"""

import time

import pytest
from conftest import CLIENT_NAME
from helpers import (
    CLIENT_B_CONTAINER,
    CLIENT_CONTAINER,
    SERVER_CONTAINER,
    TARGET_RESPONSE,
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


def _wait_for_status_sessions(
    common_name: str, wanted: int, timeout: int = 45
) -> tuple[list[str], str]:
    """Poll the server's status log until it lists ``wanted`` sessions.

    The server rewrites status.log on a 10s timer, so a read taken straight
    after a client connects still shows the previous state. Returns the
    matching lines and the last status file read, so a failure can show both.
    """
    deadline = time.monotonic() + timeout
    status = ""
    sessions: list[str] = []
    while time.monotonic() < deadline:
        status = docker_exec(
            SERVER_CONTAINER,
            "cat /var/log/vpn/status.log",
            check=False,
        ).stdout
        # Only the CLIENT LIST rows name a session; the routing table repeats
        # the common name once per virtual address and would double the count.
        sessions = [
            line
            for line in status.split("ROUTING TABLE")[0].splitlines()
            if line.startswith(f"{common_name},")
        ]
        if len(sessions) >= wanted:
            return sessions, status
        time.sleep(2)
    return sessions, status


@pytest.mark.e2e
class TestOpenVpnSharedCertificate:
    """One certificate, two live sessions -- what duplicate-cn buys."""

    def test_both_hosts_connect_on_one_certificate(
        self, openvpn_shared_pair_connection
    ):
        """Both hosts get a tunnel address from the same .ovpn."""
        ip_a = wait_for_tunnel("tun0", timeout=30, container=CLIENT_CONTAINER)
        ip_b = wait_for_tunnel("tun0", timeout=30, container=CLIENT_B_CONTAINER)

        assert ip_a.startswith("10.8.0."), f"Expected 10.8.0.0/24, got {ip_a}"
        assert ip_b.startswith("10.8.0."), f"Expected 10.8.0.0/24, got {ip_b}"
        assert ip_a != ip_b, (
            f"both sessions were given {ip_a}, so the server treated them as one"
            " connection rather than two"
        )

    def test_both_hosts_carry_traffic_at_the_same_time(
        self, openvpn_shared_pair_connection
    ):
        """Neither session was evicted: both still reach the target."""
        wait_for_tunnel("tun0", timeout=30, container=CLIENT_CONTAINER)
        wait_for_tunnel("tun0", timeout=30, container=CLIENT_B_CONTAINER)

        body_a = curl_target(container=CLIENT_CONTAINER)
        body_b = curl_target(container=CLIENT_B_CONTAINER)

        assert body_a == TARGET_RESPONSE, (
            f"the first session stopped carrying traffic once the second"
            f" connected (got {body_a!r})"
        )
        assert body_b == TARGET_RESPONSE, (
            f"the second session did not carry traffic (got {body_b!r})"
        )

    def test_server_reports_two_sessions_for_the_one_common_name(
        self, openvpn_shared_pair_connection
    ):
        """The server's own status log is the authority on session count."""
        wait_for_tunnel("tun0", timeout=30, container=CLIENT_CONTAINER)
        wait_for_tunnel("tun0", timeout=30, container=CLIENT_B_CONTAINER)

        sessions, status = _wait_for_status_sessions(CLIENT_NAME, wanted=2)

        assert len(sessions) >= 2, (
            f"the server lists {len(sessions)} session(s) for {CLIENT_NAME},"
            f" so the two hosts are not concurrently connected:\n{status}"
        )


@pytest.mark.e2e
@pytest.mark.skipif(
    "not wireguard_available()",
    reason="WireGuard kernel module not available",
)
class TestWireGuardDeviceSlots:
    """One client identity, one peer per device slot, both live."""

    def test_each_slot_gets_its_own_tunnel_address(
        self, wireguard_slot_pair_connection
    ):
        """Distinct addresses are what let the server route to both at once."""
        ip_a = wait_for_tunnel("wg0", timeout=15, container=CLIENT_CONTAINER)
        ip_b = wait_for_tunnel("wg0", timeout=15, container=CLIENT_B_CONTAINER)

        assert ip_a.startswith("10.8.3."), f"Expected 10.8.3.0/24, got {ip_a}"
        assert ip_b.startswith("10.8.3."), f"Expected 10.8.3.0/24, got {ip_b}"
        assert ip_a != ip_b, (
            f"both device slots are on {ip_a}; sharing one address means the"
            " server cannot tell the two devices apart"
        )

    def test_both_slots_carry_traffic_at_the_same_time(
        self, wireguard_slot_pair_connection
    ):
        """Both peers reach the target while both tunnels are up."""
        wait_for_tunnel("wg0", timeout=15, container=CLIENT_CONTAINER)
        wait_for_tunnel("wg0", timeout=15, container=CLIENT_B_CONTAINER)

        body_a = curl_target(container=CLIENT_CONTAINER)
        body_b = curl_target(container=CLIENT_B_CONTAINER)

        assert body_a == TARGET_RESPONSE, (
            f"device slot 1 stopped carrying traffic once slot 2 connected"
            f" (got {body_a!r})"
        )
        assert body_b == TARGET_RESPONSE, (
            f"device slot 2 did not carry traffic (got {body_b!r})"
        )

    def test_server_holds_a_handshake_for_both_peers(
        self, wireguard_slot_pair_connection
    ):
        """The kernel peer table is the authority on who is really connected."""
        wait_for_tunnel("wg0", timeout=15, container=CLIENT_CONTAINER)
        wait_for_tunnel("wg0", timeout=15, container=CLIENT_B_CONTAINER)

        # Traffic first: a peer has no handshake until it sends something.
        curl_target(container=CLIENT_CONTAINER)
        curl_target(container=CLIENT_B_CONTAINER)

        handshakes = docker_exec(
            SERVER_CONTAINER,
            "wg show wg0 latest-handshakes",
            check=False,
        ).stdout
        live = [
            line
            for line in handshakes.splitlines()
            if line.strip() and line.split()[-1] != "0"
        ]

        assert len(live) >= 2, (
            f"only {len(live)} peer(s) have handshaked, so the two device slots"
            f" are not both live:\n{handshakes}"
        )

    def test_slots_use_different_keys(self, wireguard_slot_pair_connection):
        """A shared key could not work: WireGuard keeps one endpoint per peer."""
        key_a = docker_exec(
            CLIENT_CONTAINER, "wg show wg0 public-key", check=False
        ).stdout.strip()
        key_b = docker_exec(
            CLIENT_B_CONTAINER, "wg show wg0 public-key", check=False
        ).stdout.strip()

        assert key_a and key_b, "could not read the client public keys"
        assert key_a != key_b, (
            "both device slots were issued the same keypair, so the server would"
            " answer only whichever device handshook last"
        )
