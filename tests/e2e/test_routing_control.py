#  Project:      culvert
#  File:         test_routing_control.py
#  Purpose:      E2E tests for opt-in routing control (CULVERT_FWD chain)
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E tests for routing control: client isolation, egress allow-list, and
the reverse-admin path.

Runs its own compose stack (docker-compose.routing.yml) with the feature
enabled, two clients, a receiver, and admin/non-admin sources, then asserts
the three guarantees with real traffic:

- clients cannot reach each other (client isolation);
- a source in CULVERT_DOWNSTREAM_ADMIN_CIDRS can initiate back down a tunnel,
  and one that is not cannot (reverse admin + its gate);
- clients can reach the allowed destination (egress allow-list + liveness).
"""

import subprocess
import time
from pathlib import Path

import pytest

COMPOSE_DIR = Path(__file__).parent
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.routing.yml"
PROJECT = "culvert-rc-e2e"
RECEIVER_URL = "http://172.32.1.20/"
TARGET_RESPONSE = "culvert-e2e-target-ok"
ADMIN_ROUTE_GW = "172.32.2.10"
TUN_SUBNET = "10.8.0.0/24"


def _compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT, *args]


def dexec(
    container: str, cmd: str, timeout: int = 30, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a shell command inside a container."""
    return subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def _tun_ip(container: str, timeout: int = 40) -> str:
    """Poll until the container's tun0 has an IPv4 address; return it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = dexec(
            container,
            "ip -4 addr show dev tun0 2>/dev/null | grep -oP 'inet \\K[0-9.]+'",
            check=False,
        )
        ip = result.stdout.strip()
        if ip:
            return ip
        time.sleep(1)
    raise TimeoutError(f"{container}: tun0 got no IP within {timeout}s")


def _can_ping(container: str, ip: str) -> bool:
    """True if container can ping ip (2 packets, 2s each)."""
    result = dexec(
        container,
        f"ping -c 2 -W 2 {ip}",
        timeout=15,
        check=False,
    )
    return result.returncode == 0


@pytest.fixture(scope="module", autouse=True)
def routing_stack():
    """Bring up the routing-control stack, connect both clients, tear down."""
    subprocess.run(_compose("up", "--build", "--wait", "-d"), check=True, timeout=420)
    try:
        # Generate a distinct client config for each client.
        for name in ("rc-client-a", "rc-client-b"):
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "rc-vpn-server",
                    "generate-client",
                    "--name",
                    name,
                    "--protocol",
                    "openvpn",
                    "--output",
                    "/etc/vpn/clients",
                ],
                check=True,
                timeout=120,
            )

        # Connect each client over UDP.
        for cont, name in (
            ("rc-client-a", "rc-client-a"),
            ("rc-client-b", "rc-client-b"),
        ):
            dexec(
                cont,
                f"openvpn --config /etc/vpn/clients/{name}-udp-split.ovpn"
                " --daemon --log /tmp/openvpn.log"
                " --connect-retry 1 --connect-retry-max 3",
            )
        _tun_ip("rc-client-a")
        _tun_ip("rc-client-b")

        # admin + non-admin need a route to the tunnel subnet via the server.
        for cont in ("rc-admin", "rc-nonadmin"):
            dexec(cont, f"ip route add {TUN_SUBNET} via {ADMIN_ROUTE_GW}", check=False)

        yield
    finally:
        subprocess.run(
            _compose("down", "-v", "--remove-orphans"), check=False, timeout=90
        )


@pytest.mark.e2e
class TestRoutingControl:
    """The three routing-control guarantees, exercised with real packets."""

    def test_clients_reach_allowed_destination(self):
        """Both clients reach the receiver through the tunnel (egress allow)."""
        for cont in ("rc-client-a", "rc-client-b"):
            result = dexec(
                cont,
                f"curl -sf --connect-timeout 5 {RECEIVER_URL}",
                timeout=15,
                check=False,
            )
            assert result.stdout.strip() == TARGET_RESPONSE, (
                f"{cont} could not reach the allowed receiver: {result.stdout!r}"
            )

    def test_client_to_client_is_blocked(self):
        """Client isolation: one client cannot reach another's tunnel IP."""
        peer_ip = _tun_ip("rc-client-b")
        assert not _can_ping("rc-client-a", peer_ip), (
            f"client isolation breached: rc-client-a reached {peer_ip}"
        )

    def test_reverse_admin_allowed(self):
        """A source in downstream_admin_cidrs reaches a client down the tunnel."""
        client_ip = _tun_ip("rc-client-a")
        assert _can_ping("rc-admin", client_ip), (
            f"reverse admin failed: rc-admin could not reach {client_ip}"
        )

    def test_reverse_admin_denied_for_non_admin(self):
        """A source NOT in downstream_admin_cidrs is denied."""
        client_ip = _tun_ip("rc-client-a")
        assert not _can_ping("rc-nonadmin", client_ip), (
            f"admin gate breached: rc-nonadmin reached {client_ip}"
        )
