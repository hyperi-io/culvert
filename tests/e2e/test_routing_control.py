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
from conftest import ROUTING_PROJECT, tidy_stack

# Both stacks serve the same nginx-target.conf, so the marker has one
# definition - a second copy here drifted out of step with it once already.
from helpers import TARGET_RESPONSE, docker_exec
from tidy import register_teardown

COMPOSE_DIR = Path(__file__).parent
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.routing.yml"
PROJECT = ROUTING_PROJECT
RECEIVER_URL = "http://172.29.1.20/"

# Containers, matching docker-compose.routing.yml.
SERVER = f"{ROUTING_PROJECT}-server"
CLIENT_A = f"{ROUTING_PROJECT}-client-a"
CLIENT_B = f"{ROUTING_PROJECT}-client-b"
ADMIN = f"{ROUTING_PROJECT}-admin"
NONADMIN = f"{ROUTING_PROJECT}-nonadmin"
CLIENTS = (CLIENT_A, CLIENT_B)

# Certificate names, kept distinct from the container names so that reading one
# for the other does not send you looking in the wrong place.
CERT_NAMES = {CLIENT_A: "rc-client-a", CLIENT_B: "rc-client-b"}
ADMIN_ROUTE_GW = "172.29.2.10"
TUN_SUBNET = "10.8.0.0/24"


def _compose(*args: str) -> list[str]:
    return ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT, *args]


def _tun_ip(container: str, timeout: int = 40) -> str:
    """Poll until the container's tun0 has an IPv4 address; return it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = docker_exec(
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
    result = docker_exec(
        container,
        f"ping -c 2 -W 2 {ip}",
        timeout=15,
        check=False,
    )
    return result.returncode == 0


@pytest.fixture(scope="module", autouse=True)
def routing_stack():
    """Bring up the routing-control stack, connect both clients, tear down."""
    # Clear anything an earlier run left behind before building - a killed run
    # otherwise collides on container names or reuses a stale clients volume.
    # Scoped to THIS project: the connectivity stack is session-scoped and still
    # in use by the modules that run after this one.
    tidy_stack(ROUTING_PROJECT)
    register_teardown(f"compose {ROUTING_PROJECT}", lambda: tidy_stack(ROUTING_PROJECT))

    subprocess.run(_compose("up", "--build", "--wait", "-d"), check=True, timeout=420)
    try:
        # Generate a distinct client config for each client.
        for cert_name in CERT_NAMES.values():
            subprocess.run(
                [
                    "docker",
                    "exec",
                    SERVER,
                    "generate-client",
                    "--name",
                    cert_name,
                    "--protocol",
                    "openvpn",
                    "--output",
                    "/etc/vpn/clients",
                ],
                check=True,
                timeout=120,
            )

        # Connect each client over UDP.
        for container in CLIENTS:
            config = f"{CERT_NAMES[container]}-udp-split.ovpn"
            docker_exec(
                container,
                f"openvpn --config /etc/vpn/clients/{config}"
                " --daemon --log /tmp/openvpn.log"
                " --connect-retry 1 --connect-retry-max 3",
            )
        for container in CLIENTS:
            _tun_ip(container)

        # admin + non-admin need a route to the tunnel subnet via the server.
        for container in (ADMIN, NONADMIN):
            docker_exec(
                container,
                f"ip route add {TUN_SUBNET} via {ADMIN_ROUTE_GW}",
                check=False,
            )

        yield
    finally:
        # Module-scoped, so this frees the stack's ports and subnets before the
        # modules that follow. The registered teardown is the backstop for an
        # interrupted session, when this finaliser does not run at all.
        tidy_stack(ROUTING_PROJECT)


@pytest.mark.e2e
class TestRoutingControl:
    """The three routing-control guarantees, exercised with real packets."""

    def test_clients_reach_allowed_destination(self):
        """Both clients reach the receiver through the tunnel (egress allow)."""
        for container in CLIENTS:
            result = docker_exec(
                container,
                f"curl -sf --connect-timeout 5 {RECEIVER_URL}",
                timeout=15,
                check=False,
            )
            assert result.stdout.strip() == TARGET_RESPONSE, (
                f"{container} could not reach the allowed receiver: {result.stdout!r}"
            )

    def test_client_to_client_is_blocked(self):
        """Client isolation: one client cannot reach another's tunnel IP."""
        peer_ip = _tun_ip(CLIENT_B)
        assert not _can_ping(CLIENT_A, peer_ip), (
            f"client isolation breached: {CLIENT_A} reached {peer_ip}"
        )

    def test_reverse_admin_allowed(self):
        """A source in downstream_admin_cidrs reaches a client down the tunnel."""
        client_ip = _tun_ip(CLIENT_A)
        assert _can_ping(ADMIN, client_ip), (
            f"reverse admin failed: {ADMIN} could not reach {client_ip}"
        )

    def test_reverse_admin_denied_for_non_admin(self):
        """A source NOT in downstream_admin_cidrs is denied."""
        client_ip = _tun_ip(CLIENT_A)
        assert not _can_ping(NONADMIN, client_ip), (
            f"admin gate breached: {NONADMIN} reached {client_ip}"
        )
