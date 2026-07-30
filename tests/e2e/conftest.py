#  Project:      culvert
#  File:         conftest.py
#  Purpose:      E2E test configuration - compose lifecycle and client configs
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E test configuration - compose lifecycle and client config generation."""

import subprocess
import time
from pathlib import Path

import pytest
from helpers import CLIENT_CONTAINER, SERVER_CONTAINER
from tidy import register_teardown

COMPOSE_DIR = Path(__file__).parent

# The client identity the tests issue certificates for. Deliberately NOT the
# client container's name: it names a certificate CN and the config filenames
# derived from it, and reading one for the other sends you looking in the wrong
# place.
CLIENT_NAME = "e2e-client"

# Every container, volume and network this tier creates belongs to one of these
# compose projects, which is what lets the sweep below find strays.
PROJECT = "culvert-test-e2e"
ROUTING_PROJECT = "culvert-test-e2e-routing"

# Projects these stacks used to run under. Swept too, so a stray left by a run
# from before the rename is cleared once rather than lingering forever.
LEGACY_PROJECTS = ("culvert-e2e", "culvert-routing-e2e")

COMPOSE_FILES = {
    PROJECT: COMPOSE_DIR / "docker-compose.yml",
    ROUTING_PROJECT: COMPOSE_DIR / "docker-compose.routing.yml",
}


def _compose_cmd(*args: str) -> list[str]:
    """Build a docker compose command list."""
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILES[PROJECT]),
        "-p",
        PROJECT,
        *args,
    ]


def compose_down(project: str) -> None:
    """Remove a stack's containers, volumes and networks. Safe to repeat."""
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILES[project]),
            "-p",
            project,
            "down",
            "-v",
            "--remove-orphans",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def sweep_project(project: str) -> None:
    """Remove leftovers belonging to one compose project.

    ``compose down`` only removes what the CURRENT project file describes, so an
    object left by a run whose service or volume has since been renamed survives
    it and then collides on the next ``up``.

    Selection is on compose's own project label, not on a name prefix. A prefix
    cannot separate these two stacks - ``culvert-test-e2e`` is a prefix of
    ``culvert-test-e2e-routing`` - so sweeping the connectivity stack by name
    also destroys the routing stack, and vice versa. The label matches exactly.
    """
    label = f"label=com.docker.compose.project={project}"
    sweeps = (
        (["docker", "ps", "-aq", "--filter", label], ["docker", "rm", "-f"]),
        (
            ["docker", "volume", "ls", "-q", "--filter", label],
            ["docker", "volume", "rm", "-f"],
        ),
        (
            ["docker", "network", "ls", "-q", "--filter", label],
            ["docker", "network", "rm"],
        ),
    )
    for list_cmd, remove_cmd in sweeps:
        listing = subprocess.run(
            list_cmd, capture_output=True, text=True, check=False, timeout=60
        )
        ids = listing.stdout.split()
        if ids:
            subprocess.run(
                [*remove_cmd, *ids],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )


def tidy_stack(project: str) -> None:
    """Take one stack down and clear anything it left behind."""
    compose_down(project)
    sweep_project(project)


def tidy_all() -> None:
    """Full cleanup for both e2e stacks. The manual entry point calls this too."""
    for project in COMPOSE_FILES:
        tidy_stack(project)
    for project in LEGACY_PROJECTS:
        sweep_project(project)


@pytest.fixture(scope="session")
def compose_stack():
    """Start the compose stack, generate client configs, yield, then tear down.

    Not autouse: the connectivity test modules opt in via a module-level
    ``pytestmark = pytest.mark.usefixtures("compose_stack")`` so that other
    e2e modules (e.g. routing control) can run their own stack in isolation.
    """
    # Clear anything an earlier run left behind before building, so a killed run
    # cannot make the next one fail on a name collision or a stale volume.
    tidy_stack(PROJECT)
    register_teardown(f"compose {PROJECT}", lambda: tidy_stack(PROJECT))

    # Build and start
    subprocess.run(
        _compose_cmd("up", "--build", "--wait", "-d"),
        check=True,
        timeout=300,
    )

    # Generate client configs for all protocols
    # Try full generation first; if cert already exists, use --config-only
    result = subprocess.run(
        [
            "docker",
            "exec",
            SERVER_CONTAINER,
            "generate-client",
            "--name",
            CLIENT_NAME,
            "--protocol",
            "all",
            "--output",
            "/etc/vpn/clients",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        subprocess.run(
            [
                "docker",
                "exec",
                SERVER_CONTAINER,
                "generate-client",
                "--name",
                CLIENT_NAME,
                "--protocol",
                "all",
                "--output",
                "/etc/vpn/clients",
                "--config-only",
            ],
            check=True,
            timeout=120,
        )

    # No wg0 reload here on purpose. generate-client writes the server config to
    # the path the server uses and pushes the peer into the running interface
    # itself; doing it again from the test would hide a regression in that.

    # Small delay for configs to sync via shared volume
    time.sleep(1)

    # Verify expected config files exist. This stack opts in to every listener,
    # so the HTTPS-tunnelled configs are checked here too - a test that skipped
    # on their absence would let a broken generator look green.
    expected = [
        f"{CLIENT_NAME}-udp-split.ovpn",
        f"{CLIENT_NAME}-udp-full.ovpn",
        f"{CLIENT_NAME}-tcp-split.ovpn",
        f"{CLIENT_NAME}-https-split.ovpn",
        f"{CLIENT_NAME}-stunnel.conf",
        f"{CLIENT_NAME}-wg-split.conf",
        f"{CLIENT_NAME}-wg-full.conf",
        f"{CLIENT_NAME}-wg-https-split.conf",
    ]
    result = subprocess.run(
        ["docker", "exec", CLIENT_CONTAINER, "ls", "/etc/vpn/clients/"],
        capture_output=True,
        text=True,
    )
    files = result.stdout.strip()
    for name in expected:
        assert name in files, f"Expected config {name} not found. Available: {files}"

    yield

    # Teardown is the registered one above, which also runs when the session is
    # interrupted - a finaliser here would be skipped in exactly that case.


@pytest.fixture
def openvpn_udp_connection():
    """Connect OpenVPN UDP, yield, then disconnect."""
    from helpers import connect_openvpn, disconnect_openvpn

    connect_openvpn(f"{CLIENT_NAME}-udp-split.ovpn")
    try:
        yield
    finally:
        disconnect_openvpn()


@pytest.fixture
def openvpn_udp_full_connection():
    """Connect OpenVPN UDP in FULL-tunnel mode, yield, then disconnect."""
    from helpers import connect_openvpn, disconnect_openvpn

    connect_openvpn(f"{CLIENT_NAME}-udp-full.ovpn")
    try:
        yield
    finally:
        disconnect_openvpn()


@pytest.fixture
def openvpn_tcp_connection():
    """Connect OpenVPN TCP, yield, then disconnect."""
    from helpers import connect_openvpn, disconnect_openvpn

    connect_openvpn(f"{CLIENT_NAME}-tcp-split.ovpn")
    try:
        yield
    finally:
        disconnect_openvpn()


@pytest.fixture
def openvpn_https_connection():
    """Connect OpenVPN HTTPS (via stunnel), yield, then disconnect."""
    from helpers import (
        connect_openvpn_https,
        disconnect_openvpn_https,
    )

    connect_openvpn_https(
        f"{CLIENT_NAME}-https-split.ovpn",
        f"{CLIENT_NAME}-stunnel.conf",
    )
    try:
        yield
    finally:
        disconnect_openvpn_https()


@pytest.fixture
def wireguard_connection():
    """Connect WireGuard, yield, then disconnect."""
    from helpers import connect_wireguard, disconnect_wireguard

    config_name = f"{CLIENT_NAME}-wg-split.conf"
    connect_wireguard(config_name)
    try:
        yield
    finally:
        disconnect_wireguard(config_name)


@pytest.fixture
def wireguard_full_connection():
    """Connect WireGuard in FULL-tunnel mode, yield, then disconnect."""
    from helpers import connect_wireguard, disconnect_wireguard

    config_name = f"{CLIENT_NAME}-wg-full.conf"
    connect_wireguard(config_name)
    try:
        yield
    finally:
        disconnect_wireguard(config_name)


@pytest.fixture
def wireguard_https_tunnel_connection():
    """Connect WireGuard over HTTPS (wstunnel), yield, then disconnect."""
    from helpers import (
        connect_wireguard_https_tunnel,
        disconnect_wireguard_https_tunnel,
    )

    config_name = f"{CLIENT_NAME}-wg-https-split.conf"
    connect_wireguard_https_tunnel(config_name)
    try:
        yield
    finally:
        disconnect_wireguard_https_tunnel(config_name)
