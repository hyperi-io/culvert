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

COMPOSE_DIR = Path(__file__).parent
CLIENT_NAME = "e2e-client"


def _compose_cmd(*args: str) -> list[str]:
    """Build a docker compose command list."""
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_DIR / "docker-compose.yml"),
        "-p",
        "culvert-e2e",
        *args,
    ]


@pytest.fixture(scope="session")
def compose_stack():
    """Start the compose stack, generate client configs, yield, then tear down.

    Not autouse: the connectivity test modules opt in via a module-level
    ``pytestmark = pytest.mark.usefixtures("compose_stack")`` so that other
    e2e modules (e.g. routing control) can run their own stack in isolation.
    """
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
            "e2e-vpn-server",
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
                "e2e-vpn-server",
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
        f"{CLIENT_NAME}-tcp-split.ovpn",
        f"{CLIENT_NAME}-https-split.ovpn",
        f"{CLIENT_NAME}-stunnel.conf",
        f"{CLIENT_NAME}-wg-https-split.conf",
    ]
    result = subprocess.run(
        ["docker", "exec", "e2e-vpn-client", "ls", "/etc/vpn/clients/"],
        capture_output=True,
        text=True,
    )
    files = result.stdout.strip()
    for name in expected:
        assert name in files, f"Expected config {name} not found. Available: {files}"

    yield

    # Teardown
    subprocess.run(
        _compose_cmd("down", "-v", "--remove-orphans"),
        check=False,
        timeout=60,
    )


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
