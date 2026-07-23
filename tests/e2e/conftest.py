#  Project:      culvert
#  File:         conftest.py
#  Purpose:      E2E test configuration — compose lifecycle and client configs
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""E2E test configuration — compose lifecycle and client config generation."""

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

    # generate-client writes updated server config to /etc/vpn/pki/wireguard/wg0.conf
    # but the running server uses /etc/vpn/server/wg0.conf — copy and reload
    subprocess.run(
        [
            "docker",
            "exec",
            "e2e-vpn-server",
            "bash",
            "-c",
            "cp /etc/vpn/pki/wireguard/wg0.conf /etc/vpn/server/wg0.conf"
            " && wg-quick strip /etc/vpn/server/wg0.conf > /tmp/wg0-stripped.conf"
            " && wg syncconf wg0 /tmp/wg0-stripped.conf"
            " && rm /tmp/wg0-stripped.conf",
        ],
        check=False,
        timeout=10,
    )

    # Small delay for configs to sync via shared volume
    time.sleep(1)

    # Verify expected config files exist
    expected = [
        f"{CLIENT_NAME}-udp-split.ovpn",
        f"{CLIENT_NAME}-tcp-split.ovpn",
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
def wireguard_dpi_connection():
    """Connect WireGuard via DPI bypass (wstunnel), yield, then disconnect."""
    from helpers import connect_wireguard_dpi, disconnect_wireguard_dpi

    config_name = f"{CLIENT_NAME}-wg-dpi-split.conf"
    connect_wireguard_dpi(config_name)
    try:
        yield
    finally:
        disconnect_wireguard_dpi(config_name)
