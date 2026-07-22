#  Project:      culvert
#  File:         helpers.py
#  Purpose:      Helper functions for E2E VPN connection tests
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Helper functions for E2E VPN connection tests."""

import subprocess
import time
from pathlib import Path

COMPOSE_DIR = Path(__file__).parent
TARGET_URL = "http://172.30.0.20/"
TARGET_RESPONSE = "culvert-e2e-target-ok"


def docker_exec(
    container: str, cmd: str, timeout: int = 30, check: bool = True
) -> subprocess.CompletedProcess:
    """Run a command inside a container via docker exec."""
    return subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def curl_target(timeout: int = 5) -> str | None:
    """Curl the target from the client container. Returns body or None."""
    result = docker_exec(
        "e2e-vpn-client",
        f"curl -sf --connect-timeout {timeout} {TARGET_URL}",
        timeout=timeout + 5,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def wait_for_tunnel(interface: str = "tun0", timeout: int = 30) -> str:
    """Poll until tunnel interface has an IP. Returns the IP address."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = docker_exec(
            "e2e-vpn-client",
            f"ip -4 addr show dev {interface} 2>/dev/null | grep -oP 'inet \\K[0-9.]+'",
            check=False,
        )
        ip = result.stdout.strip()
        if ip:
            return ip
        time.sleep(1)
    raise TimeoutError(
        f"Tunnel interface {interface} did not get an IP within {timeout}s"
    )


def connect_openvpn(config_name: str) -> None:
    """Start OpenVPN in background inside the client container."""
    config_path = f"/etc/vpn/clients/{config_name}"
    docker_exec(
        "e2e-vpn-client",
        f"openvpn --config {config_path}"
        " --daemon --log /tmp/openvpn.log"
        " --connect-retry 1 --connect-retry-max 3",
    )


def disconnect_openvpn() -> None:
    """Kill all OpenVPN processes in the client container."""
    docker_exec(
        "e2e-vpn-client",
        "pkill -SIGTERM openvpn || true",
        check=False,
    )
    time.sleep(2)


def connect_openvpn_https(ovpn_name: str, stunnel_name: str) -> None:
    """Start client-side stunnel + OpenVPN for HTTPS mode."""
    stunnel_path = f"/etc/vpn/clients/{stunnel_name}"

    # Patch stunnel config for e2e: disable cert verification (self-signed),
    # remove verifyChain/checkHost, and switch to background mode
    docker_exec(
        "e2e-vpn-client",
        f"sed"
        f" -e 's/^foreground.*/foreground = no/'"
        f" -e '/^verifyChain/d'"
        f" -e '/^checkHost/d'"
        f" -e '/^CApath/d'"
        f" {stunnel_path} > /tmp/stunnel-client.conf"
        " && echo 'verify = 0' >> /tmp/stunnel-client.conf",
    )

    # Start client-side stunnel (runs in background with foreground = no)
    docker_exec("e2e-vpn-client", "stunnel /tmp/stunnel-client.conf")
    time.sleep(1)

    # Start OpenVPN connecting to local stunnel port
    ovpn_path = f"/etc/vpn/clients/{ovpn_name}"
    docker_exec(
        "e2e-vpn-client",
        f"openvpn --config {ovpn_path}"
        " --daemon --log /tmp/openvpn.log"
        " --connect-retry 1 --connect-retry-max 3",
    )


def disconnect_openvpn_https() -> None:
    """Kill OpenVPN and stunnel in the client container."""
    docker_exec(
        "e2e-vpn-client",
        "pkill -SIGTERM openvpn || true; pkill -SIGTERM stunnel || true",
        check=False,
    )
    time.sleep(2)


def connect_wireguard(config_name: str) -> None:
    """Start WireGuard via wg-quick inside the client container.

    wg-quick requires the config to be at /etc/wireguard/<iface>.conf
    or specified as just an interface name. We copy to /etc/wireguard/wg0.conf.
    """
    src = f"/etc/vpn/clients/{config_name}"
    # Copy config and strip DNS line (resolvconf not available in container)
    docker_exec(
        "e2e-vpn-client",
        f"mkdir -p /etc/wireguard && sed '/^DNS/d' {src} > /etc/wireguard/wg0.conf",
    )
    docker_exec(
        "e2e-vpn-client",
        "wg-quick up wg0",
    )


def disconnect_wireguard(config_name: str) -> None:  # noqa: ARG001
    """Stop WireGuard via wg-quick inside the client container."""
    docker_exec(
        "e2e-vpn-client",
        "wg-quick down wg0",
        check=False,
    )


def connect_wireguard_dpi(config_name: str) -> None:
    """Start wstunnel client + WireGuard for DPI bypass mode.

    The DPI client config points Endpoint at 127.0.0.1:51820 (local wstunnel).
    wstunnel client tunnels that UDP over WebSocket/TLS to the server.
    """
    src = f"/etc/vpn/clients/{config_name}"
    # Copy config, strip DNS line
    docker_exec(
        "e2e-vpn-client",
        f"mkdir -p /etc/wireguard && sed '/^DNS/d' {src} > /etc/wireguard/wg0.conf",
    )

    # Start wstunnel client (tunnels local UDP 51820 to server wstunnel on 4443)
    # --tls-verify-certificate=false because server uses self-signed cert
    # Use setsid to properly daemonise inside docker exec
    # wstunnel 10.x: --tls-verify-certificate is opt-in; omit it to skip verification
    docker_exec(
        "e2e-vpn-client",
        "setsid wstunnel client"
        " -L udp://127.0.0.1:51820:127.0.0.1:51820"
        " wss://172.30.1.10:4443"
        " </dev/null >/dev/null 2>&1 &",
    )
    time.sleep(2)

    # Start WireGuard (connects to local wstunnel listener)
    docker_exec(
        "e2e-vpn-client",
        "wg-quick up wg0",
    )


def disconnect_wireguard_dpi(config_name: str) -> None:  # noqa: ARG001
    """Stop WireGuard and wstunnel client."""
    docker_exec(
        "e2e-vpn-client",
        "wg-quick down wg0 2>/dev/null; pkill -SIGTERM wstunnel || true",
        check=False,
    )
    time.sleep(1)


def has_wireguard_module() -> bool:
    """Check if WireGuard kernel module is available."""
    if Path("/sys/module/wireguard").exists():
        return True
    # Try creating a wireguard interface inside the privileged client
    result = docker_exec(
        "e2e-vpn-client",
        "ip link add wg-test type wireguard 2>/dev/null"
        " && ip link del wg-test 2>/dev/null"
        " && echo ok",
        check=False,
    )
    return "ok" in result.stdout


def get_openvpn_log() -> str:
    """Get the OpenVPN log from the client container (for debugging)."""
    result = docker_exec(
        "e2e-vpn-client",
        "cat /tmp/openvpn.log 2>/dev/null",
        check=False,
    )
    return result.stdout
