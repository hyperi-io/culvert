#  Project:      culvert
#  File:         openvpn.py
#  Purpose:      OpenVPN config generation, server startup, client auto-gen
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
OpenVPN server configuration and lifecycle management.

Generates server configs from templates, starts OpenVPN processes,
and handles auto-generation of client configs.
"""

import re
import signal
import tempfile
from pathlib import Path

from scalo.logger import logger

from lib.network import cidr_to_netmask
from lib.process import run


def generate_config(template_path: Path, output_path: Path, variables: dict) -> None:
    """Generate config from template using simple variable substitution."""
    if not template_path.exists():
        logger.warning(f"Template not found: {template_path}")
        return

    content = template_path.read_text()

    for name, value in variables.items():
        content = content.replace(f"${{{name}}}", str(value))

    output_path.write_text(content)


def _common_variables(cfg) -> dict:
    """Build common template variables from config."""
    return {
        "OPENVPN_SNDBUF": cfg.sndbuf,
        "OPENVPN_RCVBUF": cfg.rcvbuf,
        "OPENVPN_TUN_MTU": cfg.tun_mtu,
        "OPENVPN_MSSFIX": cfg.mssfix,
        "OPENVPN_KEEPALIVE_PING": cfg.keepalive_ping,
        "OPENVPN_KEEPALIVE_TIMEOUT": cfg.keepalive_timeout,
        "OPENVPN_DNS1": cfg.dns1,
        "OPENVPN_DNS2": cfg.dns2,
        "OPENVPN_MAX_CLIENTS": cfg.max_clients,
        "OPENVPN_RENEG_SEC": cfg.reneg_sec,
        "OPENVPN_VERB": cfg.verb,
        "OPENVPN_MUTE": cfg.mute,
    }


def _apply_common_options(content: str, cfg, listener: str = "") -> str:
    """Apply DNS domain, push routes, and full tunnel to config content."""
    prefix = f"{listener}: " if listener else ""

    if cfg.dns_domain:
        content += f'push "dhcp-option DOMAIN {cfg.dns_domain}"\n'
        logger.info(f"{prefix}Pushing DNS domain: {cfg.dns_domain}")

    if cfg.push_routes:
        for route in cfg.push_routes.split(","):
            route = route.strip()
            if "/" in route:
                network, prefix_len = route.split("/")
                netmask = cidr_to_netmask(int(prefix_len))
                content += f'push "route {network} {netmask}"\n'
                logger.info(f"{prefix}Pushing route: {route}")

    if cfg.full_tunnel:
        content += 'push "redirect-gateway def1 bypass-dhcp"\n'
        if listener:
            logger.info(f"{prefix}Full tunnel mode enabled")

    return content


def configure_server_udp(cfg) -> None:
    """Configure UDP OpenVPN server."""
    if not cfg.udp_enabled:
        logger.info("UDP listener disabled")
        return

    logger.info("Configuring OpenVPN server (UDP)...")

    template = cfg.server_conf.parent / "server.conf.template"
    if not template.exists():
        logger.warning("UDP server template not found, skipping")
        return

    variables = {
        "OPENVPN_UDP_NETWORK": cfg.udp_network,
        "OPENVPN_UDP_NETMASK": cfg.udp_netmask,
        "OPENVPN_UDP_PORT": cfg.udp_port,
        **_common_variables(cfg),
    }

    # Create the temp file beside the destination so the final rename stays on
    # one filesystem (Path.rename cannot cross mounts; /tmp may be a tmpfs).
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, dir=cfg.server_conf.parent
    ) as f:
        tmp_path = Path(f.name)

    try:
        generate_config(template, tmp_path, variables)

        content = tmp_path.read_text()
        if cfg.log_mode == "stdout":
            content = content.replace(
                "log-append /var/log/vpn/openvpn.log",
                "# log-append disabled (stdout mode)",
            )
            logger.info("Logging mode: stdout (K8s)")
        elif cfg.log_mode == "both":
            content += "\nlog-append /var/log/vpn/openvpn.log\n"
            logger.info("Logging mode: stdout + file")
        else:
            logger.info(f"Logging mode: file ({cfg.log_dir}/openvpn.log)")

        content = _apply_common_options(content, cfg)
        if cfg.full_tunnel:
            logger.info("Full tunnel mode enabled")

        tmp_path.write_text(content)
        tmp_path.rename(cfg.server_conf)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def configure_server_https(cfg) -> None:
    """Configure HTTPS OpenVPN server (behind stunnel)."""
    if not cfg.https_enabled:
        logger.info("HTTPS listener disabled")
        return

    logger.info(
        f"Configuring OpenVPN HTTPS server (internal port {cfg.https_internal_port})..."
    )

    template = cfg.server_https_conf.parent / "server-https.conf.template"
    if not template.exists():
        logger.warning("HTTPS server template not found, skipping")
        return

    variables = {
        "OPENVPN_HTTPS_NETWORK": cfg.https_network,
        "OPENVPN_HTTPS_NETMASK": cfg.https_netmask,
        "OPENVPN_HTTPS_INTERNAL_PORT": cfg.https_internal_port,
        **_common_variables(cfg),
    }

    # Same-filesystem temp file (see configure_server_udp).
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, dir=cfg.server_https_conf.parent
    ) as f:
        tmp_path = Path(f.name)

    try:
        generate_config(template, tmp_path, variables)

        content = tmp_path.read_text()
        content = _apply_common_options(content, cfg, "HTTPS")

        tmp_path.write_text(content)
        tmp_path.rename(cfg.server_https_conf)
        logger.info(
            f"HTTPS OpenVPN configured on internal port {cfg.https_internal_port}"
        )
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def configure_server_tcp(cfg) -> None:
    """Configure TCP OpenVPN server."""
    if not cfg.tcp_enabled:
        logger.info("TCP listener disabled")
        return

    logger.info(f"Configuring OpenVPN TCP server (port {cfg.tcp_port})...")

    template = cfg.server_tcp_conf.parent / "server-tcp.conf.template"
    if not template.exists():
        logger.warning("TCP server template not found, skipping")
        return

    variables = {
        "OPENVPN_TCP_NETWORK": cfg.tcp_network,
        "OPENVPN_TCP_NETMASK": cfg.tcp_netmask,
        "OPENVPN_TCP_PORT": cfg.tcp_port,
        **_common_variables(cfg),
    }

    # Same-filesystem temp file (see configure_server_udp).
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, dir=cfg.server_tcp_conf.parent
    ) as f:
        tmp_path = Path(f.name)

    try:
        generate_config(template, tmp_path, variables)

        content = tmp_path.read_text()
        content = _apply_common_options(content, cfg, "TCP")

        tmp_path.write_text(content)
        tmp_path.rename(cfg.server_tcp_conf)
        logger.info(f"TCP server configured on port {cfg.tcp_port}")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def start_server(cfg, proc_manager) -> None:
    """Start OpenVPN servers with proper process management."""
    logger.info("Starting OpenVPN server...")
    logger.info(f"  PKI Mode: {cfg.pki_mode}")
    logger.info(
        f"  UDP:   {'ENABLED' if cfg.udp_enabled else 'disabled'}"
        f" (port {cfg.udp_port},"
        f" network {cfg.udp_network}/{cfg.udp_netmask})"
    )
    logger.info(
        f"  HTTPS: {'ENABLED' if cfg.https_enabled else 'disabled'}"
        f" (port {cfg.https_port},"
        f" network {cfg.https_network}/{cfg.https_netmask})"
    )
    logger.info(
        f"  TCP:   {'ENABLED' if cfg.tcp_enabled else 'disabled'}"
        f" (port {cfg.tcp_port},"
        f" network {cfg.tcp_network}/{cfg.tcp_netmask})"
    )

    any_oauth2 = (
        cfg.oauth2_udp_enabled or cfg.oauth2_tcp_enabled or cfg.oauth2_https_enabled
    )
    if any_oauth2:
        logger.info("  Authentication: Certificate + OIDC SSO")
    else:
        logger.info("  Authentication: Certificate only")

    # Create run directory
    Path("/run/vpn").mkdir(exist_ok=True)

    # Start HTTPS listener (with stunnel for TLS termination)
    if cfg.https_enabled:
        if cfg.stunnel_conf.exists():
            proc_manager.start(
                "stunnel",
                ["stunnel", str(cfg.stunnel_conf)],
                daemon=True,
            )
            logger.info(
                f"stunnel started: TLS:{cfg.https_port}"
                f" -> localhost:{cfg.https_internal_port}"
            )
        else:
            logger.warning("stunnel config not found, HTTPS tunnel may not work")

        proc_manager.start(
            "openvpn-https",
            ["openvpn", "--config", str(cfg.server_https_conf)],
            daemon=True,
        )

    # Start TCP listener
    if cfg.tcp_enabled:
        proc_manager.start(
            "openvpn-tcp",
            ["openvpn", "--config", str(cfg.server_tcp_conf)],
            daemon=True,
        )

    # Start UDP listener (main process - we wait on this)
    if cfg.udp_enabled:
        proc_manager.start(
            "openvpn-udp",
            ["openvpn", "--config", str(cfg.server_conf)],
            daemon=False,
        )
        exit_code = proc_manager.wait_for_main("openvpn-udp")
        if exit_code != 0:
            logger.error(f"OpenVPN UDP exited with code {exit_code}")
        proc_manager.shutdown()
    else:
        # If UDP disabled, wait for signals
        logger.info("UDP disabled, running with HTTPS/TCP listeners only")
        signal.pause()


def auto_generate_clients(cfg) -> None:
    """Generate client configs if clients directory is mounted."""
    clients_dir = Path("/etc/vpn/clients")
    client_name = cfg.server_cn.replace(".", "-")

    if not clients_dir.exists():
        logger.info("Clients directory not mounted, skipping auto-generation")
        return

    logger.info("Checking client configs...")

    cert_path = cfg.pki_dir / "issued" / f"{client_name}.crt"
    cert_exists = cert_path.exists()

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        generate_args = ["--output", str(temp_path)]
        if cert_exists:
            generate_args.append("--config-only")

        result = run(
            ["/usr/local/bin/generate-client"] + generate_args,
            check=False,
            capture=True,
        )

        if result.returncode != 0:
            if cert_exists:
                logger.info("Config-only generation failed, trying full generation...")
                result = run(
                    [
                        "/usr/local/bin/generate-client",
                        "--output",
                        str(temp_path),
                    ],
                    check=False,
                    capture=True,
                )
                if result.returncode != 0:
                    logger.warning("Failed to generate client configs")
                    return
            else:
                logger.warning("Failed to generate client configs")
                return

        any_changed = False
        files_checked = 0

        for temp_file in temp_path.glob("*.ovpn"):
            files_checked += 1
            existing_file = clients_dir / temp_file.name

            if existing_file.exists():
                temp_content = _strip_timestamps(temp_file.read_text())
                existing_content = _strip_timestamps(existing_file.read_text())

                if temp_content != existing_content:
                    any_changed = True
                    logger.info(f"  {temp_file.name}: content changed, updating")
            else:
                any_changed = True
                logger.info(f"  {temp_file.name}: new file")

        if any_changed:
            for temp_file in temp_path.glob("*.ovpn"):
                (clients_dir / temp_file.name).write_text(temp_file.read_text())
            logger.info(f"Client configs updated ({files_checked} files)")
        else:
            logger.info(f"Client configs unchanged ({files_checked} files checked)")


def _strip_timestamps(content: str) -> str:
    """Strip timestamp comments from config content for comparison."""
    lines = []
    for line in content.split("\n"):
        if re.search(r"^#.*\d{4}-\d{2}-\d{2}", line):
            continue
        if line.startswith("# Generated:"):
            continue
        if re.match(r"^# Culvert.*\d", line):
            continue
        lines.append(line)
    return "\n".join(lines)
