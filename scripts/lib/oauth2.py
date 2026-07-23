#  Project:      culvert
#  File:         oauth2.py
#  Purpose:      OIDC SSO setup via openvpn-auth-oauth2
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
OAuth2/OIDC SSO configuration for culvert.

Manages openvpn-auth-oauth2 instances: one per enabled listener.
Validates TLS certificates against server CN, generates per-listener
configs, and configures OpenVPN management interfaces.
"""

import re
import sys
from pathlib import Path

import yaml
from scalo.logger import logger

from lib.process import run, write_secret


def validate_oauth2_tls_cert(cert_path: str, server_cn: str) -> None:
    """Validate that the TLS certificate covers the server CN."""
    if not Path(cert_path).exists():
        logger.error(f"OAuth2 TLS certificate not found: {cert_path}")
        sys.exit(1)

    # Extract CN from certificate (argv form: cert_path is
    # operator-supplied and must not pass through a shell)
    result = run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-subject"],
        capture=True,
        check=False,
    )
    cert_cn = ""
    if result.returncode == 0:
        match = re.search(r"CN=([^,/]+)", result.stdout)
        if match:
            cert_cn = match.group(1)

    # Extract SANs
    result = run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-text"],
        capture=True,
        check=False,
    )
    cert_sans = []
    if result.returncode == 0:
        for line in result.stdout.split("\n"):
            if "DNS:" in line:
                for part in line.split(","):
                    if "DNS:" in part:
                        cert_sans.append(part.split("DNS:")[-1].strip())

    # Check match
    matched = False

    if cert_cn == server_cn:
        matched = True

    if cert_cn.startswith("*."):
        wildcard_domain = cert_cn[2:]
        server_domain = server_cn.split(".", 1)[-1] if "." in server_cn else ""
        if server_domain == wildcard_domain:
            matched = True

    for san in cert_sans:
        if san == server_cn:
            matched = True
            break
        if san.startswith("*."):
            wildcard_domain = san[2:]
            server_domain = server_cn.split(".", 1)[-1] if "." in server_cn else ""
            if server_domain == wildcard_domain:
                matched = True
                break

    if not matched:
        logger.error(f"OAuth2 TLS certificate does not cover server CN: {server_cn}")
        logger.error(f"  Certificate CN: {cert_cn}")
        logger.error(f"  Certificate SANs: {', '.join(cert_sans)}")
        logger.error("TLS certificate/server CN mismatch")
        sys.exit(1)

    # Check expiry
    result = run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-checkend", "0"],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        logger.error(f"OAuth2 TLS certificate has expired: {cert_path}")
        sys.exit(1)

    # Warn if expiring within 30 days
    result = run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-checkend", "2592000"],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        logger.warning("OAuth2 TLS certificate expires within 30 days")

    logger.info(f"  TLS certificate validated for {server_cn}")


def setup_oauth2(cfg) -> None:
    """Configure OAuth2/OIDC authentication."""
    any_oauth2 = (
        cfg.oauth2_udp_enabled or cfg.oauth2_tcp_enabled or cfg.oauth2_https_enabled
    )

    if not any_oauth2:
        logger.info(
            "OIDC SSO disabled on all listeners (certificate-only authentication)"
        )
        return

    logger.info("Configuring OIDC SSO...")
    logger.info("Per-listener OAuth2 status:")
    logger.info(f"  UDP:   {cfg.oauth2_udp_enabled}")
    logger.info(f"  HTTPS: {cfg.oauth2_https_enabled}")
    logger.info(f"  TCP:   {cfg.oauth2_tcp_enabled}")

    validate_oauth2_tls_cert(cfg.oauth2_tls_cert, cfg.server_cn)

    # Generate HTTP secret if not set
    http_secret = cfg.oauth2_http_secret
    if not http_secret:
        logger.warning("CULVERT_OAUTH2_HTTP_SECRET not set, generating random secret")
        result = run("openssl rand -hex 16", capture=True)
        http_secret = result.stdout.strip()

    logger.info(f"  Issuer: {cfg.oauth2_issuer}")
    logger.info(f"  Client ID: {cfg.oauth2_client_id[:8]}...")
    logger.info(f"  TLS Cert: {cfg.oauth2_tls_cert}")

    # Generate management password
    result = run("openssl rand -hex 16", capture=True)
    mgmt_password = result.stdout.strip()
    write_secret("/etc/vpn/management.pwd", mgmt_password)

    Path("/etc/openvpn-auth-oauth2").mkdir(exist_ok=True)

    oauth2_instances = 0
    logger.info("Generating OAuth2 configs for enabled listeners:")

    if cfg.udp_enabled and cfg.oauth2_udp_enabled:
        _generate_oauth2_config(
            cfg,
            "udp",
            cfg.oauth2_udp_port,
            "/run/vpn/management-udp.sock",
            http_secret,
            mgmt_password,
        )
        oauth2_instances += 1
    elif cfg.udp_enabled:
        logger.info("  UDP: cert-only (OAuth2 disabled)")

    if cfg.https_enabled and cfg.oauth2_https_enabled:
        _generate_oauth2_config(
            cfg,
            "https",
            cfg.oauth2_https_port,
            "/run/vpn/management-https.sock",
            http_secret,
            mgmt_password,
        )
        oauth2_instances += 1
    elif cfg.https_enabled:
        logger.info("  HTTPS: cert-only (OAuth2 disabled)")

    if cfg.tcp_enabled and cfg.oauth2_tcp_enabled:
        _generate_oauth2_config(
            cfg,
            "tcp",
            cfg.oauth2_tcp_port,
            "/run/vpn/management-tcp.sock",
            http_secret,
            mgmt_password,
        )
        oauth2_instances += 1
    elif cfg.tcp_enabled:
        logger.info("  TCP: cert-only (OAuth2 disabled)")

    logger.info(f"OAuth2 instances configured: {oauth2_instances}")

    _configure_oauth2_management(cfg, mgmt_password)

    logger.info("OIDC SSO configured (multi-instance: one OAuth2 per listener)")
    logger.info("Required OIDC redirect URLs:")
    if cfg.udp_enabled and cfg.oauth2_udp_enabled:
        logger.info(
            f"  - https://{cfg.server_cn}:{cfg.oauth2_udp_port}/oauth2/callback"
        )
    if cfg.https_enabled and cfg.oauth2_https_enabled:
        logger.info(
            f"  - https://{cfg.server_cn}:{cfg.oauth2_https_port}/oauth2/callback"
        )
    if cfg.tcp_enabled and cfg.oauth2_tcp_enabled:
        logger.info(
            f"  - https://{cfg.server_cn}:{cfg.oauth2_tcp_port}/oauth2/callback"
        )


def _generate_oauth2_config(
    cfg,
    name: str,
    port: int,
    socket: str,
    http_secret: str,
    mgmt_password: str,
) -> None:
    """Generate OAuth2 config for a listener.

    Serialised with yaml.safe_dump: secrets and issuer URLs are
    operator-supplied, so hand-rolled f-string YAML would break (or
    inject keys) on quotes and newlines.
    """
    http_section: dict = {
        "listen": f":{port}",
        "secret": http_secret,
        "baseurl": f"https://{cfg.server_cn}:{port}",
        "tls": True,
        "cert": cfg.oauth2_tls_cert,
        "key": cfg.oauth2_tls_key,
        "assets-path": cfg.oauth2_assets_path,
    }
    if cfg.oauth2_template:
        http_section["template"] = cfg.oauth2_template

    oauth2_section: dict = {
        "issuer": cfg.oauth2_issuer,
        "client": {
            "id": cfg.oauth2_client_id,
            "secret": cfg.oauth2_client_secret,
        },
        "scopes": [s.strip() for s in cfg.oauth2_scopes.split(",") if s.strip()],
    }
    if cfg.oauth2_validate_groups:
        oauth2_section["validate"] = {
            "groups": [
                g.strip() for g in cfg.oauth2_validate_groups.split(",") if g.strip()
            ]
        }

    config = {
        "http": http_section,
        "oauth2": oauth2_section,
        "openvpn": {"addr": f"unix://{socket}", "password": mgmt_password},
        "log": {"level": "info"},
    }
    config_path = Path(f"/etc/openvpn-auth-oauth2/config-{name}.yaml")
    write_secret(config_path, yaml.safe_dump(config, sort_keys=False))
    logger.info(f"  {name}: port {port} -> {socket}")


def _configure_oauth2_management(cfg, mgmt_password: str) -> None:
    """Configure management interface for OAuth2-enabled listeners."""
    mgmt_block = """
#===============================================================================
# Management Interface (for openvpn-auth-oauth2 OIDC)
#===============================================================================
management {socket} unix /etc/vpn/management.pwd
management-client-auth
auth-user-pass-optional
"""

    def update_config(conf_path: Path, socket: str) -> None:
        if not conf_path.exists():
            return
        content = conf_path.read_text()
        lines = []
        for line in content.split("\n"):
            if not line.startswith(
                (
                    "management ",
                    "management-hold",
                    "management-client-auth",
                    "auth-user-pass-optional",
                )
            ):
                lines.append(line)
        content = "\n".join(lines)
        content += mgmt_block.format(socket=socket)
        conf_path.write_text(content)

    if cfg.udp_enabled and cfg.oauth2_udp_enabled:
        update_config(cfg.server_conf, "/run/vpn/management-udp.sock")
        logger.info("Management interface configured for UDP listener")

    if cfg.https_enabled and cfg.oauth2_https_enabled:
        update_config(
            cfg.server_https_conf,
            "/run/vpn/management-https.sock",
        )
        logger.info("Management interface configured for HTTPS listener")

    if cfg.tcp_enabled and cfg.oauth2_tcp_enabled:
        update_config(cfg.server_tcp_conf, "/run/vpn/management-tcp.sock")
        logger.info("Management interface configured for TCP listener")


def start_oauth2(cfg, proc_manager) -> None:
    """Start openvpn-auth-oauth2 instances under ProcessManager supervision.

    Each instance is tracked so it is terminated on shutdown, rather than
    being shell-backgrounded and orphaned.
    """
    any_oauth2 = (
        cfg.oauth2_udp_enabled or cfg.oauth2_tcp_enabled or cfg.oauth2_https_enabled
    )

    if not any_oauth2:
        return

    logger.info("Starting openvpn-auth-oauth2 instances...")
    Path("/run/vpn").mkdir(exist_ok=True)

    # Gate on BOTH the transport flag and the per-listener OAuth2 flag, so a
    # stale config-*.yaml left in a persistent volume from a previous run does
    # not resurrect a now-disabled listener. Mirrors setup_oauth2's generation.
    listeners = [
        (
            "udp",
            cfg.udp_enabled and cfg.oauth2_udp_enabled,
            cfg.oauth2_udp_port,
        ),
        (
            "https",
            cfg.https_enabled and cfg.oauth2_https_enabled,
            cfg.oauth2_https_port,
        ),
        (
            "tcp",
            cfg.tcp_enabled and cfg.oauth2_tcp_enabled,
            cfg.oauth2_tcp_port,
        ),
    ]

    started = 0
    for name, enabled, port in listeners:
        config_path = Path(f"/etc/openvpn-auth-oauth2/config-{name}.yaml")
        if enabled and config_path.exists():
            proc_manager.start(
                f"oauth2-{name}",
                ["openvpn-auth-oauth2", "--config", str(config_path)],
                daemon=True,
            )
            logger.info(f"  oauth2-{name} started (port {port})")
            started += 1

    logger.info(f"openvpn-auth-oauth2: {started} instance(s) started")
