#  Project:      culvert
#  File:         config.py
#  Purpose:      Config dataclass and validation using scalo settings
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""
Configuration for culvert using scalo Dynaconf cascade.

All environment variables use the CULVERT_ prefix exclusively.
No legacy VPN_* or OPENVPN_* aliases.

Example:
    CULVERT_SERVER_CN=vpn.example.com
    CULVERT_PROTOCOL=both
    CULVERT_UDP_PORT=1194
"""

import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scalo.config import get_config
from scalo.logger import logger


def _get_settings():
    """Create a fresh Dynaconf settings instance.

    Called each time from_settings() is invoked so that env var
    changes (e.g. in tests via monkeypatch) are always reflected.
    Loads an optional profile YAML via CULVERT_PROFILE.
    """
    additional: list[str] = []
    profile = os.environ.get("CULVERT_PROFILE", "").strip()
    if profile:
        if "/" in profile or profile.endswith(".yaml"):
            path = Path(profile)
        else:
            path = Path(f"/etc/vpn/profiles/{profile}.yaml")
        # Resolve to absolute: get_config() rebases a RELATIVE path onto
        # its own config_dir and silently skips it if missing, so a bare
        # relative CULVERT_PROFILE would pass the check below yet never
        # load. Resolving here keeps the existence check and the loader
        # looking at the same file.
        path = path.expanduser().resolve()
        if not path.exists():
            logger.error(f"CULVERT_PROFILE not found: {path}")
            sys.exit(1)
        additional.append(str(path))
    return get_config(
        env_prefix="CULVERT",
        additional_files=additional,
    )


class ValidationError(Exception):
    """Configuration validation error."""


def validate_ipv4(value: str, name: str) -> None:
    """Validate an IPv4 address."""
    if not value:
        return
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValidationError(f"{name}='{value}' is not a valid IPv4 address")


def validate_port(value: int, name: str) -> None:
    """Validate a port number."""
    if value < 1 or value > 65535:
        raise ValidationError(f"{name}={value} must be between 1 and 65535")


def validate_bool(value: str, name: str) -> None:
    """Validate a boolean value."""
    if value and value.lower() not in (
        "true",
        "false",
        "1",
        "0",
        "yes",
        "no",
    ):
        raise ValidationError(f"{name}='{value}' must be 'true' or 'false'")


def validate_hostname(value: str, name: str) -> None:
    """Validate a hostname/FQDN."""
    if not value:
        raise ValidationError(f"{name} is required")
    pattern = (
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
    )
    if not re.match(pattern, value):
        raise ValidationError(f"{name}='{value}' is not a valid hostname")


def validate_url(value: str, name: str) -> None:
    """Validate a URL."""
    if not value.startswith(("http://", "https://")):
        raise ValidationError(f"{name}='{value}' must be a valid URL")


def validate_cidr_routes(value: str, name: str) -> None:
    """Validate comma-separated CIDR routes."""
    if not value:
        return
    for route in value.split(","):
        route = route.strip()
        try:
            ipaddress.IPv4Network(route, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            raise ValidationError(f"{name} contains invalid CIDR: '{route}'")


def _subnet_or_none(network: str, netmask: str) -> str | None:
    """CIDR string for a network/netmask pair, or None if malformed."""
    try:
        return str(ipaddress.IPv4Network(f"{network}/{netmask}", strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


@dataclass
class Config:
    """Container configuration populated from scalo settings.

    All fields are read from CULVERT_* environment variables via the
    Dynaconf settings cascade. Use Config.from_settings() to construct.
    """

    # Server Identity
    # org_name identifies the deploying organisation. Used to derive
    # ca_cn when not explicitly set (e.g. org_name="Acme" -> ca_cn="Acme VPN CA").
    # Leave empty for a neutral default ("VPN CA").
    org_name: str = ""
    ca_cn: str = ""
    server_cn: str = ""
    key_type: str = "ec"
    key_size: str = "secp384r1"

    # PKI Mode
    pki_mode: str = "local"

    # PKI Paths
    pki_dir: Path = field(default=Path("/etc/vpn/pki"))
    server_conf: Path = field(default=Path("/etc/vpn/server/server.conf"))
    server_tcp_conf: Path = field(default=Path("/etc/vpn/server/server-tcp.conf"))
    server_https_conf: Path = field(default=Path("/etc/vpn/server/server-https.conf"))
    ccd_dir: Path = field(default=Path("/etc/vpn/server/ccd"))
    scripts_dir: Path = field(default=Path("/etc/vpn/scripts"))
    log_dir: Path = field(default=Path("/var/log/vpn"))
    stunnel_conf: Path = field(default=Path("/etc/vpn/server/stunnel.conf"))
    wg_conf: Path = field(default=Path("/etc/vpn/server/wg0.conf"))

    # Protocol selection
    protocol: str = "openvpn"

    # Tunnel addressing lives in 10.8.0.0/22, one /24 per listener. The
    # edge-fleet preset moves to CGNAT slices instead; docs/ADDRESSING.md
    # covers when each applies. Cascade-overridable.

    # UDP Listener
    udp_enabled: bool = True
    udp_port: int = 1194
    udp_network: str = "10.8.0.0"
    udp_netmask: str = "255.255.255.0"

    # TCP Listener (opt-in)
    tcp_enabled: bool = False
    tcp_port: int = 1194
    tcp_network: str = "10.8.1.0"
    tcp_netmask: str = "255.255.255.0"

    # HTTPS Listener (via stunnel, opt-in)
    https_enabled: bool = False
    https_port: int = 443
    https_internal_port: int = 1195
    https_network: str = "10.8.2.0"
    https_netmask: str = "255.255.255.0"

    # stunnel TLS (required when HTTPS listener enabled)
    stunnel_cert: str = ""
    stunnel_key: str = ""

    # DNS
    dns1: str = "1.1.1.1"
    dns2: str = "1.0.0.1"
    dns_domain: str = ""

    # Routing
    full_tunnel: bool = False
    push_routes: str = ""

    # Routing control (opt-in FORWARD filtering). When enabled:
    # clients cannot reach each other (client_isolation, overridable),
    # nothing outside may initiate into the tunnels except
    # downstream_admin_cidrs, and if allowed_destinations is set clients
    # may only initiate to those CIDRs.
    routing_control_enabled: bool = False
    client_isolation: bool = True
    allowed_destinations: str = ""
    downstream_admin_cidrs: str = ""

    # Network Profile
    network_profile: str = "default"

    # Performance (set by __post_init__ based on network_profile)
    sndbuf: int = 0
    rcvbuf: int = 0
    tun_mtu: int = 1500
    mssfix: int = 1450
    keepalive_ping: int = 10
    keepalive_timeout: int = 60

    # Server Limits
    max_clients: int | None = None
    reneg_sec: int = 3600

    # Logging
    log_mode: str = "file"
    verb: int = 3
    mute: int = 20

    # OAuth2/OIDC
    oauth2_enabled: bool = False
    oauth2_udp_enabled: bool = False
    oauth2_tcp_enabled: bool = False
    oauth2_https_enabled: bool = False
    oauth2_issuer: str = ""
    oauth2_client_id: str = ""
    oauth2_client_secret: str = ""
    oauth2_tls_cert: str = ""
    oauth2_tls_key: str = ""
    oauth2_http_secret: str = ""
    oauth2_scopes: str = "openid,profile,email"
    oauth2_validate_groups: str = ""
    oauth2_template: str = ""
    oauth2_assets_path: str = "/etc/openvpn-auth-oauth2/assets"
    oauth2_udp_port: int = 9000
    oauth2_https_port: int = 9001
    oauth2_tcp_port: int = 9002

    # WireGuard
    wg_port: int = 51820
    wg_network: str = "10.8.3.0/24"
    wg_mtu: int = 1420
    wg_persistent_keepalive: int = 25
    wg_https_tunnel_enabled: bool = False
    wg_https_tunnel_port: int = 4443
    wg_post_up: str = ""
    wg_post_down: str = ""

    # Observability: ONE listener serves health probes always, and
    # /metrics when metrics_enabled
    metrics_enabled: bool = False
    metrics_addr: str = "0.0.0.0:9090"

    # OTel
    otel_enabled: bool = False
    otel_endpoint: str = ""
    otel_protocol: str = "grpc"
    otel_insecure: bool = False

    crl_refresh_hours: int = 24

    # Client Download Server
    client_download_enabled: bool = False
    client_download_port: int = 8443
    client_download_bind: str = "127.0.0.1"
    client_download_token: str = ""
    client_download_tls_cert: str = ""
    client_download_tls_key: str = ""

    # Secrets / External PKI
    secrets_provider: str = ""
    secrets_ca_cert_path: str = ""
    secrets_server_cert_path: str = ""
    secrets_server_key_path: str = ""
    secrets_crl_path: str = ""
    # The tls-crypt-v2 server key. Optional for one server, REQUIRED to run
    # more than one: a client's tls-crypt-v2 key is derived from it, so a client
    # issued by one server cannot reach a sibling that minted a different key.
    secrets_tc_key_path: str = ""
    secrets_openbao_address: str = ""
    secrets_openbao_auth_method: str = ""
    secrets_openbao_token: str = ""
    secrets_openbao_role: str = ""
    secrets_aws_region: str = ""

    def __post_init__(self):
        """Apply network profile defaults and derived identity fields."""
        # Derive ca_cn from org_name when not explicitly set.
        # "Acme" -> "Acme VPN CA"; empty org_name -> "VPN CA".
        if not self.ca_cn:
            if self.org_name:
                self.ca_cn = f"{self.org_name} VPN CA"
            else:
                self.ca_cn = "VPN CA"

        if self.network_profile in ("wireless", "mobile", "4g"):
            if self.sndbuf == 0:
                self.sndbuf = 393216
            if self.rcvbuf == 0:
                self.rcvbuf = 393216
            if self.tun_mtu == 1500:
                self.tun_mtu = 1400
            if self.mssfix == 1450:
                self.mssfix = 1400
            if self.keepalive_ping == 10:
                self.keepalive_ping = 30
            if self.keepalive_timeout == 60:
                self.keepalive_timeout = 120
            logger.info("Network profile: wireless (4G/mobile optimised)")
        else:
            logger.info("Network profile: default (fast internet)")

        # Per-listener OAuth2 inheritance: if no explicit per-listener
        # setting, inherit from global oauth2_enabled
        # (from_settings reads these explicitly, but for direct
        # construction we apply inheritance here)

        # Calculate max_clients if not explicitly set
        if self.max_clients is None:
            self.max_clients = self._calculate_max_clients()

    def _calculate_max_clients(self) -> int:
        """Calculate max clients from CPU/RAM (container-aware)."""
        cpu_cores = self._get_cpu_cores()
        ram_gb = self._get_ram_gb()

        # Formula: min(CPU_cores * 64, RAM_GB * 650, 1000)
        cpu_limit = cpu_cores * 64
        ram_limit = int(ram_gb * 650)
        calculated = min(cpu_limit, ram_limit, 1000)
        calculated = max(calculated, 10)  # Minimum 10

        logger.info(
            f"max-clients calculated: {calculated} ({cpu_cores} cores, {ram_gb}GB RAM)"
        )
        return calculated

    def _get_cpu_cores(self) -> int:
        """Get CPU core count (cgroup-aware).

        Handles fractional CPU limits correctly (e.g. 500m = 0.5 cores
        rounds up to 1).
        """
        import math

        # Try cgroup v2
        cpu_max = Path("/sys/fs/cgroup/cpu.max")
        if cpu_max.exists():
            try:
                content = cpu_max.read_text().strip()
                quota, period = content.split()
                if quota != "max":
                    return max(
                        1,
                        math.ceil(int(quota) / int(period)),
                    )
            except (OSError, ValueError):
                pass

        # Try cgroup v1
        quota_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        period_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if quota_path.exists() and period_path.exists():
            try:
                quota = int(quota_path.read_text().strip())
                period = int(period_path.read_text().strip())
                if quota > 0:
                    return max(
                        1,
                        math.ceil(quota / period),
                    )
            except (OSError, ValueError):
                pass

        # Fall back to os.cpu_count()
        return os.cpu_count() or 1

    def _get_ram_gb(self) -> float:
        """Get RAM in GB (cgroup-aware).

        Returns float to handle sub-GB limits (e.g. 512Mi = 0.5).
        """
        # Try cgroup v2
        mem_max = Path("/sys/fs/cgroup/memory.max")
        if mem_max.exists():
            try:
                content = mem_max.read_text().strip()
                if content != "max":
                    return max(0.5, int(content) / (1024**3))
            except (OSError, ValueError):
                pass

        # Try cgroup v1
        mem_limit = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        if mem_limit.exists():
            try:
                limit = int(mem_limit.read_text().strip())
                # Not effectively unlimited
                if limit < 9223372036854771712:
                    return max(0.5, limit / (1024**3))
            except (OSError, ValueError):
                pass

        # Fall back to /proc/meminfo
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return max(0.5, kb / (1024**2))
        except (OSError, ValueError):
            pass

        return 0.5

    @classmethod
    def from_settings(cls) -> "Config":
        """Build Config from scalo settings cascade.

        Reads all fields from Dynaconf settings with CULVERT_ env prefix.
        Parses 'auto' max_clients to None; explicit int values are kept.
        """
        s = _get_settings()

        raw_max = s.get("max_clients", None)
        if raw_max is None or str(raw_max).lower() == "auto":
            max_clients = None
        else:
            max_clients = int(raw_max)

        # Read per-listener OAuth2 with fallback to global
        oauth2_enabled = _settings_bool(s, "oauth2_enabled", False)
        oauth2_udp_enabled = _settings_bool(s, "oauth2_udp_enabled", oauth2_enabled)
        oauth2_tcp_enabled = _settings_bool(s, "oauth2_tcp_enabled", oauth2_enabled)
        oauth2_https_enabled = _settings_bool(s, "oauth2_https_enabled", oauth2_enabled)

        # Read performance tuning; network_profile drives defaults
        network_profile = s.get("network_profile", "default")
        is_wireless = network_profile in ("wireless", "mobile", "4g")

        return cls(
            # Server identity
            org_name=s.get("org_name", ""),
            server_cn=s.get("server_cn", ""),
            ca_cn=s.get("ca_cn", ""),
            key_type=s.get("key_type", "ec"),
            key_size=s.get("key_size", "secp384r1"),
            # PKI
            pki_mode=s.get("pki_mode", "local"),
            # Protocol
            protocol=s.get("protocol", "openvpn"),
            # UDP
            udp_enabled=_settings_bool(s, "udp_enabled", True),
            udp_port=_settings_int(s, "udp_port", 1194),
            udp_network=s.get("udp_network", "10.8.0.0"),
            udp_netmask=s.get("udp_netmask", "255.255.255.0"),
            # TCP
            tcp_enabled=_settings_bool(s, "tcp_enabled", False),
            tcp_port=_settings_int(s, "tcp_port", 1194),
            tcp_network=s.get("tcp_network", "10.8.1.0"),
            tcp_netmask=s.get("tcp_netmask", "255.255.255.0"),
            # HTTPS
            https_enabled=_settings_bool(s, "https_enabled", False),
            https_port=_settings_int(s, "https_port", 443),
            https_internal_port=_settings_int(s, "https_internal_port", 1195),
            https_network=s.get("https_network", "10.8.2.0"),
            https_netmask=s.get("https_netmask", "255.255.255.0"),
            # stunnel
            stunnel_cert=s.get("stunnel_cert", ""),
            stunnel_key=s.get("stunnel_key", ""),
            # DNS
            dns1=s.get("dns1", "1.1.1.1"),
            dns2=s.get("dns2", "1.0.0.1"),
            dns_domain=s.get("dns_domain", ""),
            # Routing
            full_tunnel=_settings_bool(s, "full_tunnel", False),
            push_routes=s.get("push_routes", ""),
            routing_control_enabled=_settings_bool(s, "routing_control_enabled", False),
            client_isolation=_settings_bool(s, "client_isolation", True),
            allowed_destinations=s.get("allowed_destinations", ""),
            downstream_admin_cidrs=s.get("downstream_admin_cidrs", ""),
            # Network profile + performance
            network_profile=network_profile,
            sndbuf=_settings_int(s, "sndbuf", 393216 if is_wireless else 0),
            rcvbuf=_settings_int(s, "rcvbuf", 393216 if is_wireless else 0),
            tun_mtu=_settings_int(s, "tun_mtu", 1400 if is_wireless else 1500),
            mssfix=_settings_int(s, "mssfix", 1400 if is_wireless else 1450),
            keepalive_ping=_settings_int(
                s, "keepalive_ping", 30 if is_wireless else 10
            ),
            keepalive_timeout=_settings_int(
                s, "keepalive_timeout", 120 if is_wireless else 60
            ),
            # Server limits
            max_clients=max_clients,
            reneg_sec=_settings_int(s, "reneg_sec", 3600),
            # Logging
            log_mode=s.get("log_mode", "file"),
            verb=_settings_int(s, "verb", 3),
            mute=_settings_int(s, "mute", 20),
            # OAuth2
            oauth2_enabled=oauth2_enabled,
            oauth2_udp_enabled=oauth2_udp_enabled,
            oauth2_tcp_enabled=oauth2_tcp_enabled,
            oauth2_https_enabled=oauth2_https_enabled,
            oauth2_issuer=s.get("oauth2_issuer", ""),
            oauth2_client_id=s.get("oauth2_client_id", ""),
            oauth2_client_secret=s.get("oauth2_client_secret", ""),
            oauth2_tls_cert=s.get("oauth2_tls_cert", ""),
            oauth2_tls_key=s.get("oauth2_tls_key", ""),
            oauth2_http_secret=s.get("oauth2_http_secret", ""),
            oauth2_scopes=s.get("oauth2_scopes", "openid,profile,email"),
            oauth2_validate_groups=s.get("oauth2_validate_groups", ""),
            oauth2_template=s.get("oauth2_template", ""),
            oauth2_assets_path=s.get(
                "oauth2_assets_path",
                "/etc/openvpn-auth-oauth2/assets",
            ),
            oauth2_udp_port=_settings_int(s, "oauth2_udp_port", 9000),
            oauth2_https_port=_settings_int(s, "oauth2_https_port", 9001),
            oauth2_tcp_port=_settings_int(s, "oauth2_tcp_port", 9002),
            # WireGuard
            wg_port=_settings_int(s, "wg_port", 51820),
            wg_network=s.get("wg_network", "10.8.3.0/24"),
            wg_mtu=_settings_int(s, "wg_mtu", 1420),
            wg_persistent_keepalive=_settings_int(s, "wg_persistent_keepalive", 25),
            wg_https_tunnel_enabled=_settings_bool(s, "wg_https_tunnel_enabled", False),
            wg_https_tunnel_port=_settings_int(s, "wg_https_tunnel_port", 4443),
            wg_post_up=s.get("wg_post_up", ""),
            wg_post_down=s.get("wg_post_down", ""),
            # Observability
            metrics_enabled=_settings_bool(s, "metrics_enabled", False),
            metrics_addr=s.get("metrics_addr", "0.0.0.0:9090"),
            # OTel
            otel_enabled=_settings_bool(s, "otel_enabled", False),
            otel_endpoint=s.get("otel_endpoint", ""),
            otel_protocol=s.get("otel_protocol", "grpc"),
            otel_insecure=_settings_bool(s, "otel_insecure", False),
            crl_refresh_hours=_settings_int(s, "crl_refresh_hours", 24),
            # Client download
            client_download_enabled=_settings_bool(s, "client_download_enabled", False),
            client_download_port=_settings_int(s, "client_download_port", 8443),
            client_download_bind=s.get("client_download_bind", "127.0.0.1"),
            client_download_token=s.get("client_download_token", ""),
            client_download_tls_cert=s.get("client_download_tls_cert", ""),
            client_download_tls_key=s.get("client_download_tls_key", ""),
            # Secrets / External PKI
            secrets_provider=s.get("secrets_provider", ""),
            secrets_ca_cert_path=s.get("secrets_ca_cert_path", ""),
            secrets_server_cert_path=s.get("secrets_server_cert_path", ""),
            secrets_server_key_path=s.get("secrets_server_key_path", ""),
            secrets_crl_path=s.get("secrets_crl_path", ""),
            secrets_tc_key_path=s.get("secrets_tc_key_path", ""),
            secrets_openbao_address=s.get("secrets_openbao_address", ""),
            secrets_openbao_auth_method=s.get("secrets_openbao_auth_method", ""),
            secrets_openbao_token=s.get("secrets_openbao_token", ""),
            secrets_openbao_role=s.get("secrets_openbao_role", ""),
            secrets_aws_region=s.get("secrets_aws_region", ""),
        )

    def validate(self) -> None:
        """Validate all configuration values.

        Raises SystemExit on validation failure.
        """
        logger.info("Validating environment configuration...")

        errors: list[str] = []
        warnings: list[str] = []

        # Server CN -- hard requirement for OpenVPN; advisory for WireGuard-only.
        # The WireGuard server runtime does not use server_cn, but generated
        # client configs still want it for the Endpoint line.
        if self.protocol in ("openvpn", "both"):
            try:
                validate_hostname(self.server_cn, "CULVERT_SERVER_CN")
            except ValidationError as e:
                errors.append(str(e))
        elif not self.server_cn:
            warnings.append(
                "CULVERT_SERVER_CN is empty; WireGuard client configs"
                " will have an empty Endpoint"
            )

        # Ports
        for name, value in [
            ("CULVERT_UDP_PORT", self.udp_port),
            ("CULVERT_TCP_PORT", self.tcp_port),
            ("CULVERT_HTTPS_PORT", self.https_port),
        ]:
            try:
                validate_port(value, name)
            except ValidationError as e:
                errors.append(str(e))

        # Networks
        for name, value in [
            ("CULVERT_UDP_NETWORK", self.udp_network),
            ("CULVERT_TCP_NETWORK", self.tcp_network),
            ("CULVERT_HTTPS_NETWORK", self.https_network),
            ("CULVERT_DNS1", self.dns1),
            ("CULVERT_DNS2", self.dns2),
        ]:
            try:
                validate_ipv4(value, name)
            except ValidationError as e:
                errors.append(str(e))

        # Network/netmask pairs must form a valid subnet - setup_network derives
        # the NAT prefix from these, so a malformed netmask must fail here rather
        # than crash iptables setup at runtime.
        for name, network, netmask in [
            ("CULVERT_UDP", self.udp_network, self.udp_netmask),
            ("CULVERT_TCP", self.tcp_network, self.tcp_netmask),
            ("CULVERT_HTTPS", self.https_network, self.https_netmask),
        ]:
            try:
                ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                errors.append(
                    f"{name}_NETWORK/{name}_NETMASK is not a valid subnet:"
                    f" {network}/{netmask}"
                )

        # Push routes + routing-control CIDR lists
        for name, value in [
            ("CULVERT_PUSH_ROUTES", self.push_routes),
            ("CULVERT_ALLOWED_DESTINATIONS", self.allowed_destinations),
            ("CULVERT_DOWNSTREAM_ADMIN_CIDRS", self.downstream_admin_cidrs),
        ]:
            try:
                validate_cidr_routes(value, name)
            except ValidationError as e:
                errors.append(str(e))

        if not self.routing_control_enabled and (
            self.allowed_destinations or self.downstream_admin_cidrs
        ):
            warnings.append(
                "routing-control CIDRs are set but"
                " CULVERT_ROUTING_CONTROL_ENABLED is false -"
                " no FORWARD filtering will be applied"
            )

        # PKI mode
        if self.pki_mode not in ("local", "external"):
            errors.append(
                f"CULVERT_PKI_MODE='{self.pki_mode}' must be 'local' or 'external'"
            )

        # stunnel cert/key required when HTTPS listener enabled
        if self.https_enabled and self.protocol in (
            "openvpn",
            "both",
        ):
            if not self.stunnel_cert:
                errors.append(
                    "CULVERT_STUNNEL_CERT is required when HTTPS listener enabled"
                )
            if not self.stunnel_key:
                errors.append(
                    "CULVERT_STUNNEL_KEY is required when HTTPS listener enabled"
                )

        # The download server fails closed without a bearer token (the
        # served configs embed client private keys) - surface that as a
        # config error here instead of a mid-startup ValueError traceback
        if self.client_download_enabled and not self.client_download_token:
            errors.append(
                "CULVERT_CLIENT_DOWNLOAD_TOKEN is required when the client"
                " download server is enabled (configs embed private keys)"
            )

        # wstunnel serves WSS with the same cert pair; without it the
        # wstunnel server exits at startup and the HTTPS-tunnel port is dead
        if self.wg_https_tunnel_enabled and self.protocol in (
            "wireguard",
            "both",
        ):
            if not self.stunnel_cert:
                errors.append(
                    "CULVERT_STUNNEL_CERT is required when WireGuard over HTTPS enabled"
                )
            if not self.stunnel_key:
                errors.append(
                    "CULVERT_STUNNEL_KEY is required when WireGuard over HTTPS enabled"
                )

        # External PKI validation
        if self.pki_mode == "external":
            valid_providers = ("file", "openbao", "aws")
            if not self.secrets_provider:
                errors.append(
                    "CULVERT_SECRETS_PROVIDER is required when PKI_MODE=external"
                )
            elif self.secrets_provider not in valid_providers:
                errors.append(
                    f"CULVERT_SECRETS_PROVIDER="
                    f"'{self.secrets_provider}'"
                    f" must be one of {valid_providers}"
                )

            for field_name, var_name in [
                (
                    "secrets_ca_cert_path",
                    "CULVERT_SECRETS_CA_CERT_PATH",
                ),
                (
                    "secrets_server_cert_path",
                    "CULVERT_SECRETS_SERVER_CERT_PATH",
                ),
                (
                    "secrets_server_key_path",
                    "CULVERT_SECRETS_SERVER_KEY_PATH",
                ),
            ]:
                if not getattr(self, field_name):
                    errors.append(f"{var_name} is required when PKI_MODE=external")

            if self.secrets_provider == "openbao":
                if not self.secrets_openbao_address:
                    errors.append(
                        "CULVERT_SECRETS_OPENBAO_ADDRESS"
                        " is required for openbao provider"
                    )
                if (
                    self.secrets_openbao_auth_method == "kubernetes"
                    and not self.secrets_openbao_role
                ):
                    errors.append(
                        "CULVERT_SECRETS_OPENBAO_ROLE is required for kubernetes auth"
                    )

            if self.secrets_provider == "aws":
                if not self.secrets_aws_region:
                    errors.append(
                        "CULVERT_SECRETS_AWS_REGION is required for aws provider"
                    )

        # Key type
        if self.key_type not in ("ec", "rsa"):
            errors.append(f"CULVERT_KEY_TYPE='{self.key_type}' must be 'ec' or 'rsa'")

        # Protocol
        if self.protocol not in ("openvpn", "wireguard", "both"):
            errors.append(
                f"CULVERT_PROTOCOL='{self.protocol}'"
                " must be openvpn, wireguard, or both"
            )

        # At least one listener (OpenVPN-specific)
        if self.protocol in ("openvpn", "both"):
            if not (self.udp_enabled or self.tcp_enabled or self.https_enabled):
                errors.append(
                    "At least one OpenVPN listener must be enabled (UDP, TCP, or HTTPS)"
                )

        # Subnet overlap across ALL enabled tunnel networks, for any protocol
        # combination -- guarantees no collision even when every listener is
        # opted in at once, not just when protocol=both.
        overlap_subnets = []
        if self.protocol in ("openvpn", "both"):
            candidates = []
            if self.udp_enabled:
                candidates.append(("OpenVPN-UDP", self.udp_network, self.udp_netmask))
            if self.tcp_enabled:
                candidates.append(("OpenVPN-TCP", self.tcp_network, self.tcp_netmask))
            if self.https_enabled:
                candidates.append(
                    ("OpenVPN-HTTPS", self.https_network, self.https_netmask)
                )
            for label, net, mask in candidates:
                # Skip malformed netmasks - already reported above; can't
                # overlap-check invalid input.
                subnet = _subnet_or_none(net, mask)
                if subnet is not None:
                    overlap_subnets.append((label, subnet))
        if self.protocol in ("wireguard", "both"):
            overlap_subnets.append(("WireGuard", self.wg_network))

        if len(overlap_subnets) > 1:
            try:
                from lib.wireguard import validate_subnets_no_overlap

                for err in validate_subnets_no_overlap(overlap_subnets):
                    errors.append(err)
            except ImportError:
                logger.warning(
                    "wireguard module not available, skipping subnet overlap check"
                )

        # OAuth2 validation
        any_oauth2 = (
            self.oauth2_udp_enabled
            or self.oauth2_tcp_enabled
            or self.oauth2_https_enabled
        )
        if any_oauth2:
            if not self.oauth2_issuer:
                errors.append(
                    "CULVERT_OAUTH2_ISSUER is required when OAuth2 is enabled"
                )
            elif not self.oauth2_issuer.startswith(("http://", "https://")):
                errors.append(
                    f"CULVERT_OAUTH2_ISSUER='{self.oauth2_issuer}' must be a valid URL"
                )

            if not self.oauth2_client_id:
                errors.append(
                    "CULVERT_OAUTH2_CLIENT_ID is required when OAuth2 is enabled"
                )

            if not self.oauth2_client_secret:
                errors.append(
                    "CULVERT_OAUTH2_CLIENT_SECRET is required when OAuth2 is enabled"
                )

            if not self.oauth2_tls_cert:
                errors.append(
                    "CULVERT_OAUTH2_TLS_CERT is required when OAuth2 is enabled"
                )
            elif not Path(self.oauth2_tls_cert).exists():
                warnings.append(
                    f"CULVERT_OAUTH2_TLS_CERT="
                    f"'{self.oauth2_tls_cert}' does not exist yet"
                )

            if not self.oauth2_tls_key:
                errors.append(
                    "CULVERT_OAUTH2_TLS_KEY is required when OAuth2 is enabled"
                )
            elif not Path(self.oauth2_tls_key).exists():
                warnings.append(
                    f"CULVERT_OAUTH2_TLS_KEY='{self.oauth2_tls_key}' does not exist yet"
                )

        # Report results
        for warning in warnings:
            logger.warning(f"CONFIG: {warning}")

        if errors:
            for error in errors:
                logger.error(f"CONFIG: {error}")
            logger.error(f"Configuration validation failed: {len(errors)} error(s)")
            sys.exit(1)

        logger.info("Configuration validation passed")


def _settings_bool(s, key: str, default: bool) -> bool:
    """Read a boolean from settings with a default."""
    val = s.get(key, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "on")
    return bool(val)


def _settings_int(s, key: str, default: int) -> int:
    """Read an integer from settings with a default."""
    val = s.get(key, default)
    if isinstance(val, int):
        return val
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
