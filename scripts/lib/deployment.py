#  Project:      culvert
#  File:         deployment.py
#  Purpose:      Declare culvert's scalo deployment contract
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Culvert's deployment contract for the scalo artefact generators.

scalo's ``deployment`` subsystem turns a :class:`DeploymentContract` into the
fleet-standard Helm chart and Compose fragment. Culvert declares its contract
once, here, from its :class:`~lib.config.Config` defaults, so the same values
flow into both the running container and the generated deployment artefacts.

The contract captures only what a generic Python-service generator can express:
the app identity, the metrics/health port, the always-on OpenVPN UDP listener,
the image registry, and the OCI labels. The VPN-specific runtime surface a
generic generator has no field for -- the ``NET_ADMIN`` capability, the
``/dev/net/tun`` device, ``net.ipv4.ip_forward`` sysctls, and the opt-in
listener ports -- is layered onto the generated chart by
``scripts/generate-deploy-artefacts.py`` and documented there.

This module imports ``scalo.deployment``, which is gated behind the
``[deployment]`` extra (pydantic). It is a dev/CI-time import only; the culvert
runtime never imports it.
"""

from __future__ import annotations

from scalo.deployment import (
    DeploymentContract,
    HealthContract,
    OciLabels,
    PortContract,
)

from lib.config import Config

# Registry + image identity for the published GHCR image.
IMAGE_REGISTRY = "ghcr.io/hyperi-io"
APP_NAME = "culvert"

# Culvert is env-var driven (no config file), but the generated chart mounts a
# ConfigMap where an operator can drop a CULVERT_PROFILE YAML. This is the path
# the entrypoint loads when CULVERT_PROFILE=culvert is set.
CONFIG_MOUNT_PATH = "/etc/vpn/profiles/culvert.yaml"


def _metrics_port(addr: str) -> int:
    """Extract the TCP port from a ``host:port`` bind address.

    Args:
        addr: The metrics bind address, e.g. ``0.0.0.0:9090`` or ``[::]:9090``.

    Returns:
        The port number.

    Raises:
        ValueError: If ``addr`` has no parseable trailing port.
    """
    _, sep, port = addr.rpartition(":")
    if not sep:
        raise ValueError(f"metrics_addr has no port: {addr!r}")
    return int(port)


def deployment_contract(
    cfg: Config | None = None,
    # scalo's optional-import shim confuses ty's static resolution of the
    # DeploymentContract symbol (pydantic IS installed via the dev extra)
) -> DeploymentContract:  # ty: ignore[invalid-type-form]
    """Build culvert's deployment contract from its config defaults.

    Args:
        cfg: Config to read defaults from. Defaults to a fresh ``Config()``
            (all hard-coded defaults), which is what the generators use so the
            chart reflects the shipped defaults rather than any live env.

    Returns:
        The populated :class:`DeploymentContract`.
    """
    cfg = cfg or Config()

    return DeploymentContract(
        app_name=APP_NAME,
        description=(
            "OpenVPN + WireGuard VPN server with DPI bypass, OIDC SSO, and external PKI"
        ),
        # The observability port: health probes always, /metrics when enabled.
        metrics_port=_metrics_port(cfg.metrics_addr),
        health=HealthContract(
            liveness_path="/healthz",
            readiness_path="/readyz",
            metrics_path="/metrics",
        ),
        env_prefix="CULVERT",
        metric_prefix="culvert",
        config_mount_path=CONFIG_MOUNT_PATH,
        image_registry=IMAGE_REGISTRY,
        # The default is the simplest working server: OpenVPN over UDP. Every
        # other listener (TCP, HTTPS/stunnel, WireGuard, wstunnel, OIDC,
        # client download) is a deliberate opt-in, added via the chart's
        # `extraPorts` values rather than the always-on contract ports.
        extra_ports=[
            PortContract(name="openvpn-udp", port=cfg.udp_port, protocol="UDP"),
        ],
        oci_labels=OciLabels(
            title=APP_NAME,
            description=("OpenVPN + WireGuard with DPI bypass, OIDC SSO, external PKI"),
            licenses="Apache-2.0",
        ),
    )
