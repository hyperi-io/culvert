#  Project:      culvert
#  File:         deployment.py
#  Purpose:      Declare culvert's scalo deployment contract
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Culvert's deployment contract for the scalo artefact generators.

scalo's ``deployment`` subsystem reads a :class:`DeploymentContract`. Culvert
declares its contract once, here, from its :class:`~lib.config.Config` defaults,
so the same values flow into the running container and every artefact built
from the contract.

Two consumers read it:

- the scalo-service library chart, through the thin chart hyperi-ci assembles
  from ``deploy/deployment-contract.json``. It renders every field below,
  including the port gate, the PKI claim, the root identity and the
  capabilities;
- scalo-py's ``generate_chart``, behind the reference chart under
  ``deploy/helm/culvert``. It reads none of the v4 fields (writable paths,
  resources, security, singleton) and carries every port it is given, so
  ``scripts/generate-deploy-artefacts.py`` hands it the always-on ports only and
  layers the VPN surface on top.

This module imports ``scalo.deployment``, which is gated behind the
``[deployment]`` extra (pydantic). It is a dev/CI-time import only; the culvert
runtime never imports it.
"""

from scalo.deployment import (
    DeploymentContract,
    HealthContract,
    OciLabels,
    OneOfCondition,
    PortContract,
    ResourceList,
    ResourcesContract,
    SecretEnvContract,
    SecretGroupContract,
    SecurityContract,
    WritablePath,
)

from lib.config import Config

# Registry + image identity for the published GHCR image.
IMAGE_REGISTRY = "ghcr.io/hyperi-io"
APP_NAME = "culvert"

# The profile CULVERT_PROFILE=culvert loads. The chart's `config` values render
# here, beside the profiles the image ships in the same directory.
CONFIG_MOUNT_PATH = "/etc/vpn/profiles/culvert.yaml"

# The CULVERT_PROTOCOL values that start the WireGuard server.
WIREGUARD_PROTOCOLS = ("wireguard", "both")

# The contract's oauth2 group: each OIDC secret culvert reads, by its env var and
# the key the chart's secrets.oauth2 values name it by.
OAUTH2_SECRETS = (
    ("CULVERT_OAUTH2_CLIENT_SECRET", "client-secret"),
    ("CULVERT_OAUTH2_HTTP_SECRET", "http-secret"),
)


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


# scalo gates its deployment types behind the [deployment] extra, rebinding each
# name to a stub when pydantic is absent. ty therefore reads each one as
# `Stub | Class` and rejects it as a return annotation. pydantic IS installed here
# (the dev extra), so the ty: ignore below is that shim, not a real type error.
def deployment_contract(
    cfg: Config | None = None,
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
            "OpenVPN + WireGuard VPN server, optionally tunnelled over HTTPS,"
            " with OIDC SSO and external PKI"
        ),
        # The observability port: health probes always, /metrics when enabled.
        metrics_port=_metrics_port(cfg.metrics_addr),
        health=HealthContract(
            liveness_path="/livez",
            readiness_path="/readyz",
            metrics_path="/metrics",
        ),
        env_prefix="CULVERT",
        metric_prefix="culvert",
        config_mount_path=CONFIG_MOUNT_PATH,
        image_registry=IMAGE_REGISTRY,
        # OpenVPN over UDP is the default server. WireGuard listens only where
        # the profile's `protocol` starts it, so a default server opens no port
        # with nothing behind it.
        extra_ports=[
            PortContract(
                name="wireguard",
                port=cfg.wg_port,
                protocol="UDP",
                when=OneOfCondition(
                    path="config.protocol", values=list(WIREGUARD_PROTOCOLS)
                ),
                public=True,
            ),
            PortContract(
                name="openvpn-udp", port=cfg.udp_port, protocol="UDP", public=True
            ),
        ],
        # Optional, so a server with OIDC off starts without the Secret.
        secrets=[
            SecretGroupContract(
                group_name="oauth2",
                env_vars=[
                    SecretEnvContract(env_var=env_var, key_name=key, secret_key=env_var)
                    for env_var, key in OAUTH2_SECRETS
                ],
                optional=True,
            ),
        ],
        # The CA, the CRL and the WireGuard peer allocations. A restart without
        # the claim mints a new CA and invalidates every issued client config.
        writable_paths=[
            WritablePath(
                name="pki", path=str(cfg.pki_dir), persistent=True, size="1Gi"
            ),
        ],
        termination_grace_seconds=30,
        resources=ResourcesContract(
            requests=ResourceList(cpu="250m", memory="256Mi"),
            limits=ResourceList(cpu="2", memory="1Gi"),
        ),
        # Root with NET_ADMIN: OpenVPN and wg-quick create the tun device and
        # program routing and NAT, and OpenVPN then drops to nobody, which needs
        # SETPCAP, SETGID and SETUID. The root filesystem stays writable because
        # the server writes its configs and client bundles under /etc/vpn.
        security=SecurityContract(
            run_as_user=0,
            run_as_group=0,
            fs_group=0,
            read_only_root_filesystem=False,
            capabilities_add=["NET_ADMIN", "SETPCAP", "SETGID", "SETUID"],
        ),
        # WireGuard mints its server key in the pod, so a second pod would issue
        # client configs the first rejects.
        singleton=True,
        oci_labels=OciLabels(
            title=APP_NAME,
            description=(
                "OpenVPN + WireGuard, optionally tunnelled over HTTPS,"
                " with OIDC SSO and external PKI"
            ),
            licenses="Apache-2.0",
        ),
    )
