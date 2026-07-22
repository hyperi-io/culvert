#!/usr/bin/env python3
#  Project:      culvert
#  File:         generate-deploy-artefacts.py
#  Purpose:      Generate the reference Helm chart + Compose fragment from the
#                scalo deployment contract, then layer culvert's VPN overlay.
#  Language:     Python
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

"""Generate culvert's deployment artefacts from its scalo deployment contract.

Run this to (re)produce the committed reference chart and Compose fragment::

    .venv/bin/python scripts/generate-deploy-artefacts.py

It does two things:

1. Calls scalo's ``generate_chart`` / ``generate_compose_fragment`` to emit the
   fleet-standard boilerplate (~80%): identity, the metrics/health probe wiring
   on the observability port, the Service, ConfigMap, ServiceAccount, HPA and
   NOTES.

2. Layers culvert's VPN overlay (~20%) onto the generated chart. A generic
   Python-service generator has no field for the runtime surface a VPN needs, so
   these are applied here, on top of the generated files, via anchored inserts
   that fail loudly if scalo's output shape changes:

   - ``NET_ADMIN`` container capability (tun device, routing, NAT);
   - ``net.ipv4.ip_forward`` pod sysctl;
   - ``/dev/net/tun`` host-device passthrough (toggle);
   - a ``CULVERT_*`` env map (at least ``CULVERT_SERVER_CN``);
   - opt-in listener ports (TCP, HTTPS/stunnel, WireGuard, wstunnel, OIDC,
     client download) -- default none, so the chart defaults to the simplest
     working server: OpenVPN over UDP.

The overlay markers in the generated files are commented ``culvert VPN
overlay``. The dependency arrow is dfe-infra -> culvert: dfe-infra consumes this
chart for its inbound VPN; culvert never depends on dfe-* or anything internal.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from lib.deployment import deployment_contract  # noqa: E402
from scalo.deployment import generate_chart, generate_compose_fragment  # noqa: E402

CHART_DIR = _REPO_ROOT / "deploy" / "helm" / "culvert"
COMPOSE_FILE = _REPO_ROOT / "deploy" / "compose" / "culvert.yaml"


def _replace_once(path: Path, old: str, new: str) -> None:
    """Replace ``old`` with ``new`` in ``path``, asserting a single match.

    Fails loudly if the anchor is absent or ambiguous -- that means scalo's
    generated output shape moved and the overlay needs revisiting, rather than
    silently producing a chart missing its VPN wiring.

    Args:
        path: File to edit.
        old: Exact anchor text (must occur exactly once).
        new: Replacement text.

    Raises:
        RuntimeError: If ``old`` does not occur exactly once in ``path``.
    """
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"overlay anchor found {count} times (expected 1) in {path.name}:\n{old!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


# --- VPN overlay fragments ---------------------------------------------------

_VALUES_SECURITY = """
# -- culvert VPN overlay: the VPN data plane. OpenVPN and wg-quick create the
# tun device, program routing and NAT, so the container runs as root with
# NET_ADMIN. This is the deliberate exception the generic scalo generator does
# not emit -- a restricted-PodSecurity namespace rejects it, so give culvert its
# own namespace labelled `pod-security.kubernetes.io/enforce: privileged`.
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault
  # ip_forward lets client traffic route through the pod. It is an unsafe
  # sysctl: allow it on the kubelet (--allowed-unsafe-sysctls net.ipv4.ip_forward)
  # or let the entrypoint set it at runtime (it holds NET_ADMIN).
  sysctls:
    - name: net.ipv4.ip_forward
      value: "1"

securityContext:
  # NET_ADMIN: open/configure the tun device, iptables NAT, routing. Add
  # SYS_MODULE too if the host offers OpenVPN DCO kernel offload.
  capabilities:
    drop:
      - ALL
    add:
      - NET_ADMIN
  allowPrivilegeEscalation: false
"""

_VALUES_VPN = """
# -- culvert VPN overlay: /dev/net/tun host passthrough. Required for OpenVPN
# and WireGuard. On a cluster with a TUN device plugin, disable this and request
# the device resource instead.
tunDevice:
  enabled: true
  hostPath: /dev/net/tun

# -- culvert VPN overlay: CULVERT_* environment. At minimum set
# CULVERT_SERVER_CN to the DNS name clients dial. See .env.example for the full
# catalogue of CULVERT_* knobs and their defaults.
env:
  CULVERT_SERVER_CN: vpn.example.com

# -- culvert VPN overlay: opt-in listener ports, beyond the always-on OpenVPN
# UDP (1194/udp) and the observability port (9090/tcp). Uncomment the ones whose
# CULVERT_* feature you switch on via `env` above. Each renders a containerPort
# and a matching Service port.
extraPorts: []
  # - name: openvpn-tcp      # CULVERT_TCP_ENABLED=true
  #   port: 1194
  #   protocol: TCP
  # - name: openvpn-https    # CULVERT_HTTPS_ENABLED=true (stunnel DPI bypass)
  #   port: 443
  #   protocol: TCP
  # - name: wireguard        # CULVERT_PROTOCOL=wireguard or both
  #   port: 51820
  #   protocol: UDP
  # - name: wg-dpi           # CULVERT_WG_DPI_BYPASS_ENABLED=true (wstunnel)
  #   port: 4443
  #   protocol: TCP
  # - name: oauth2-udp       # CULVERT_OAUTH2_ENABLED=true
  #   port: 9000
  #   protocol: TCP
  # - name: oauth2-https
  #   port: 9001
  #   protocol: TCP
  # - name: oauth2-tcp
  #   port: 9002
  #   protocol: TCP
  # - name: client-download  # CULVERT_CLIENT_DOWNLOAD_ENABLED=true
  #   port: 8443
  #   protocol: TCP
"""


def _apply_vpn_overlay(chart_dir: Path) -> None:
    """Layer culvert's VPN-specific wiring onto the scalo-generated chart.

    Args:
        chart_dir: The generated chart directory.
    """
    chart = chart_dir / "Chart.yaml"
    values = chart_dir / "values.yaml"
    deployment = chart_dir / "templates" / "deployment.yaml"
    service = chart_dir / "templates" / "service.yaml"

    # Chart.yaml: neutralise the generator's fleet keywords. culvert is a
    # standalone public chart -- the internal `dfe` keyword must not leak into a
    # published artefact (dfe-infra depends on culvert, never the reverse).
    _replace_once(
        chart,
        "keywords:\n  - hyperi\n  - dfe\n",
        "keywords:\n  - vpn\n  - openvpn\n  - wireguard\n  - hyperi\n",
    )

    # values.yaml: security context after the serviceAccount block; VPN knobs
    # after the config block.
    _replace_once(
        values,
        "serviceAccount:\n"
        "  create: true\n"
        "  annotations: {}\n"
        "  # -- If not set, name is generated from fullname\n"
        '  name: ""\n\n',
        "serviceAccount:\n"
        "  create: true\n"
        "  annotations: {}\n"
        "  # -- If not set, name is generated from fullname\n"
        '  name: ""\n'
        f"{_VALUES_SECURITY}\n",
    )
    _replace_once(
        values,
        "# -- Application configuration (mounted as "
        "/etc/vpn/profiles/culvert.yaml)\nconfig: {}\n\n",
        "# -- Application configuration (mounted as "
        "/etc/vpn/profiles/culvert.yaml)\nconfig: {}\n"
        f"{_VALUES_VPN}\n",
    )

    # deployment.yaml: pod securityContext before containers.
    _replace_once(
        deployment,
        '      serviceAccountName: {{ include "culvert.serviceAccountName" . }}\n'
        "      containers:\n",
        '      serviceAccountName: {{ include "culvert.serviceAccountName" . }}\n'
        "      # culvert VPN overlay: the VPN never calls the K8s API.\n"
        "      automountServiceAccountToken: false\n"
        "      # culvert VPN overlay: pod securityContext (seccomp + routing sysctls).\n"
        "      {{- with .Values.podSecurityContext }}\n"
        "      securityContext:\n"
        "        {{- toYaml . | nindent 8 }}\n"
        "      {{- end }}\n"
        "      containers:\n",
    )

    # deployment.yaml: container securityContext before the ports block.
    _replace_once(
        deployment,
        "          imagePullPolicy: {{ .Values.image.pullPolicy }}\n          ports:\n",
        "          imagePullPolicy: {{ .Values.image.pullPolicy }}\n"
        "          # culvert VPN overlay: NET_ADMIN for tun/routing/NAT.\n"
        "          {{- with .Values.securityContext }}\n"
        "          securityContext:\n"
        "            {{- toYaml . | nindent 12 }}\n"
        "          {{- end }}\n"
        "          ports:\n",
    )

    # deployment.yaml: opt-in extraPorts + CULVERT_* env after the fixed ports.
    _replace_once(
        deployment,
        "            - name: openvpn-udp\n"
        "              containerPort: 1194\n"
        "              protocol: UDP\n"
        "          livenessProbe:\n",
        "            - name: openvpn-udp\n"
        "              containerPort: 1194\n"
        "              protocol: UDP\n"
        "            # culvert VPN overlay: opt-in listener ports (default none).\n"
        "            {{- range .Values.extraPorts }}\n"
        "            - name: {{ .name }}\n"
        "              containerPort: {{ .port }}\n"
        '              protocol: {{ .protocol | default "TCP" }}\n'
        "            {{- end }}\n"
        "          # culvert VPN overlay: CULVERT_* env (set CULVERT_SERVER_CN).\n"
        "          {{- with .Values.env }}\n"
        "          env:\n"
        "            {{- range $k, $v := . }}\n"
        "            - name: {{ $k }}\n"
        "              value: {{ $v | quote }}\n"
        "            {{- end }}\n"
        "          {{- end }}\n"
        "          livenessProbe:\n",
    )

    # deployment.yaml: tun device volumeMount.
    _replace_once(
        deployment,
        "          volumeMounts:\n"
        "            - name: config\n"
        "              mountPath: /etc/vpn/profiles\n"
        "              readOnly: true\n",
        "          volumeMounts:\n"
        "            - name: config\n"
        "              mountPath: /etc/vpn/profiles\n"
        "              readOnly: true\n"
        "            # culvert VPN overlay: /dev/net/tun passthrough.\n"
        "            {{- if .Values.tunDevice.enabled }}\n"
        "            - name: tun\n"
        "              mountPath: /dev/net/tun\n"
        "            {{- end }}\n",
    )

    # deployment.yaml: tun device hostPath volume.
    _replace_once(
        deployment,
        "      volumes:\n"
        "        - name: config\n"
        "          configMap:\n"
        '            name: {{ include "culvert.fullname" . }}-config\n',
        "      volumes:\n"
        "        - name: config\n"
        "          configMap:\n"
        '            name: {{ include "culvert.fullname" . }}-config\n'
        "        # culvert VPN overlay: /dev/net/tun host device.\n"
        "        {{- if .Values.tunDevice.enabled }}\n"
        "        - name: tun\n"
        "          hostPath:\n"
        "            path: {{ .Values.tunDevice.hostPath }}\n"
        "            type: CharDevice\n"
        "        {{- end }}\n",
    )

    # service.yaml: opt-in extraPorts.
    _replace_once(
        service,
        "      name: openvpn-udp\n  selector:\n",
        "      name: openvpn-udp\n"
        "    {{- range .Values.extraPorts }}\n"
        "    - port: {{ .port }}\n"
        "      targetPort: {{ .port }}\n"
        '      protocol: {{ .protocol | default "TCP" }}\n'
        "      name: {{ .name }}\n"
        "    {{- end }}\n"
        "  selector:\n",
    )


def _write_compose(contract, path: Path) -> None:
    """Write the scalo-generated Compose fragment with a provenance header.

    The fragment is a contract-shape reference: it shows how the observability
    port and health probe map into Compose. It is NOT the authoritative runtime
    definition -- ``docker-compose.yaml`` at the repo root is, and it carries the
    VPN specifics (NET_ADMIN, /dev/net/tun, sysctls, the UDP listener).

    Args:
        contract: The deployment contract.
        path: Output path.
    """
    header = (
        "# AUTOGENERATED from culvert's scalo deployment contract by\n"
        "# scripts/generate-deploy-artefacts.py -- do not edit by hand.\n"
        "#\n"
        "# Contract-shape reference only (identity, image, observability port,\n"
        "# health probe). The AUTHORITATIVE single-host runtime is\n"
        "# docker-compose.yaml at the repo root, which carries the VPN specifics\n"
        "# the generic generator does not model: NET_ADMIN, /dev/net/tun,\n"
        "# net.ipv4.ip_forward sysctls, and the UDP listener publish.\n"
        "\n"
    )
    fragment = generate_compose_fragment(contract)
    if fragment is None:
        raise SystemExit("scalo generate_compose_fragment produced no output")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        header + fragment,
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    """Generate the chart + Compose fragment and apply the VPN overlay."""
    contract = deployment_contract()

    generate_chart(contract, CHART_DIR)
    _apply_vpn_overlay(CHART_DIR)
    _write_compose(contract, COMPOSE_FILE)

    print(f"Wrote Helm chart:       {CHART_DIR}")
    print(f"Wrote Compose fragment: {COMPOSE_FILE}")


if __name__ == "__main__":
    main()
