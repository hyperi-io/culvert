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
   conventional boilerplate (~80%): identity, the metrics/health probe wiring
   on the observability port, the Service, ConfigMap, ServiceAccount, HPA and
   NOTES.

2. Layers culvert's VPN overlay (~20%) onto the generated chart. A generic
   Python-service generator has no field for the runtime surface a VPN needs, so
   these are applied here, on top of the generated files, via anchored inserts
   that fail loudly if scalo's output shape changes:

   - ``NET_ADMIN`` container capability (tun device, routing, NAT);
   - ``/dev/net/tun`` host-device passthrough (toggle);
   - an optional PVC for ``/etc/vpn/pki``, plus a guard refusing local PKI
     across replicas;
   - a ``CULVERT_*`` env map (at least ``CULVERT_SERVER_CN``);
   - opt-in listener ports (TCP, HTTPS/stunnel, WireGuard, wstunnel, OIDC,
     client download) -- default none, so the chart defaults to the simplest
     working server: OpenVPN over UDP.

The overlay markers in the generated files are commented ``culvert VPN
overlay``. The chart is standalone: culvert depends on nothing beyond its own
image, so consumers can adopt it without inheriting anything else.
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

# The generator ships a non-root floor (runAsNonRoot, drop ALL). A VPN cannot
# run under it: OpenVPN and wg-quick create the tun device and program routing
# and NAT, which needs root plus NET_ADMIN. The overlay substitutes both blocks
# rather than appending, so the chart carries one coherent answer.
#
# The anchor deliberately includes the generator's comment prose as well as its
# keys: leaving that prose in place would sit "requires runAsNonRoot" directly
# above values that run as root. A reworded comment upstream therefore raises
# from _replace_once, which is the intended outcome - a human re-reads the
# substitution rather than shipping a chart that argues with itself.
_VALUES_SECURITY_GENERATED = """# -- Pod-level security context (non-root floor; the container standard).
# The image runs as UID 1000; a restricted-PodSecurity namespace requires
# runAsNonRoot. Empty this map to opt out (you own the consequence).
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

# -- Container-level hardening. readOnlyRootFilesystem is deliberately NOT
# set: a service that mints a key or writes a cache to the image rootfs
# needs a writable FS. Mount that state on a shared Secret/volume, then
# add `readOnlyRootFilesystem: true` here.
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
"""

_VALUES_SECURITY = """# -- culvert VPN overlay: the VPN data plane runs as root with NET_ADMIN,
# because OpenVPN and wg-quick create the tun device and program routing and
# NAT. That replaces the generator's non-root floor, so a restricted-
# PodSecurity namespace will reject this pod - give culvert its own namespace
# labelled `pod-security.kubernetes.io/enforce: privileged`.
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault
  # net.ipv4.ip_forward has to be on for client traffic to route through the
  # pod. It is NOT requested here by default: it is an unsafe sysctl, so a
  # kubelet without `--allowed-unsafe-sysctls net.ipv4.ip_forward` rejects the
  # pod outright, and most clusters do not set that. The `ipForward` init
  # container below handles it instead, on any cluster. Uncomment this and set
  # ipForward.enabled=false where your kubelet does allow the sysctl.
  #sysctls:
  #  - name: net.ipv4.ip_forward
  #    value: "1"

# -- culvert VPN overlay: container hardening. Everything is dropped except the
# four capabilities the VPN data plane needs:
#   NET_ADMIN  opens and configures the tun device, iptables NAT and routing
#   SETUID     OpenVPN drops to `user nobody` once the sockets are bound
#   SETGID     and to `group nogroup`
#   SETPCAP    retains NET_ADMIN across that drop
# Without SETPCAP/SETUID/SETGID, OpenVPN cannot complete the privilege drop and
# exits 1 during startup. Add SYS_MODULE too if the host offers OpenVPN DCO
# kernel offload. readOnlyRootFilesystem is NOT set: in local-PKI mode the
# server mints its CA and keys onto the container filesystem. Put that state on
# a volume first, then add `readOnlyRootFilesystem: true` here.
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_ADMIN
      - SETPCAP
      - SETGID
      - SETUID
  allowPrivilegeEscalation: false
"""

_VALUES_VPN = """
# -- culvert VPN overlay: enable net.ipv4.ip_forward in the pod's own network
# namespace, via a short privileged init container.
#
# Client traffic does not leave the pod without it. It cannot be done from the
# server container: a container's /proc/sys is mounted read-only regardless of
# capabilities, so NET_ADMIN is not enough. The init container runs `sysctl -w`
# and exits, and only the pod's namespace is affected - not the node's.
#
# Turn it off only if you are setting the sysctl another way, e.g.
# podSecurityContext.sysctls on a kubelet started with
# `--allowed-unsafe-sysctls net.ipv4.ip_forward`. IPv6 forwarding is left off
# deliberately: culvert's routing controls are iptables-only, so forwarded IPv6
# would bypass client isolation and the egress allow-list.
ipForward:
  enabled: true

# -- culvert VPN overlay: /dev/net/tun host passthrough. Required for OpenVPN
# and WireGuard. On a cluster with a TUN device plugin, disable this and request
# the device resource instead.
tunDevice:
  enabled: true
  hostPath: /dev/net/tun

# -- culvert VPN overlay: persist the PKI directory.
#
# In local PKI mode (the default) the server mints its own CA on first start and
# writes it to /etc/vpn/pki. Without a volume that lives on the container's
# writable layer, so EVERY RESTART MINTS A NEW CA and every client config issued
# against the old one stops working.
#
# Off by default because it needs a StorageClass, which not every cluster has,
# and because the production answer is usually CULVERT_PKI_MODE=external. Turn
# it on for a durable single-replica local-PKI server.
#
# It does not help past one replica: each replica gets its own volume and mints
# its own CA, so clients would trust whichever pod answered first. The chart
# refuses that combination rather than letting you find out in production - use
# external PKI to scale out.
persistence:
  enabled: false
  # storageClass: ""        # "" uses the cluster default
  accessMode: ReadWriteOnce
  size: 1Gi
  # existingClaim: ""       # bring your own PVC instead

# -- culvert VPN overlay: CULVERT_* environment. At minimum set
# CULVERT_SERVER_CN to the DNS name clients dial. See .env.example for the full
# catalogue of CULVERT_* knobs and their defaults. NON-SECRET values only --
# these render as plaintext into the Deployment. Secrets go via existingSecret.
env:
  CULVERT_SERVER_CN: vpn.example.com
  # OpenVPN's own log goes to stdout so `kubectl logs` shows why a pod failed.
  # The image default writes it to /var/log/vpn/openvpn.log instead, which is
  # unreachable once the container has exited.
  CULVERT_LOG_MODE: stdout

# -- culvert VPN overlay: name of a pre-created Secret to load as environment
# (envFrom). This is where the SENSITIVE CULVERT_* values belong -- OIDC client
# secret, client-download token, OpenBao token -- so they never land in a
# ConfigMap or a plaintext env value. Create it yourself (External Secrets
# Operator, sealed-secrets, or kubectl) with keys like CULVERT_OAUTH2_CLIENT_SECRET;
# empty string disables the envFrom.
existingSecret: ""

# -- culvert VPN overlay: PKI material for external-PKI mode, delivered as a
# Secret rather than fetched over the network.
#
# Name a Secret carrying the server's identity and the chart mounts it read-only
# and points CULVERT_SECRETS_* at the mount, so the container copies it into the
# writable PKI directory on start. Keys:
#
#   ca.crt      REQUIRED  the CA clients must trust
#   server.crt  REQUIRED  the server certificate
#   server.key  REQUIRED  its private key
#   crl.pem     optional  revocation list
#   tc.key      optional for one replica, REQUIRED for more than one -- a
#               client's tls-crypt-v2 key is derived from this server key, so
#               replicas that each mint their own reject each other's clients
#
# This is the only way to run more than one replica: every replica then presents
# the same CA and the same tls-crypt-v2 key, so any of them can serve any client.
# Leave it empty to use local PKI (the single-server default), or set
# CULVERT_SECRETS_PROVIDER to openbao/aws in `env` to fetch over the network
# instead.
pkiSecret: ""
pkiSecretMountPath: /etc/vpn/pki-external

# -- culvert VPN overlay: opt-in listener ports, beyond the always-on OpenVPN
# UDP (1194/udp) and the observability port (9090/tcp). Uncomment the ones whose
# CULVERT_* feature you switch on via `env` above. Each renders a containerPort
# and a matching Service port.
extraPorts: []
  # - name: openvpn-tcp      # CULVERT_TCP_ENABLED=true
  #   port: 1194
  #   protocol: TCP
  # - name: openvpn-https    # CULVERT_HTTPS_ENABLED=true (stunnel, OpenVPN over HTTPS)
  #   port: 443
  #   protocol: TCP
  # - name: wireguard        # CULVERT_PROTOCOL=wireguard or both
  #   port: 51820
  #   protocol: UDP
  # - name: wg-https           # CULVERT_WG_HTTPS_TUNNEL_ENABLED=true (wstunnel)
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

    # values.yaml: say plainly that it is generated, as the compose fragment
    # already does - otherwise a hand-edit is lost on the next run.
    _replace_once(
        values,
        "# culvert Helm chart values\n#\n# Generated by scalo deployment module.\n"
        "# Contract points validated by pytest.\n",
        "# culvert Helm chart values\n"
        "#\n"
        "# AUTOGENERATED from culvert's scalo deployment contract by\n"
        "# scripts/generate-deploy-artefacts.py -- do not edit by hand.\n"
        "# Override these values at install time (-f my-values.yaml) instead.\n",
    )

    # Chart.yaml: the generator hardcodes version 0.1.0 / appVersion "1.0.0".
    # appVersion is what `image.tag: ""` falls back to, and no culvert image is
    # tagged 1.0.0, so the shipped chart would ImagePullBackOff on a plain
    # `helm install`. Both come from VERSION instead; the published image tags
    # carry a `v` prefix, so appVersion does too.
    version = (_REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip().lstrip("v")
    _replace_once(
        chart,
        'version: 0.1.0\nappVersion: "1.0.0"\n',
        f'version: {version}\nappVersion: "v{version}"\n',
    )

    # Chart.yaml: replace the generator's default keywords, which name another
    # product, with culvert's own, and set the icon Artifact Hub renders.
    _replace_once(
        chart,
        "keywords:\n  - hyperi\n  - dfe\n",
        "icon: https://raw.githubusercontent.com/hyperi-io/culvert/main/"
        "assets/brand/product-culvert/light/product-culvert_square_400w.png\n\n"
        "keywords:\n  - vpn\n  - openvpn\n  - wireguard\n  - hyperi\n",
    )

    # values.yaml: swap the generated non-root floor for the VPN's root +
    # NET_ADMIN reality; VPN knobs after the config block.
    _replace_once(values, _VALUES_SECURITY_GENERATED, _VALUES_SECURITY)
    _replace_once(
        values,
        "# -- Application configuration (mounted as "
        "/etc/vpn/profiles/culvert.yaml)\nconfig: {}\n\n",
        "# -- Application configuration (mounted as "
        "/etc/vpn/profiles/culvert.yaml)\nconfig: {}\n"
        f"{_VALUES_VPN}\n",
    )

    # values.yaml: the generator's service block only knows type and port. A VPN
    # published on a LoadBalancer needs the rest, and an operator reading this
    # file has no other way to discover the knobs exist.
    _replace_once(
        values,
        "# -- Metrics and health endpoint service\nservice:\n"
        "  type: ClusterIP\n  port: 9090\n",
        "# -- Metrics and health endpoint service. This one Service also carries\n"
        "# the VPN listener ports, so a LoadBalancer publishes :9090 with it.\n"
        "service:\n"
        "  type: ClusterIP\n"
        "  port: 9090\n"
        "  # -- culvert VPN overlay: CIDRs allowed to reach the LB. Leaving this\n"
        "  # empty on a LoadBalancer exposes /livez, /readyz and /metrics\n"
        "  # unauthenticated to everything the LB is reachable from.\n"
        "  loadBalancerSourceRanges: []\n"
        "  # -- culvert VPN overlay: pin the LB address clients dial.\n"
        '  loadBalancerIP: ""\n'
        "  # -- culvert VPN overlay: `Local` preserves the client's real source\n"
        "  # IP, which per-client routing rules and the connection log need.\n"
        "  # `Cluster` (the Kubernetes default) SNATs every client to a node IP.\n"
        '  externalTrafficPolicy: ""\n'
        "  # -- culvert VPN overlay: `ClientIP` keeps a client on the pod that\n"
        "  # accepted it. Set this whenever more than one replica is behind the\n"
        "  # Service: tunnel state is per-pod, so a flow that lands elsewhere\n"
        "  # is a dropped connection.\n"
        '  sessionAffinity: ""\n',
    )

    # deployment.yaml: the generator emits both securityContext blocks, wired to
    # the values the overlay just replaced, so only the token opt-out is added.
    _replace_once(
        deployment,
        '      serviceAccountName: {{ include "culvert.serviceAccountName" . }}\n',
        '      serviceAccountName: {{ include "culvert.serviceAccountName" . }}\n'
        "      # culvert VPN overlay: the VPN never calls the K8s API.\n"
        "      automountServiceAccountToken: false\n",
    )

    # deployment.yaml: turn on IP forwarding inside the pod's own network
    # namespace. A container's /proc/sys is mounted read-only whatever
    # capabilities it holds, so the entrypoint cannot do this itself, and without
    # it the server completes handshakes and then forwards nothing. A privileged
    # init container can, and needs no cluster-level configuration - unlike
    # podSecurityContext.sysctls, which most kubelets reject for this sysctl.
    _replace_once(
        deployment,
        "      containers:\n        - name: {{ .Chart.Name }}\n",
        "      # culvert VPN overlay: IP forwarding in the pod network namespace.\n"
        "      {{- if .Values.ipForward.enabled }}\n"
        "      initContainers:\n"
        "        - name: enable-ip-forward\n"
        '          image: "{{ .Values.image.repository }}:'
        '{{ .Values.image.tag | default .Chart.AppVersion }}"\n'
        "          imagePullPolicy: {{ .Values.image.pullPolicy }}\n"
        '          command: ["sysctl", "-w", "net.ipv4.ip_forward=1"]\n'
        "          securityContext:\n"
        "            privileged: true\n"
        "          resources:\n"
        "            requests:\n"
        "              cpu: 10m\n"
        "              memory: 16Mi\n"
        "      {{- end }}\n"
        "      containers:\n        - name: {{ .Chart.Name }}\n",
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
        "          {{- $env := default dict .Values.env }}\n"
        "          {{- if or $env .Values.pkiSecret }}\n"
        "          env:\n"
        "            {{- range $k, $v := $env }}\n"
        "            - name: {{ $k }}\n"
        "              value: {{ $v | quote }}\n"
        "            {{- end }}\n"
        "            # culvert VPN overlay: point external PKI at the mounted\n"
        "            # Secret. Anything set in `env` above wins, so an operator\n"
        "            # can fetch from openbao/aws instead.\n"
        "            {{- if .Values.pkiSecret }}\n"
        "            {{- $mount := .Values.pkiSecretMountPath }}\n"
        "            {{- range $k, $v := dict"
        ' "CULVERT_PKI_MODE" "external"'
        ' "CULVERT_SECRETS_PROVIDER" "file"'
        ' "CULVERT_SECRETS_CA_CERT_PATH" (printf "%s/ca.crt" $mount)'
        ' "CULVERT_SECRETS_SERVER_CERT_PATH" (printf "%s/server.crt" $mount)'
        ' "CULVERT_SECRETS_SERVER_KEY_PATH" (printf "%s/server.key" $mount)'
        ' "CULVERT_SECRETS_CRL_PATH" (printf "%s/crl.pem" $mount)'
        ' "CULVERT_SECRETS_TC_KEY_PATH" (printf "%s/tc.key" $mount)'
        " }}\n"
        "            {{- if not (hasKey $env $k) }}\n"
        "            - name: {{ $k }}\n"
        "              value: {{ $v | quote }}\n"
        "            {{- end }}\n"
        "            {{- end }}\n"
        "            {{- end }}\n"
        "          {{- end }}\n"
        "          # culvert VPN overlay: SENSITIVE CULVERT_* from a pre-created Secret.\n"
        "          {{- if .Values.existingSecret }}\n"
        "          envFrom:\n"
        "            - secretRef:\n"
        "                name: {{ .Values.existingSecret }}\n"
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
        "            {{- end }}\n"
        "            # culvert VPN overlay: durable PKI (local-PKI mode).\n"
        "            {{- if .Values.persistence.enabled }}\n"
        "            - name: pki\n"
        "              mountPath: /etc/vpn/pki\n"
        "            {{- end }}\n"
        "            # culvert VPN overlay: external PKI material (file provider).\n"
        "            {{- if .Values.pkiSecret }}\n"
        "            - name: pki-external\n"
        "              mountPath: {{ .Values.pkiSecretMountPath }}\n"
        "              readOnly: true\n"
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
        "        {{- end }}\n"
        "        # culvert VPN overlay: durable PKI (local-PKI mode).\n"
        "        {{- if .Values.persistence.enabled }}\n"
        "        - name: pki\n"
        "          persistentVolumeClaim:\n"
        "            claimName: {{ .Values.persistence.existingClaim"
        ' | default (printf "%s-pki" (include "culvert.fullname" .)) }}\n'
        "        {{- end }}\n"
        "        # culvert VPN overlay: external PKI material (file provider).\n"
        "        {{- if .Values.pkiSecret }}\n"
        "        - name: pki-external\n"
        "          secret:\n"
        "            secretName: {{ .Values.pkiSecret }}\n"
        "            defaultMode: 0400\n"
        "        {{- end }}\n",
    )

    # deployment.yaml: refuse the replica counts that cannot work. Two separate
    # pieces of per-server state break a multi-replica install, and both surface
    # only as client-side failures long after the deploy looks fine, so the chart
    # fails at template time with the fix named:
    #   * the CA - each local-PKI replica mints its own, so a client trusts
    #     whichever pod answered first;
    #   * the tls-crypt-v2 server key - a client's key is derived from it, so a
    #     replica that minted a different one rejects that client outright.
    _replace_once(
        deployment,
        "apiVersion: apps/v1\nkind: Deployment\n",
        "{{- $env := default dict .Values.env }}\n"
        '{{- $external := or .Values.pkiSecret (eq (default "local"'
        ' $env.CULVERT_PKI_MODE) "external") }}\n'
        "{{- $sharedTcKey := or .Values.pkiSecret"
        " $env.CULVERT_SECRETS_TC_KEY_PATH }}\n"
        "{{- $replicas := .Values.replicaCount }}\n"
        "{{- if .Values.autoscaling.enabled }}"
        "{{- $replicas = .Values.autoscaling.minReplicas }}{{- end }}\n"
        "{{- if .Values.keda.enabled }}{{- $replicas = 2 }}{{- end }}\n"
        "{{- if and (not $external) (not .Values.persistence.enabled)"
        " (gt (int $replicas) 1) }}\n"
        '{{- fail (printf "culvert: %d replicas with local PKI and no'
        " persistence. Each replica would mint its own CA, so clients would"
        " trust whichever pod answered first. Either supply shared PKI material"
        " (pkiSecret), or set persistence.enabled=true and stay at one"
        ' replica." (int $replicas)) }}\n'
        "{{- end }}\n"
        "{{- if and (gt (int $replicas) 1) (not $sharedTcKey) }}\n"
        '{{- fail (printf "culvert: %d replicas with no shared tls-crypt-v2'
        " server key. Each replica mints its own, and a client config only"
        " works against the replica that issued it, so connections would fail"
        " at random. Set pkiSecret to a Secret carrying tc.key, or point"
        " env.CULVERT_SECRETS_TC_KEY_PATH at a shared one in your secrets"
        ' backend." (int $replicas)) }}\n'
        "{{- end }}\n"
        "apiVersion: apps/v1\nkind: Deployment\n",
    )

    # A PVC for the PKI directory, rendered only when persistence is on and no
    # existing claim was supplied. Written rather than patched because the
    # generic generator has no persistence concept to hook into.
    (chart_dir / "templates" / "pvc.yaml").write_text(
        "{{- if and .Values.persistence.enabled"
        " (not .Values.persistence.existingClaim) }}\n"
        "# culvert VPN overlay: durable /etc/vpn/pki for local-PKI mode.\n"
        "apiVersion: v1\n"
        "kind: PersistentVolumeClaim\n"
        "metadata:\n"
        '  name: {{ include "culvert.fullname" . }}-pki\n'
        "  labels:\n"
        '    {{- include "culvert.labels" . | nindent 4 }}\n'
        "spec:\n"
        "  accessModes:\n"
        "    - {{ .Values.persistence.accessMode }}\n"
        "  {{- with .Values.persistence.storageClass }}\n"
        "  storageClassName: {{ . }}\n"
        "  {{- end }}\n"
        "  resources:\n"
        "    requests:\n"
        "      storage: {{ .Values.persistence.size }}\n"
        "{{- end }}\n",
        encoding="utf-8",
        newline="\n",
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

    # service.yaml: culvert VPN overlay. One Service carries the VPN port AND
    # the unauthenticated observability port (9090), so a LoadBalancer would
    # publish 9090 too. Let operators clamp the source ranges, pin the address,
    # and steer a VPN flow at one pod.
    _replace_once(
        service,
        "spec:\n  type: {{ .Values.service.type }}\n",
        "spec:\n  type: {{ .Values.service.type }}\n"
        "  {{- with .Values.service.loadBalancerSourceRanges }}\n"
        "  # culvert VPN overlay: restrict who can reach the LB (incl. :9090).\n"
        "  loadBalancerSourceRanges:\n"
        "    {{- toYaml . | nindent 4 }}\n"
        "  {{- end }}\n"
        "  {{- with .Values.service.loadBalancerIP }}\n"
        "  # culvert VPN overlay: clients dial a fixed address, so pin it.\n"
        "  loadBalancerIP: {{ . }}\n"
        "  {{- end }}\n"
        "  {{- with .Values.service.externalTrafficPolicy }}\n"
        "  # culvert VPN overlay: Local keeps the client's real source IP and\n"
        "  # steers each flow at a pod on the receiving node.\n"
        "  externalTrafficPolicy: {{ . }}\n"
        "  {{- end }}\n"
        "  {{- with .Values.service.sessionAffinity }}\n"
        "  # culvert VPN overlay: pin a client to the pod that accepted it.\n"
        "  sessionAffinity: {{ . }}\n"
        "  {{- end }}\n",
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

    # The generator emits bare "1194:1194", which Compose reads as TCP. The
    # contract declares this listener UDP and the default server listens on UDP
    # only, so publish it as UDP or the fragment describes a port nothing binds.
    udp_port = (
        f'      - "{contract.extra_ports[0].port}:{contract.extra_ports[0].port}"\n'
    )
    if udp_port not in fragment:
        raise SystemExit(f"compose fragment has no {udp_port.strip()} line to fix up")
    fragment = fragment.replace(udp_port, udp_port.rstrip("\n")[:-1] + '/udp"\n')

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
