# Kubernetes at scale

Not a profile - a deploy shape. Run the Helm chart at
[`deploy/helm/culvert`](../deploy/helm/culvert) behind a load balancer:
probes, SIGTERM drain, autoscaling, external PKI, Prometheus. The chart
defaults to the simplest working server (OpenVPN UDP, NET_ADMIN,
`/dev/net/tun`); every other listener is an opt-in.

Read [connection affinity](#connection-affinity-read-this) before you
pick a load balancer - it is the one thing that will silently break a
multi-pod VPN.

## 1. A namespace the pod is allowed in

The VPN data plane creates the tun device, programs routing and NAT, and
sets `net.ipv4.ip_forward`. That needs `NET_ADMIN`, the `/dev/net/tun`
host device, and an unsafe sysctl - a restricted-PodSecurity namespace
rejects it. Give culvert its own namespace at the privileged level:

```bash
kubectl create namespace vpn
kubectl label namespace vpn pod-security.kubernetes.io/enforce=privileged
```

`net.ipv4.ip_forward` is an unsafe sysctl - either allow it on the
kubelet (`--allowed-unsafe-sysctls net.ipv4.ip_forward`) or let the
entrypoint set it at runtime (it holds `NET_ADMIN`). The chart requests
it via `podSecurityContext.sysctls`.

## 2. Install

```bash
helm install culvert deploy/helm/culvert -n vpn \
  --set env.CULVERT_SERVER_CN=vpn.example.com
```

At minimum set `CULVERT_SERVER_CN` to the DNS name clients dial. Every
`CULVERT_*` knob from [.env.example](../.env.example) goes under `env`;
see [values.yaml](../deploy/helm/culvert/values.yaml) for the chart's own
overlay (`tunDevice`, `podSecurityContext`, `securityContext`,
`extraPorts`, `service`, `autoscaling`).

A `values-k8s-scale.yaml` starter lives alongside the chart in
[`deploy/helm/culvert`](../deploy/helm/culvert) with the scale-out knobs
already set - copy it and pass `-f values-k8s-scale.yaml`.

## 3. Expose UDP 1194 externally

The chart renders one Service carrying the metrics port (`9090/TCP`),
`openvpn-udp` (`1194/UDP`), and any `extraPorts`. Its type is
`ClusterIP` by default. To reach clients from outside, either:

- set `service.type=LoadBalancer` (the cloud LB fronts the UDP port), or
- put a Gateway API `UDPRoute` (or TLS passthrough for the HTTPS
  listeners) in front of the ClusterIP Service.

One Service carries every port, so `LoadBalancer` also publishes the
observability port `9090` (`/livez`, `/readyz`, and `/metrics` when
enabled) - unauthenticated. Restrict it with `loadBalancerSourceRanges`,
or keep the Service `ClusterIP` and expose only the VPN port through
Gateway API. The `values-k8s-scale.yaml` starter notes this.

## 4. Opt listeners in

Each extra listener is two edits that must agree: turn the feature on via
`env`, and add the matching `extraPorts` entry so the containerPort and
Service port render. For example, WireGuard alongside OpenVPN:

```yaml
env:
  CULVERT_SERVER_CN: vpn.example.com
  CULVERT_PROTOCOL: both
extraPorts:
  - name: wireguard
    port: 51820
    protocol: UDP
```

The commented block in [values.yaml](../deploy/helm/culvert/values.yaml)
lists every listener (`openvpn-tcp`, `openvpn-https`, `wireguard`,
`wg-https`, the `oauth2-*` callbacks, `client-download`) with the
`CULVERT_*` switch each one pairs with.

## 5. Scale and observe

- **Autoscaling:** `autoscaling.enabled=true` renders a CPU-target HPA
  (`autoscaling.minReplicas` / `maxReplicas` /
  `targetCPUUtilizationPercentage`). Mutually exclusive with `keda`.
- **Metrics:** the pod carries `prometheus.io/scrape`,
  `prometheus.io/port: "9090"`, `prometheus.io/path: "/metrics"`
  annotations by default. `/metrics` serves when
  `CULVERT_METRICS_ENABLED=true`.
- **Probes:** liveness `/livez`, readiness `/readyz`, both on the metrics
  port (`9090`) - served always, independent of the metrics toggle. There
  is no separate startup path: point a `startupProbe` at `/livez` too, and
  Kubernetes suspends liveness until it passes.
- **Drain:** the container handles SIGTERM to drain connections on
  rollout / scale-down.

## 6. External PKI

Production clusters generally do not want a self-generated CA per pod.
Set `CULVERT_PKI_MODE=external` and point at one of:

- **File** - certs mounted from a Kubernetes Secret (or cert-manager)
  volume; `CULVERT_SECRETS_*_PATH` are file paths.
- **OpenBao** - Kubernetes auth exchanges the pod ServiceAccount token
  for a short-lived token (no static secret in env).
- **AWS Secrets Manager** - use IRSA on EKS; no static AWS keys.

Detail is in [External PKI in the README](../README.md#external-pki) and
the External PKI / Secrets Management sections of
[.env.example](../.env.example).

## Connection affinity - read this

A single VPN flow must stay pinned to one culvert pod for its whole life.
State is per-pod: the OpenVPN client-IP allocation, the TLS session, the
WireGuard peer table all live in the pod that accepted the connection.
Steer packets from one flow to a different pod mid-session and the tunnel
breaks.

So the load balancer must be connection / 5-tuple based, not per-packet:

- For a cloud `LoadBalancer` Service, use a connection-hashing scheme and
  avoid per-packet round-robin. Consider
  `externalTrafficPolicy: Local` and a client-IP / 5-tuple hash.
- Multiple replicas work, but each flow is sticky to the pod that
  answered it. Scaling adds capacity for new connections; it does not
  rebalance live ones.

This is why the edge-fleet shape (below) calls out a connection-sticky LB
specifically.

## See also

- [use-case-edge-fleet.md](use-case-edge-fleet.md) - the hub-and-spoke
  fleet shape that runs on this chart behind a connection-sticky LB
- [use-case-corporate.md](use-case-corporate.md) - OIDC SSO and per-user
  certs, the config side of a corporate cluster deploy
- [Deployment in the README](../README.md#deployment) and
  [Observability](../README.md#observability)
- [addressing.md](addressing.md) - tunnel subnet defaults and overrides
