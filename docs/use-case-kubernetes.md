# Kubernetes

Not a profile - a deploy shape, and a walkthrough you follow top to bottom.
Each release publishes a Helm chart beside the image, at
`oci://ghcr.io/hyperi-io/charts/culvert`. The chart version is the release
version, so chart `X.Y.Z` deploys image `vX.Y.Z`. Nothing is cloned to
install it.

The chart runs one replica. The contract marks culvert a singleton, so it
renders a Recreate rollout, no autoscaler and no disruption budget. WireGuard
mints its server key inside the pod, and a second pod would issue client
configs the first rejects.

## 1. A namespace the pod is allowed in

The VPN data plane creates the tun device, programs routing and NAT, and sets
`net.ipv4.ip_forward`. That needs root, `NET_ADMIN` and the `/dev/net/tun` host
device, so a restricted-PodSecurity namespace rejects it. Give culvert its own
namespace at the privileged level:

```bash
kubectl create namespace vpn
kubectl label namespace vpn pod-security.kubernetes.io/enforce=privileged
```

## 2. Install

The chart renders the pod from culvert's contract and nothing more. The tun
device, `ip_forward`, the config file and the opt-in listeners all come from
values. Write this as `values.yaml`:

```yaml
# Mount `config` as the single file /etc/vpn/profiles/culvert.yaml, so the
# image's own profiles stay beside it. CULVERT_PROFILE makes culvert read it.
configMount:
  subPath: true

extraEnv:
  CULVERT_PROFILE: culvert
  CULVERT_SERVER_CN: vpn.example.com
  CULVERT_LOG_MODE: stdout

# /proc/sys is read-only inside a container, so ip_forward is set by a short
# privileged init container. It changes the pod's network namespace only.
initContainers:
  - name: enable-ip-forward
    image: '{{ include "scalo-service.image" . }}'
    command: [sysctl, -w, net.ipv4.ip_forward=1]
    securityContext:
      privileged: true
    resources:
      requests:
        cpu: 10m
        memory: 16Mi

# OpenVPN and WireGuard open /dev/net/tun.
extraVolumes:
  - name: tun
    hostPath:
      path: /dev/net/tun
      type: CharDevice
extraVolumeMounts:
  - name: tun
    mountPath: /dev/net/tun

# LoadBalancer Services for every port marked `public`.
publicService:
  enabled: true
  externalTrafficPolicy: Local

# Opt-in listeners. Keep the entries whose CULVERT_* switch you turn on.
extraPorts:
  - { name: openvpn-tcp, port: 1194, protocol: TCP, public: true }
  - { name: openvpn-https, port: 443, protocol: TCP, public: true }
  - { name: wg-https, port: 4443, protocol: TCP, public: true }
  - { name: oauth2-udp, port: 9000, protocol: TCP, public: true }
  - { name: oauth2-https, port: 9001, protocol: TCP, public: true }
  - { name: oauth2-tcp, port: 9002, protocol: TCP, public: true }
  - { name: client-download, port: 8443, protocol: TCP, public: true }
```

Then install the release you want. `helm show chart
oci://ghcr.io/hyperi-io/charts/culvert` prints the newest:

```bash
helm install culvert oci://ghcr.io/hyperi-io/charts/culvert \
  --version <release> -n vpn -f values.yaml
```

Four notes on the values:

- `config:` is written to `culvert.yaml`. Put anything you would put in a
  profile there. Without `CULVERT_PROFILE: culvert` the file is never read.
- `extraEnv` takes every `CULVERT_*` knob from [.env.example](../.env.example)
  that is not a secret. Secrets go in a Secret (see section 5).
- `image: '{{ include "scalo-service.image" . }}'` gives the init container the
  pod's own image, so it never drifts from the release.
- Helm replaces a list rather than merging it. A second values file that sets
  `extraVolumes` or `extraVolumeMounts` has to repeat the tun entries.

On a kubelet started with `--allowed-unsafe-sysctls net.ipv4.ip_forward` you can
drop the init container and set `podSecurityContext.sysctls` instead.

## 3. The PKI volume

The chart renders a `culvert-pki` PersistentVolumeClaim (1Gi, ReadWriteOnce)
by default and mounts it at `/etc/vpn/pki`. It holds the CA, the CRL and the
WireGuard peer allocations. Lose it and every issued client config stops
working, because the next start mints a new CA.

The claim names no StorageClass, so it takes the cluster default. On a cluster
with no default StorageClass the claim stays `Pending` and the pod waits on it.
Name one, or bring your own claim:

```yaml
writablePaths:
  pki:
    persistence:
      storageClass: fast-ssd   # or: existingClaim: my-pki
      size: 1Gi
```

`persistence.enabled: false` swaps the claim for an `emptyDir`. Every restart
then mints a new CA. Use it for a throwaway test and nothing else.

## 4. Expose and open listeners

The chart renders a ClusterIP Service for the pod: the metrics port `9090` and
every VPN port. `publicService.enabled` adds LoadBalancer Services for the
ports marked `public: true`:

- `culvert-public` carries the TCP ports and `culvert-public-udp` the UDP ones,
  because many clouds refuse one Service that mixes the two.
- The metrics port is not public, so the LoadBalancer never publishes `/livez`,
  `/readyz` or `/metrics`.
- `externalTrafficPolicy: Local` keeps the client's real source address, which
  per-client routing rules and the connection log need.

Pin the addresses clients dial with `publicService.loadBalancerIP` (TCP) and
`publicService.udpLoadBalancerIP` (UDP), and clamp who can reach them with
`publicService.loadBalancerSourceRanges`. Or leave `publicService` off and put
a Gateway API `UDPRoute` (or TLS passthrough for the HTTPS listeners) in front
of the ClusterIP Service.

OpenVPN over UDP (`1194/UDP`) is always on. Every other listener is two edits
that must agree: the `CULVERT_*` switch in `extraEnv`, and its `extraPorts`
entry so the port reaches the Service.

| Port name | Port | Switch | Notes |
|-----------|------|--------|-------|
| `openvpn-tcp` | 1194/TCP | `CULVERT_TCP_ENABLED=true` | TCP fallback |
| `openvpn-https` | 443/TCP | `CULVERT_HTTPS_ENABLED=true` | OpenVPN over HTTPS (stunnel) |
| `wg-https` | 4443/TCP | `CULVERT_WG_HTTPS_TUNNEL_ENABLED=true` | WireGuard over HTTPS (wstunnel) |
| `oauth2-udp` | 9000/TCP | `CULVERT_OAUTH2_ENABLED=true` | OIDC callback for the UDP listener |
| `oauth2-https` | 9001/TCP | `CULVERT_OAUTH2_ENABLED=true` | OIDC callback for the HTTPS listener |
| `oauth2-tcp` | 9002/TCP | `CULVERT_OAUTH2_ENABLED=true` | OIDC callback for the TCP listener |
| `client-download` | 8443/TCP | `CULVERT_CLIENT_DOWNLOAD_ENABLED=true` | Needs `CULVERT_CLIENT_DOWNLOAD_BIND=0.0.0.0` and a bearer token |

WireGuard is the exception. Set `config.protocol` to `wireguard` or `both` and
the chart opens `51820/UDP` itself, with no `extraPorts` entry.

## 5. OIDC and other secrets

The OIDC client secrets come from a Secret the chart reads by name,
`culvert-oauth2` unless `secrets.oauth2.existingSecret` says otherwise:

```bash
kubectl -n vpn create secret generic culvert-oauth2 \
  --from-literal=CULVERT_OAUTH2_CLIENT_SECRET=... \
  --from-literal=CULVERT_OAUTH2_HTTP_SECRET=...
```

Both keys are optional, so a server with OIDC off starts without the Secret.
The non-secret OIDC settings (`CULVERT_OAUTH2_ISSUER`, `CULVERT_OAUTH2_CLIENT_ID`
and the rest in [.env.example](../.env.example)) go in `extraEnv`. The callbacks
also need a TLS pair at `CULVERT_OAUTH2_TLS_CERT` and `CULVERT_OAUTH2_TLS_KEY`,
which are required while OIDC is on. Mount a Secret there with `extraVolumes`
and `extraVolumeMounts`.

Any other secret, such as the client-download token, comes in from a Secret too:

```yaml
extraEnv:
  CULVERT_CLIENT_DOWNLOAD_TOKEN:
    valueFrom:
      secretKeyRef:
        name: culvert-download
        key: token
```

`extraEnvFrom` loads a whole Secret as environment when you would rather.

## 6. External PKI

Production clusters generally do not want a self-generated CA. Set
`CULVERT_PKI_MODE=external` and point at one of:

- **File** - certs mounted from a Kubernetes Secret (or cert-manager) volume.
  `CULVERT_SECRETS_*_PATH` are file paths. The values below do this.
- **OpenBao** - Kubernetes auth exchanges the pod ServiceAccount token for a
  short-lived token, with no static secret in env.
- **AWS Secrets Manager** - use IRSA on EKS, with no static AWS keys.

For the file provider, create the Secret, then add this to `values.yaml`:

```bash
kubectl -n vpn create secret generic culvert-pki-external \
  --from-file=ca.crt --from-file=server.crt --from-file=server.key \
  --from-file=crl.pem --from-file=tc.key
```

```yaml
extraEnv:
  CULVERT_PKI_MODE: external
  CULVERT_SECRETS_PROVIDER: file
  CULVERT_SECRETS_CA_CERT_PATH: /etc/vpn/pki-external/ca.crt
  CULVERT_SECRETS_SERVER_CERT_PATH: /etc/vpn/pki-external/server.crt
  CULVERT_SECRETS_SERVER_KEY_PATH: /etc/vpn/pki-external/server.key
  CULVERT_SECRETS_CRL_PATH: /etc/vpn/pki-external/crl.pem
  CULVERT_SECRETS_TC_KEY_PATH: /etc/vpn/pki-external/tc.key

# These replace the lists from section 2, so they carry the tun entries too.
extraVolumes:
  - name: tun
    hostPath:
      path: /dev/net/tun
      type: CharDevice
  - name: pki-external
    secret:
      secretName: culvert-pki-external
      defaultMode: 0400
extraVolumeMounts:
  - name: tun
    mountPath: /dev/net/tun
  - name: pki-external
    mountPath: /etc/vpn/pki-external
    readOnly: true
```

`ca.crt`, `server.crt` and `server.key` are required. `crl.pem` and `tc.key` are
optional, so drop their paths if the Secret does not carry them. With no
`tc.key` the server mints its own tls-crypt-v2 key, and a client config only
works against the server that issued it.

Detail is in [External PKI in the README](../README.md#external-pki) and the
External PKI section of [.env.example](../.env.example).

## 7. Observe

- **Probes:** liveness `/livez`, readiness `/readyz` and a startup probe on
  `/livez`, all on the metrics port (`9090`). They are served always,
  independent of the metrics toggle.
- **Metrics:** the pod carries `prometheus.io/scrape`, `prometheus.io/port` and
  `prometheus.io/path` annotations. `/metrics` serves when
  `CULVERT_METRICS_ENABLED=true`.
- **Drain:** the container handles SIGTERM to drain connections on a rollout,
  inside a 30 second termination grace period.

## See also

- [use-case-edge-fleet.md](use-case-edge-fleet.md) - the hub-and-spoke fleet
  shape that runs on this chart
- [use-case-corporate.md](use-case-corporate.md) - OIDC SSO and per-user
  certs, the config side of a corporate cluster deploy
- [Deployment in the README](../README.md#deployment) and
  [Observability](../README.md#observability)
- [addressing.md](addressing.md) - tunnel subnet defaults and overrides
