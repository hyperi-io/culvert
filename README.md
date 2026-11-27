# <img src="assets/brand/product-culvert/tertiary/product-culvert_square.svg" alt="Culvert icon" width="40"> Culvert

OpenVPN and WireGuard in one container, with OpenVPN reachable over HTTPS and OIDC sign-in.

## What it does

- The VPN server that installs as a container: `docker run` it on one host, or install the Helm chart. In a DFE deployment it is the edge-fleet VPN, the door an appliance dials before it posts to dfe-receiver.
- OpenVPN on UDP or TCP and WireGuard, alone or both at once.
- Either protocol wrapped in TLS on a web port: stunnel for OpenVPN on TCP 443 and wstunnel for WireGuard on TCP 4443 by default. A network that lets out HTTPS on 443 alone passes the OpenVPN tunnel, and the WireGuard one once its port is moved or opened.
- OIDC sign-in on OpenVPN with Microsoft Entra ID, Google Workspace, Okta, Keycloak, Auth0 or any other OIDC provider, through [openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2). WireGuard uses keys.
- PKI from file mounts, OpenBao or Vault, or AWS Secrets Manager, with a self-generated Easy-RSA CA when you bring none.
- TLS 1.3 only, AES-256-GCM, SHA-384 and P-384 on the OpenVPN path, the CNSA 2.0 classical suite ([docs/cryptography.md](docs/cryptography.md)).
- Prometheus `/metrics` and OTLP export, `/livez` and `/readyz`, a drain on SIGTERM and cgroup-aware resource detection. Images for `linux/amd64` and `linux/arm64`.

Culvert is a classic hub VPN server you run yourself, one image with no management plane and no per-user fees. Coming from something else?

| If you use | What you gain with Culvert |
|------------|----------------------------|
| [AWS Client VPN](https://aws.amazon.com/vpn/) | Flat cost of a node instead of per-subnet-association plus per-connection charges. Adds WireGuard, any-IdP OIDC, and the HTTPS-tunnelled listeners. You lose the managed control plane. |
| [kylemanna/docker-openvpn](https://github.com/kylemanna/docker-openvpn) | Appears unmaintained since 2020 and its image ships OpenVPN 2.4. Culvert is a maintained alternative: OpenVPN 2.7 with DCO, plus everything above. |
| [angristan/openvpn-install](https://github.com/angristan/openvpn-install) | Same result without a host-mutating bash script: the server is an image, config is env vars, upgrades are a `docker pull`. |
| [OpenVPN Access Server](https://openvpn.net/access-server/) | No per-connection licensing. Culvert adds WireGuard and provider-neutral OIDC. |
| [wg-easy](https://github.com/wg-easy/wg-easy) | Keep the WireGuard simplicity, add OpenVPN for the clients that need it, external PKI, and either protocol over HTTPS. wg-easy's OAuth signs users into its web UI, and Culvert's OIDC gates the VPN session itself. |

## Quick start

The default is the simplest working server: OpenVPN over UDP, local PKI, nothing else.

```bash
docker run -d \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194/udp \
  -p 127.0.0.1:9090:9090/tcp \
  -e CULVERT_SERVER_CN=vpn.yourdomain.example \
  -v culvert-pki:/etc/vpn/pki \
  -v culvert-clients:/etc/vpn/clients \
  ghcr.io/hyperi-io/culvert:latest
```

Then mint a client and hand it the file it writes into the `culvert-clients` volume, over a channel you trust, because the `.ovpn` embeds the private key:

```bash
docker exec -it <container> generate-client --name zaphod
docker exec -it <container> generate-client --status   # CURRENT, STALE or UNKNOWN per client, non-zero exit on either of the last two
docker exec -it <container> revoke-client zaphod        # access ends here, not when the file goes
```

The `culvert-pki` volume holds the CA that signs every OpenVPN client and the WireGuard server key. Back it up and keep it private: losing it invalidates every issued config, and leaking the CA key lets someone else issue OpenVPN certificates. A client name cannot end in `-proxy`, because `generate-client --proxy` writes `<name>-proxy-stunnel.conf`.

One identity covers Zaphod's devices at once: OpenVPN shares the certificate across sessions, and WireGuard gets one peer per device slot (`CULVERT_SHARED_CLIENT_SLOTS`). Set `CULVERT_ALLOW_SHARED_CLIENTS=false` to hold each credential to one connection at a time. WireGuard slots issued before the change keep connecting until you revoke the client. The client side, provider by provider, is [docs/vpn-client-setup.md](docs/vpn-client-setup.md).

Everything else is an opt-in, each on a separate port:

| Capability | Enable with | Port |
|------------|-------------|------|
| WireGuard (alongside or instead) | `CULVERT_PROTOCOL=both` (or `wireguard`) | `51820/udp` |
| TCP fallback listener | `CULVERT_TCP_ENABLED=true` | `1194/tcp` |
| OpenVPN over HTTPS | `CULVERT_HTTPS_ENABLED=true` + stunnel certs | `443/tcp` |
| WireGuard over HTTPS | `CULVERT_WG_HTTPS_TUNNEL_ENABLED=true` + the same certs | `4443/tcp` |
| OIDC SSO | `CULVERT_OAUTH2_ENABLED=true` + IdP config | `9000-9002/tcp` |
| Prometheus metrics | `CULVERT_METRICS_ENABLED=true` | on `9090/tcp` |

## Configuration

Everything is a `CULVERT_*` environment variable, read through [scalo](https://pypi.org/project/scalo/)'s cascade (env, `.env`, a profile, `settings.{env}.yaml`, `settings.yaml`, `defaults.yaml`, built-in). [.env.example](.env.example) documents the common variables with example values. `CULVERT_ORG_NAME=Acme` names the self-generated CA `Acme VPN CA`.

A profile is a YAML of site defaults under `profiles/`, loaded with `CULVERT_PROFILE=<name>` (the shipped ones live at `/etc/vpn/profiles/` in the image, so the bare name works), and an explicit env var always wins over it. Four shipped profiles have a walkthrough, and `example` is a placeholder template to copy:

| Profile | Use case | Walkthrough |
|---------|-------|-------------|
| `home` | OpenVPN UDP, split tunnel, local PKI: reach your home LAN or a lab VM | [docs/use-case-home.md](docs/use-case-home.md) |
| `corporate` | Per-user certs, OIDC SSO, group gating, TCP fallback, clean offboarding | [docs/use-case-corporate.md](docs/use-case-corporate.md) |
| `travel` | OpenVPN and WireGuard over HTTPS, for networks that only pass web traffic | [docs/use-case-travel.md](docs/use-case-travel.md) |
| `edge-fleet` | An EdgeStream Hub appliance fleet streaming to a central receiver, reverse admin down the tunnels, CGNAT addressing | [docs/use-case-edge-fleet.md](docs/use-case-edge-fleet.md) |

Kubernetes has no profile but has a walkthrough: [docs/use-case-kubernetes.md](docs/use-case-kubernetes.md), the chart at `oci://ghcr.io/hyperi-io/charts/culvert`, one replica, assembled from [deploy/deployment-contract.json](deploy/deployment-contract.json) on the scalo-service library chart.

External PKI keeps the CA key at your CA, so Culvert neither signs nor revokes OpenVPN client certificates. Issue one there, place it at `pki/issued/<name>.crt` and `pki/private/<name>.key`, and run `generate-client --config-only --name <name>`. Revoke at the CA, and the refresh from `CULVERT_SECRETS_CRL_PATH` ends the session.

One listener (`CULVERT_METRICS_ADDR`, default `0.0.0.0:9090`) serves `/livez`, `/readyz` and, with `CULVERT_METRICS_ENABLED=true`, `/metrics`. OTLP push needs metrics on as well, then `CULVERT_OTEL_ENABLED=true` and `CULVERT_OTEL_ENDPOINT`. Point a `startupProbe` at `/livez`: Kubernetes suspends liveness until it passes, so one path covers a generous boot and a tight liveness period.

Two metrics earn an alert. `vpn_crl_seconds_until_expiry` goes negative once the CRL expires, and OpenVPN then rejects every client, valid ones included, with `certificate expired`. The auto-refresh keeps it topped up, so a falling value means the refresh is failing. A refresh that does not rewrite the CRL logs a warning, one that raises logs `CRL refresh error` at error, and under 7 days of CRL life left logs at error. `vpn_wireguard_endpoint_flaps_total{peer}` counts a peer's endpoint returning to an address it left within 10 minutes: a roaming phone moves once and stays, and a key loaded on two devices makes them take turns. Culvert logs a warning naming the peer and both addresses.

## Documentation, help and licence

- [docs/architecture.md](docs/architecture.md): what runs inside culvert and what it talks to, what it depends on, and why it's one container.
- [docs/addressing.md](docs/addressing.md): why the tunnels default to `10.8.0.0/22`, and when to use the CGNAT range.
- [docs/cryptography.md](docs/cryptography.md): the CNSA 2.0 classical suite, and what is not there yet.
- [docs/performance.md](docs/performance.md): throughput, DCO and the cipher choice.
- [docs/supply-chain.md](docs/supply-chain.md): how the image is built and pinned.
- [CHANGELOG.md](CHANGELOG.md): releases follow SemVer, published to GHCR as multi-arch images.

The suite's published docs are at <https://dfe.docs.hyperi.io>, and this repository's pages at <https://dfe.docs.hyperi.io/culvert/>.

How to work in this repo, the commands that prove a change and what tends to bite are in [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go to the [security policy](https://github.com/hyperi-io/culvert/security/policy), and community expectations are the [code of conduct](https://github.com/hyperi-io/.github/blob/main/.github/CODE_OF_CONDUCT.md).

Open bugs: [this repo](https://github.com/hyperi-io/culvert/issues?q=is%3Aopen+is%3Aissue+type%3ABug+-label%3Abacklog+-label%3Anext-minor) | [whole DFE suite](https://github.com/search?type=issues&q=is%3Aopen+is%3Aissue+type%3ABug+-label%3Abacklog+-label%3Anext-minor+repo%3Ahyperi-io%2Fdfe-infra+repo%3Ahyperi-io%2Fdfe-docker+repo%3Ahyperi-io%2Fdfe-deploy+repo%3Ahyperi-io%2Fdfe-engine+repo%3Ahyperi-io%2Fdfe-loader+repo%3Ahyperi-io%2Fdfe-receiver+repo%3Ahyperi-io%2Fdfe-fetcher+repo%3Ahyperi-io%2Fdfe-archiver+repo%3Ahyperi-io%2Fdfe-transform-vrl+repo%3Ahyperi-io%2Fdfe-transform-vector+repo%3Ahyperi-io%2Fdfe-transform-elastic+repo%3Ahyperi-io%2Fdfe-ui+repo%3Ahyperi-io%2Fdfe-hyperdx+repo%3Ahyperi-io%2Fscalo-rs+repo%3Ahyperi-io%2Fscalo-py+repo%3Ahyperi-io%2Flogreducer+repo%3Ahyperi-io%2Fdfe-schemas+repo%3Ahyperi-io%2Fvector-vrl+repo%3Ahyperi-io%2Fculvert+repo%3Ahyperi-io%2Fdfe-clickhouse-rs+repo%3Ahyperi-io%2Ffactbook-rs)

[Apache-2.0](LICENSE). Third-party components bundled in the container image are listed in [NOTICE](NOTICE) with their licences.
