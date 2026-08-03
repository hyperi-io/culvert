# Changelog

Rendered by CI and committed back at the end of a release -- do not edit by
hand. Release notes also appear on the GitHub Releases page, one per tag.

## [2.1.11](https://github.com/hyperi-io/culvert/compare/v2.1.10...v2.1.11) (2026-08-03)

## [2.1.10](https://github.com/hyperi-io/culvert/compare/v2.1.9...v2.1.10) (2026-08-03)

## [2.1.9](https://github.com/hyperi-io/culvert/compare/v2.1.8...v2.1.9) (2026-08-03)

## [2.1.8](https://github.com/hyperi-io/culvert/compare/v2.1.7...v2.1.8) (2026-08-03)

## [2.1.7](https://github.com/hyperi-io/culvert/compare/v2.1.6...v2.1.7) (2026-08-03)

## [2.1.6](https://github.com/hyperi-io/culvert/compare/v2.1.5...v2.1.6) (2026-08-03)

## [2.1.5](https://github.com/hyperi-io/culvert/compare/v2.1.4...v2.1.5) (2026-08-02)

# Changelog

Notable changes, by release. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

Per-commit release notes are generated from the conventional-commit history and
published on the [GitHub releases page](https://github.com/hyperi-io/culvert/releases).
This file is the human summary of what changed and why it matters; it is not a
second copy of that log.

## [Unreleased]

### Changed

- Renamed from `hyperi-vpn` to `culvert`, relicensed BUSL-1.1 -> Apache-2.0, and
  published as a general-consumption container image
- Runs on [scalo](https://pypi.org/project/scalo/) (Apache-2.0) for its config
  cascade, logging, observability server and deployment contract
- **Probe surface is now `/livez`, `/readyz` and `/metrics` only.** `/healthz`
  and every `/health/*` alias were retired upstream and return 404. Update any
  probe, monitor or chart that referenced the old names
- WireGuard-over-HTTPS configuration renamed from `CULVERT_WG_DPI_BYPASS_*` to
  `CULVERT_WG_HTTPS_TUNNEL_*`, and the generated client files from
  `*-wg-dpi-*.conf` to `*-wg-https-*.conf`
- Product described as a VPN that travels over HTTPS rather than specifically as
  DPI bypass - censorship circumvention is one use of that, not the definition

### Fixed

- The Helm chart could not start OpenVPN: it granted only `NET_ADMIN`, and
  OpenVPN's privilege drop to `user nobody` also needs `SETUID`, `SETGID` and
  `SETPCAP`
- Kubernetes pods forwarded no client traffic, because `/proc/sys` is read-only
  in a container and nothing could enable `net.ipv4.ip_forward`. A privileged
  init container now does, on any cluster
- The server pushed `block-outside-dns` to every client. It is Windows-only, and
  an OpenVPN 2.7 client rejects the whole pushed option set over it, so no
  current Linux or macOS client could establish a full tunnel
- External PKI rejected certificates written by Easy-RSA or `openssl x509`,
  because the PEM check required the file to begin with the BEGIN line
- Issuing a WireGuard client did not add the peer to the running server, so the
  new client could not connect until the container was restarted
- WireGuard client traffic was never masqueraded, so it left the server with its
  tunnel source address and went nowhere
- `values-edge-fleet.yaml` shipped an unrestricted LoadBalancer, publishing the
  unauthenticated observability port, and could not render at all

### Added

- `pkiSecret` in the Helm chart mounts external PKI material from a Secret,
  which makes the documented file-based external-PKI path usable on Kubernetes
- `CULVERT_SECRETS_TC_KEY_PATH` shares the tls-crypt-v2 server key, which is
  what allows more than one replica to serve the same clients. The chart refuses
  a multi-replica install without it rather than failing at random in production
- `service.loadBalancerIP`, `sessionAffinity` and `externalTrafficPolicy` in the
  chart, with all four LoadBalancer knobs documented in `values.yaml`

## [2.1.0] - 2026-07-22

### Added

- Initial public release of `culvert`
- Default server is OpenVPN UDP-only; TCP, HTTPS/stunnel, WireGuard, and
  the WireGuard bypass are opt-in. Every listener uses a distinct subnet,
  so any combination can run together without collision (validated)
- `CULVERT_PROFILE` environment variable loads site-specific
  YAML profiles
- Shipped `profiles/example.yaml` as a reference site profile template
- `CULVERT_ORG_NAME` configuration field drives generic CA naming
  (`<org> VPN CA`); explicit `ca_cn` still wins
- Config validation: `CULVERT_STUNNEL_CERT` and `_STUNNEL_KEY`
  required when the HTTPS listener is enabled
- OSS metadata: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `NOTICE`, GitHub issue and PR templates

### Changed

- All configuration uses the `CULVERT_*` environment prefix
- Default `ca_cn` now derives from `org_name` (empty -> `"VPN CA"`)
- Default `server_cn` no longer set - must be explicitly configured
- Default `stunnel_cert` / `stunnel_key` no longer set - must be
  explicitly configured when the HTTPS listener is enabled
- OIDC log strings genericised: `"Entra ID"` -> `"OIDC"`
- Client config headers and OAuth2 login page branded `"Culvert"`
- Dockerfile pulls `openvpn-auth-oauth2` and `wstunnel` directly from
  upstream GitHub releases
- Dockerfile labels for public release (GHCR source, Apache-2.0 licence)
- Python runtime library pinned to a compatible major range

### Removed

- Internal build args, registry fallbacks, and CI steps
- Generated `config/*.conf` artefacts (now gitignored)
- Internal hostnames, subnets, and infrastructure references from docs
  and examples

### Notes

- Releases follow SemVer and publish to GHCR as multi-arch images
