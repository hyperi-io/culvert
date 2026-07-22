# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.1.0] - Unreleased

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
- Default `ca_cn` now derives from `org_name` (empty → `"VPN CA"`)
- Default `server_cn` no longer set — must be explicitly configured
- Default `stunnel_cert` / `stunnel_key` no longer set — must be
  explicitly configured when the HTTPS listener is enabled
- OIDC log strings genericised: `"Entra ID"` → `"OIDC"`
- Client config headers and OAuth2 login page branded `"Culvert"`
- Dockerfile pulls `openvpn-auth-oauth2` and `wstunnel` directly from
  upstream GitHub releases
- Dockerfile labels for public release (GHCR source, Apache-2.0 licence)
- `hyperi-pylib` pinned to `>=2.25,<3`

### Removed

- Internal build args, registry fallbacks, and CI steps
- Generated `config/*.conf` artefacts (now gitignored)
- Internal hostnames, subnets, and infrastructure references from docs
  and examples

### Notes

- Releases follow SemVer and publish to GHCR as multi-arch images
