# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.1.0] - Unreleased

### Added

- Open source launch of `hyperi-vpn`
- `HYPERI_VPN_PROFILE` environment variable loads site-specific
  YAML profiles
- Shipped `profiles/dfe.yaml` as reference profile for HyperI DFE
  deployments
- `HYPERI_VPN_ORG_NAME` configuration field drives generic CA naming
  (`<org> VPN CA`); explicit `ca_cn` still wins
- Config validation: `HYPERI_VPN_STUNNEL_CERT` and `_STUNNEL_KEY`
  required when the HTTPS listener is enabled
- OSS metadata: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `AI-TRAINING-POLICY.md`, `COMMERCIAL.md`, GitHub issue and PR
  templates

### Changed

- Renamed from private `dfe-vpn` project. Config prefix
  `DFE_VPN_*` → `HYPERI_VPN_*` (clean break, no aliases)
- Default `ca_cn` now derives from `org_name` (empty → `"VPN CA"`)
- Default `server_cn` no longer set — must be explicitly configured
- Default `stunnel_cert` / `stunnel_key` no longer set — must be
  explicitly configured when HTTPS listener enabled
- OIDC log strings genericised: `"Entra ID"` → `"OIDC"`
- `.ovpn` and stunnel client headers: `"DFE VPN"` → `"HyperI VPN"`
- OAuth2 login page CSS branded `"HyperI VPN"` (was `"DFE VPN"`)
- Dockerfile simplified: removed internal Artifactory fallback, pulls
  `openvpn-auth-oauth2` and `wstunnel` directly from upstream GitHub
  releases
- Dockerfile labels updated for public release (GHCR source,
  FSL-1.1-ALv2 licence)
- `hyperi-pylib` pinned to `>=2.25,<3`

### Removed

- `DFE_VPN_*` environment variable prefix (migrate to `HYPERI_VPN_*`)
- Internal `REGISTRY`, `ARTIFACTORY_USER`, `ARTIFACTORY_TOKEN` build
  args and secret mounts from the Dockerfile
- Internal Artifactory steps from CI workflows
- Generated `config/*.conf` artefacts (now gitignored)
- Internal HyperI hostnames, subnets, and proxmox/tyrell references
  from docs and examples

### Notes

- Prior history lives in the archived private `dfe-vpn` repository
  (not publicly accessible)
- Versioning continues from the `dfe-vpn` v2.x line as a +0.1 feature
  release
