# Supply Chain

All third-party binaries are pulled directly from their upstream
GitHub releases during image build:

| Dependency | Source | Pinned version |
|------------|--------|----------------|
| Base image | `ubuntu:24.04` | pinned by `sha256` digest in `BASE_IMAGE` |
| `openvpn-auth-oauth2` | [github.com/jkroepke/openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) | `1.28.3`, `sha256`-verified per arch |
| `wstunnel` | [github.com/erebe/wstunnel](https://github.com/erebe/wstunnel) | `10.6.2`, `sha256`-verified per arch |
| `openvpn` (server) | [build.openvpn.net](https://build.openvpn.net) (official APT repo) | stable channel, 2.7.x+ |
| `easy-rsa` | Ubuntu archive | System package (from digest-pinned base) |
| `stunnel4` | Ubuntu archive | System package (from digest-pinned base) |
| `scalo` (HyperI-own) | PyPI | `==2.29.11`; ships immediately (no cooldown); `uv.lock` pins the dev/CI tree with hashes |

External dependencies track "latest stable released at least 7 days ago"
-- the org `minimumReleaseAge` cooldown, a buffer against fresh-release
regressions and the supply-chain attack window. HyperI-own packages
(`scalo`) are exempt and track latest, per the supply-chain
cooldown policy in the org standards.

No private registries or mirrors are used for the public image. If you
operate in an air-gapped environment, fork and add your own registry
mirror logic.

## Verification

Each dependency's release artefact is fetched via HTTPS from GitHub and
installed into the image. Image provenance is published via GHCR's
attestation features when released.

Check image labels for source and version:

```bash
docker inspect ghcr.io/hyperi-io/culvert:latest \
  --format '{{json .Config.Labels}}' | jq
```

## Version Pinning

All dependencies are version-pinned in `Dockerfile` ARGs, and the
downloaded binaries are `sha256`-verified per architecture before
install:

```dockerfile
ARG BASE_IMAGE="ubuntu:24.04@sha256:..."   # base image pinned by digest
ARG OPENVPN_AUTH_OAUTH2_VERSION="1.28.3"   # + SHA256_AMD64 / SHA256_ARM64
ARG WSTUNNEL_VERSION="10.6.2"              # + SHA256_AMD64 / SHA256_ARM64
```

## Updating Dependencies

Bump a version ARG in `Dockerfile`, commit with conventional-commit
prefix (`fix:` for patch, `feat:` for minor), push to `main`. The CI
pipeline runs semantic-release and - if the commit list produces a
version bump - publishes a new image.

For CVE-driven updates, prefer `sec:` as the commit type to flag the
intent.

## Multi-Architecture Support

Published images are multi-arch manifests for `linux/amd64` and
`linux/arm64`. Docker selects the correct architecture automatically.
