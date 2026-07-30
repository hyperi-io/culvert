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
| `scalo` (HyperI-own) | PyPI | image installs `==2.29.11` from the hash-pinned `requirements-docker.txt`; source range is `>=2.29.11,<3`; ships immediately (no cooldown); `uv.lock` pins the dev/CI tree with hashes |

External dependencies track "latest stable released at least 7 days ago"
-- the org `minimumReleaseAge` cooldown, a buffer against fresh-release
regressions and the supply-chain attack window. HyperI-own packages
(`scalo`) are exempt and track latest, per the supply-chain
cooldown policy in the org standards.

No private registries or mirrors are used for the public image. If you
operate in an air-gapped environment, fork and add your own registry
mirror logic.

## What is verified at build time

Each of these is enforced by the build, which fails closed if the check
does not pass:

- **Base image** is pinned by `sha256` digest, not by tag.
- **`openvpn-auth-oauth2` and `wstunnel`** are fetched over HTTPS from the
  upstream GitHub release and checked against a `sha256` pinned per
  architecture in the `Dockerfile`.
- **The OpenVPN APT repository key** is checked to be EXACTLY one primary
  key whose fingerprint is the pinned one. Requiring a single `pub` record
  rather than grepping for ours means a compromised endpoint serving the
  real key alongside an attacker's key is rejected rather than accepted.
- **The installed OpenVPN version** is checked against
  `ARG OPENVPN_MIN_VERSION` with `dpkg --compare-versions`. The server
  config depends on 2.7 behaviour, so an older package aborts the build.
- **Python dependencies** are installed from `requirements-docker.txt`,
  which pins every package to an exact version with hashes.

**Not** verified: the image carries no provenance attestation. Nothing in
the release pipeline generates one today, so there is no signature or
SLSA statement to check a pulled image against - only the digest you
pulled and the labels below. If you need attested provenance, build the
image yourself from a tagged commit.

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
