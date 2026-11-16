# Supply Chain

Where every third-party piece of the image comes from, what the build checks, and what it does not. The `Dockerfile` pins and checks each one at build time:

| Dependency | Source | Pinned version |
|------------|--------|----------------|
| Base image | `ubuntu` | tag and `sha256` digest in `BASE_IMAGE` |
| `openvpn-auth-oauth2` | [github.com/jkroepke/openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) release `.deb` | `OPENVPN_AUTH_OAUTH2_VERSION`, `sha256`-verified per arch |
| `wstunnel` | [github.com/erebe/wstunnel](https://github.com/erebe/wstunnel) release tarball | `WSTUNNEL_VERSION`, `sha256`-verified per arch |
| `openvpn` (server) | [build.openvpn.net](https://build.openvpn.net) (official APT repo) | stable channel, at least `OPENVPN_MIN_VERSION` |
| `easy-rsa`, `stunnel4`, `iptables`, `wireguard-tools` | Ubuntu archive | not pinned: whatever the archive serves for the base image's release at build time |
| Python packages, `scalo` included | PyPI | the exact versions and hashes in `requirements-docker.txt`, an export of `uv.lock` |

External dependencies track the latest stable release that is at least 7 days old: the `minimumReleaseAge` cooldown in the org Renovate preset, a buffer against fresh-release regressions and the supply-chain attack window. HyperI's packages (`scalo`) are exempt from the cooldown and track latest. `openvpn-auth-oauth2` moves through `dependency-check.yml`, which proposes the next version and both checksums as a PR.

Published images are multi-arch manifests for `linux/amd64` and `linux/arm64`, set in `.hyperi-ci.yaml`. No private registries or mirrors are used for the public image. In an air-gapped environment, fork and add a registry mirror.

## What is verified at build time

The build fails closed when any of these does not hold:

- The base image resolves through its `sha256` digest, so the tag beside it cannot move what is pulled.
- `openvpn-auth-oauth2` and `wstunnel` are fetched over HTTPS from the upstream GitHub release and checked against a `sha256` pinned per architecture in the `Dockerfile`.
- The OpenVPN APT repository key must be EXACTLY one primary key, with the pinned fingerprint. Requiring a single `pub` record rather than grepping for ours means a compromised endpoint serving the pinned key alongside an attacker's key is rejected.
- The installed OpenVPN version is checked against `ARG OPENVPN_MIN_VERSION` with `dpkg --compare-versions`. The server config depends on 2.7 behaviour, so an older package aborts the build.
- Python dependencies install from `requirements-docker.txt` with `--require-hashes`, so a package that differs from its recorded hash fails the build.

What is NOT verified: the image is unsigned. Each platform has BuildKit's SLSA provenance attestation and no SBOM, and nothing signs either, so the provenance tells you how the image says it was built rather than proving it. If you need signed provenance, build the image yourself from a tagged commit and sign it.

Read the provenance and the labels of a release:

```bash
docker buildx imagetools inspect ghcr.io/hyperi-io/culvert:vX.Y.Z --format '{{json .Provenance}}'
docker buildx imagetools inspect ghcr.io/hyperi-io/culvert:vX.Y.Z \
  --format '{{json (index .Image "linux/amd64").Config.Labels}}'
```

To update a dependency, bump a version ARG and its checksums in the `Dockerfile`, and commit with a conventional-commit prefix (`fix:` for patch, `feat:` for minor). A security fix is `fix(security):`. Merging to `main` validates the change but does not ship it: publishing needs a `Release: true` trailer on the head commit, or a manual `workflow_dispatch` with `from-head=true`. [ci-environment.md](ci-environment.md) has the trigger table.
