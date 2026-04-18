# Supply Chain

All third-party binaries are pulled directly from their upstream
GitHub releases during image build:

| Dependency | Source | Pinned version |
|------------|--------|----------------|
| `openvpn-auth-oauth2` | [github.com/jkroepke/openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) | `${OPENVPN_AUTH_OAUTH2_VERSION}` in Dockerfile |
| `wstunnel` | [github.com/erebe/wstunnel](https://github.com/erebe/wstunnel) | `${WSTUNNEL_VERSION}` in Dockerfile |
| `openvpn` (server) | [build.openvpn.net](https://build.openvpn.net) (official APT repo) | Ubuntu LTS default, 2.6.x+ |
| `easy-rsa` | Ubuntu archive | System package |
| `stunnel4` | Ubuntu archive | System package |
| `hyperi-pylib` | PyPI | `>=2.25,<3` |

No private registries or mirrors are used for the public image. If you
operate in an air-gapped environment, fork and add your own registry
mirror logic.

## Verification

Each dependency's release artefact is fetched via HTTPS from GitHub and
installed into the image. Image provenance is published via GHCR's
attestation features when released.

Check image labels for source and version:

```bash
docker inspect ghcr.io/hyperi-io/hyperi-vpn:latest \
  --format '{{json .Config.Labels}}' | jq
```

## Version Pinning

All dependencies are version-pinned in `Dockerfile` ARGs:

```dockerfile
ARG OPENVPN_AUTH_OAUTH2_VERSION="1.26.0"
ARG WSTUNNEL_VERSION="10.5.2"
```

## Updating Dependencies

Bump a version ARG in `Dockerfile`, commit with conventional-commit
prefix (`fix:` for patch, `feat:` for minor), push to `main`. The CI
pipeline runs semantic-release and — if the commit list produces a
version bump — publishes a new image.

For CVE-driven updates, prefer `sec:` as the commit type to flag the
intent.

## Multi-Architecture Support

Published images are multi-arch manifests for `linux/amd64` and
`linux/arm64`. Docker selects the correct architecture automatically.
