# CI/CD Environment Configuration

This document describes the environment variables, secrets, and
configuration required for the culvert CI/CD pipeline.

## Build Configuration

| Variable | Value | Description |
|----------|-------|-------------|
| `IMAGE_NAME` | `ghcr.io/hyperi-io/culvert` | Full image name |
| `BUILD_PLATFORMS` | `linux/amd64,linux/arm64` | Multi-arch targets |

## GitHub Actions Secrets (Required)

Configure these in **Settings -> Secrets and variables -> Actions -> Secrets**:

| Secret | Description |
|--------|-------------|
| `GH_APP_PRIVATE_KEY` | GitHub App private key (PEM format) |

The GitHub App is identified by the `GH_APP_CLIENT_ID` repository *variable*
(Settings -> Variables), not a secret - the App token is minted from the
client ID, not the numeric App ID.

`GITHUB_TOKEN` is provided automatically by GitHub Actions and is used
for GHCR login during publish.

## GitHub Actions Variables (Optional)

Configure these in **Settings -> Secrets and variables -> Actions -> Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `GH_RUNNER_DEFAULT` | `ubuntu-latest` | Default runner for jobs |

## Local Development

```bash
# Build development image
docker build -t culvert:dev .

# Run unit tests locally
uv run pytest tests/unit/ -q
```

## Workflow Triggers

There are two workflows: `ci.yml` (the main pipeline, delegating to the shared
hyperi-ci reusable workflow) and `dependency-check.yml` (weekly upstream-version
checks). Publishing is gated - see the push-to-main rows.

| Trigger | Action |
|---------|--------|
| Pull request to main | Full pipeline: lint, test, container build (no push) |
| Push to main, no `Publish: true` trailer | Validate-only: no tag, no publish |
| Push to main with a `Publish: true` trailer | Semantic-release -> multi-arch build -> push to GHCR |
| `workflow_dispatch` (`from-head=true`) | Same publish path, triggered by hand |
| Dependency Check (weekly, Mon 09:00 UTC) | Check for new upstream versions, open PR |

## Image Tags

| Tag | Description |
|-----|-------------|
| `vX.Y.Z` | Semantic version (immutable) |
| `latest` | Most recent release |

## Vendored Dependencies

Third-party binaries are pulled directly from upstream GitHub releases
during image build. See [supply-chain.md](supply-chain.md) for the full
list and versions.
