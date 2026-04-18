# CI/CD Environment Configuration

This document describes the environment variables, secrets, and
configuration required for the hyperi-vpn CI/CD pipeline.

## Build Configuration

| Variable | Value | Description |
|----------|-------|-------------|
| `IMAGE_NAME` | `ghcr.io/hyperi-io/hyperi-vpn` | Full image name |
| `BUILD_PLATFORMS` | `linux/amd64,linux/arm64` | Multi-arch targets |

## GitHub Actions Secrets (Required)

Configure these in **Settings → Secrets and variables → Actions → Secrets**:

| Secret | Description |
|--------|-------------|
| `GH_APP_ID` | GitHub App ID for semantic-release |
| `GH_APP_PRIVATE_KEY` | GitHub App private key (PEM format) |

`GITHUB_TOKEN` is provided automatically by GitHub Actions and is used
for GHCR login during publish.

## GitHub Actions Variables (Optional)

Configure these in **Settings → Secrets and variables → Actions → Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `GH_RUNNER_DEFAULT` | `ubuntu-latest` | Default runner for jobs |

## Local Development

```bash
# Build development image
docker build -t hyperi-vpn:dev .

# Run unit tests locally
uv run pytest tests/unit/ -q
```

## Workflow Triggers

| Workflow | Trigger | Action |
|----------|---------|--------|
| CI | Push/PR to main | Lint, build (no push), test |
| Release | Push to main | Semantic-release → multi-arch build → push to GHCR |
| Dependency Check | Weekly (Mon 09:00 UTC) | Check for new upstream versions, open PR |

## Image Tags

| Tag | Description |
|-----|-------------|
| `vX.Y.Z` | Semantic version (immutable) |
| `latest` | Most recent release |

## Vendored Dependencies

Third-party binaries are pulled directly from upstream GitHub releases
during image build. See [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) for the full
list and versions.
