# CI/CD Environment Configuration

The secrets and variables the culvert pipeline reads, the triggers that run it, and the tags it publishes.

## Build configuration

`.hyperi-ci.yaml` carries it. The image is `ghcr.io/hyperi-io/culvert`, built from `Dockerfile` for `linux/amd64` and `linux/arm64` on a release, and for amd64 alone on a pull request.

## Secrets and variables

| Name | Kind | What reads it |
|------|------|---------------|
| `GH_APP_PRIVATE_KEY` | Secret, org or repo | The release tags as the GitHub App. Optional: without it the release tags as `github-actions`, cannot bypass required checks, and its push triggers no workflows |
| `GH_APP_CLIENT_ID` | Variable, org or repo | Identifies the App. The token is minted from the client ID, not the numeric App ID |
| `GH_RUNNER_DEFAULT` | Variable, optional | The runner for `dependency-check.yml`, `ubuntu-latest` when unset. `ci.yml` passes `runner-mode: free`, so its jobs run on GitHub-hosted runners whatever this says |

`GITHUB_TOKEN` is provided by GitHub Actions and logs in to GHCR during publish.

## Local development

```bash
# Build development image
docker build -t culvert:dev .

# Run unit tests locally
uv run pytest tests/unit/ -q
```

## Workflow triggers

There are two workflows: `ci.yml` (the main pipeline, delegating to the shared hyperi-ci reusable workflow) and `dependency-check.yml` (weekly upstream-version checks). Publishing is gated, as the push-to-main rows show.

| Trigger | Action |
|---------|--------|
| Pull request to main | Full pipeline: lint, test, container build (no push) |
| Push to main, no `Release: true` trailer | Validate-only: no tag, no publish |
| Push to main with a `Release: true` trailer | Semantic-release -> multi-arch build -> push to GHCR |
| `workflow_dispatch` (`from-head=true`) | Same publish path, triggered by hand |
| Dependency Check (weekly, Mon 09:00 UTC) | Check for a new `openvpn-auth-oauth2` release, open PR |

A release pushes the image as `vX.Y.Z`, `latest` and `sha-<first 8 hex of the commit>`, and the Helm chart as `oci://ghcr.io/hyperi-io/charts/culvert` at `X.Y.Z`. [supply-chain.md](supply-chain.md) lists where each third-party binary comes from.
