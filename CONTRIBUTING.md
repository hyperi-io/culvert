# Contributing

We welcome contributions to this project. By contributing, you agree to the
terms outlined below.

## Commit Message Format

HyperI projects use [Conventional Commits](https://www.conventionalcommits.org/)
and [semantic-release](https://semantic-release.gitbook.io/) for automated
versioning and changelog generation. All commits must follow this format:

```text
<type>(<scope>): <subject>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | A new feature | Minor (0.X.0) |
| `fix` | A bug fix | Patch (0.0.X) |
| `docs` | Documentation only | None |
| `style` | Code style (formatting, semicolons, etc.) | None |
| `refactor` | Code change that neither fixes a bug nor adds a feature | None |
| `perf` | Performance improvement | Patch (0.0.X) |
| `test` | Adding or correcting tests | None |
| `build` | Changes to build system or dependencies | None |
| `ci` | Changes to CI configuration | None |
| `chore` | Other changes that don't modify src or test files | None |
| `revert` | Reverts a previous commit | Varies |

### Breaking Changes

For breaking changes that require a major version bump, add `!` after the type
or include `BREAKING CHANGE:` in the footer:

```text
feat!: remove deprecated API endpoints

BREAKING CHANGE: The /v1/users endpoint has been removed. Use /v2/users instead.
```

### Examples

```text
feat(auth): add OAuth2 support for Google login

fix(api): handle null response from upstream service

docs: update installation instructions for Windows

refactor(core)!: restructure module exports

BREAKING CHANGE: Named exports are now used instead of default exports.
```

### Scope

Scope is optional but recommended. Use it to indicate the area of the codebase
affected (e.g., `api`, `auth`, `core`, `cli`, `docs`).

## Semantic Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes that require users to modify their code
- **MINOR** (0.X.0): New features that are backwards-compatible
- **PATCH** (0.0.X): Bug fixes and minor improvements

Versions are automatically determined by semantic-release based on commit
messages. Do not manually update version numbers.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin (DCO) to ensure that
contributors have the right to submit their contributions.

By making a contribution to this project, you certify that:

1. The contribution was created in whole or in part by you and you have the
   right to submit it under the license indicated in the file; or

2. The contribution is based upon previous work that, to the best of your
   knowledge, is covered under an appropriate open source license and you
   have the right under that license to submit that work with modifications;
   or

3. The contribution was provided directly to me by some other person who
   certified (1), (2) or (3) and you have not modified it.

4. You understand and agree that this project and the contribution are public
   and that a record of the contribution (including all personal information
   you submit with it, including your sign-off) is maintained indefinitely
   and may be redistributed consistent with this project or the license(s)
   involved.

## How to Sign Off Your Commits

You must sign off each commit to indicate your acceptance of the DCO. Combine
the signoff with your conventional commit message:

```bash
git commit --signoff -m "feat(auth): add two-factor authentication"
```

This produces:

```text
feat(auth): add two-factor authentication

Signed-off-by: Your Name <your.email@example.com>
```

Make sure your Git configuration has your correct name and email:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## License for Contributions

All contributions to this project are licensed under the Apache License,
Version 2.0, the same license that covers the project (inbound = outbound).

## How to Contribute

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following the commit message format above
3. **Sign off your commits** with the DCO
4. **Test your changes** to ensure they work as expected
5. **Submit a pull request** with a clear description of what you've done

### Pull Request Checklist

- [ ] Commits follow the conventional commit format
- [ ] All commits are signed off (DCO)
- [ ] Tests pass (if applicable)
- [ ] Documentation is updated (if applicable)

## Run the checks locally before you push

HyperI projects gate every push through CI (lint, format, tests, secret scan,
dependency audit, build). Run the SAME checks locally first so your change lands
green instead of bouncing:

```bash
hyperi-ci check
```

`hyperi-ci` is the HyperI CI CLI (public on PyPI). If you do not have it, install
it once with `uv tool install hyperi-ci` (or `pipx install hyperi-ci`), or run it
ad hoc with `uvx hyperi-ci check`. It runs the project's full local validation --
the same suite CI runs -- and reports what to fix. Run it before every push and before opening a
pull request. It is the single best way to give your change the best chance of
surviving CI.

## CI/CD Workflow

Every push and pull request runs the full CI pipeline - lint, format, tests,
secret scan, dependency audit, and a container build - through the shared
hyperi-ci reusable workflow.

Publishing is deliberate, not a side effect of merging. A plain merge to
`main` is a validate-only run: it does not tag or publish. A release happens
only when the head commit on `main` carries a `Publish: true` trailer, or when
the workflow is dispatched by hand (Actions -> CI -> Run workflow, with
`from-head=true`). On a publish run, semantic-release reads the commits since
the last release, works out the next version from their types, updates the
CHANGELOG, tags a GitHub release, and pushes the multi-arch image to GHCR.

So land your change with a normal `fix:`/`feat:` merge, then trigger the
publish separately when you want it shipped.

## culvert Conventions

### Environment variables

All runtime configuration is namespaced under `CULVERT_*` and is
read by `scalo` via a 7-layer cascade (CLI -> env -> `.env` ->
`settings.{env}.yaml` -> `settings.yaml` -> `defaults.yaml` ->
hard-coded), with profile YAML as an additional config source.
When adding a config field:

- Add it to `scripts/lib/config.py` as a dataclass attribute with a
  sensible generic default (`""` or `0`, never a HyperI-specific value).
- Document validation rules in `__post_init__`.
- Update `.env.example` with the new variable name (prefixed
  `CULVERT_`) and quoted value (empty string is fine for defaults).
- Add a unit test in `tests/unit/test_config.py` that asserts the
  default and any validation behaviour.

### Deployment profiles

Site-specific defaults ship as YAML files under `profiles/` and load
opt-in via `CULVERT_PROFILE=/etc/vpn/profiles/<name>.yaml`. The
shipped `example.yaml` profile is a placeholder template. Copy it and
edit the values for your own site profile. Env vars always override
profile values.

### Template variables

Config templates under `config/*.template` use envsubst-style
`${VAR}` placeholders. Only keys rendered by `entrypoint.py` belong
here. Do not introduce new template placeholders without wiring them
through `scripts/lib/openvpn.py` or `scripts/lib/stunnel.py`.

## Questions

If you have questions about contributing, please open an issue or contact us.

## Context

### What this is

A VPN server shipped as one container image. Python inside, but not a Python
package -- the PyPI publish is opted out and a wheel is built only for pipeline
parity. Anyone deploys it, so defaults are generic and anything site-shaped
belongs in a profile or the deployment values. It replaced dfe-vpn, now
retired, so older references to that repo are stale.

### Where things live

| Path | What it holds |
|---|---|
| `scripts/entrypoint.py` | Thin orchestrator. Owns the startup ORDER |
| `scripts/lib/` | One module per concern -- config, network, pki, openvpn, wireguard, stunnel, wstunnel, oauth2, health, metrics, process, download |
| `config/*.template` | `${VAR}` templates rendered at runtime |
| `profiles/` | Opt-in site presets loaded by `CULVERT_PROFILE` |
| `deploy/` | Deployment contract and compose fragment, GENERATED by `scripts/generate-deploy-artefacts.py`. The Helm chart is assembled from the contract at release and committed nowhere |
| `docs/architecture.md` | Startup order, the two iptables chains, the PKI invariants |

### Commands that prove a change

`hyperi-ci check` locally, `tests/run-all.sh` for the tiers.

Green in CI is the UNIT tier alone, with coverage of `scripts/` held to hyperi-ci's default 80% floor. `.hyperi-ci.yaml` disables integration, e2e and k8s and leaves `ty` non-blocking. Run the rest yourself:

```bash
pytest tests/e2e/ -m e2e -v     # needs Docker and TUN
pytest tests/k8s/ -m k8s -v     # needs a kubeconfig and CULVERT_K8S_*
```

`addopts` carries no `-m "not e2e"`, so a bare `pytest` tries the e2e tier and
fails without Docker rather than skipping.

### What tends to bite

| Don't | Do | Why |
|---|---|---|
| Write the skip-CI marker literally in a commit message | Describe it | GitHub scans the whole message, body included, so a literal marker anywhere in it gives the PR no CI run at all |
| Hand-edit `deploy/deployment-contract.json` or `deploy/compose/culvert.yaml` | Re-run `scripts/generate-deploy-artefacts.py` | Both render from the scalo deployment contract in `scripts/lib/deployment.py`, and a unit test compares the committed output against a fresh render |
| Call `easyrsa init-pki` | Create the directories directly, as `lib/pki.py` does | On 3.2.x it removes the PKI directory unconditionally. That is a volume mount, so it fails outright, and where it succeeds it takes the CA ([issue #11](https://github.com/hyperi-io/culvert/issues/11)) |
| Check a renamed doc's links on macOS | Let `tests/unit/test_docs_links.py` do it | It compares against `git ls-files`, so case matters. A new doc also has to be linked from `docs/README.md` |
| Read a green PR as proof the image runs | Confirm the Container job built | Only the Container job starts the image, so a base-image bump or a broken config can pass every other check and die at startup |

### Where this sits

Inbound: **hyperi-io/scalo-py**, the only suite edge. `pyproject.toml` declares
`scalo[metrics,secrets-vault,secrets-aws]` bounded below 3 at runtime, plus a
dev-only `scalo[deployment]` range the artefact generators need and the runtime
never imports. Granular extras on purpose.

Outbound: nothing in the suite graph consumes culvert, and it is an optional
member. It reaches consumers as a public container image on GHCR.
