# Culvert documentation

Start with the [README](../README.md) for what culvert is and the
five-minute `docker run`. This directory is everything past that.

Docs are grouped by what you are trying to do, not by feature.

## Connect a client

- [vpn-client-setup.md](vpn-client-setup.md) - installing and connecting on
  macOS, Linux, Windows, iOS and Android, for both protocols and for the
  HTTPS-tunnelled variants. This one also ships inside the image at
  `/etc/vpn/docs/`, so it is available on the server itself.

## Deploy a shape

Each of these is a full walkthrough - deploy, issue a client, operate it -
for one of the opinionated `CULVERT_PROFILE=` presets.

- [use-case-home.md](use-case-home.md) - home LAN or a lab VM. OpenVPN UDP,
  split tunnel, local PKI.
- [use-case-corporate.md](use-case-corporate.md) - per-user certificates plus
  OIDC SSO, group gating, TCP fallback, offboarding.
- [use-case-travel.md](use-case-travel.md) - the VPN over HTTPS, for networks
  that only pass web traffic. Includes what that does and does not defeat.
- [use-case-k8s-scale.md](use-case-k8s-scale.md) - the Helm chart behind a load
  balancer: probes, drain, autoscaling, external PKI, metrics.
- [use-case-edge-fleet.md](use-case-edge-fleet.md) - an appliance fleet into a
  central receiver, with reverse admin back down the tunnels.

## Understand a decision

- [addressing.md](addressing.md) - why the tunnels default to `10.8.0.0/22`,
  and when to move to the CGNAT range instead.

## Look something up

- [supply-chain.md](supply-chain.md) - where every third-party binary comes
  from, what the build verifies, and what it does not.
- [ci-environment.md](ci-environment.md) - the secrets and variables CI needs.
- [scalo-reference.md](scalo-reference.md) - the scalo calls culvert actually
  makes. The [scalo repo](https://github.com/hyperi-io/scalo-py) is the API
  source of truth.

## Conventions

Filenames are lowercase-kebab because slugs are case-sensitive and static-site
generators lowercase them. Each doc covers one reader mode - follow a path, or
look a fact up - and says which at the top.
