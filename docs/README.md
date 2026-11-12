# Culvert documentation

Start with the [README](../README.md) for what culvert is and the
five-minute `docker run`. This directory is everything past that.

Docs are grouped by what you are trying to do, not by feature.

## Connect a client

- [vpn-client-setup.md](vpn-client-setup.md) - installing and connecting on
  macOS, Linux and Windows, plus the WireGuard mobile apps, for both protocols and for the
  HTTPS-tunnelled variants. This one also ships inside the image at
  `/etc/vpn/docs/`, so it is available on the server itself.

## Deploy a shape

Each of these is a full walkthrough - deploy, issue a client, operate it.
Home, corporate, travel and edge-fleet each match a `CULVERT_PROFILE=` preset,
and kubernetes is a deploy shape, not a profile. The `mobile` preset
(`profiles/mobile.yaml`) has no walkthrough: [performance.md](performance.md)
covers what it changes.

- [use-case-home.md](use-case-home.md) - home LAN or a lab VM. OpenVPN UDP,
  split tunnel, local PKI.
- [use-case-corporate.md](use-case-corporate.md) - per-user certificates plus
  OIDC SSO, group gating, TCP fallback, offboarding.
- [use-case-travel.md](use-case-travel.md) - the VPN over HTTPS, for networks
  that only pass web traffic. Includes what that does and does not defeat.
- [use-case-kubernetes.md](use-case-kubernetes.md) - the published Helm chart,
  one replica: install values, the PKI volume, external PKI, probes, metrics.
- [use-case-edge-fleet.md](use-case-edge-fleet.md) - an appliance fleet into a
  central receiver, with reverse admin back down the tunnels.

## Understand a decision

- [architecture.md](architecture.md) - what is in the image, the startup order,
  the two iptables chains and why their order is what it is, and the PKI
  invariants. Start here before changing any of them.
- [addressing.md](addressing.md) - why the tunnels default to `10.8.0.0/22`,
  and when to move to the CGNAT range instead.
- [performance.md](performance.md) - the cipher stance (AES-256-GCM the
  compliance default, ChaCha20 offered), what the tuning profiles change, and
  the host-side throughput levers (DCO, sysctl).


## Conventions

Filenames are lowercase-kebab because slugs are case-sensitive and static-site
generators lowercase them. Each doc covers one reader mode - follow a path, or
look a fact up - and says which at the top.
