# Addressing

Which IP range the tunnels use, why the default is what it is, and when
to change it. If you followed a link here from one of the use-case docs,
this is the whole answer.

## The short version

Every VPN hands its clients addresses from some private range. Pick a
range that clashes with a network the client is already on and traffic
goes to the wrong place. Culvert defaults to `10.8.0.0/22` because that
is the range home and small-office networks are least likely to be using,
so it "just works" out of the box. If you run bigger networks, check it
against your plan and override if needed.

That is the practical takeaway. The rest is the why.

## The default: 10.8.0.0/22

Culvert carves one `/24` per listener out of `10.8.0.0/22`:

| Listener | Subnet |
|----------|--------|
| OpenVPN UDP | `10.8.0.0/24` |
| OpenVPN TCP | `10.8.1.0/24` |
| OpenVPN HTTPS (stunnel) | `10.8.2.0/24` |
| WireGuard | `10.8.3.0/24` |

Distinct subnets mean any combination of listeners - and WireGuard
alongside - can run at once without colliding.

`10.8.x` is the hub-VPN convention. OpenVPN's own reference config,
[angristan/openvpn-install](https://github.com/angristan/openvpn-install),
and [wg-easy](https://github.com/wg-easy/wg-easy) all default into
`10.8.x`. Home and small-office LANs almost always sit in `192.168.x`
(and larger ones in `10.0.x` / `172.16.x`), so a client dialing in from
home does not find its tunnel address clashing with its own LAN. Picking
the same convention as the common tooling is the point - it is the range
least likely to already be in use where clients connect from.

## Why not 100.64.0.0/10 (CGNAT) by default

`100.64.0.0/10` is the RFC 6598 carrier-grade NAT range. Overlay meshes
like Tailscale and NetBird default into it, which is a fair question:
why not culvert too?

Because that range is already occupied on exactly the links a travelling
client uses. Carrier WANs - Starlink, 4G/5G mobile - put the subscriber's
own WAN address inside `100.64/10`. A machine already on Tailscale is
carrying `100.x` addresses too.

Here is the real failure. Starlink gives your router a `100.64/10` WAN
address. If the VPN then also hands the tunnel a `100.64/10` address, the
client has two reasons to route `100.x` traffic - the underlay (its path
to the Starlink gateway and the internet) and the tunnel. Those routes
overlap, the client sends tunnel-destined packets at the underlay (or the
reverse), and the transport the VPN itself rides on breaks. CGNAT tunnel
on top of CGNAT underlay is a self-inflicted routing loop.

`10.8.x` does not have this problem, so it is the default.

## When to override

- **Corporate / larger networks.** `10.8.0.0/22` is safe for homes, but a
  company already using `10.8.x` internally will clash. Check the `/22`
  against your addressing plan and move it if it collides.
- **Edge fleet.** The [edge-fleet preset](use-case-edge-fleet.md) opts
  INTO `100.64/10` on purpose. There the operator controls both ends of
  every tunnel and knows the appliances are not on CGNAT WANs, so the
  range that is wrong for a travelling laptop is exactly right for
  keeping appliance LANs and the receiver network from ever overlapping.

The rule of thumb: use `10.8.x` (or your own `10.x` / `172.16.x` block)
whenever a client might be on a network you do not control. Reach for
`100.64/10` only when you own both ends and want the overlap-avoidance it
buys.

## How to override

The OpenVPN listeners each take a network address plus a netmask; the NAT
masquerade rule derives its prefix from that netmask, so the two always
agree. WireGuard takes a single CIDR.

```bash
# OpenVPN UDP listener
-e CULVERT_UDP_NETWORK=10.20.0.0
-e CULVERT_UDP_NETMASK=255.255.255.0

# and the same NETWORK / NETMASK pair for the TCP and HTTPS listeners:
-e CULVERT_TCP_NETWORK=10.20.1.0
-e CULVERT_TCP_NETMASK=255.255.255.0
-e CULVERT_HTTPS_NETWORK=10.20.2.0
-e CULVERT_HTTPS_NETMASK=255.255.255.0

# WireGuard takes a CIDR, not a network/netmask pair
-e CULVERT_WG_NETWORK=10.20.3.0/24
```

Keep the listeners in distinct subnets so they do not collide. Or bake
the values into a profile - the `edge-fleet` profile does exactly this
for the CGNAT case (`udp_network: "100.64.0.0"`). See the
[deployment profiles](../README.md#deployment-profiles) section of the
README.

## See also

- [use-case-edge-fleet.md](use-case-edge-fleet.md) - the one shape that
  opts into `100.64/10`, and why
- [use-case-home.md](use-case-home.md) and
  [use-case-corporate.md](use-case-corporate.md) - the split-tunnel and
  full-tunnel cases that push these subnets to clients
- [Multi-Listener Configuration in .env.example](../.env.example) - the
  per-listener `CULVERT_*_NETWORK` / `_NETMASK` variables and defaults
