# Edge fleet -> receiver

An appliance fleet streaming data into a central receiver, with reverse
admin back down the same tunnels. Any hub-and-spoke telemetry fleet has
this shape: edge stream hubs pushing into a central ingest service, and
operators needing a way back down to the appliances. It is the
`edge-fleet` profile.

This is the shape we run culvert in ourselves, which is why the profile
is opinionated rather than a blank template.

Two things make this different from an ordinary client VPN. Understand
both before you deploy it.

## Difference 1: reverse admin

A normal VPN only ever lets clients initiate outbound. This shape also
lets named admin networks INITIATE back DOWN an established client
tunnel to reach an appliance - for updates, restricted repos, remote
support. That inbound-to-client path is deliberate and needed here; it is
not something you want on a general-purpose VPN.

It is gated: only the CIDRs in `CULVERT_DOWNSTREAM_ADMIN_CIDRS` may
initiate inbound. Everything else unsolicited into the tunnels is
dropped.

## Difference 2: CGNAT addressing

Because the operator controls BOTH ends (the appliances and the
receiver), the tunnels use `100.64.0.0/10` (RFC 6598, the carrier-grade
NAT range) instead of the default `10.8.0.0/22`. The appliances' own LANs
and the destination network do not sit in `100.64/10`, so tunnel
addresses never collide with either end and no NAT gateway is needed just
to dodge overlap.

**Warning:** do not use this preset for laptops on carrier or Starlink
links. Those WANs already sit in `100.64/10`, as do Tailscale clients -
run a CGNAT tunnel on top of a CGNAT underlay and the transport
misroutes. The why is in [addressing.md](addressing.md). This is safe
here precisely because the operator owns both ends and knows the
appliances are not on CGNAT WANs.

## Traffic model

State it exactly:

```
outbound (data):  appliance      -> culvert -> receiver
inbound  (admin): admin / repos  -> culvert (back down tunnel) -> appliance
```

Data flows up from the appliances to the receiver. Admin flows down from
the admin networks to the appliances, over the tunnels the appliances
already established.

## Routing control

`CULVERT_ROUTING_CONTROL_ENABLED=true` installs a dedicated FORWARD
filtering chain. With the `edge-fleet` profile it enforces:

- **Replies always pass.** Established/related flows are accepted, so an
  appliance reaching the receiver still gets its answers back.
- **Appliances cannot reach each other.** `CULVERT_CLIENT_ISOLATION` is
  on - client-to-client traffic is dropped.
- **Appliances may only initiate to the receiver.**
  `CULVERT_ALLOWED_DESTINATIONS` is the receiver CIDR; clients may
  initiate only to those destinations. Pair it with
  `CULVERT_PUSH_ROUTES` so clients are routed at exactly what they are
  allowed to reach.
- **Only admin CIDRs may initiate inbound.**
  `CULVERT_DOWNSTREAM_ADMIN_CIDRS` are the only sources allowed to open
  connections down into the tunnels; all other unsolicited inbound is
  dropped.

The profile ships example CIDRs - set them to yours:

```yaml
allowed_destinations: "10.20.0.0/16"          # the receiver network
downstream_admin_cidrs: "10.10.0.0/16"        # admin / bastion networks
push_routes: "10.20.0.0/16,10.10.0.0/16"      # receiver AND admin - see below
udp_network:  "100.64.0.0"                    # CGNAT tunnel subnet
udp_netmask:  "255.255.255.0"
```

`push_routes` covers both the receiver and the admin CIDRs. The receiver
route carries the appliance's outbound data; the admin route is what lets
an appliance's REPLY to an admin-initiated connection travel back UP the
tunnel instead of leaking out its own default gateway. Omit the admin
CIDR and reverse admin fails one-way - the admin can send but never gets
a response.

Those are illustrative ranges, not real addresses. Substitute your own
receiver, admin, and tunnel CIDRs.

## Deploying it

The profile also sets `log_mode: stdout` for the cluster log pipeline and
starts on a local CA (external PKI - a fleet CA in OpenBao or a mounted
Secret - is typical here; set `CULVERT_PKI_MODE=external` +
`CULVERT_SECRETS_*` to swap).

Run it on the Helm chart the same way as any scaled deploy - see
[use-case-k8s-scale.md](use-case-k8s-scale.md). The load balancer MUST be
connection-sticky: a single UDP or TCP flow has to stay pinned to one
culvert pod, because the client-IP allocation and certificate state are
per-pod. A per-packet LB will break the tunnels.

A `values-edge-fleet.yaml` starter lives alongside the chart in
[`deploy/helm/culvert`](../deploy/helm/culvert) with this shape's knobs
already set - copy it and pass `-f values-edge-fleet.yaml`.

## See also

- [use-case-k8s-scale.md](use-case-k8s-scale.md) - the chart, the
  privileged namespace, and the connection-affinity requirement in full
- [addressing.md](addressing.md) - why `100.64/10` here and why it is
  wrong for laptops
- [Routing Control in .env.example](../.env.example) - the exact
  `CULVERT_*` routing-control variables
