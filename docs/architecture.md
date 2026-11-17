# Architecture

What culvert is made of, why it is one container instead of a stack, and the
invariants that no single file makes obvious. Look a fact up here before you
change the startup order, the firewall chains or the PKI paths.

A VPN server is easy to install and hard to keep correct. The usual answers
either mutate a host with a shell script, or ship a management plane, a
database and a web UI to configure one daemon. Culvert takes the other route:
one image, configuration by environment variable, and every capability past
plain OpenVPN over UDP an explicit opt-in. Upgrading is a `docker pull`.

That choice decides everything below. There is no state store, so a
replica is defined entirely by its environment and its mounted volumes. There
is no control plane, so the container itself has to refuse to start when a
control it was asked for did not install.

Diagram map:

- [L1 Context -- Culvert](#l1-context-and-l3-components)
  - [L3 Components -- Culvert](#l1-context-and-l3-components)
    - [L4 Detail -- Startup sequence](#one-entrypoint-one-ordered-sequence)
  - [L4 Detail -- Edge fleet traffic](use-case-edge-fleet.md#reverse-admin-and-cgnat-addressing)

## L1 context and L3 components

Clients tunnel into culvert, which routes their traffic to the site networks.

```mermaid
---
config:
  theme: base
  look: neo
  fontFamily: Inter, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif
  flowchart:
    curve: linear
    nodeSpacing: 40
    rankSpacing: 64
    padding: 18
    wrappingWidth: 280
    htmlLabels: true
  elk:
    preset: modelOrder
  themeVariables:
    fontSize: 15px
    lineColor: "#64748B"
    primaryTextColor: "#0F172A"
    clusterBorder: "#0072B2"
    edgeLabelBackground: "#FFFFFF"
  themeCSS: >-
    p{margin:0}
    .node[data-look] rect,.node[data-look] path,.node[data-look] polygon,.node[data-look] .outer-path{filter:drop-shadow(0 1px 2px rgba(15,23,42,.10)) drop-shadow(0 6px 14px rgba(15,23,42,.10))}
    .node rect{rx:10px;ry:10px}
    .cluster rect{rx:16px;ry:16px}
    .node .label div{min-width:150px}
    .node.decision .label div{min-width:0}
    .cluster[data-look] rect{filter:none}
    .nodeLabel{line-height:1.35}
    .nodeLabel b{font-weight:600;font-size:15px;letter-spacing:-0.01em}
    .nodeLabel span{font-size:12.5px;font-weight:400;color:#334155}
    .cluster-label span.nodeLabel{display:inline-block;background:#FFFFFF;color:#0B2A3F;border:1.5px solid #0072B2;border-radius:999px;padding:2px 12px;font-size:11.5px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
    .flowchart-link{stroke-width:1.75px}
    .labelBkg{background:transparent!important}
    span.edgeLabel{display:inline-block;background:#FFFFFF!important;color:#1E293B;border:1px solid #94A3B8;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:500}
    span.edgeLabel p{background:transparent!important}
    .label-icon{width:20px;height:20px;vertical-align:-4px;margin-right:6px}
    .ingest .label-icon{color:#0E8A7D}
    .xform .label-icon{color:#7B4FB0}
    .load .label-icon{color:#0072B2}
    .bus .label-icon{color:#A8517F}
    .store .label-icon{color:#00785A}
    .ui .label-icon{color:#D9480F}
    .ext .label-icon{color:#64748B}
---
flowchart LR
    accTitle: L1 Context -- Culvert
    accDescr: VPN clients open tunnels to culvert, which routes their traffic to site networks. An external PKI can supply certificates, an OIDC provider signs users in, and a metrics collector receives metrics.

    clients("<b>VPN clients</b>")
    pki("<b>External PKI</b>")
    culvert[["<b>Culvert</b><br/><span>one container, OpenVPN and WireGuard</span>"]]
    networks("<b>Site networks</b>")
    idp("<b>OIDC provider</b>")
    collector("<b>Metrics collector</b>")

    clients -->|tunnels| culvert
    pki -.->|certificates| culvert
    culvert -->|routed traffic| networks
    culvert -.->|sign-in| idp
    culvert -.->|metrics| collector

    class clients,pki,networks,idp,collector ext
    class culvert control
  classDef ext fill:#F4F6F8,stroke:#94A3B8,stroke-width:1.5px,stroke-dasharray:5 4,color:#0F172A
  classDef ingest fill:#FFFFFF,stroke:#0E8A7D,stroke-width:3px,color:#0F172A
  classDef xform fill:#FFFFFF,stroke:#7B4FB0,stroke-width:3px,color:#0F172A
  classDef load fill:#FFFFFF,stroke:#0072B2,stroke-width:3px,color:#0F172A
  classDef bus fill:#FFFFFF,stroke:#A8517F,stroke-width:3px,color:#0F172A
  classDef store fill:#FFFFFF,stroke:#00785A,stroke-width:3px,color:#0F172A
  classDef ui fill:#FFFFFF,stroke:#D9480F,stroke-width:3px,color:#0F172A
  classDef decision fill:#FFFFFF,stroke:#9A6700,stroke-width:3px,color:#0F172A
  classDef error fill:#FFFFFF,stroke:#C2410C,stroke-width:3px,color:#0F172A
  classDef control fill:#FFFFFF,stroke:#334155,stroke-width:3px,color:#0F172A
  classDef part fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
```

*Figure 1. L1 Context -- Culvert. Dashed boxes are external, and dotted arrows are opt-in.* Up: top of culvert. Down: [L3 Components -- Culvert](#l1-context-and-l3-components).

stunnel fronts OpenVPN and wstunnel fronts WireGuard.

```mermaid
---
config:
  theme: base
  look: neo
  fontFamily: Inter, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif
  flowchart:
    curve: linear
    nodeSpacing: 40
    rankSpacing: 64
    padding: 18
    wrappingWidth: 280
    htmlLabels: true
  elk:
    preset: modelOrder
  themeVariables:
    fontSize: 15px
    lineColor: "#64748B"
    primaryTextColor: "#0F172A"
    clusterBorder: "#0072B2"
    edgeLabelBackground: "#FFFFFF"
  themeCSS: >-
    p{margin:0}
    .node[data-look] rect,.node[data-look] path,.node[data-look] polygon,.node[data-look] .outer-path{filter:drop-shadow(0 1px 2px rgba(15,23,42,.10)) drop-shadow(0 6px 14px rgba(15,23,42,.10))}
    .node rect{rx:10px;ry:10px}
    .cluster rect{rx:16px;ry:16px}
    .node .label div{min-width:150px}
    .node.decision .label div{min-width:0}
    .cluster[data-look] rect{filter:none}
    .nodeLabel{line-height:1.35}
    .nodeLabel b{font-weight:600;font-size:15px;letter-spacing:-0.01em}
    .nodeLabel span{font-size:12.5px;font-weight:400;color:#334155}
    .cluster-label span.nodeLabel{display:inline-block;background:#FFFFFF;color:#0B2A3F;border:1.5px solid #0072B2;border-radius:999px;padding:2px 12px;font-size:11.5px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
    .flowchart-link{stroke-width:1.75px}
    .labelBkg{background:transparent!important}
    span.edgeLabel{display:inline-block;background:#FFFFFF!important;color:#1E293B;border:1px solid #94A3B8;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:500}
    span.edgeLabel p{background:transparent!important}
    .label-icon{width:20px;height:20px;vertical-align:-4px;margin-right:6px}
    .ingest .label-icon{color:#0E8A7D}
    .xform .label-icon{color:#7B4FB0}
    .load .label-icon{color:#0072B2}
    .bus .label-icon{color:#A8517F}
    .store .label-icon{color:#00785A}
    .ui .label-icon{color:#D9480F}
    .ext .label-icon{color:#64748B}
---
flowchart LR
    accTitle: L3 Components -- Culvert
    accDescr: Clients reach OpenVPN directly or through stunnel, and WireGuard directly or through wstunnel. OpenVPN hands sign-in to openvpn-auth-oauth2. One listener serves health and metrics.

    clients("<b>VPN clients</b>")
    pki("<b>External PKI</b>")

    subgraph culvert["Culvert"]
        direction LR
        stunnel("<b>stunnel</b><br/><span>TLS in front of OpenVPN</span>") --> openvpn("<b>OpenVPN</b>") --> oauth2("<b>openvpn-auth-oauth2</b><br/><span>OIDC sign-in</span>")
        wstunnel("<b>wstunnel</b><br/><span>TLS in front of WireGuard</span>") --> wireguard("<b>WireGuard wg0</b>")
        observability("<b>Health and metrics</b><br/><span>one listener</span>")
    end

    networks("<b>Site networks</b>")
    idp("<b>OIDC provider</b>")
    collector("<b>Metrics collector</b>")

    clients -->|tunnels| culvert
    pki -.->|certificates| culvert
    culvert -->|routed traffic| networks
    culvert -.->|sign-in| idp
    culvert -.->|metrics| collector

    class clients,pki,networks,idp,collector ext
    class stunnel,openvpn,oauth2,wstunnel,wireguard,observability part
  classDef ext fill:#F4F6F8,stroke:#94A3B8,stroke-width:1.5px,stroke-dasharray:5 4,color:#0F172A
  classDef ingest fill:#FFFFFF,stroke:#0E8A7D,stroke-width:3px,color:#0F172A
  classDef xform fill:#FFFFFF,stroke:#7B4FB0,stroke-width:3px,color:#0F172A
  classDef load fill:#FFFFFF,stroke:#0072B2,stroke-width:3px,color:#0F172A
  classDef bus fill:#FFFFFF,stroke:#A8517F,stroke-width:3px,color:#0F172A
  classDef store fill:#FFFFFF,stroke:#00785A,stroke-width:3px,color:#0F172A
  classDef ui fill:#FFFFFF,stroke:#D9480F,stroke-width:3px,color:#0F172A
  classDef decision fill:#FFFFFF,stroke:#9A6700,stroke-width:3px,color:#0F172A
  classDef error fill:#FFFFFF,stroke:#C2410C,stroke-width:3px,color:#0F172A
  classDef control fill:#FFFFFF,stroke:#334155,stroke-width:3px,color:#0F172A
  classDef part fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
  style culvert fill:none,stroke:#0072B2,stroke-width:1.5px,stroke-dasharray:6 4
```

*Figure 2. L3 Components -- Culvert. Dashed boxes are external, and dotted arrows are opt-in.* Up: [L1 Context -- Culvert](#l1-context-and-l3-components). Down: [L4 Detail -- Startup sequence](#one-entrypoint-one-ordered-sequence).

A client on an open network dials OpenVPN or WireGuard directly. Behind HTTPS-only egress it dials stunnel or wstunnel, which unwrap the TLS and hand the session on inside the container. Each process runs when its switch is on:

| Process | Port | Runs when |
|---|---|---|
| OpenVPN | `1194/udp`, `1194/tcp` | `CULVERT_PROTOCOL` is `openvpn` (the default) or `both`. UDP runs when `CULVERT_UDP_ENABLED` is true (the default), TCP once `CULVERT_TCP_ENABLED=true` |
| stunnel | `443/tcp` | OpenVPN runs and `CULVERT_HTTPS_ENABLED=true` |
| openvpn-auth-oauth2 | `9000-9002/tcp` | One per enabled OpenVPN listener with `CULVERT_OAUTH2_UDP_ENABLED`, `_HTTPS_ENABLED` or `_TCP_ENABLED` is true. Each defaults to `CULVERT_OAUTH2_ENABLED` |
| WireGuard `wg0` | `51820/udp` | `CULVERT_PROTOCOL` is `wireguard` or `both` |
| wstunnel | `4443/tcp` | WireGuard runs and `CULVERT_WG_HTTPS_TUNNEL_ENABLED=true` |
| Health and metrics | `9090/tcp` | Always, with `/metrics` once `CULVERT_METRICS_ENABLED=true` |

## What is in the image

The base is the Ubuntu image `BASE_IMAGE` pins by tag and digest in the `Dockerfile`. Every third-party binary comes
from upstream directly, and each arrives with a verification step:

| Component | Source | How it is verified |
|---|---|---|
| OpenVPN 2.7+ | The project's signed apt repo | Downloaded keyring must hold exactly one primary key, with a pinned fingerprint. Installed version then checked against a floor |
| easy-rsa, iptables, wireguard-tools, stunnel4 | Ubuntu archive | apt, over the base image's trust |
| openvpn-auth-oauth2 | Pinned GitHub release `.deb` | SHA256 per architecture, checked before `dpkg` |
| wstunnel | Pinned GitHub release tarball | SHA256 per architecture, checked before extract |
| Python dependencies | `requirements-docker.txt`, exported from `uv.lock` | `pip --require-hashes`, so a drifted release fails the build |

Counting `pub` records rather than `fpr` records on the OpenVPN keyring is
deliberate. A key with signing subkeys emits one `fpr` line per subkey, all
legitimately the same primary, so counting fingerprints would reject a valid
key and counting keys catches a second one smuggled in alongside the pinned one.

The apt repo serves one version per suite and cannot be pinned, which is why
the version floor is asserted after install rather than requested before it.
The server config depends on 2.7 behaviour, so building on 2.6 would change it
silently: 2.7 deprecates `persist-key` on the server, and 2.7 clients
reject an unknown pushed option where 2.6 ones ignore it, which is why `block-outside-dns` is not pushed. `openvpn-auth-oauth2` gets the artefact treatment instead because its
apt repo serves the latest release alone and cannot be pinned at all.

DCO is supported but no kernel module ships in the image. Inside a container
DKMS would compile against kernel headers that are not there, and the module
has to be on the host regardless. OpenVPN 2.7 uses the `ovpn` module, in the
kernel from Linux 6.16 and built by ovpn-backports on older ones. Leaving it out
drops a compiler toolchain from the image at no cost to the capability.

## One entrypoint, one ordered sequence

`scripts/entrypoint.py` is a thin orchestrator. Every piece of work lives
in a focused module under `scripts/lib/`, and the entrypoint's job is the
order.

Network and firewall come up before either VPN.

```mermaid
---
config:
  theme: base
  look: neo
  fontFamily: Inter, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif
  flowchart:
    curve: linear
    nodeSpacing: 40
    rankSpacing: 64
    padding: 18
    wrappingWidth: 280
    htmlLabels: true
  elk:
    preset: modelOrder
  themeVariables:
    fontSize: 15px
    lineColor: "#64748B"
    primaryTextColor: "#0F172A"
    clusterBorder: "#0072B2"
    edgeLabelBackground: "#FFFFFF"
  themeCSS: >-
    p{margin:0}
    .node[data-look] rect,.node[data-look] path,.node[data-look] polygon,.node[data-look] .outer-path{filter:drop-shadow(0 1px 2px rgba(15,23,42,.10)) drop-shadow(0 6px 14px rgba(15,23,42,.10))}
    .node rect{rx:10px;ry:10px}
    .cluster rect{rx:16px;ry:16px}
    .node .label div{min-width:150px}
    .node.decision .label div{min-width:0}
    .cluster[data-look] rect{filter:none}
    .nodeLabel{line-height:1.35}
    .nodeLabel b{font-weight:600;font-size:15px;letter-spacing:-0.01em}
    .nodeLabel span{font-size:12.5px;font-weight:400;color:#334155}
    .cluster-label span.nodeLabel{display:inline-block;background:#FFFFFF;color:#0B2A3F;border:1.5px solid #0072B2;border-radius:999px;padding:2px 12px;font-size:11.5px;font-weight:700;letter-spacing:.09em;text-transform:uppercase}
    .flowchart-link{stroke-width:1.75px}
    .labelBkg{background:transparent!important}
    span.edgeLabel{display:inline-block;background:#FFFFFF!important;color:#1E293B;border:1px solid #94A3B8;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:500}
    span.edgeLabel p{background:transparent!important}
    .label-icon{width:20px;height:20px;vertical-align:-4px;margin-right:6px}
    .ingest .label-icon{color:#0E8A7D}
    .xform .label-icon{color:#7B4FB0}
    .load .label-icon{color:#0072B2}
    .bus .label-icon{color:#A8517F}
    .store .label-icon{color:#00785A}
    .ui .label-icon{color:#D9480F}
    .ext .label-icon{color:#64748B}
---
flowchart TB
    accTitle: L4 Detail -- Startup sequence
    accDescr: Three stages run in order. Prepare loads config and sets up directories, log rotation and the network. Firewall and protocols installs routing control and the forward guards, then sets up OpenVPN and WireGuard. Serve starts observability and any CRL refresh or client download, then runs the OpenVPN listeners, or waits for signals when WireGuard runs alone.

    subgraph s1["1 Prepare"]
        direction LR
        config("<b>Load config</b>") --> directories("<b>Directories</b>") --> logrotation("<b>Log rotation</b>") --> network("<b>Network</b>")
    end
    subgraph s2["2 Firewall and protocols"]
        direction LR
        routing("<b>Routing control</b>") --> guards("<b>Forward guards</b>") --> ovpnsetup("<b>OpenVPN setup</b>") --> wgsetup("<b>WireGuard setup</b>")
    end
    subgraph s3["3 Serve"]
        direction LR
        observe("<b>Observability</b>") --> crl("<b>CRL refresh</b>") --> download("<b>Client download</b>") --> block(["<b>Run OpenVPN</b><br/><span>or wait</span>"])
    end
    s1 --> s2 --> s3

    class config,directories,logrotation,network,routing,guards,ovpnsetup,wgsetup,observe,crl,download,block part
  classDef ext fill:#F4F6F8,stroke:#94A3B8,stroke-width:1.5px,stroke-dasharray:5 4,color:#0F172A
  classDef ingest fill:#FFFFFF,stroke:#0E8A7D,stroke-width:3px,color:#0F172A
  classDef xform fill:#FFFFFF,stroke:#7B4FB0,stroke-width:3px,color:#0F172A
  classDef load fill:#FFFFFF,stroke:#0072B2,stroke-width:3px,color:#0F172A
  classDef bus fill:#FFFFFF,stroke:#A8517F,stroke-width:3px,color:#0F172A
  classDef store fill:#FFFFFF,stroke:#00785A,stroke-width:3px,color:#0F172A
  classDef ui fill:#FFFFFF,stroke:#D9480F,stroke-width:3px,color:#0F172A
  classDef decision fill:#FFFFFF,stroke:#9A6700,stroke-width:3px,color:#0F172A
  classDef error fill:#FFFFFF,stroke:#C2410C,stroke-width:3px,color:#0F172A
  classDef control fill:#FFFFFF,stroke:#334155,stroke-width:3px,color:#0F172A
  classDef part fill:#FFFFFF,stroke:#94A3B8,stroke-width:1.5px,color:#0F172A
  style s1 fill:none,stroke:#0072B2,stroke-width:1.5px,stroke-dasharray:6 4
  style s2 fill:none,stroke:#0072B2,stroke-width:1.5px,stroke-dasharray:6 4
  style s3 fill:none,stroke:#0072B2,stroke-width:1.5px,stroke-dasharray:6 4
```

*Figure 3. L4 Detail -- Startup sequence. Read each stage left to right, then down.* Up: [L3 Components -- Culvert](#l1-context-and-l3-components).

The OpenVPN branch initialises PKI, renders the UDP, HTTPS and TCP server
configs from `config/*.template`, sets up stunnel, generates any auto-clients
and starts the OIDC helper. The WireGuard branch brings up `wg0` through
`wg-quick`, starts wstunnel and starts a connection monitor. `CULVERT_PROTOCOL`
selects one, the other, or both, and `both` runs both branches in full.

In WireGuard-only mode there is no OpenVPN process to block on, so the
entrypoint marks itself started and ready and waits on signals. The kernel
interface is up by that point, which is why readiness flips there
rather than in the server starter.

## PKI: two modes, and local disk is the source of truth

Local mode has Easy-RSA generate a CA and a server certificate. External mode
fetches them through scalo secrets from a file mount, OpenBao or AWS Secrets
Manager. In both modes the files under the PKI directory are what OpenVPN
reads, and a remote provider is the update mechanism rather than the authority.
That is what lets an external deployment keep serving when the provider is
unreachable, on cached certificates, with a warning.

Three things here are not guessable from reading the code:

- `easyrsa init-pki` is never called. All it creates is three directories,
  and it insists on removing the PKI directory first, unconditionally on 3.2.x
  with no opt-out. The directory is a volume mount, so the removal fails
  outright, and where it could succeed it would take the CA and every
  certificate issued from it. 3.1.x's `init-pki soft` is not a portable
  substitute either, because 3.2.x reads that argument as a curve name.
  Culvert creates the directories itself, and `build-ca` still declines to
  overwrite an existing CA, so a half-built PKI fails loudly instead of being
  replaced.
- The `tls-crypt-v2` server key is minted locally unless a provider
  supplies one. A client's key derives from it, so two servers with
  different keys reject each other's clients. Once
  `CULVERT_SECRETS_TC_KEY_PATH` is set, a failed fetch is fatal rather than a
  fall back to minting, because an install that comes up healthy and rejects
  clients at random is worse than one that fails to start.
- CRL refresh differs by mode and cannot be shared. Local PKI regenerates
  from its CA. External PKI has no CA key present, so the one way to pick
  up a revocation is to re-fetch. OpenVPN re-reads the CRL on every handshake,
  so a changed file needs no reload. The server reloads when the fetched CRL
  revokes a certificate the old one did not, to end that session before it
  renegotiates, and that reload drops every connected client.

A CRL that reaches its `nextUpdate` makes OpenVPN refuse every client,
including valid ones. The refresher therefore reports remaining life on every
cycle, not just whether the last refresh worked.

## Enforcement is two iptables chains, and the order matters

NAT and MSS clamping go in the base `FORWARD` and `POSTROUTING` paths.
Every policy rule lives in two dedicated chains, both rebuilt on each
start so restarts cannot stack duplicates:

- `CULVERT_FWD` -- opt-in routing control. Client isolation, the egress
  allow-list, and the downstream-admin gate that lets an operator initiate back
  into the tunnels.
- `CULVERT_GUARD` -- always on by default. Drops forwarded client traffic to
  link-local, which on a cloud instance is the metadata service and this host's
  credentials.

Four ordering rules hold this together, and each exists because the obvious
arrangement is wrong:

1. `CULVERT_GUARD` is installed AFTER `CULVERT_FWD`. Both insert at `FORWARD`
   position 1, so the last one installed is evaluated first, and the guard has
   to be. It is separate from routing control precisely because routing control
   is opt-in and the guard must hold on a default configuration.
2. `CULVERT_FWD` is detached from `FORWARD` before it is flushed, built
   completely, and jumped at last. A flushed chain that is still jumped falls
   through to the `FORWARD` policy, so there must be no window where it is
   jumped and empty.
3. Client-to-client rules sit above the conntrack accept, so cross-tunnel
   traffic is decided without reference to state and a RELATED packet cannot
   slip between clients.
4. Reverse-admin replies get a NAT `RETURN`, scoped to established flows.
   Without it the general masquerade rewrites the client's reply to the
   server's address and the exchange never completes. Scoping it keeps a
   client that initiates towards the admin range masqueraded.

Rules of this kind are not advisory, so a failed install raises and the
container exits. Serving clients and reporting a control that is not there is
the outcome being avoided. Chain creation and rule deletion stay tolerant,
because both are expected to fail on a normal restart.

The guard is scoped to `FORWARD` deliberately, which leaves the server's
access to the metadata service intact -- external PKI on AWS authenticates with
exactly those instance credentials. The tunnels are IPv4 and `net.ipv4.ip_forward` is the
one forwarding sysctl enabled, so there is no ip6tables setup at all.

## Observability is one listener

`CULVERT_METRICS_ADDR` (default `0.0.0.0:9090`) serves `/livez` and `/readyz`
always, and `/metrics` when metrics are enabled. OTLP is a push to a collector,
so it adds no listener. Health and metrics deliberately share the port so that
one published port covers the operator surface and nothing about it rides on
the VPN listeners.

## Deployment artefacts are generated, not authored

`deploy/deployment-contract.json` and the compose fragment are rendered from
culvert's scalo deployment contract by `scripts/generate-deploy-artefacts.py`.
Editing either by hand puts it out of step with the contract, and a unit test
compares the committed output against a fresh render. The release assembles the
Helm chart from the contract file on the scalo-service library chart, which
renders every contract field: the WireGuard port gate, the PKI claim, the root
identity, the capabilities and the single replica. The chart's `version` and
`appVersion` come from the release, so the chart and the image it deploys move
together. No chart is committed to this repository.

## Invariants, collected

- Configuration is `CULVERT_*` environment variables through scalo's cascade,
  with profile YAML as an extra source. Explicit env always beats a profile.
- `/etc/vpn` and `/var/log/vpn` are the canonical paths and nothing aliases
  them. No symlink points at the OpenVPN package's directories: the package
  ships them as directories, so a link lands inside one and the PKI no
  longer persists.
- The chart runs one replica. WireGuard mints its server key in the pod and
  the PKI volume is ReadWriteOnce, so the chart renders a singleton. Several
  OpenVPN instances on shared storage are the compose overlay's job, with the
  limits in [shared-storage.md](shared-storage.md).
- Defaults are generic, never site-specific. Anything specific to one site belongs in a
  profile or the deployment values.
