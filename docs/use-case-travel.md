# Travel / hostile networks

For networks that block or throttle VPNs. Culvert can run listeners that
look like ordinary HTTPS, so protocol blocking does not see a VPN on the
wire. This is the `travel` profile. It carries a real cost - extra
listeners and a TLS certificate - so it is a deliberate opt-in, not a
default.

Read the [threat model](#what-this-does-and-does-not-defeat) before you
rely on it.

## 1. Get a real TLS certificate first

It is only as convincing as the certificate. Get a real cert
for your server name (Let's Encrypt is fine). A self-signed cert defeats
the point - an inspector that hits a self-signed cert on port 443 has
found you.

Point culvert at the cert and key:

```bash
-e CULVERT_STUNNEL_CERT=/etc/vpn/tls/fullchain.pem
-e CULVERT_STUNNEL_KEY=/etc/vpn/tls/privkey.pem
```

Mount the actual files into the container at those paths. The same pair
covers both HTTPS-tunnelled listeners.

## 2. Turn on the profile

`CULVERT_PROFILE=travel` runs both protocols with their HTTPS-tunnelled
listeners, a full tunnel (a split tunnel leaks which sites you reach
directly), and mobile-tolerant timers:

- **OpenVPN inside TLS on 443** (stunnel) - `CULVERT_HTTPS_ENABLED=true`,
  publish `443/tcp`. On the wire this is a TLS session on the HTTPS port
  with a valid certificate.
- **WireGuard over WebSocket/TLS on 4443** (wstunnel) -
  `CULVERT_WG_HTTPS_TUNNEL_ENABLED=true`, publish `4443/tcp`. Same
  treatment for the WireGuard path (`4443` avoids colliding with
  stunnel on `443`).

Publish the ports you use:

```
-p 443:443/tcp     # OpenVPN via stunnel
-p 4443:4443/tcp   # WireGuard via wstunnel
```

## 3. Generate a client

```bash
docker exec -it <container> generate-client --name laptop
```

For OpenVPN this emits, among the set, `laptop-https-split.ovpn`,
`laptop-https-full.ovpn`, and a matching `laptop-stunnel.conf`. For
WireGuard (the profile runs both protocols) it also emits
`laptop-wg-https-split.conf` and `laptop-wg-https-full.conf`.

## 4. Connect through the tunnel

**OpenVPN** - start stunnel, then connect the HTTPS profile through it:

```bash
# terminal 1: keep this running
stunnel laptop-stunnel.conf

# terminal 2
sudo openvpn --config laptop-https-full.ovpn
```

stunnel listens on `127.0.0.1:1195` and forwards to your server on
`443`; the `.ovpn` connects to that local port.

**WireGuard** - start the wstunnel client, then activate the `-wg-https-`
config:

```bash
wstunnel client wss://vpn.example.com:4443 -L udp://51820:127.0.0.1:51820
# then activate laptop-wg-https-full.conf in your WireGuard client
```

Full platform detail (install steps, one-liners, wrapper scripts, the
Windows path) is in
[vpn-client-setup.md](vpn-client-setup.md#running-the-vpn-over-https).

## What this does and does not defeat

Be straight about the threat model:

- **Defeats protocol blocking.** To on-path inspection the traffic is
  TLS on `443` (or `4443`) presenting a valid certificate for your
  server name. A censor that drops "things that look like OpenVPN or
  WireGuard" does not see either.
- **Does not defeat an active-probing or flow-analysis censor.** A censor
  that actively probes your endpoint, or does long-term traffic-flow
  analysis (timing, volume, connection duration), is playing a different
  game. This buys you "indistinguishable from HTTPS at a glance", not
  invisibility.
- **A full tunnel routes your traffic; it does not by itself settle DNS.**
  The server pushes its DNS servers, and whether your client uses them to
  the exclusion of the network's own resolver is up to the client. On
  **Windows** you must uncomment `block-outside-dns` in the `.ovpn` -
  without it applications can query the local network's resolver, which
  leaks the names you look up even though the traffic itself is tunnelled.
  It ships commented because OpenVPN 2.7 on Linux and macOS refuses to
  start on an option it does not know. After connecting, check what
  resolver you are actually using before trusting the tunnel.

Use it where the barrier is protocol fingerprinting. Do not oversell it
to yourself where the adversary is nation-state grade and paying
attention to you specifically.

## See also

- [vpn-client-setup.md](vpn-client-setup.md#running-the-vpn-over-https)
  - installing stunnel / wstunnel and connecting on each platform
- [Cryptography and CNSA 2.0 in the README](../README.md#cryptography-and-cnsa-20)
  - what the crypto does and does not give you
- [use-case-corporate.md](use-case-corporate.md) - the same HTTPS listener
  as a managed corporate fallback with SSO
