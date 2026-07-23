# Travel / hostile networks

For networks that block or throttle VPNs. Culvert can run listeners that
look like ordinary HTTPS, so protocol blocking does not see a VPN on the
wire. This is the `travel` profile. It carries a real cost - extra
listeners and a TLS certificate - so it is a deliberate opt-in, not a
default.

Read the [threat model](#what-this-does-and-does-not-defeat) before you
rely on it.

## 1. Get a real TLS certificate first

The camouflage is only as convincing as the certificate. Get a real cert
for your server name (Let's Encrypt is fine). A self-signed cert defeats
the point - an inspector that hits a self-signed cert on port 443 has
found you.

Point culvert at the cert and key:

```bash
-e CULVERT_STUNNEL_CERT=/etc/vpn/tls/fullchain.pem
-e CULVERT_STUNNEL_KEY=/etc/vpn/tls/privkey.pem
```

Mount the actual files into the container at those paths. The same pair
covers both camouflage listeners.

## 2. Turn on the profile

`CULVERT_PROFILE=travel` runs both protocols with their HTTPS-camouflage
listeners, a full tunnel (a split tunnel on a censored network leaks
which sites you reach directly), and mobile-tolerant timers:

- **OpenVPN inside TLS on 443** (stunnel) - `CULVERT_HTTPS_ENABLED=true`,
  publish `443/tcp`. On the wire this is a TLS session on the HTTPS port
  with a valid certificate.
- **WireGuard over WebSocket/TLS on 4443** (wstunnel) -
  `CULVERT_WG_DPI_BYPASS_ENABLED=true`, publish `4443/tcp`. Same
  camouflage for the WireGuard path (`4443` avoids colliding with
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
`laptop-wg-dpi-split.conf` and `laptop-wg-dpi-full.conf`.

## 4. Connect through the camouflage

**OpenVPN** - start stunnel, then connect the HTTPS profile through it:

```bash
# terminal 1: keep this running
stunnel laptop-stunnel.conf

# terminal 2
sudo openvpn --config laptop-https-full.ovpn
```

stunnel listens on `127.0.0.1:1195` and forwards to your server on
`443`; the `.ovpn` connects to that local port.

**WireGuard** - start the wstunnel client, then activate the `-dpi-`
config:

```bash
wstunnel client wss://vpn.example.com:4443 -L udp://51820:127.0.0.1:51820
# then activate laptop-wg-dpi-full.conf in your WireGuard client
```

Full platform detail (install steps, one-liners, wrapper scripts, the
Windows path) is in
[VPN-CLIENT-SETUP.md](VPN-CLIENT-SETUP.md#dpi-bypass-china--restricted-networks).

## What this does and does not defeat

Be straight about the threat model:

- **Defeats protocol blocking.** To on-path inspection the traffic is
  TLS on `443` (or `4443`) presenting a valid certificate for your
  server name. A censor that drops "things that look like OpenVPN or
  WireGuard" does not see either.
- **Does not defeat an active-probing or flow-analysis censor.** A censor
  that actively probes your endpoint, or does long-term traffic-flow
  analysis (timing, volume, connection duration), is playing a different
  game. Camouflage buys you "not obviously a VPN", not invisibility.

Use it where the barrier is protocol fingerprinting. Do not oversell it
to yourself where the adversary is nation-state grade and paying
attention to you specifically.

## See also

- [VPN-CLIENT-SETUP.md](VPN-CLIENT-SETUP.md#dpi-bypass-china--restricted-networks)
  - installing stunnel / wstunnel and connecting on each platform
- [Cryptography and CNSA 2.0 in the README](../README.md#cryptography-and-cnsa-20)
  - what the crypto does and does not give you
- [USE-CASE-CORPORATE.md](USE-CASE-CORPORATE.md) - the same HTTPS listener
  as a managed corporate fallback with SSO
