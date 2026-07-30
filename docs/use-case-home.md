# Home / lab access

Reach your home LAN, or a throwaway VM, from the outside. OpenVPN over
UDP, split tunnel, a self-generated local CA - nothing else. This is the
`home` profile and the beginner path; it builds on the
[README quick start](../README.md#quick-start).

## 1. Run the server

Same as the quick start, with `CULVERT_PROFILE=home` added. Set
`CULVERT_SERVER_CN` to a name clients can reach from outside - your DDNS
hostname, or the VM's public IP.

```bash
docker run -d \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194/udp \
  -p 127.0.0.1:9090:9090/tcp \
  -e CULVERT_PROFILE=home \
  -e CULVERT_SERVER_CN=vpn.yourdomain.example \
  -v culvert-pki:/etc/vpn/pki \
  -v culvert-clients:/etc/vpn/clients \
  ghcr.io/hyperi-io/culvert:latest
```

The shipped profiles live at `/etc/vpn/profiles/` inside the image, so
the bare name `home` resolves. Explicit `CULVERT_*` env vars always
override profile values.

Or use the repo's compose file, which publishes the same default set:

```bash
docker compose up -d
```

## 2. Open UDP 1194 to the host

The server is only reachable once the port reaches it:

- **Home:** forward UDP `1194` on your router to the host running the
  container.
- **Cloud VM:** allow inbound UDP `1194` in the security group / firewall.

The observability port (`9090`) is published on loopback only - it is
not part of what you expose.

## 3. Choose what the tunnel reaches

The `home` profile is split tunnel: only the VPN subnet and the routes
you push go down the tunnel, the rest of the client's traffic stays
local. The profile pushes `192.168.1.0/24` as a starting point - set it
to your actual LAN:

```bash
-e CULVERT_PUSH_ROUTES=192.168.50.0/24
```

Want everything routed through home instead (for example to use its
public IP)? Switch to full tunnel:

```bash
-e CULVERT_FULL_TUNNEL=true
```

Addressing background - why the tunnel itself defaults to `10.8.0.0/22`
and when a home LAN could still clash - is in
[addressing.md](addressing.md).

## 4. Generate a client

```bash
docker exec -it <container> generate-client --name laptop
```

This writes a set of `.ovpn` files to the clients volume. For the home
case the one you want is `laptop-udp-split.ovpn` (UDP, split tunnel);
`laptop-udp-full.ovpn` is the full-tunnel variant. The TCP and HTTPS
variants are for later cases and need their listeners enabled server
side.

To remove access again:

```bash
docker exec -it <container> revoke-client laptop
```

## 5. Import and connect

Copy `laptop-udp-split.ovpn` to the client and import it. Platform steps
(OpenVPN Connect, Tunnelblick, the Linux CLI, always-on setups) are in
[vpn-client-setup.md](vpn-client-setup.md).

## See also

- [vpn-client-setup.md](vpn-client-setup.md) - installing and connecting
  the client
- [addressing.md](addressing.md) - the tunnel subnet defaults and when to
  override
- [use-case-corporate.md](use-case-corporate.md) - when you outgrow one
  shared config and want per-user certs plus SSO
- [README quick start](../README.md#quick-start) and the
  [profiles table](../README.md#deployment-profiles)
