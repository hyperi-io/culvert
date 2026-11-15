# Culvert Client Setup Guide

This guide covers installing and configuring OpenVPN and WireGuard clients on Linux, macOS, and Windows.

## Client Requirements

### Minimum Versions

| Client | Minimum Version | OAuth2/SSO Support | Download |
|--------|-----------------|-------------------|----------|
| **OpenVPN Connect** | 3.4.0+ | Yes | <https://openvpn.net/client/> |
| **OpenVPN GUI (Windows)** | 2.6.0+ | Yes | <https://openvpn.net/community-downloads/> |
| **OpenVPN (Linux CLI)** | 2.6.0+ | No (certificate only) | <https://openvpn.net/community-downloads/> |
| **Tunnelblick (macOS)** | 3.8.8+ | No (certificate only) | <https://tunnelblick.net/> |
| **WireGuard** | Any | N/A (key-based) | <https://www.wireguard.com/install/> |

### OAuth2/SSO Authentication

If your organisation uses OAuth2/OIDC SSO (e.g., Microsoft Entra ID, Okta, Google), use OpenVPN Connect 3.4.0+ or OpenVPN GUI 2.6.0+ (Windows). These clients support the web-based OAuth2 authentication flow required for SSO. When connecting, your browser will open to complete authentication.

Certificate-only authentication works with any OpenVPN 2.6+ client.

WireGuard uses key-based authentication and does not support OAuth2/SSO. Keys are distributed via configuration files provided by the VPN administrator.

---

## Configuration Files Included

### OpenVPN

| File | Protocol | Use Case |
|------|----------|----------|
| `*-udp-split.ovpn` | UDP 1194 | **Recommended** - Fastest, VPN routes only |
| `*-udp-full.ovpn` | UDP 1194 | All traffic through VPN |
| `*-tcp-split.ovpn` | TCP 1194 | Fallback when UDP blocked |
| `*-tcp-full.ovpn` | TCP 1194 | All traffic, TCP fallback |
| `*-https-split.ovpn` | TCP 443 (stunnel) | over HTTPS, VPN routes only |
| `*-https-full.ovpn` | TCP 443 (stunnel) | over HTTPS, all traffic |
| `*-stunnel.conf` | - | stunnel config for HTTPS tunnel |

### WireGuard

WireGuard configs come in a folder named for you, because the file name is the
name of the tunnel and Linux and Android allow it 15 characters.

| File | Protocol | Use Case |
|------|----------|----------|
| `wg-split.conf` | UDP 51820 | **Recommended** - VPN routes only |
| `wg-full.conf` | UDP 51820 | All traffic through VPN |
| `wg-https-split.conf` | WSS 4443 (wstunnel) | over HTTPS, VPN routes only |
| `wg-https-full.conf` | WSS 4443 (wstunnel) | over HTTPS, all traffic |

### Using more than one device

The same `.ovpn` works on a laptop and a phone at once. WireGuard does not: a
key connects from one place at a time, so you get a set of files per device -
`wg-split.conf` for the first, `wg2-split.conf` for the second. Load one set
per device, or they will keep knocking each other offline.

Which to use:

1. Try WireGuard first (best performance, simplest setup)
2. If WireGuard is blocked, try OpenVPN UDP (UDP 1194)
3. If UDP blocked, try OpenVPN TCP (TCP 1194)
4. If still blocked, run the VPN over HTTPS - WireGuard via wstunnel (WSS 4443) or OpenVPN via stunnel (TCP 443)

### When to get a new file

These files are a snapshot of the server's settings when they were issued. Ask your administrator for a new set after the server's address, ports, DNS, MTU, routes or keys change. Restarting the server does not update a file already imported on a device.

---

## WireGuard Client Setup

### Installation

- Windows: download from <https://www.wireguard.com/install/>
- macOS: `brew install wireguard-tools` or "WireGuard" from the App Store
- Linux (Ubuntu/Debian): `sudo apt install wireguard-tools`
- Linux (Fedora/RHEL): `sudo dnf install wireguard-tools`
- Linux (Arch): `sudo pacman -S wireguard-tools`
- iOS/Android: WireGuard app from the App Store / Play Store

### Importing Configuration

1. Request your configuration files from the VPN administrator
2. You will receive `wg-split.conf` and `wg-full.conf`, in a folder named for you
3. Import into your WireGuard client (drag and drop, or "Import tunnel from file")
4. Activate the tunnel

The split tunnel (`wg-split.conf`) sends only VPN traffic through the tunnel, and internet traffic uses your normal connection. The full tunnel (`wg-full.conf`) sends all traffic through it. Use it when you need full network isolation.

### Linux: Command Line

```bash
# Import and bring up the tunnel
sudo wg-quick up ./wg-split.conf

# Check status
sudo wg show

# Bring down the tunnel
sudo wg-quick down ./wg-split.conf
```

### Linux: Always-On WireGuard (systemd)

```bash
# Copy config to system directory
sudo cp wg-split.conf /etc/wireguard/culvert.conf

# Enable and start
sudo systemctl enable wg-quick@culvert
sudo systemctl start wg-quick@culvert

# Check status
sudo systemctl status wg-quick@culvert
```

### macOS and Windows

1. Install WireGuard from the App Store (macOS) or <https://www.wireguard.com/install/> (Windows)
2. Open WireGuard, click "Import tunnel(s) from file"
3. Select your `.conf` file
4. Click "Activate"

On macOS the command line works too: `brew install wireguard-tools`, then `sudo wg-quick up ./wg-split.conf`.

---

## Running the VPN over HTTPS

Use these configs where the network blocks the VPN protocols themselves but
allows ordinary HTTPS: tight corporate egress, hotel and conference wifi,
captive portals, cloud egress policy.

To on-path inspection the traffic is TLS on 443 (or 4443) presenting a valid
certificate for your server name, so a network that drops "things that look
like OpenVPN or WireGuard" does not see either. It is NOT tested against, and
makes no claim about, a censor that actively probes your endpoint or does
traffic-flow analysis on timing, volume and connection duration. Treat this as
"indistinguishable from HTTPS at a glance", not as invisibility, and do not rely
on it where being wrong carries a personal risk.

### OpenVPN over HTTPS (stunnel)

The `*-https-*.ovpn` configs connect to stunnel on `127.0.0.1:1195`, and stunnel wraps the session in TLS to the server on port 443. No OpenVPN client starts stunnel for you: run it with the matching `*-stunnel.conf` first. The OpenVPN sections below show it per platform.

### WireGuard over HTTPS: install wstunnel

The HTTPS-tunnel configs (`wg-https-*.conf`) need wstunnel on your machine.

- macOS: `brew install wstunnel`
- Linux: download the binary for your architecture from <https://github.com/erebe/wstunnel/releases>
- Windows: download the `.exe` from <https://github.com/erebe/wstunnel/releases>

### WireGuard over HTTPS: connect

1. Start wstunnel first:

   ```bash
   wstunnel client -L udp://127.0.0.1:51820:127.0.0.1:51820 \
     --tls-verify-certificate wss://vpn.example.com:4443
   ```

   (Replace `vpn.example.com` with your VPN server hostname. The first lines of
   each `wg-https-*.conf` carry the exact command for that config, including
   `--tls-sni-override` when the server is dialled by address.)

   A full tunnel would route wstunnel's own connection into the tunnel it
   carries. Before you activate `wg-https-full.conf`, route the server's address
   through the gateway you use now, for example
   `sudo ip route add 203.0.113.10 via 192.168.1.1` on Linux. The config's first
   lines give the macOS and Windows forms.

2. Then import and activate the `wg-https-*.conf` config in your WireGuard client

3. The VPN traffic is tunnelled over WebSocket/TLS on port 4443, which looks like normal HTTPS to firewalls

### WireGuard over HTTPS: one script (Linux/macOS)

```bash
#!/usr/bin/env bash
# Start wstunnel + WireGuard in one command
VPN_SERVER="vpn.example.com"
WS_PORT="4443"

wstunnel client -L udp://127.0.0.1:51820:127.0.0.1:51820 \
  --tls-verify-certificate "wss://${VPN_SERVER}:${WS_PORT}" &
WSTUNNEL_PID=$!
sleep 2

sudo wg-quick up ./wg-https-split.conf

# Cleanup on exit
trap 'sudo wg-quick down ./wg-https-split.conf; kill $WSTUNNEL_PID' EXIT
wait
```

---

## OpenVPN on Linux

### OpenVPN 3 (for OAuth2/SSO)

```bash
# Ubuntu/Debian - add the OpenVPN 3 repository
curl -fsSL https://packages.openvpn.net/packages-repo.gpg | sudo gpg --dearmor -o /etc/apt/keyrings/openvpn3.gpg
echo "deb [signed-by=/etc/apt/keyrings/openvpn3.gpg] https://packages.openvpn.net/openvpn3/debian $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/openvpn3.list
sudo apt update
sudo apt install -y openvpn3

# Import and connect
openvpn3 config-import --config alice-udp-split.ovpn --name culvert
openvpn3 session-start --config culvert
```

### OpenVPN 2 (open source, certificate only)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y openvpn

# Fedora/RHEL
sudo dnf install -y openvpn

# Arch
sudo pacman -S openvpn
```

The minimum version is 2.6.0 (run `openvpn --version` to check).

### Direct Connection (UDP/TCP)

```bash
# Connect (runs in foreground, Ctrl+C to disconnect)
sudo openvpn --config alice-udp-split.ovpn

# Or run in background
sudo openvpn --config alice-udp-split.ovpn --daemon
sudo killall openvpn  # To disconnect
```

### HTTPS Tunnel (stunnel + OpenVPN)

The HTTPS tunnel wraps OpenVPN in TLS on port 443, so on the wire it is an ordinary HTTPS session. That gets it through networks which only permit web traffic, and past filters that block VPN protocols by signature.

```bash
# Install stunnel: Ubuntu/Debian, Fedora/RHEL, Arch
sudo apt install -y stunnel4
sudo dnf install -y stunnel
sudo pacman -S stunnel

# Terminal 1: Start stunnel (keep running)
stunnel alice-stunnel.conf

# Terminal 2: Connect OpenVPN through stunnel
sudo openvpn --config alice-https-split.ovpn
```

In the background instead, and to disconnect:

```bash
stunnel alice-stunnel.conf &
sleep 2
sudo openvpn --config alice-https-split.ovpn --daemon

sudo killall openvpn
killall stunnel
```

### Always-On OpenVPN (systemd)

For a direct connection (UDP/TCP):

```bash
# Copy config to system directory
sudo mkdir -p /etc/openvpn/client
sudo cp alice-udp-split.ovpn /etc/openvpn/client/culvert.conf

# Enable and start
sudo systemctl enable openvpn-client@culvert
sudo systemctl start openvpn-client@culvert

# Check status
sudo systemctl status openvpn-client@culvert
```

For the HTTPS tunnel, run stunnel as its own service and make the OpenVPN unit depend on it:

```bash
sudo tee /etc/systemd/system/stunnel-vpn.service << 'EOF'
[Unit]
Description=stunnel VPN tunnel
Before=openvpn-client@culvert-https.service

[Service]
Type=forking
ExecStart=/usr/bin/stunnel /etc/openvpn/client/culvert-stunnel.conf
ExecStop=/usr/bin/killall stunnel
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# stunnel config, switched to daemon mode
sudo mkdir -p /etc/openvpn/client
sudo cp alice-stunnel.conf /etc/openvpn/client/culvert-stunnel.conf
sudo sed -i 's/foreground = yes/foreground = no/' /etc/openvpn/client/culvert-stunnel.conf

# OpenVPN config
sudo cp alice-https-split.ovpn /etc/openvpn/client/culvert-https.conf

# OpenVPN service dependency
sudo mkdir -p /etc/systemd/system/openvpn-client@culvert-https.service.d
sudo tee /etc/systemd/system/openvpn-client@culvert-https.service.d/override.conf << 'EOF'
[Unit]
Requires=stunnel-vpn.service
After=stunnel-vpn.service
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable stunnel-vpn.service
sudo systemctl enable openvpn-client@culvert-https
sudo systemctl start stunnel-vpn.service
sudo systemctl start openvpn-client@culvert-https

# Check status
sudo systemctl status stunnel-vpn.service
sudo systemctl status openvpn-client@culvert-https
```

---

## OpenVPN on macOS and Windows

### macOS: OpenVPN Connect (required for OAuth2/SSO)

Download it from <https://openvpn.net/client/> or the Mac App Store. The minimum version is 3.4.0.

1. Download and install OpenVPN Connect
2. Open the app and click **Import Profile** -> **FILE**
3. Select your `.ovpn` file
4. Click **Connect**

If OAuth2/SSO is enabled, your browser will open for authentication.

### macOS: Tunnelblick or the command line (certificate only)

[Tunnelblick](https://tunnelblick.net/) is a free, open-source OpenVPN GUI for macOS, minimum version 3.8.8. Install it, double-click the `.ovpn` file to import it, then pick "Connect" for the configuration from the menu bar icon. Tunnelblick does not support OAuth2/SSO or stunnel, so use it for certificate-only direct UDP/TCP connections.

```bash
# Command line, via Homebrew
brew install openvpn
sudo /opt/homebrew/sbin/openvpn --config alice-udp-split.ovpn

# HTTPS tunnel
brew install stunnel
stunnel alice-stunnel.conf &
sudo /opt/homebrew/sbin/openvpn --config alice-https-split.ovpn
```

### Windows: OpenVPN Connect or OpenVPN GUI

OpenVPN Connect (<https://openvpn.net/client/>, minimum 3.4.0) supports OAuth2/SSO:

1. Download and install OpenVPN Connect
2. Open the app and click **Import Profile** -> **FILE**
3. Select your `.ovpn` file
4. Click **Connect**

OpenVPN GUI (<https://openvpn.net/community-downloads/>, minimum 2.6.0) also supports OAuth2/SSO:

1. Download and install OpenVPN (includes GUI)
2. Copy `.ovpn` file to `C:\Users\<username>\OpenVPN\config\`
3. Right-click the OpenVPN GUI icon in system tray
4. Select your configuration and click **Connect**

With OAuth2/SSO enabled, either one opens your browser for authentication.

### Windows: HTTPS Tunnel

1. Install stunnel from <https://www.stunnel.org/downloads.html>
2. Copy `alice-stunnel.conf` to `C:\Program Files (x86)\stunnel\config\` and update its paths if needed. Windows paths use forward slashes or escaped backslashes:

   ```ini
   CApath = C:/Program Files (x86)/stunnel/certs
   ```

3. Start stunnel from the Start Menu, or from a Command Prompt run as Administrator:

   ```cmd
   "C:\Program Files (x86)\stunnel\bin\stunnel.exe" "C:\Program Files (x86)\stunnel\config\alice-stunnel.conf"
   ```

4. Import and connect the `*-https-split.ovpn` file as normal

### Windows: Always-On OpenVPN

- OpenVPN Connect: in its settings, enable "Launch on Windows startup", then "Connect on launch" for your profile.
- OpenVPN GUI: install OpenVPN with "Launch on Windows startup", copy the `.ovpn` to `C:\Users\<username>\OpenVPN\config\`, then right-click the config in the system tray -> **Connect on startup**.
- OpenVPN Service: copy the `.ovpn` to `C:\Program Files\OpenVPN\config-auto\`, then set `OpenVPNService` to start automatically and start it (`sc config OpenVPNService start= auto`, then `sc start OpenVPNService`). The service starts every config in that folder, and needs the installer's "OpenVPN Service" component.

---

## Troubleshooting

### OAuth2/SSO Issues

- "Browser doesn't open": check you're using OpenVPN Connect 3.4.0+
- "Authentication failed": check with your administrator that your account has VPN access
- "Redirect URL mismatch": contact your administrator, the OAuth2 callback URL may be misconfigured

### Connection Timeouts

1. Check the firewall: outbound UDP/TCP 1194 or TCP 443 must be allowed
2. Try a different protocol: if UDP fails, try TCP, and if TCP fails, try the HTTPS tunnel
3. Check DNS: verify your VPN server hostname resolves correctly from the client

### TLS Handshake Failed

- Check the system time is accurate (TLS certificates are time-sensitive)
- Check if your network blocks VPN protocols (use HTTPS tunnel)
- Verify you're using OpenVPN 2.6.0+ (older versions may not support TLS 1.3)

### HTTPS Tunnel Issues

- Verify stunnel is running before starting OpenVPN
- Check stunnel logs for certificate verification errors
- Check the `.ovpn` file connects to `127.0.0.1:1195` (local stunnel)

### WireGuard Issues

- "Handshake did not complete": check that the server is reachable on port 51820 (or 4443 for the HTTPS tunnel)
- DNS not working: check DNS settings in the `.conf` file
- Connected but no internet: try the split tunnel config instead of full tunnel
- wstunnel connection refused: WireGuard over HTTPS must be enabled on the server (`CULVERT_WG_HTTPS_TUNNEL_ENABLED=true`)

### WireGuard in a container: handshake succeeds but nothing flows

Running the client inside a container or a Kubernetes pod, on a full tunnel
(`AllowedIPs = 0.0.0.0/0`)? Look for this line in the `wg-quick up` output:

```text
[#] sysctl -q net.ipv4.conf.all.src_valid_mark=1
sysctl: setting key "net.ipv4.conf.all.src_valid_mark", ignoring: Read-only file system
```

wg-quick routes a full tunnel with an fwmark and a policy rule, and that needs
`src_valid_mark=1` or strict reverse-path filtering discards every encrypted
packet coming back. A container's `/proc/sys` is read-only however many
capabilities it holds, so wg-quick's own attempt fails - and it fails quietly,
leaving a tunnel that shows a recent handshake and carries no data. `wg show`
gives it away: a few hundred bytes sent, ~92 bytes received, and nothing more.

Two ways out:

- Set the sysctl from a privileged container in the same network namespace
  before the client starts. In Kubernetes that is an init container:
  `command: ["sysctl", "-w", "net.ipv4.conf.all.src_valid_mark=1"]` with
  `securityContext.privileged: true`.
- Or use the split tunnel config, which routes normally and needs no sysctl.

This is a client-side container limitation, not a server setting - the same
config works unchanged on a normal host.

### Split vs Full Tunnel

- Split tunnel: only routes to your site's internal networks go through the VPN
- Full tunnel: all traffic, internet included. OpenVPN refuses IPv6 while it is up, as the tunnel carries IPv4 only.

---

## Security Notes and Support

- Keep `.ovpn` and `.conf` files secure - they contain your VPN credentials or keys
- OpenVPN uses TLS 1.3 with AES-256-GCM encryption (the CNSA 2.0 classical suite)
- tls-crypt-v2 provides metadata protection and DoS mitigation
- HTTPS tunnel adds an additional layer of TLS 1.3 encryption
- WireGuard uses ChaCha20-Poly1305 encryption with Curve25519 key exchange
- WireGuard over HTTPS (wstunnel) adds a WebSocket/TLS layer on port 4443

For issues, contact your system administrator or open a ticket. The internal networks routed through the VPN are set by your administrator through `CULVERT_PUSH_ROUTES`, so your site's own documentation lists them.
