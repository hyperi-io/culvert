# Culvert Client Setup Guide

This guide covers installing and configuring OpenVPN and WireGuard clients on Linux, macOS, and Windows.

## Client Requirements

### Minimum Versions

| Client | Minimum Version | OAuth2/SSO Support | Download |
|--------|-----------------|-------------------|----------|
| **OpenVPN Connect** | 3.4.0+ | Yes | https://openvpn.net/client/ |
| **OpenVPN GUI (Windows)** | 2.6.0+ | Yes | https://openvpn.net/community-downloads/ |
| **OpenVPN (Linux CLI)** | 2.6.0+ | No (certificate only) | https://openvpn.net/community-downloads/ |
| **Tunnelblick (macOS)** | 3.8.8+ | No (certificate only) | https://tunnelblick.net/ |
| **WireGuard** | Any | N/A (key-based) | https://www.wireguard.com/install/ |

### OAuth2/SSO Authentication

If your organisation uses **OAuth2/OIDC SSO** (e.g., Microsoft Entra ID, Okta, Google):

> **Use OpenVPN Connect 3.4.0+ or OpenVPN GUI 2.6.0+ (Windows)**

These clients support the web-based OAuth2 authentication flow required for SSO. When connecting, your browser will open to complete authentication.

**Certificate-only authentication** works with any OpenVPN 2.6+ client.

**WireGuard** uses key-based authentication and does not support OAuth2/SSO. Keys are distributed via configuration files provided by the VPN administrator.

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

| File | Protocol | Use Case |
|------|----------|----------|
| `*-wg-split.conf` | UDP 51820 | **Recommended** - VPN routes only |
| `*-wg-full.conf` | UDP 51820 | All traffic through VPN |
| `*-wg-https-split.conf` | WSS 4443 (wstunnel) | over HTTPS, VPN routes only |
| `*-wg-https-full.conf` | WSS 4443 (wstunnel) | over HTTPS, all traffic |

**Which to use:**
1. Try **WireGuard** first (best performance, simplest setup)
2. If WireGuard is blocked, try **OpenVPN UDP** (UDP 1194)
3. If UDP blocked, try **OpenVPN TCP** (TCP 1194)
4. If still blocked, run the VPN **over HTTPS** - WireGuard via wstunnel (WSS 4443) or OpenVPN via stunnel (TCP 443)

---

## WireGuard Client Setup

### Installation

- **Windows:** Download from https://www.wireguard.com/install/
- **macOS:** `brew install wireguard-tools` or "WireGuard" from the App Store
- **Linux (Ubuntu/Debian):** `sudo apt install wireguard-tools`
- **Linux (Fedora/RHEL):** `sudo dnf install wireguard-tools`
- **Linux (Arch):** `sudo pacman -S wireguard-tools`
- **iOS/Android:** WireGuard app from the App Store / Play Store

### Importing Configuration

1. Request your configuration files from the VPN administrator
2. You will receive `{name}-wg-split.conf` and `{name}-wg-full.conf`
3. Import into your WireGuard client (drag and drop, or "Import tunnel from file")
4. Activate the tunnel

### Split vs Full Tunnel

- **Split tunnel** (`*-wg-split.conf`): Only VPN traffic goes through the tunnel. Internet traffic uses your normal connection.
- **Full tunnel** (`*-wg-full.conf`): All traffic goes through the tunnel. Use when you need full network isolation.

### Linux: Command Line

```bash
# Import and bring up the tunnel
sudo wg-quick up ./alice-wg-split.conf

# Check status
sudo wg show

# Bring down the tunnel
sudo wg-quick down ./alice-wg-split.conf
```

### Linux: Always-On WireGuard (systemd)

```bash
# Copy config to system directory
sudo cp alice-wg-split.conf /etc/wireguard/culvert.conf

# Enable and start
sudo systemctl enable wg-quick@culvert
sudo systemctl start wg-quick@culvert

# Check status
sudo systemctl status wg-quick@culvert
```

### macOS

**GUI (recommended):**

1. Install WireGuard from the App Store or `brew install wireguard-tools`
2. Open WireGuard, click "Import tunnel(s) from file"
3. Select your `.conf` file
4. Click "Activate"

**Command line:**

```bash
brew install wireguard-tools
sudo wg-quick up ./alice-wg-split.conf
```

### Windows

1. Download and install WireGuard from https://www.wireguard.com/install/
2. Open WireGuard, click "Import tunnel(s) from file"
3. Select your `.conf` file
4. Click "Activate"

---

## Running the VPN over HTTPS

### OpenVPN over HTTPS (stunnel)

The `*-https-*.ovpn` configs use stunnel to wrap OpenVPN in real TLS on port 443. Most OpenVPN clients handle this automatically. See the OpenVPN HTTPS tunnel sections below for platform-specific instructions.

### WireGuard over HTTPS (wstunnel)

For networks that block WireGuard (e.g. China GFW), use the HTTPS-tunnel configs (`*-wg-https-*.conf`). These require wstunnel on your machine.

#### Installing wstunnel

- **macOS:** `brew install wstunnel`
- **Linux:** Download the binary for your architecture from https://github.com/erebe/wstunnel/releases
- **Windows:** Download the `.exe` from https://github.com/erebe/wstunnel/releases

#### Connecting

1. Start wstunnel first:
   ```bash
   wstunnel client wss://vpn.example.com:4443 -L udp://51820:127.0.0.1:51820
   ```
   (Replace `vpn.example.com` with your VPN server hostname)

2. Then import and activate the `*-wg-https-*.conf` config in your WireGuard client

3. The VPN traffic is tunnelled over WebSocket/TLS on port 4443, which looks like normal HTTPS to firewalls

#### Wrapper Script (Linux/macOS)

```bash
#!/usr/bin/env bash
# Start wstunnel + WireGuard in one command
VPN_SERVER="vpn.example.com"
WS_PORT="4443"

wstunnel client "wss://${VPN_SERVER}:${WS_PORT}" -L udp://51820:127.0.0.1:51820 &
WSTUNNEL_PID=$!
sleep 2

sudo wg-quick up ./your-config-wg-https-split.conf

# Cleanup on exit
trap 'sudo wg-quick down ./your-config-wg-https-split.conf; kill $WSTUNNEL_PID' EXIT
wait
```

---

## OpenVPN Client Setup

### Linux

#### Install OpenVPN Connect (Recommended for OAuth2/SSO)

```bash
# Ubuntu/Debian - Add OpenVPN repository
curl -fsSL https://swupdate.openvpn.net/repos/openvpn-repo-pkg-key.pub | sudo gpg --dearmor -o /etc/apt/keyrings/openvpn.gpg
echo "deb [signed-by=/etc/apt/keyrings/openvpn.gpg] https://swupdate.openvpn.net/community/openvpn3/repos/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/openvpn3.list
sudo apt update
sudo apt install -y openvpn3

# Import and connect
openvpn3 config-import --config alice-udp-split.ovpn --name culvert
openvpn3 session-start --config culvert
```

Download: https://openvpn.net/client/

#### Install OpenVPN (Open Source - Certificate Only)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y openvpn

# Fedora/RHEL
sudo dnf install -y openvpn

# Arch
sudo pacman -S openvpn
```

**Minimum version:** 2.6.0 (run `openvpn --version` to check)

#### Direct Connection (UDP/TCP)

```bash
# Connect (runs in foreground, Ctrl+C to disconnect)
sudo openvpn --config alice-udp-split.ovpn

# Or run in background
sudo openvpn --config alice-udp-split.ovpn --daemon
sudo killall openvpn  # To disconnect
```

#### HTTPS Tunnel (stunnel + OpenVPN)

The HTTPS tunnel wraps OpenVPN in TLS on port 443, so on the wire it is an ordinary HTTPS session. That is what gets it through networks which only permit web traffic - and past filters that block VPN protocols by signature.

**Install stunnel:**

```bash
# Ubuntu/Debian
sudo apt install -y stunnel4

# Fedora/RHEL
sudo dnf install -y stunnel

# Arch
sudo pacman -S stunnel
```

**Connect via HTTPS tunnel:**

```bash
# Terminal 1: Start stunnel (keep running)
stunnel alice-stunnel.conf

# Terminal 2: Connect OpenVPN through stunnel
sudo openvpn --config alice-https-split.ovpn
```

**One-liner (background):**

```bash
stunnel alice-stunnel.conf &
sleep 2
sudo openvpn --config alice-https-split.ovpn --daemon
```

**Disconnect:**

```bash
sudo killall openvpn
killall stunnel
```

#### Linux: Always-On OpenVPN (systemd)

Create a systemd service for automatic VPN connection on boot.

**For direct connection (UDP/TCP):**

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

**For HTTPS tunnel (stunnel + OpenVPN):**

Create stunnel service:

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
```

Update stunnel config for daemon mode:

```bash
sudo mkdir -p /etc/openvpn/client
sudo cp alice-stunnel.conf /etc/openvpn/client/culvert-stunnel.conf

# Edit to run as daemon (change foreground = yes to foreground = no)
sudo sed -i 's/foreground = yes/foreground = no/' /etc/openvpn/client/culvert-stunnel.conf
```

Copy OpenVPN config:

```bash
sudo cp alice-https-split.ovpn /etc/openvpn/client/culvert-https.conf
```

Create OpenVPN service dependency:

```bash
sudo mkdir -p /etc/systemd/system/openvpn-client@culvert-https.service.d
sudo tee /etc/systemd/system/openvpn-client@culvert-https.service.d/override.conf << 'EOF'
[Unit]
Requires=stunnel-vpn.service
After=stunnel-vpn.service
EOF
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable stunnel-vpn.service
sudo systemctl enable openvpn-client@culvert-https
sudo systemctl start stunnel-vpn.service
sudo systemctl start openvpn-client@culvert-https

# Check status
sudo systemctl status stunnel-vpn.service
sudo systemctl status openvpn-client@culvert-https
```

### macOS

#### Option 1: OpenVPN Connect (Recommended - Required for OAuth2/SSO)

Download: https://openvpn.net/client/ or from the Mac App Store

**Minimum version:** 3.4.0

1. Download and install OpenVPN Connect
2. Open the app and click **Import Profile** -> **FILE**
3. Select your `.ovpn` file
4. Click **Connect**

If OAuth2/SSO is enabled, your browser will open for authentication.

#### Option 2: Tunnelblick (Certificate Only)

[Tunnelblick](https://tunnelblick.net/) is a free, open-source OpenVPN GUI for macOS.

**Minimum version:** 3.8.8

1. Download and install from https://tunnelblick.net/
2. Double-click the `.ovpn` file to import
3. Click the Tunnelblick icon in the menu bar
4. Select "Connect" for your VPN configuration

> **Note:** Tunnelblick does not support OAuth2/SSO or stunnel. Use for certificate-only authentication with direct UDP/TCP connections.

#### Option 3: Command Line (Certificate Only)

```bash
# Install via Homebrew
brew install openvpn

# Connect (may need to run with sudo)
sudo /opt/homebrew/sbin/openvpn --config alice-udp-split.ovpn
```

#### HTTPS Tunnel on macOS

```bash
# Install stunnel
brew install stunnel

# Start stunnel
stunnel alice-stunnel.conf &

# Connect OpenVPN
sudo /opt/homebrew/sbin/openvpn --config alice-https-split.ovpn
```

### Windows

#### Option 1: OpenVPN Connect (Recommended - Required for OAuth2/SSO)

Download: https://openvpn.net/client/

**Minimum version:** 3.4.0

1. Download and install OpenVPN Connect
2. Open the app and click **Import Profile** -> **FILE**
3. Select your `.ovpn` file
4. Click **Connect**

If OAuth2/SSO is enabled, your browser will open for authentication.

#### Option 2: OpenVPN GUI (Supports OAuth2/SSO)

Download: https://openvpn.net/community-downloads/

**Minimum version:** 2.6.0

1. Download and install OpenVPN (includes GUI)
2. Copy `.ovpn` file to `C:\Users\<username>\OpenVPN\config\`
3. Right-click the OpenVPN GUI icon in system tray
4. Select your configuration and click **Connect**

If OAuth2/SSO is enabled, your browser will open for authentication.

#### HTTPS Tunnel on Windows

1. **Install stunnel:**
   - Download from https://www.stunnel.org/downloads.html
   - Run the installer

2. **Configure stunnel:**
   - Copy `alice-stunnel.conf` to `C:\Program Files (x86)\stunnel\config\`
   - Edit the file and update paths if needed:
     ```ini
     # Windows paths use forward slashes or escaped backslashes
     CApath = C:/Program Files (x86)/stunnel/certs
     ```

3. **Start stunnel:**
   - Run stunnel from Start Menu, or
   - Open Command Prompt as Administrator:
     ```cmd
     "C:\Program Files (x86)\stunnel\bin\stunnel.exe" "C:\Program Files (x86)\stunnel\config\alice-stunnel.conf"
     ```

4. **Connect OpenVPN:**
   - Import and connect the `*-https-split.ovpn` file as normal

#### Windows: Always-On OpenVPN

**Using OpenVPN Connect:**

1. Open OpenVPN Connect settings
2. Enable "Launch on Windows startup"
3. Enable "Connect on launch" for your profile

**Using OpenVPN GUI:**

1. Install OpenVPN with the option "Launch on Windows startup"
2. Copy `.ovpn` to `C:\Users\<username>\OpenVPN\config\`
3. Right-click the config in system tray -> **Connect on startup**

**Using OpenVPN Service:**

1. Copy `.ovpn` to `C:\Program Files\OpenVPN\config\`
2. Rename to `client.ovpn`
3. Open Services (services.msc)
4. Find "OpenVPN Service" -> Set to "Automatic"
5. Start the service

---

## Troubleshooting

### OAuth2/SSO Issues

- **"Browser doesn't open"**: Ensure you're using OpenVPN Connect 3.4.0+
- **"Authentication failed"**: Check with your administrator that your account has VPN access
- **"Redirect URL mismatch"**: Contact administrator - OAuth2 callback URL may be misconfigured

### Connection Timeouts

1. **Check firewall:** Ensure outbound UDP/TCP 1194 or TCP 443 is allowed
2. **Try different protocol:** If UDP fails, try TCP; if TCP fails, try HTTPS tunnel
3. **Check DNS:** Verify your VPN server hostname resolves correctly from the client

### TLS Handshake Failed

- Ensure system time is accurate (TLS certificates are time-sensitive)
- Check if your network blocks VPN protocols (use HTTPS tunnel)
- Verify you're using OpenVPN 2.6.0+ (older versions may not support TLS 1.3)

### HTTPS Tunnel Issues

- Verify stunnel is running before starting OpenVPN
- Check stunnel logs for certificate verification errors
- Ensure the `.ovpn` file connects to `127.0.0.1:1195` (local stunnel)

### WireGuard Issues

- **"Handshake did not complete"** - check that the server is reachable on port 51820 (or 4443 for the HTTPS tunnel)
- **DNS not working** - check DNS settings in the `.conf` file
- **Connected but no internet** - try the split tunnel config instead of full tunnel
- **wstunnel connection refused** - ensure WireGuard over HTTPS is enabled on the server (`CULVERT_WG_HTTPS_TUNNEL_ENABLED=true`)

#### Handshake succeeds but nothing flows, in a container

Running the client inside a container or a Kubernetes pod, on a full tunnel
(`AllowedIPs = 0.0.0.0/0`)? Look for this line in the `wg-quick up` output:

```
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

- **Split tunnel:** Only routes to your site's internal networks go through the VPN
- **Full tunnel:** All traffic goes through VPN (including internet)

Use split tunnel for normal work; use full tunnel for maximum security.

---

## Security Notes

- Keep `.ovpn` and `.conf` files secure - they contain your VPN credentials or keys
- OpenVPN uses TLS 1.3 with AES-256-GCM encryption (the CNSA 2.0 classical suite)
- tls-crypt-v2 provides metadata protection and DoS mitigation
- HTTPS tunnel adds an additional layer of TLS 1.3 encryption
- WireGuard uses ChaCha20-Poly1305 encryption with Curve25519 key exchange
- WireGuard over HTTPS (wstunnel) adds a WebSocket/TLS layer on port 4443

---

## Support

For issues, contact your system administrator or open a ticket.

### Internal networks accessible via VPN

The list of internal networks routed through the VPN is configured by
your administrator via `CULVERT_PUSH_ROUTES`. Consult your site's
documentation for the specific routes.
