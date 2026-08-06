# Performance, tuning, and the cipher stance

culvert's defaults err high-security first and resilient-everywhere second.
This note explains what actually moves the needle for a client on a hostile
network, what is a deployment/host concern rather than a culvert setting, and
why the shipped cipher is the "boring" one.

## Tuning profiles

Tuning is data, not code. It lives in `profiles/*.yaml`, loaded via
`CULVERT_PROFILE` (a shipped name, or a path to your own file). Two are
shipped:

- **default** - the general-purpose baseline: `mssfix 1420` (off the PPPoE
  fragmentation cliff), OS-auto socket buffers, WireGuard MTU 1420.
- **mobile** - constrained or extra-encapsulated paths (5G, phone tether,
  hotel/captive wifi, CGNAT): larger OpenVPN buffers, `tun-mtu`/`mssfix` 1400,
  tolerant keepalive, and **WireGuard MTU 1280**.

The one client-resilience knob that matters most is **MTU**. A 1420 WireGuard
tunnel black-holes on a ~1400 NAT64/CGNAT/PPPoE path: it connects, the
handshake completes, then large transfers stall silently because carriers
filter the ICMP that would signal "too big". 1280 is the IPv6 minimum every
network must carry, so it gets through with headroom. Everything else in the
profiles (buffers, keepalive) is smoothing; MTU is the difference between
"works" and "connects but hangs".

Copy a profile, change values, point `CULVERT_PROFILE` at your file. There are
no hidden presets in code.

## Ciphers: the compliance default, and the cryptographer's favourite

The data channel ships `data-ciphers AES-256-GCM:CHACHA20-POLY1305` - AES-256-GCM
first, ChaCha20-Poly1305 offered as the secondary.

Derek would prefer ChaCha20-Poly1305 as the default - it is one of his
favourites, and on the merits it is arguably the safer universal choice:
constant-time by construction (no cache-timing side-channels the way software
AES has without AES-NI), no hardware dependency, uniform speed from a Xeon to a
Cortex-A53. It is the default in TLS 1.3, SSH, and WireGuard for those reasons.

For compliance we go boring with **AES-256-GCM**. CNSA 2.0 and FIPS mandate
AES-256; ChaCha20 is on neither list. culvert's target deployments often *must*
tick that box, and for them "high security" means "the algorithm an auditor
accepts". So AES-256-GCM leads, and the CNSA-classical path (TLS 1.3, P-384,
SHA-384, tls-crypt-v2, AES-256-GCM) stays intact by default.

The cipher order is a per-profile knob (`data_ciphers`, or `CULVERT_DATA_CIPHERS`):

- **default** profile: `AES-256-GCM:CHACHA20-POLY1305` - the CNSA/FIPS lead,
  with ChaCha20 still offered as the secondary. This is the shipped default.
- **mobile** profile: `CHACHA20-POLY1305:AES-256-GCM` - ChaCha20 first, for the
  AES-NI-less clients that profile targets. **Choosing the mobile profile is
  the informed opt-in**: the operator picks it knowing it leaves the CNSA suite
  in exchange for mobile-client performance. AES-256-GCM stays offered as the
  fallback, so nothing weaker is ever negotiated.
- **Want ChaCha20 everywhere without OpenVPN at all?** Use **WireGuard** - its
  suite is fixed at ChaCha20-Poly1305 / Curve25519 / BLAKE2s, fast on every
  CPU, and it is the better mobile-roaming path (native re-handshake across
  network switches). WireGuard is outside CNSA by design.
- **Need CNSA/FIPS?** Use the default profile, and pin
  `CULVERT_DATA_CIPHERS=AES-256-GCM` to refuse the ChaCha20 fallback outright.

So the split: **AES-256-GCM is the compliance default; ChaCha20 is the
cryptographer's default (and a personal favourite -- DT).** The default profile
stays CNSA-safe; the mobile profile makes the ChaCha20 trade a deliberate,
labelled choice - the operator opts in knowing what they get. Never reorder the
default to ChaCha20-first; that would leave CNSA silently.

## Data Channel Offload (DCO) - a host readiness item, not a culvert setting

DCO moves OpenVPN's data-channel crypto into the kernel and multi-threads it,
the single biggest OpenVPN throughput win (independent tests show 130-200%,
and 1 -> 10 Gbit/s per tunnel on server hardware). It is a **host** property,
not something a profile can turn on:

- Mainline: the `ovpn` module landed in Linux **6.16**. That is recent; a
  2-3-year-old kernel is fine instead via the **ovpn-backports** DKMS project,
  which builds the module for older kernels. Either way needs OpenVPN 2.7+
  (culvert ships it) and an AEAD cipher with no compression (culvert's
  defaults already satisfy this).
- Without the module, OpenVPN silently runs its data channel in **userspace** -
  correct and secure, just slower, and single-core-per-tunnel. The startup log
  shows `DCO version: N/A`. Check it if throughput matters.

DCO is a server-scale throughput win; it does not change a single client's
resilience on a bad link. Prioritise it for a busy multi-client deployment,
not for a handful of road-warrior tunnels.

## Host sysctl - the other server-side lever

For lossy or high-latency (i.e. mobile) paths, set on the VPN host:

```
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.ip_forward = 1
```

BBR + `fq` and larger UDP socket buffers are the biggest server-side help on
long-fat or lossy networks. NIC offloads (GRO/GSO/TSO) can batch packets for a
large CPU saving, but they are tuned on the *physical* NIC, not the tunnel
interface, and can regress inside virtualised/tunnel-in-tunnel stacks
(Proxmox, VXLAN) - treat them as a diagnostic lever, not a blanket default.

## What does NOT earn a place

- Reordering OpenVPN to ChaCha20-first as a default - leaves CNSA (see above).
- OpenVPN `float` for roaming - it widens attack surface by accepting an
  authenticated session from a new source IP. Use WireGuard for roaming
  instead.
- Compression - disabled on purpose (VORACLE), and it also disables DCO.
