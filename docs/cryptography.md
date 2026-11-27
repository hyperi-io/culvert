# Cryptography and CNSA 2.0

The OpenVPN path ships the CNSA 2.0 *classical* suite by default, aligned
to what can be deployed rather than to the policy text. No commonly deployable
OSS VPN stack is fully CNSA 2.0, and the gap everywhere is ML-DSA.

What the defaults give you (OpenVPN, both the plain and the
HTTPS-tunnelled listeners):

- TLS 1.3 only (`tls-version-min 1.3`), no downgrade
- Data channel AES-256-GCM, SHA-384 control-channel auth. DCO needs an
  AEAD cipher rather than this one specifically - ChaCha20-Poly1305
  qualifies as well. DCO itself needs the `ovpn` kernel module on the HOST (Linux
  6.16+, or ovpn-backports). Without it OpenVPN encrypts in userspace and says
  so at startup
- Key exchange hybrid ML-KEM first: `SecP384r1MLKEM1024` (P-384 plus
  ML-KEM-1024), then `X25519MLKEM768`, then classical P-384 (`secp384r1`) and
  X25519 for clients whose OpenSSL predates ML-KEM. The image's OpenSSL 3.5
  carries the hybrid groups
- PKI defaults to EC P-384 certificates (`CULVERT_KEY_TYPE=ec`,
  `CULVERT_KEY_SIZE=secp384r1`), and RSA-4096 is available
  (`CULVERT_KEY_TYPE=rsa`, `CULVERT_KEY_SIZE=4096`)
- `tls-crypt-v2` wraps the TLS handshake in a pre-shared symmetric
  layer (metadata protection and DoS mitigation)

The limits, for those cryptanalysis inclined:

- ChaCha20-Poly1305 and X25519 are accepted as secondary options for client
  compatibility. Strict deployments pin the data channel with
  `CULVERT_DATA_CIPHERS=AES-256-GCM`.
  `tls-groups SecP384r1MLKEM1024:X25519MLKEM768:secp384r1:X25519` is written
  into the server templates under `config/`, so dropping X25519 or the
  classical fallback means mounting your templates over
  `/etc/vpn/server/*.conf.template`.
- WireGuard is outside CNSA by design. Its suite is fixed (Curve25519,
  ChaCha20-Poly1305, BLAKE2s) and not configurable, a property of the WireGuard
  protocol. Use the OpenVPN path where CNSA alignment matters.
- Post-quantum key exchange is hybrid, and the client decides which group it
  gets. A client on OpenSSL 3.5 or later with its default groups negotiates
  `X25519MLKEM768` (ML-KEM-768). CNSA 2.0's ML-KEM-1024 needs a client that
  offers `SecP384r1MLKEM1024` in its own `tls-groups`. The issued client
  configs set no `tls-groups`, because an older client refuses a group name it
  does not know. A client on an older OpenSSL negotiates classical P-384 or
  X25519, whichever its key share carries, and its session keys stay open to
  harvest-now-decrypt-later. The `tls-crypt-v2` pre-shared wrap protects only
  the handshake metadata. ML-DSA-87 authentication is not offered: the
  certificates are P-384 or RSA.
- On "fully CNSA 2.0": ML-KEM appears elsewhere - strongSwan 6.0+ ships
  `mlkem1024` for IKEv2, for instance. What no commonly deployable stack has is
  ML-DSA for authentication.

The cipher choice against throughput is in [performance.md](performance.md).
