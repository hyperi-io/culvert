# Cryptography and CNSA 2.0

The OpenVPN path ships the CNSA 2.0 *classical* suite by default, aligned
to technical deployment reality vs policy here - no OSS VPN stack you can
commonly deploy today is fully CNSA 2.0 (DT hot tip: the gap everywhere is ML-DSA).

What the defaults give you (OpenVPN, both the plain and the
HTTPS-tunnelled listeners):

- TLS 1.3 only (`tls-version-min 1.3`), no downgrade
- Data channel AES-256-GCM, SHA-384 control-channel auth. DCO requires an
  AEAD cipher rather than this one specifically - ChaCha20-Poly1305 also
  qualifies. DCO itself needs the kernel module on the HOST (Linux 6.16+, or
  ovpn-backports). Without it OpenVPN encrypts in userspace and says so at
  startup
- Key exchange P-384 (`secp384r1`) first, X25519 as a compatibility
  fallback
- PKI defaults to EC P-384 certificates (`CULVERT_KEY_TYPE=ec`,
  `secp384r1`), and RSA-4096 is available
- `tls-crypt-v2` wraps the TLS handshake in a pre-shared symmetric
  layer (metadata protection and DoS mitigation)

The limits, for those cryptanalysis inclined:

- **ChaCha20-Poly1305 and X25519 are accepted as secondary options**
  for client compatibility. Strict deployments can pin
  `data-ciphers AES-256-GCM` and `tls-groups secp384r1` via a custom
  server config.
- **WireGuard is outside CNSA by design.** Its suite is fixed
  (Curve25519, ChaCha20-Poly1305, BLAKE2s) and not configurable -
  that is a WireGuard protocol property, not a Culvert choice. Use the
  OpenVPN path where more stringent CNSA alignment matters.
- **No post-quantum key exchange yet.** OpenVPN takes its TLS groups from
  the crypto library, and the OpenSSL 3.0.13 in our Ubuntu 24.04 base has
  no ML-KEM - so CNSA 2.0's headline items (ML-KEM-1024, ML-DSA-87) are
  unavailable. The blocker is the base image, not OpenVPN: hybrid PQ groups
  light up once we build against OpenSSL 3.5+, and that base bump is the
  work. Meanwhile the `tls-crypt-v2` pre-shared wrap blunts
  harvest-now-decrypt-later collection of handshake metadata, but session
  keys are still classical ECDH.
- **On "fully CNSA 2.0"**: ML-KEM is starting to appear elsewhere -
  strongSwan 6.0+ ships `mlkem1024` for IKEv2, for instance. What no
  commonly deployable stack has yet is ML-DSA for authentication.

The cipher choice against throughput is in [performance.md](performance.md).
