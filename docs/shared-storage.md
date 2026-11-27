# Several OpenVPN instances on shared storage

`docker-compose.shared.yaml` unsets `container_name` and mounts one PKI, clients and `ccd` directory from `SHARED_STORAGE_PATH`, so several instances of the compose service can run behind one address. The Helm chart stays one replica. Use the overlay with the base file:

```bash
docker compose -f docker-compose.yaml -f docker-compose.shared.yaml up -d
```

The instances share the CA, the server certificate, `tc.key` and `crl.pem` under the PKI directory. Local mode keeps `tc.key` there, so every instance holds the same one. External PKI needs `CULVERT_SECRETS_TC_KEY_PATH`, or a client issued by one instance is rejected by the others ([PKI invariants](../CONTRIBUTING.md#pki-invariants)).

The code has no answer to these limits:

- Nothing locks the PKI. Start one instance and let it finish building the CA before starting the rest, because the check for an existing PKI and the `build-ca` that follows it are not atomic.
- Issue and revoke clients from one instance at a time. Culvert takes no lock around Easy-RSA's index and serial files, and the only `flock` in the scripts guards WireGuard's peer list.
- Under local PKI every instance regenerates the same `crl.pem` on its own refresh timer. Revoke on any instance and the others read the new file on their next handshake.
- Each instance hands out tunnel addresses from its own pool of the same network, and the server templates have no `ifconfig-pool-persist`. Two clients on different instances can hold one tunnel address. Pin an address with a `ccd` entry, which every instance reads.
- WireGuard is single-instance. A peer issued or revoked on one instance updates that instance's running `wg0` only.
- Logs stay on each instance's own volume unless you swap in the shared line.

Up: [docs index](README.md).
