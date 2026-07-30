# Corporate access

Per-user certificates plus human SSO against your identity provider,
group gating, and a TCP fallback for hostile guest networks. This is the
`corporate` profile. Every connection then needs BOTH a valid client
certificate AND a live IdP login - the certificate proves the device,
the OIDC login proves the person.

## What the profile sets

`CULVERT_PROFILE=corporate` turns on:

- OpenVPN UDP primary plus a TCP fallback (hotel / captive-portal
  networks routinely drop UDP)
- OIDC SSO (`oauth2_enabled`)
- group gating (`oauth2_validate_groups`, default `vpn-users`)
- full tunnel (common for compliance - all client traffic inspected and
  routed via the VPN; flip `CULVERT_FULL_TUNNEL=false` for split)
- a local CA to start

The profile sets the shape only. The OIDC secrets are yours to supply.

## 1. Supply the OIDC config

These come from the environment or your secret store - never commit them
into a profile or image:

| Variable | What it is |
|----------|------------|
| `CULVERT_OAUTH2_ISSUER` | Your IdP's issuer URL (discovery does the rest) |
| `CULVERT_OAUTH2_CLIENT_ID` | The app registration's client ID |
| `CULVERT_OAUTH2_CLIENT_SECRET` | Secret - from env / secret store |
| `CULVERT_OAUTH2_TLS_CERT` | TLS cert for the callback listener (most IdPs require HTTPS redirect URIs) |
| `CULVERT_OAUTH2_TLS_KEY` | Key for that cert |

`CULVERT_OAUTH2_HTTP_SECRET` (session secret,
`openssl rand -hex 16`) is also required. The `CLIENT_SECRET`, `TLS_KEY`
and `HTTP_SECRET` are secrets - inject them via Kubernetes Secrets, a
secret store, or the External Secrets Operator, not into git. See the
Secrets Management section of [.env.example](../.env.example) for
identity-based ESO wiring on AWS / Azure / GCP / OpenBao.

OIDC works with any OIDC-compliant provider via discovery. Tested with
Microsoft Entra ID, Google Workspace, Okta, Keycloak, and Auth0. Issuer
URL examples are in [.env.example](../.env.example); provider setup
snippets are in [vpn-client-setup.md](vpn-client-setup.md).

## 2. Gate on a group

Restrict access to members of an IdP group:

```bash
-e CULVERT_OAUTH2_VALIDATE_GROUPS=vpn-users
```

Use your IdP's group identifier - GUIDs for Entra ID, names for most
others. Delete the value to allow any authenticated user. A user outside
the group cannot connect even with a valid certificate.

## 3. Publish the ports

- `1194/udp` - primary
- `1194/tcp` - fallback for networks that drop UDP
- `9000-9002/tcp` - the OAuth2 callback listeners

openvpn-auth-oauth2 runs one callback instance per enabled OpenVPN
listener: UDP uses `9000`, HTTPS `9001`, TCP `9002`. With the corporate
profile (UDP + TCP) you need `9000` and `9002`; publishing the whole
`9000-9002` range is simplest. These ports must be reachable and their
`https://<server>:<port>/oauth2/callback` URLs registered with your IdP.

## 4. Per-user lifecycle

One certificate per person, not one shared config:

```bash
# issue
docker exec -it <container> generate-client --name jsmith

# offboard
docker exec -it <container> revoke-client jsmith
```

`revoke-client` revokes the certificate, regenerates the CRL, and
removes the client's files. The server enforces the CRL, so a revoked
device is refused on its next reconnect - independent of whether the
person can still log in to the IdP. Both gates stand on their own:
revoke the cert to kill the device, disable the IdP account or drop the
group membership to kill the person.

## External PKI

The profile starts on a local CA. When the company CA must sign the
server certificate, switch to external PKI: set
`CULVERT_PKI_MODE=external` and the `CULVERT_SECRETS_*` variables
(file mounts, OpenBao, or AWS Secrets Manager). See
[External PKI in the README](../README.md#external-pki) and the PKI Mode
section of [.env.example](../.env.example).

## See also

- [vpn-client-setup.md](vpn-client-setup.md) - OAuth2-capable clients
  (OpenVPN Connect 3.4.0+ / OpenVPN GUI) and provider setup
- [use-case-k8s-scale.md](use-case-k8s-scale.md) - running this shape on
  the Helm chart with external PKI and metrics
- [use-case-travel.md](use-case-travel.md) - run the VPN over HTTPS for
  users on networks that block VPNs outright
- [addressing.md](addressing.md) - check the `10.8.0.0/22` default
  against your corporate addressing plan
