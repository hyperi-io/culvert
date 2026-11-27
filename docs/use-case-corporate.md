# Corporate access

Status: OIDC sign-in is a beta, off by default behind `CULVERT_OAUTH2_ENABLED` (default `false`), and this profile turns it on. Unit tests cover the openvpn-auth-oauth2 config culvert writes, and no automated test signs in against an IdP. Tracked in <https://github.com/hyperi-io/culvert/issues/135>.

Per-user certificates plus human SSO against your identity provider,
group gating, and a TCP fallback for hostile guest networks. This is the
`corporate` profile. Every connection then needs BOTH a valid client
certificate AND a live IdP login by the user that certificate was issued to.
The certificate proves the device, the OIDC login proves the person, and the
profile's login rule refuses a login whose IdP username is not the
certificate's CN.

`CULVERT_PROFILE=corporate` turns on:

- OpenVPN UDP primary plus a TCP fallback (hotel / captive-portal
  networks routinely drop UDP)
- OIDC SSO (`oauth2_enabled`)
- group gating (`oauth2_validate_groups`, default `vpn-users`)
- a login rule (`oauth2_validate_expression`) that the IdP's
  `preferred_username` is the certificate's CN, so one person's login cannot
  carry another person's certificate
- full tunnel (common for compliance - all client traffic inspected and
  routed via the VPN, and `CULVERT_FULL_TUNNEL=false` flips it to split)
- a local CA to start, called `Acme VPN CA` from the profile's placeholder
  `org_name: Acme`, so set `CULVERT_ORG_NAME` to your organisation before the
  first start mints it

The profile sets defaults and nothing else. The OIDC secrets are yours to supply.

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

Set `CULVERT_OAUTH2_HTTP_SECRET` (session secret, `openssl rand -hex 16`)
as well. Left unset, the server generates a random one at every start.
`CULVERT_OAUTH2_CLIENT_SECRET`, the key behind `CULVERT_OAUTH2_TLS_KEY` and
`CULVERT_OAUTH2_HTTP_SECRET` are secrets - inject them via Kubernetes Secrets,
a secret store, or the External Secrets Operator, not into git. See the
Secrets Management section of [.env.example](../.env.example) for
identity-based ESO wiring on AWS / Azure / GCP / OpenBao.

OIDC works with any OIDC-compliant provider that supports discovery. Issuer
URL examples for Entra ID, Okta, Google, Keycloak and Auth0 are in
[.env.example](../.env.example).

## 2. Gate on a group

Restrict access to members of an IdP group:

```bash
-e CULVERT_OAUTH2_VALIDATE_GROUPS=vpn-users
```

Use your IdP's group identifier - GUIDs for Entra ID, names for most
others. The profile gates on `vpn-users`, so allowing any authenticated user
takes the variable set and empty (`CULVERT_OAUTH2_VALIDATE_GROUPS=`). A user outside
the group cannot connect even with a valid certificate.

## 3. Publish the ports

- `1194/udp` - primary
- `1194/tcp` - fallback for networks that drop UDP
- `9000-9002/tcp` - the OAuth2 callback listeners

openvpn-auth-oauth2 runs one callback instance per enabled OpenVPN
listener: UDP uses `9000`, HTTPS `9001`, TCP `9002`. With the corporate
profile (UDP + TCP) you need `9000` and `9002`, and publishing the whole
`9000-9002` range is simplest. These ports must be reachable and their
`https://<server>:<port>/oauth2/callback` URLs registered with your IdP.

## 4. Per-user lifecycle

One certificate per person, not one shared config, named for the person's IdP
username (`preferred_username` on most IdPs):

```bash
# issue
docker exec -it <container> generate-client --name jsmith

# offboard
docker exec -it <container> revoke-client jsmith
```

The profile's rule is:

```text
auth.mode == 'non-interactive' || (has(token.claims.preferred_username) && openvpn.commonName == user.username)
```

openvpn-auth-oauth2 checks it at sign-in. A login whose ID token has no
`preferred_username` is refused, because the username would otherwise fall back
to the certificate's CN and match itself. A token refresh keeps the session the
sign-in bound, so it skips the comparison.

- Client names take letters, digits, `-` and `_` only. Where IdP usernames
  carry `@` or `.`, such as `jsmith@example.com`, map them in your own rule,
  replacing the last comparison with
  `openvpn.commonName == user.username.split('@')[0].replace('.', '-')`.
- An IdP that sends no `preferred_username` needs a rule on a claim it does
  send, e.g. `has(token.claims.email) && ...`.
- `CULVERT_OAUTH2_CHECK_IPADDR=true` also refuses a login from a browser on a
  different IP from the VPN client. It is off by default, because a phone that
  signs in over IPv6 and tunnels over IPv4 fails it.
- `CULVERT_OAUTH2_VALIDATE_EXPRESSION=` (set and empty) drops the rule, so any
  user in the group can sign in with any valid certificate.

`revoke-client` revokes the certificate, regenerates the CRL, sends `kill`
for the client on each listener's management socket, and removes the client's
files. A socket it cannot reach is a warning, not a failure, and a session on
that listener lasts until its next renegotiation (`CULVERT_RENEG_SEC`, an hour
by default), so read the output. The server enforces the CRL, so the revoked
device cannot reconnect - independent of whether the person can still log in
to the IdP. Each gate stands alone:
revoke the cert to kill the device, disable the IdP account or drop the
group membership to kill the person.

## External PKI

The profile starts on a local CA. When the company CA must sign the
server certificate, switch to external PKI: set
`CULVERT_PKI_MODE=external` and the `CULVERT_SECRETS_*` variables
(file mounts, OpenBao, or AWS Secrets Manager). See
[External PKI in the README](../README.md#configuration) and the PKI Mode
section of [.env.example](../.env.example).

Related pages:

- [vpn-client-setup.md](vpn-client-setup.md) - OAuth2-capable clients
  (OpenVPN Connect 3.4.0+ / OpenVPN GUI)
- [use-case-kubernetes.md](use-case-kubernetes.md) - running this deployment on
  the Helm chart with external PKI and metrics
- [use-case-travel.md](use-case-travel.md) - run the VPN over HTTPS for
  users on networks that block VPNs outright
- [addressing.md](addressing.md) - check the `10.8.0.0/22` default
  against your corporate addressing plan
