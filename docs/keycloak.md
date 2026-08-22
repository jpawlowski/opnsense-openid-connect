# Keycloak

The most straightforward of the five: a confidential client with the standard
flow, and nothing about it fights the plugin's checks.

## At Keycloak

Pick the realm first — everything below is per realm, and the issuer contains
its name.

**Clients > Create client.**

| Step | Setting | Value |
|---|---|---|
| General settings | Client type | **OpenID Connect** |
| | Client ID | e.g. `opnsense` |
| Capability config | **Client authentication** | **On** — this is what makes it confidential |
| | Standard flow | on |
| | Direct access grants | off; nothing here uses them |
| | Implicit flow, Service accounts | off |
| Login settings | Valid redirect URIs | one entry per address, each ending in `/api/openidconnect/auth/callback` |
| | Valid post logout redirect URIs | `https://<firewall>/` if you want *Return here after logout* |

**Credentials tab** — the client secret appears once *Client authentication* is
on.

**Client scopes** — the default `profile` and `email` scopes are what this
needs; they are attached to a new client already.

## On the firewall

| Field | Value |
|---|---|
| Provider URL | `https://<keycloak>/realms/<realm>` |
| Username claim | `preferred_username` |
| Scopes | `openid,email,profile` |

Keycloak's issuer has no `/auth` in it since version 17. On an older
installation behind the legacy path it is
`https://<keycloak>/auth/realms/<realm>`.

## Worth knowing

**Custom claims default to UserInfo only.** A mapper you add yourself is
returned from the UserInfo endpoint unless you tick "Add to ID token" as well.
Either way works here, because the plugin reads both.

**Signing** is RS256 per realm by default (*Realm settings > Keys*). Keycloak
can be switched to ES256 or EdDSA; do not, or the login is refused with
`Refusing a token signed with ...`. RSA-PSS (`PS256`) is accepted as well.

**Group mapping**, if you decide you want it: add a *Group Membership* mapper to
the client with token claim name `groups`, untick "Full group path" so the names
match your local group names, add `groups` to the scopes on the firewall and set
*Group claim* to `groups`. Set *Assignable groups* as well so that only the
groups you name can be handed out.
