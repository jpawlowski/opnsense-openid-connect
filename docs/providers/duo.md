# Cisco Duo Single Sign-On

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Duo added a generic OAuth 2.1 / OIDC provider in 2026. Use that SSO application,
not the separate OAuth client-credentials application, which authenticates
machines rather than WebGUI users.

## Duo

1. Add **OAuth 2.1 / OIDC - Single Sign-On** from the Duo application catalog.
2. Grant the intended active users or groups access. A new Duo application does
   not allow users until this policy is set.
3. Add the exact OPNsense callback as a sign-in redirect URL and create a
   confidential client. Copy its client ID and secret.
4. On **Metadata**, copy the displayed **Issuer**. Do not paste the OIDC
   Discovery URL into the issuer field.
5. Grant the client the `openid`, `email` and `profile` scopes.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Cisco Duo Single Sign-On |
| Exact issuer URL | the per-application Issuer shown by Duo |
| Username claim | `email` |
| Claims source | Require UserInfo |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

Duo's published metadata supports only the code response and advertises PKCE
`S256`, matching this plugin's mandatory flow. Duo's example UserInfo response
contains `email` and `user`, but not `preferred_username`, which is why this
profile selects e-mail. Stable identity still uses `sub`; keep first binding
strict or deliberately bootstrap to the intended local account.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

Reference: [Duo Single Sign-On for OAuth 2.1 and OIDC](https://duo.com/docs/sso-oauth-server).
