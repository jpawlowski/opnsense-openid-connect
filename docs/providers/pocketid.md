# Pocket ID

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in Pocket ID

1. Create a normal OIDC client in Pocket ID (not a public Client ID Metadata
   Document client).
2. Add the exact OPNsense callback and copy its client ID/secret.
3. Under allowed user groups, explicitly allow the groups intended to sign in.
   Pocket ID denies all users when a new client's allowed-group list is empty.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Pocket ID |
| Exact issuer URL | the instance `APP_URL`, normally without a trailing slash; confirm Discovery |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile`; add `groups` for group mapping |
| Authentication method | Follow the provider |
| Redirect the Log Out menu entry | On |

Pocket ID is passkey-oriented, but OPNsense only sees the resulting standard
OIDC authentication. Keep HTTPS correct at the reverse proxy and do not follow
troubleshooting advice to add an HTTP callback for this firewall.

The newer Client ID Metadata Document feature supports only public clients with
`token_endpoint_auth_method=none`; that mode is intentionally outside this
plugin. Use a manually registered confidential client.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Pocket ID common OIDC issues](https://pocket-id.org/docs/troubleshooting/common-issues),
[allowed groups](https://pocket-id.org/docs/configuration/allowed-groups),
[Client ID Metadata Documents](https://pocket-id.org/docs/guides/client-id-metadata-documents),
and [a documented Pocket ID logout integration](https://pocket-id.org/docs/client-examples/bookstack).
