# Dex

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Dex is commonly self-hosted behind a reverse proxy. Its configured `issuer`
must be the same stable HTTPS address browsers and OPNsense use.

## Dex static client

```yaml
staticClients:
  - id: opnsense
    name: OPNsense
    secret: '<high-entropy secret>'
    redirectURIs:
      - 'https://firewall.example.com/api/openidconnect/auth/callback/dex-main'
```

Use a confidential client (`public: false`/unset). Ensure the reverse proxy does
not rewrite the issuer, discovery endpoints or callback parameters.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Dex |
| Exact issuer URL | Dex's configured `issuer` |
| Username claim | `preferred_username` |
| Claims source | Automatic (or ID Token only) |
| Authorization response mode | Query |
| Scopes | `openid,email,profile`; add `groups` when needed |
| Authentication method | Follow the provider |

Dex's `groups` claim is available only when the `groups` scope is requested and
depends on the upstream connector. E-mail verification also reflects what the
connector can establish. Do not use Dex's cross-client `audience:` scopes for
this firewall: the ID Token must be issued directly to its own client ID.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

Reference: [Dex scopes, claims and clients](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/).
