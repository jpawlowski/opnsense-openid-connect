# Authelia

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Create a confidential client in Authelia's `identity_providers.oidc.clients`
configuration. Use a generated secret digest as required by your Authelia
version, enable Authorization Code, and require PKCE `S256`.

Example shape (field names can evolve; follow the documentation for the exact
installed version):

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: opnsense
        client_name: OPNsense
        client_secret: '<Authelia client-secret digest>'
        public: false
        authorization_policy: two_factor
        redirect_uris:
          - 'https://firewall.example.com/api/openidconnect/auth/callback/authelia-main'
        scopes: [openid, profile, email, groups]
        response_types: [code]
        grant_types: [authorization_code]
        token_endpoint_auth_method: client_secret_basic
```

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Authelia |
| Exact issuer URL | Authelia's configured issuer, normally its public root URL |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` plus `groups` if used |
| Authentication method | Follow the provider, or Insist on Basic to match the client |

Authelia is OpenID Certified and documents `S256`; do not enable `plain` PKCE.
If UserInfo signing is set to `none`, that means plain JSON (not an unsigned ID
Token) and is supported through TLS/access-token/subject binding. If a signed
UserInfo response is selected, use an asymmetric algorithm supported here.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Authelia OIDC integration](https://www.authelia.com/integration/openid-connect/introduction/),
[client configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/).
