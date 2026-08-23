# Generic OpenID Connect provider

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Use this profile for a provider not named in the selector. It applies no vendor
exceptions and is the reference configuration for a standards-compliant
confidential web client.

## Provider

- Enable Authorization Code and disable implicit/password grants.
- Register the exact callback displayed by OPNsense.
- Enable PKCE `S256`, `openid` scope, asymmetric ID Token signing and either
  `client_secret_basic` or `client_secret_post`.
- Publish OIDC Discovery at the standard location. Its `issuer` must exactly
  equal the configured issuer, including trailing slash.
- When Discovery publishes `pushed_authorization_request_endpoint`, OPNsense
  automatically uses PAR with the same confidential-client authentication and
  does not fall back if the push fails.
- Optionally register the displayed front/back-channel logout URLs and the
  WebGUI origin as post-logout redirect.
- For provider-managed pairwise subjects, choose **Pairwise subject sector** and
  give the provider the resulting
  `https://<chosen-origin>/api/openidconnect/auth/sector/<application-code>`
  sector identifier URI. It returns the exact callback URI array as JSON only
  at that saved origin.

## Enter or change these OPNsense values

| Field | Start with |
|---|---|
| Provider profile | Generic OpenID Connect |
| Exact issuer URL | the discovery document's exact `issuer` value |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

Run discovery. If it does not advertise an asymmetric signing algorithm or a
supported secret method, this confidential-client profile is not compatible.
Do not choose a named provider merely to bypass a warning; named profiles never
weaken protocol checks anyway.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html),
[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html).
