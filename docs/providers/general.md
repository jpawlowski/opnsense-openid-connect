# Generic OpenID Connect provider

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code**, confidential **Client ID** and either a **Client Secret** or registered
client signing certificate. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Use this profile for a provider not named in the selector. It applies no vendor
exceptions and is the reference configuration for a standards-compliant
confidential web client.

## Provider

- Enable Authorization Code and disable implicit/password grants.
- Register the exact callback displayed by OPNsense.
- Enable PKCE `S256`, `openid` scope, asymmetric ID Token signing and either
  `client_secret_basic`, `client_secret_post` or `private_key_jwt`. For
  `private_key_jwt`, publish a supported signing algorithm in Discovery and
  register the public OPNsense certificate at the client.
- Publish OIDC Discovery at the standard location. Its `issuer` must exactly
  equal the configured issuer, including trailing slash.
- When Discovery publishes `pushed_authorization_request_endpoint`, OPNsense
  uses PAR according to **Pushed authorization requests**. Automatic mode
  bypasses only a temporarily unavailable optional endpoint and restores it in
  the background; choose Required when browser parameters are unacceptable.
- For signed RFC 9101 requests, publish
  `request_object_signing_alg_values_supported`, register a dedicated OPNsense
  certificate public key under the `kid` shown in the firewall, and set
  `require_signed_request_object=true` only after that registration is active.
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
| Authorization response mode | Query; use a signed JARM mode only when the provider advertises and is configured for it |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Pushed authorization requests | Automatic with availability fallback |
| Request Object signing key | Disabled until its public key and `kid` are registered |

Run discovery. If it does not advertise an asymmetric ID Token algorithm and a
client authentication method with the metadata needed by that method, this
confidential-client profile is not compatible.
Do not choose a named provider merely to bypass a warning; named profiles never
weaken protocol checks anyway.

The [JARM specification](https://openid.net/specs/oauth-v2-jarm.html) defines
the signed Query and signed Form POST response modes. Select one only after the
provider application has been configured for a supported asymmetric response
signature; encrypted responses are outside this plugin's profile.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, provider logout notifications set
to **Both**, and both optional outbound logout switches off. The table above
contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html),
[OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html),
[OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[PAR](https://www.rfc-editor.org/rfc/rfc9126.html),
[JAR](https://www.rfc-editor.org/rfc/rfc9101.html),
[authorization issuer](https://www.rfc-editor.org/rfc/rfc9207.html),
[token revocation](https://www.rfc-editor.org/rfc/rfc7009.html),
[RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html),
[front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html),
[back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html),
[Shared Signals](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html),
[REFEDS MFA](https://refeds.org/profile/mfa), and
[EAP ACR values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html).
