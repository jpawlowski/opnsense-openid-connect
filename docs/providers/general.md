# Generic OpenID Connect provider

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** plus a **Client Secret**, a registered
client signing certificate, or an OPNsense mTLS **Client certificate**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Use this profile for a provider not named in the selector. It applies no vendor
exceptions and is the reference configuration for a standards-compliant
confidential web client.

## Provider

- Enable Authorization Code and disable implicit/password grants.
- Register the exact callback displayed by OPNsense.
- Enable PKCE `S256`, `openid` scope, asymmetric ID Token signing and either
  `client_secret_basic`, `client_secret_post`, `private_key_jwt`,
  `tls_client_auth` or `self_signed_tls_client_auth`.
- For `private_key_jwt`, publish a supported signing algorithm in Discovery and
  register the public OPNsense signing certificate at the client.
- For RFC 8705, register the selected OPNsense certificate, publish any
  `mtls_endpoint_aliases`, and advertise
  `tls_client_certificate_bound_access_tokens=true` before the matching local
  option is enabled.
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
- Register the displayed lifecycle-test return as an exact post-logout redirect.
  Optionally register the displayed front/back-channel logout URLs and the
  WebGUI origin when ordinary **Return here after logout** is enabled.
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
| Client signing certificate | None unless this client is registered for `private_key_jwt` |
| Client certificate | None unless this client is registered for mutual TLS |
| Require certificate-bound access tokens | Off unless the provider registration enables them |
| Pushed authorization requests | Automatic with availability fallback |
| Request Object signing key | Disabled until its public key and `kid` are registered |

Run discovery. If it does not advertise an asymmetric ID Token algorithm and a
client authentication method with the metadata needed by that method, this
profile is not compatible.
Do not choose a named provider merely to bypass a warning; named profiles never
weaken protocol checks anyway.

The [JARM specification](https://openid.net/specs/oauth-v2-jarm.html) defines
the signed Query and signed Form POST response modes. Select one only after the
provider application has been configured for a supported asymmetric response
signature; encrypted responses are outside this plugin's profile.

## Optional authentication-strength enforcement

Use **Required authentication** only when the provider documentation establishes
the complete chain for this exact client. For **Multi-factor authentication**,
the provider must honor the requested REFEDS MFA context and return that `acr`
plus `mfa` in the signed ID Token's `amr` array. For **Phishing-resistant
authentication**, it must honor `phr` or `phrh` and return a matching registered
method such as `fido`, `pop`, `hwk` or `swk` in `amr`.

Configure the provider's policy, authentication flow and token mapper first.
Then select the tier in OPNsense and run **Test sign-in**. If the provider uses
different documented context or method values, enter those exact values in the
advanced fields. Keep **Provider policy only** when the provider merely performs
MFA but does not bind the request, enforcement and signed evidence together.

The successful result names the authorization response mode, actual PAR/JAR/DPoP
use, token authentication, issued token kinds and selected signed claims without
displaying a token. **Validate sign-out** then opens a separate tab, requests
provider logout and returns to this server row without ending the current
OPNsense WebGUI session. Depending on the provider's logout semantics, that
request may end its wider SSO session or sessions for other clients. A configured
front/back-channel row passes only when that notification reached OPNsense and
completed its normal issuer, session and signature validation. "Not observed"
is therefore an actionable provider-registration result, not a successful test.

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
[OAuth mutual TLS](https://www.rfc-editor.org/rfc/rfc8705.html),
[RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html),
[front-channel logout](https://openid.net/specs/openid-connect-frontchannel-1_0.html),
[back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html),
[Shared Signals](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html),
[REFEDS MFA](https://refeds.org/profile/mfa), and
[EAP ACR values](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html).
