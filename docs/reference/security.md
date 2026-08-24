# Security, conformance and threat model

## Supported standards profile

“Supported” in this section describes intended implementation scope, not a
completed conformance claim. The generated [standards and provider capability
matrix](provider-capabilities.md) is the publication authority: it remains
unverified until the complete applicable normative inventory and its evidence
pass the repository gate.

The implementation targets these normative parts:

- OpenID Connect Core 1.0 Authorization Code flow, ID Token validation and
  UserInfo subject binding
- OpenID Connect Discovery 1.0 with exact issuer matching
- OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
- PKCE (RFC 7636), always `S256`, following OAuth 2.0 Security BCP (RFC 9700)
- OAuth 2.0 Pushed Authorization Requests (RFC 9126), with explicit Automatic,
  Required and Disabled policy and provider-required PAR always enforced
- OAuth 2.0 Token Revocation (RFC 7009), when advertised
- REFEDS Multi-Factor Authentication Profile for its exact MFA context
- OpenID Connect Extended Authentication Profile `phr` and `phrh` contexts
- OIDC RP-Initiated Logout 1.0, Front-Channel Logout 1.0 and Back-Channel
  Logout 1.0
- OpenID Shared Signals Framework 1.0 signed SET profile and transmitter discovery
- RFC 8935 push delivery, for selected CAEP 1.0 and RISC 1.0 session-ending events
- JWS asymmetric algorithms `RS*`, `PS*`, and `ES*` listed in the README

Supported client authentication is `client_secret_basic` and
`client_secret_post`. Both are standard and cover the named provider profiles.
The client is confidential and still always uses PKCE.

## Optional features outside this release

These are optional protocol features, not silently accepted variants:

- public clients and `token_endpoint_auth_method=none`
- `private_key_jwt`, `client_secret_jwt` or mutual-TLS client authentication
- DPoP sender-constrained access and refresh tokens
- implicit/hybrid/device/password/client-credentials flows
- Dynamic Client Registration, JAR, JARM, CIBA and Rich Authorization Requests
- login-time `id_token_hint` or `login_hint` authorization parameters
- encrypted ID Tokens or UserInfo (JWE)
- symmetric `HS*` ID Token signatures and EdDSA
- distributed/aggregated claims and automated Graph/API fallback for Entra group
  overage
- SSF polling, automatic stream management, subject administration and full
  CAEP interoperability certification

Providers requiring one of these need a future explicit implementation; checks
must not be disabled to emulate support.

## Normative references

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)](https://www.rfc-editor.org/rfc/rfc9207.html)
- [Proof Key for Code Exchange (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636.html)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OAuth 2.0 Pushed Authorization Requests (RFC 9126)](https://www.rfc-editor.org/rfc/rfc9126.html)
- [OAuth 2.0 Token Revocation (RFC 7009)](https://www.rfc-editor.org/rfc/rfc7009.html)
- [REFEDS Multi-Factor Authentication Profile](https://refeds.org/profile/mfa)
- [OpenID Connect Extended Authentication Profile ACR Values 1.0](https://openid.net/specs/openid-connect-eap-acr-values-1_0.html)
- [Authentication Method Reference Values (RFC 8176)](https://www.rfc-editor.org/rfc/rfc8176.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [OpenID Continuous Access Evaluation Profile 1.0](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID RISC Profile 1.0](https://openid.net/specs/openid-risc-1_0-final.html)
- [Push-Based SET Delivery (RFC 8935)](https://www.rfc-editor.org/rfc/rfc8935.html)

## Threats and controls

| Threat | Control |
|---|---|
| forged/replayed callback | random server-bound state, nonce and PKCE; state consumed before processing; bounded one-time server index for `form_post` under SameSite=Lax; PAR keeps the complete request server-to-server when advertised |
| authorization-server mix-up | frozen exact issuer/endpoints, distinct callback per provider, RFC 9207 when advertised |
| forged ID Token | asymmetric JWKS signature, algorithm allow-list, key metadata/curve/use checks, minimum 2048-bit RSA |
| provider ignores or misinterprets a requested authentication strength | an enabled requirement needs exact signed `acr`/`acrs` context and bounded `amr` evidence frozen into the login transaction; missing or mismatched evidence is refused before account lookup |
| token for another client | exact `aud` and `azp` rules |
| stale/future token | strict integer `exp`, `iat`, optional `nbf`, 60-second clock tolerance |
| UserInfo substitution | access token over TLS, credential redirects forbidden, exact ID Token/UserInfo `sub` binding |
| open redirect/Host injection | local target sanitizer, strict Host grammar, HTTPS origin matched to OPNsense hostname/domain, alternate hostnames and core's IP-literal rule, or to an explicit exact custom list; disabling OPNsense DNS-rebinding checks does not widen hostname acceptance |
| HTTP WebGUI or forged proxy scheme | native HTTP blocks enabled providers and sign-in tests; TLS offloading requires an explicit per-provider exception, exact custom HTTPS origins and exact Host matching; forwarded scheme headers and PROXY protocol are not treated as TLS proof |
| session fixation | fail-closed PHP session ID regeneration with old ID removal after elevation |
| identity reassignment after rename | persistent exact `(issuer, sub)` to numeric UID binding |
| unverified e-mail takeover | strict admission by default; automatic e-mail admission requires a unique verified address unless unsafe matching is explicitly selected |
| any global social account reaches the firewall | unknown identities are refused with the same public response as every unusable account; Administrator approval privately queues an exact issuer/subject without a session, with bounded 0600 storage and no unauthenticated config write |
| unauthorized identity rebinding or account creation | the manager API extends core's System: Authentication Servers ACL, repeats that privilege check in the controller and applies `user-config-readonly` to every mutation; inline accounts additionally require core's System: Access: Management privilege, start with a scrambled password and receive no groups or privileges; binding operations target one exact saved server and use record IDs to detect concurrent changes |
| Microsoft multitenant issuer substitution | Microsoft-only authority modes require GUID `tid`, exact tenant issuer, selected organizations/consumers population and matching signing-key issuer |
| provider grants excessive privilege | no group claim by default, explicit assignable local groups, root denied |
| logout forgery/replay | signed logout token, issuer/audience/event/integer `exp`/time/`jti`, replay cache retained through signed expiry, exact `sid`/`sub` lookup, bounded session-lock retry and retryable failure without consuming the replay marker |
| forged or replayed Shared Signals event | exact transmitter discovery issuer and audience, asymmetric SET signature, mandatory `secevent+jwt` type, pre-crypto bearer authentication, bounded `jti` digest cache and provider-and-issuer-scoped subject lookup |
| delayed security event ends a new session | each indexed session records its creation time; an event acts only on sessions present at `event_timestamp` or `iat`, with the fixed clock tolerance |
| credential leakage by HTTP redirect | POST and credential-bearing GET redirects rejected |
| resource exhaustion | response limits, field/key/claim limits, connection/total timeouts, bounded transaction/session/replay indexes and at most 100 deduplicated pending identities |
| account/configuration enumeration | every missing, disabled, expired, privileged or approval-pending account receives the same public refusal; precise reasons remain in the log |
| third-party content or administrator text on login page | named profiles use reviewed package-owned SVGs; custom remote icons are proxied by the firewall with content-type/size checks and an SVG sandbox; provider labels and custom wording are bounded plain text and HTML-escaped; no raw custom markup reaches the page |
| authorization codes, state, identity details or failure references retained or leaked by the browser | private responses use `no-store`, `no-referrer`, `nosniff` and a deny-by-default CSP; successful package-owned or proxied icons are the only cacheable plugin responses |

## Browser response security

Response headers complement the protocol controls above. State, nonce, PKCE and
token validation decide whether an OIDC response is authentic; browser headers
limit what happens to the resulting document, redirect or error after it has
been returned.

| Response class | Cache, referrer and MIME policy | Content and framing policy |
|---|---|---|
| Public login, callback, logout, back-channel logout and protocol errors | `Cache-Control: no-store`, legacy `Pragma: no-cache`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` | deny-by-default CSP with `frame-ancestors 'none'` and `base-uri 'none'` |
| Public Shared Signals push success and error | same private policy; RFC 8935 success is empty `202`, validation errors are bounded JSON | deny-by-default CSP; no subject, token or claim value is reflected |
| Sign-in-test and WebGUI-access-denied pages | same private policy; cross-site `form_post` results also remove the temporary session's `Set-Cookie` | self-contained HTML; only inline styling is allowed, with all other sources, framing, base-URL changes and form submission denied |
| Front-channel logout | private policy | `default-src 'none'; frame-ancestors *` is an intentional exception because the provider must load this endpoint in an iframe |
| Successful package-owned or proxied login icon | `Cache-Control: public, max-age=86400`, `no-referrer`, `nosniff` | sandboxed image response; package assets are reviewed and self-contained; remote responses cannot execute as page markup |
| Missing, failed or rejected login icon | `no-store`, `no-referrer`, `nosniff`, explicit plain-text type | sandboxed deny-by-default CSP with framing denied |
| Authenticated Discovery, sign-in-test, provider-setup and identity-approval APIs | `no-store`, `Pragma: no-cache`, `no-referrer`, `nosniff` | JSON or download response; the headers are applied before core authentication and CSRF processing, so early `401`, `403` and redirects are covered too |

`Strict-Transport-Security` is intentionally not emitted by individual plugin
controllers. HSTS is a host-wide transport promise and belongs to the native
OPNsense WebGUI listener, or to the reverse proxy that terminates TLS. The same
boundary owns the WebGUI session cookie's `Secure`, `HttpOnly` and `SameSite`
attributes; under the explicit TLS-offload exception the proxy must add the
transport protection that an internal HTTP listener cannot infer safely.

The plugin uses CSP `frame-ancestors` instead of duplicating it with
`X-Frame-Options`, because front-channel logout needs one explicit framing
exception that `X-Frame-Options` cannot express consistently. Blanket
`Permissions-Policy`, COOP or COEP headers are not added: these static responses
do not request powerful browser features, while cross-origin isolation can
interfere with provider redirects and the required logout iframe without
strengthening OIDC validation.

The CSP from OPNsense core's `guiconfig.inc` protects normal WebGUI-rendered
pages only. Direct controller responses do not pass through that renderer, so
the plugin sets their complete policy itself before callback processing can
produce a redirect, stand-alone document or error.

The disposable browser E2E test adds an independent passive OWASP ZAP pass over
the real responses. Playwright reaches the stateful and authenticated outcomes;
ZAP parses only plugin traffic and applies an endpoint-aware failure policy.
The scanner therefore cannot replace the exact assertions above: host-owned
HSTS, JSON APIs, the front-channel iframe, inline styling and cacheable icons
have intentionally different requirements. The firewall may remain private and
use a self-signed WebGUI certificate because the proxy and browser run locally
inside the isolated test boundary.

## Accepted residual risks

- A compromised identity provider can authenticate its users and assert any
  configured group/role. Local scoping limits consequences but cannot restore
  trust in that provider.
- An administrator may configure an internal IdP. Blocking private IP space
  would break that supported deployment, so provider and custom icon URLs are
  privileged SSRF-capable settings. Named profile icons do not perform an
  outbound request. Only administrators with the relevant
  configuration/discovery permission should control custom URLs.
- Tokens needed for logout are present in the authenticated PHP session. A
  local root compromise or arbitrary WebGUI code execution already crosses the
  firewall's security boundary and can read them.
- Front-channel logout depends on browser iframe/CSP behaviour and is less
  reliable than back-channel logout. Prefer back-channel where available.
- Removing access at the provider does not end an already established local
  session unless the provider sends OIDC logout, an enabled supported Shared
  Signals event, or its normal OPNsense timeout ends.
- Under the explicit HTTP-backend TLS-offloading exception, reverse-proxy
  isolation and response-cookie hardening are administrator responsibilities.
  The plugin cannot prove that no alternate route reaches the listener.

## Release security

Every published package receives keyless GitHub/Sigstore build provenance bound
to its exact digest, this repository's release workflow and the source commit.
The workflow stages the complete asset set in a draft and publishes only once;
GitHub release immutability then locks both tag and assets and creates a separate
release attestation. Release notes put attestation, checksum and any optional
offline RSA verification before `pkg add`.

OPNsense `pkg` does not understand GitHub attestations for a directly supplied
file. Operators therefore verify provenance on an administrator workstation
before copying the package to the firewall. A checksum alone is only a transfer
integrity check. During beta there is deliberately no package repository,
repository trust fingerprint or automatic `pkg install` update path.

Do not publish client secrets, tokens, complete session files, or unredacted
provider responses in issues. See [SECURITY.md](../../SECURITY.md).
