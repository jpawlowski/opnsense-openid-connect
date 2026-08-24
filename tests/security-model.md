<!-- Source fragment for docs/reference/security-and-conformance.md. -->

Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

## Threats and controls

| Threat | Control |
|---|---|
| forged/replayed callback | random server-bound state, nonce and PKCE; state consumed before processing; bounded one-time server index for Form POST modes under SameSite=Lax; PAR keeps the complete request server-to-server when advertised |
| authorization request tampering or replay | optional or provider-required RFC 9101 signature over every authorization parameter; exact client/issuer audience binding, explicit JWT type, registered key `kid`, 60-second expiry and fresh `jti`; outer request carries only the matching client ID and `request` or provider-issued PAR reference |
| forged or downgraded JARM response | the requested signed mode is frozen into the one-time transaction; asymmetric signature, advertised algorithm, exact issuer/audience, time, state and transport are checked before code or error processing |
| authorization-server mix-up | frozen exact issuer/endpoints, distinct callback per provider, RFC 9207 when advertised and signed JARM issuer/audience binding when selected |
| forged ID Token | verified RS/PS/ES/Ed25519 JWKS signature profile, public-key type/curve/size/use/operations/algorithm binding, 2048–8192-bit RSA bound |
| provider ignores or misinterprets a requested authentication strength | an enabled requirement needs exact signed `acr`/`acrs` context and bounded `amr` evidence frozen into the login transaction; missing or mismatched evidence is refused before account lookup |
| token for another client | exact `aud` and `azp` rules |
| stale/future token | strict integer `exp`, `iat`, optional `nbf`, 60-second clock tolerance |
| UserInfo substitution | access token over TLS, credential redirects forbidden, exact ID Token/UserInfo `sub` binding |
| stolen access token replay | when a compatible provider profile documents RFC 9449 access-token support and Discovery advertises ES256 DPoP, the authorization code and access token are bound to a mode-0600 per-provider key; every protected request carries a fresh method-, URI- and token-bound proof, and a DPoP token is never downgraded to Bearer |
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
