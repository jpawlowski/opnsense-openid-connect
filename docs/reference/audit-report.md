# Pre-release implementation audit

Date: 23 August 2026
Scope: WebGUI administrator login only
Target: OPNsense Community Edition 26.1 and 26.7

## Executive result

The codebase has been reworked into a focused OpenID Connect relying party and
the vendored Jumbojett client has been removed completely. Findings from the
manual implementation review are recorded below; the generated test snapshot
under **Verification evidence** is authoritative for the current tree. A disposable
Keycloak-to-OPNsense browser test now exercises the complete implemented flow
against the real WebGUI. It is suitable for continued pre-release testing, but
it is **not yet a supported release**: a live authentik run on the intended
tenant and a live 26.1 installation remain release gates. This is an
implementation review, not OpenID certification or an independent penetration
test.

## Scope and architecture

The plugin intentionally implements only OPNsense WebGUI authentication. It
does not attempt Captive Portal or OPNWAF authentication. Protocol, transport,
cryptography, local identity policy, browser endpoints and runtime indexes are
separate components; see [architecture.md](architecture.md).

Cryptographic arithmetic is not implemented locally. RSA, RSA-PSS and ECDSA
verification use OPNsense's installed phpseclib3 runtime. The plugin owns the
narrow protocol policy around those primitives: accepted algorithms, JWK
selection, JWT structure and OIDC claim validation.

## Findings addressed

| ID | Severity | Finding or review objective | Resolution |
|---|---:|---|---|
| A-01 | high | A mutable username/e-mail must not remain the durable identity | exact `(issuer, sub)` is persisted to numeric local UID; ambiguous/conflicting bindings fail closed |
| A-02 | high | Local account policy could be bypassed by a federated path | disabled/expired users are refused; UID 0 is denied by default; strict/administrator approval are safe defaults and automatic matching/JIT are explicit opt-ins |
| A-03 | high | Multi-provider mix-up and Host/open-redirect risks | exact issuer, frozen metadata, unique callbacks, RFC 9207 when advertised, strict accepted HTTPS origins and local redirect sanitising |
| A-04 | high | Token/JWT validation needed a small auditable policy rather than a broad vendored client | strict JWS/JWK and `iss/sub/aud/azp/exp/iat/nbf/nonce/auth_time/at_hash` validation; only asymmetric RSA/PSS/ECDSA algorithms |
| A-05 | high | Provider-controlled groups could silently become local privilege | group claims are off by default; empty allow-list grants none; all-groups delegation is a separate warning-labelled option |
| A-06 | high | Session elevation must never survive failure to rotate its identifier | rotation removes the old ID and now fails closed by destroying the login session |
| A-07 | high | Stored grants could be sent to a replacement issuer if an auth-server name were reused | the session stores its exact issuer; logout discovers and matches it before any token is revoked or sent |
| A-08 | high | Provider HTTP redirects/media ambiguity could leak credentials or accept unintended payloads | TLS validation, HTTPS-only URLs, bounded bodies/time/redirects; POST and credential-bearing redirects refused; strict JSON/JWT media types |
| A-09 | medium | OPNsense's `SameSite=Lax` cookie makes OIDC `form_post` lose the initiating session | only form-post flows use a bounded, mode-`0600`, ten-minute, single-use transaction index; the WebGUI cookie remains Lax |
| A-10 | medium | Federated logout needed authenticity, lookup and replay controls | RP-initiated, front-channel and signed back-channel logout; exact issuer/audience/event/time checks; required `jti` replay cache; `sid` preferred over `sub` |
| A-11 | medium | Public login icons can be active third-party content or an administrator-configured outbound fetch | named profiles use reviewed self-contained package SVGs; custom URLs retain HTTPS/size/media limits, no credential redirects, SVG sandbox, image-only data URIs, protocol-relative paths refused and disabled-provider refusal |
| A-12 | medium | Configuration errors were discoverable only during login, and provider/client setup had a circular dependency | authenticated Discovery and non-mutating browser sign-in tests, exact endpoint preview, independently saveable disabled drafts, no-secret authentik/Keycloak imports, conditional sections, password field, named presets, application-code uniqueness and safe defaults |
| A-13 | medium | A manually installed authentication package needs provenance and drift visibility | deterministic package, file checksums/ownership tests, honest dirty-tree annotation, pinned checkout action, optional detached signature and nightly live/core watchdog |
| A-14 | low | Detailed public failures can enumerate configuration/accounts or expose provider detail | public protocol failures are generic and carry a random reference; details go to audit/system logs without tokens or secrets |

No validation exception was added for a provider. Named profiles change safe
defaults or diagnostics only. Core issuer, signature, audience, nonce, time,
subject, HTTPS and redirect rules are invariant.

## Standards profile

Implemented and reviewed:

- OpenID Connect Core Authorization Code flow, ID Token validation and UserInfo
  subject binding;
- OpenID Connect Discovery with exact issuer and required metadata types;
- OAuth PKCE, always transaction-specific `S256`, plus state and nonce;
- OAuth Authorization Server Issuer Identification (`iss`) when advertised,
  with distinct callbacks as the universal mix-up control;
- Token Revocation when advertised;
- RP-Initiated, Front-Channel and Back-Channel Logout;
- confidential-client `client_secret_basic` and `client_secret_post`.

Unsupported optional features are enumerated in [security.md](security.md),
including public clients, private-key/mTLS/DPoP client authentication, PAR/JAR/
JARM, implicit/hybrid flows, JWE, HS/EdDSA and automated Entra Graph group
overage. A provider requiring one of them is reported incompatible instead of
being accepted under weaker checks.

## Provider compatibility and special cases

There are 25 named profiles plus Generic. Guides cover Entra ID and personal
Microsoft accounts, Google, Okta,
Auth0, Cognito, JumpCloud, Apple, authentik, Keycloak, Authelia, ZITADEL, Ping,
OneLogin, Dex, GitLab, Pocket ID, FusionAuth, Cisco Duo SSO, IBM Security
Verify, Oracle IDCS/OCI IAM, WSO2, LinkedIn, Slack, Yahoo and ORCID.

Special handling is deliberately small:

- Entra group-overage markers refuse ambiguous authorization and direct the
  operator to filtered groups or app roles;
- Microsoft tenant-independent authorities validate the signed token's GUID
  tenant, exact issuer path and signing-key issuer, then enforce the selected
  organizations/consumers/common audience;
- Apple selects `form_post`, ID Token claims and its documented scopes; its
  documented POST token authentication is enforced, while its expiring signed
  client-secret JWT remains an operator rotation task;
- Cognito defaults to `cognito:username`;
- Duo defaults to e-mail from UserInfo because its published example does not
  emit `preferred_username`;
- ZITADEL role objects are read by key without a ZITADEL-only parser;
- WSO2 documents that the exact issuer can intentionally look like the token
  endpoint;
- LinkedIn and ORCID enforce documented POST token authentication even where
  metadata is absent or leaves no alternative;
- tenant-specific issuer values are never synthesized at runtime; the form only
  shows a provider-shaped placeholder or an editable public-service default.

Google, Apple, JumpCloud US, LinkedIn, Slack, Yahoo, ORCID and the
Microsoft common/consumers authorities were exercised through live Discovery
from OPNsense. This validates their published metadata against the plugin's
strict Discovery policy, not a complete sign-in; full login compatibility
remains documentation-based until recorded otherwise.
GitHub, Discord and Login with Amazon user login are explicitly documented but
excluded because their official login interfaces are OAuth 2.0 rather than
OIDC user-provider flows.

## Function and UX result

The local password form remains available. Each enabled provider receives an
escaped login button/link and a distinct callback. The form groups settings by
purpose, masks the client secret, and labels the exact authorization,
post-logout, front-channel and back-channel addresses by purpose. It tests
Discovery under normal authenticated CSRF protection, inherits the WebGUI names
already accepted by OPNsense by default, and hides fields that do not apply.
Every named profile covers every provider-dependent field from one server-side
catalog, including safe icon and button-wording defaults. Recommended values remain editable, documented invariants
are locked and enforced at runtime, tenant-specific issuer fields have concrete
shape hints, and a one-click restore returns experimental edits to the profile
starting point. New named profiles start with non-admitting administrator
approval; Generic remains strict.
Disabled drafts may be saved before a provider exists. authentik and Keycloak
setup files can be downloaded from unsaved values without credentials or a
network call. High-risk root, unverified e-mail and all-groups choices are
separate opt-ins with direct warnings.

Recovery is package removal over console/SSH; configuration survives. Public
errors are safe but actionable through their matching log reference. The
nightly watchdog checks both the actual login-page shape and core integration
fingerprints.

## Commercial comparison

The detailed source-limited comparison is in
[commercial-comparison.md](commercial-comparison.md). Published OPNsense
Business Edition functionality covers WebGUI/Admin, Captive Portal and OPNWAF;
this project intentionally covers only the first. The commercial path has the
clear advantage of vendor integration and a commercial firmware relationship.
This plugin's differentiators are narrow scope, transparent protocol policy,
stable issuer/subject binding, explicit provider guidance and reviewable tests.
Where commercial behaviour is not public, the comparison says “not
documented”, never “absent”.

## Verification evidence

<!-- BEGIN GENERATED: host-independent-test-evidence -->
The following snapshot is generated by `python3 tests/update-audit-report.py --update`
from the canonical `./tests/run.sh` command. Do not edit the table manually.

Overall host-independent result: **PASSED**

| Stage | Result | Evidence |
|---|---:|---|
| Syntax | **passed** | all files parse |
| Behaviour | **passed** | 404 checks passed |
| Commit/release convention | **passed** | 47 checks passed |
| Package/archive/supply chain | **passed** | 333 checks passed |
<!-- END GENERATED: host-independent-test-evidence -->

Real OPNsense CE 26.7.2_2:

- install, forced upgrade, removal and reinstall tested; `pkg check -s` clean;
- login form with zero/disabled/enabled providers and exact PKCE redirect tested;
- settings form fields, authenticated Discovery API and provider-setup API exercised;
- public error routes and cache/referrer/content-type headers exercised;
- RS256, exact-policy PS256 and IEEE ES256 verified through OPNsense phpseclib;
- logout-token replay and all four mode-`0600` runtime indexes tested,
  including the bounded pending-identity registry;
- Google, Apple, JumpCloud, LinkedIn, Slack, Yahoo and ORCID Discovery
  passed exact-issuer validation; Microsoft common/consumers metadata passed
  their documented template/fixed-issuer rules;
- watchdog live probe and core fingerprint clean.

Disposable Keycloak 26.7.2 and Playwright E2E against that OPNsense host:

- downloaded and inspected a no-secret Keycloak partial import from the unsaved
  form, then saved and reopened a disabled draft with empty issuer, Client ID
  and Client Secret without sending a Discovery request;
- created the confidential client and OPNsense server through their real
  interfaces, with exact Discovery and an asymmetric signing key;
- Authorization Code login with mandatory PKCE S256, state and nonce passed;
- first-login account creation/default group, stable issuer/subject binding,
  session-ID rotation and later login with creation disabled passed;
- unknown-identity refusal, administrator approval to an existing local UID,
  and the subsequent approved login passed without automatic account creation;
- social-provider labels, named-profile application/restoration, fixed and
  editable fields, preserved saved overrides and Microsoft-only conditional
  audience controls were verified in the real settings form;
- replaying the consumed callback was rejected with the generic public error;
- OPNsense-initiated RP logout ended both the local and Keycloak sessions;
- genuine signed Keycloak back-channel logout and browser-delivered
  front-channel logout each invalidated the intended local session;
- `form_post` and `client_secret_post` passed through the real browser/token
  endpoints;
- the independent local root-password recovery path remained usable;
- the random realm, user, server and short-lived CA were removed automatically.

The live run also established a Keycloak-specific operational fact documented
in its provider guide: enabling Keycloak **Front channel logout** selects that
browser mechanism instead of also sending the back-channel notification.

Provider-import validation outside the browser flow:

- authentik 2026.8.0 imported the generated Blueprint through its official API,
  created one confidential provider and linked application with exact typed
  redirects, standard scopes and an asymmetric signing key, and a repeat import
  preserved the generated Client ID and Client Secret;
- Keycloak accepted the generated partial-import JSON, created the confidential
  client with exact origins/redirects and PKCE S256, and a repeat import reported
  one skipped resource with no overwrite.

## Remaining gates and residual risks

Required before the first supported release:

1. Complete authentik authorization-code login, stable binding, local and
   provider logout on the supplied tenant.
2. Repeat install/UI/login-page/error/watchdog smoke tests on OPNsense 26.1.
3. Complete narrow-viewport visual QA; the desktop WebGUI and browser flow have
   been exercised by Playwright.

Optional but recommended before distributing beyond private testing:

- create an offline RSA release key and publish only its public half; until
  then, a checksum beside the package proves integrity, not publisher identity;
- run an external OIDC conformance suite and independent security review;
- record live Entra and additional provider results individually.

Accepted operational risks remain: the configured IdP is a trust anchor; an
administrator-approved internal provider/icon URL grants bounded outbound HTTPS
from the firewall; logout grants reside in the protected PHP session; provider
deprovisioning needs a logout notification or local timeout; front-channel
logout depends on browser behaviour. The plugin adds no global IP rate limiter
to the WebGUI; public reachability and request-rate controls remain an OPNsense
firewall/reverse-proxy policy decision.
