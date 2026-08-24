# Settings reference

Named provider profiles preselect every provider-dependent value. The form marks
fixed provider invariants as read-only and recommended values as editable. See
[provider profiles and defaults](provider-profiles.md) for the complete matrix. A
guide's “Enter or change these values” table takes precedence over the general
defaults below.

## Connection and protocol

| Setting | Safe/default behaviour | Change it when |
|---|---|---|
| Offer on the login page | Off for a newly created server | Discovery, identity policy and a recovery login are ready |
| Application code | `main`; choosing a named profile suggests its short name on a new form; a case-insensitive conflict names the existing owner immediately and is rejected again on Save | choose a different unique code for each additional OIDC server; a lowercase descriptive code such as `authentik` is easier to recognize |
| Provider profile | Generic OpenID Connect | a named provider is available; its preset and diagnostics then apply |
| Microsoft account audience | One specific Entra tenant; shown only for the Microsoft profile | one button should accept any Entra organization, personal Microsoft accounts, or both |
| Exact issuer URL | may be empty only while disabled | copy the provider's exact `issuer`, including path and trailing slash, before enabling; a pasted URL ending in `/.well-known/openid-configuration` is accepted and stored without that suffix, while named profiles retain a documented significant trailing slash |
| Client ID / Client Secret | may be empty only while disabled | enter the confidential web application's credentials before enabling |
| Authentication method | profile preset, normally Follow the provider | the application was explicitly configured for Basic or POST and the profile does not already enforce a documented requirement |
| Pushed authorization requests | Automatic with availability fallback | use Required when authorization parameters must never pass through the browser, or Disabled for a provider whose optional PAR path is intentionally unreachable; a provider requirement always wins |
| Request Object signing key | Disabled | select a dedicated OPNsense certificate only after its public key and displayed `kid` have been registered for this client at the provider; a provider requirement always wins |
| Username claim | `preferred_username` | the provider guide specifies `email`, a vendor claim or a custom mapping |
| Claims source | Automatic | all required claims must come only from the ID Token, or UserInfo is explicitly required |
| Authorization response mode | Query | Apple with requested user scopes requires Form POST; select signed Query or signed Form POST only for a provider configured to return JARM |
| Required authentication | Provider policy only; stronger choices are unavailable unless the selected profile has a documented request, enforcement and signed-token evidence path | use documented Auth0 MFA, manual Keycloak setup, Okta, one Entra tenant, or the explicitly assessed Generic profile |
| Authentication context request | provider preset; essential `acr` for Generic/Keycloak, `acr_values` for Auth0/Okta, and `acrs` for Entra | the provider guide documents a different request form for a Generic installation |
| Accepted authentication contexts | requirement/provider preset | the provider uses an installation-specific, documented exact `acr` value |
| Accepted authentication methods | requirement/provider preset | the provider documents different exact `amr` values; any configured value may satisfy the method check |
| Microsoft authentication context | empty and shown only for Entra | choose the tenant Conditional Access context `c1`-`c25` that enforces this requirement |
| Match by e-mail address | Only a verified address | username-only matching is required, or a provider omitting `email_verified` has been assessed |
| Scopes | profile preset, normally `openid,email,profile` | another scope such as `groups` is required; `openid` is always included |
| Always show account selection | Off | users commonly have several accounts at the provider and should choose explicitly on every new login; this sends `prompt=select_account` |
| WebGUI address policy | Follow OPNsense WebGUI settings | select Custom origins for this provider only to replace the inherited set for a provider restriction, reverse proxy or different external port |
| Trusted reverse-proxy TLS offloading | Off and hidden while OPNsense itself serves HTTPS | only for an HTTP backend exclusively reachable through one trusted public HTTPS proxy; Custom origins and explicit public HTTPS addresses are mandatory, the proxy must preserve Host and add Secure to the session cookie, and source-network ACLs require trusted client-address propagation |
| Additional or overridden WebGUI origins | empty; Follow mode inherits configured names, actual local interface addresses and virtual IPs at the WebGUI port | add exact browser-facing HTTPS origins in Follow mode, or define the complete replacement set in Custom mode; never enter callback paths |
| Pairwise subject sector | Off; the choices are the effective exact WebGUI origins | a provider should issue pairwise `sub` values and accepts a sector identifier URI; choose a stable origin before creating the provider client, save the server as a disabled draft, and do not change it after identity bindings exist |
| Maximum authentication age | `14400` seconds (four hours) | use `3600` for one hour, `28800` for eight hours, or `0` to require active authentication at the provider for every new OPNsense login; this does not limit an OPNsense session that is already established |
| Receive Shared Signals | Off | this provider should be allowed to end matching sessions through signed SSF push or explicitly configured poll events |
| Shared Signals transmitter issuer | Empty | copy the transmitter's exact HTTPS issuer before enabling Shared Signals |
| Shared Signals audience | Empty | copy the immutable `aud` assigned to the receiver's stream |
| Shared Signals delivery method | Push | choose Poll only when discovery advertises it and a managed stream assigns its endpoint |
| Shared Signals management authorization | Empty | enter the complete Bearer or Basic value issued for stream management; polling requires it |
| Shared Signals stream ID | Empty | retain the immutable ID returned by Create or Read stream; polling requires it |
| Shared Signals poll endpoint | Empty | retain the exact HTTPS endpoint returned for a poll stream; never infer it from push failure |
| Shared Signals delivery secret | Empty | generate it for push and send the displayed Bearer header through managed or manual stream configuration |
| Previous Shared Signals delivery secret | Empty | temporarily retain the former push credential only during the documented overlap rotation |

The authentication requirement checks both context and method evidence from the
already signature-verified ID Token. Missing, malformed or nonmatching evidence
ends the login before a local account is resolved. The accepted-method setting
is an exact vocabulary, not an “any value wins” list: a recognized standard
context still needs sufficient evidence for its selected policy. The inventory
below follows the [IANA AMR registry](https://www.iana.org/assignments/authentication-method-reference-values/).

| Evidence | Authentication methods | Effect |
|---|---|---|
| Explicit MFA | `mfa` | directly reports multiple-factor authentication |
| Knowledge factor | `kba`, `pin`, `pwd` | combines with a different factor type for REFEDS MFA |
| Possession factor | `hwk`, `otp`, `pop`, `sc`, `sms`, `swk`, `tel` | combines with knowledge or inherence for REFEDS MFA |
| Inherence factor | `face`, `fpt`, `iris`, `retina`, `vbm` | combines with knowledge or possession for REFEDS MFA |
| No portable factor proof | `geo`, `mca`, `rba`, `user`, `wia` | never raises the achieved assurance level |

The EAP `phr` context additionally needs `pop`, `hwk` or `swk`; its
hardware-protected `phrh` context needs `hwk`. A provider-specific value counts
only when it was entered exactly as a documented local mapping. Unknown token
values, ACR names repeated as AMR values and the nonstandard `hw` spelling do
not count. Microsoft Entra requires `mfa` for both tiers and, for
phishing-resistant authentication, also its documented `fido`, `hwk` or `x509`
method. Microsoft explicitly states that `x509` alone is insufficient.

Passwordless is deliberately not a separate policy because it describes the
sign-in experience rather than a portable assurance level; Passkeys and FIDO2
belong under phishing-resistant authentication.

DPoP is negotiated protocol behavior rather than an administrator setting. If
the selected provider profile documents RFC 9449 access-token support and
Discovery advertises `ES256` in `dpop_signing_alg_values_supported`, the plugin
binds the authorization code and access token to its per-provider proof key and
refuses a Bearer downgrade. Providers that do not advertise DPoP continue to use
Bearer access tokens. authentik's documented `bound_key` profile binds an ID
Token while retaining a Bearer access token, so it is not negotiated as this
RFC 9449 access-token profile.

The signed Query and signed Form POST choices request JARM. OPNsense then accepts
only the `response` JWT, verifies an advertised supported asymmetric signature,
exact issuer and client audience, time and the one-time transaction state, and
only afterwards processes its code or provider error. Encrypted JARM responses
are not supported. Register or enable the matching signed authorization-response
algorithm at the provider before selecting either mode.

Unsupported named profiles do not merely hide the setting. Save validation
rejects a crafted value, and the login path refuses an older or manually edited
configuration which still requests an unavailable tier. This prevents a token
mapper that merely writes plausible `acr` or `amr` strings from being mistaken
for provider-side enforcement. See the complete capability matrix in
[provider profiles and defaults](provider-profiles.md).

Shared Signals is independent of offering new logins. It only ends sessions
previously created by the same saved authentication server and never changes a
local account, binding, group or privilege. See the [receiver setup](shared-signals.md)
for its supported CAEP/RISC events, stream lifecycle, rotation and bounded poll
worker.

## Local identity and privileges

| Setting | Safe/default behaviour | Change it when |
|---|---|---|
| Create an account on first login | Off; unavailable for Apple, Google, LinkedIn, ORCID, Slack, Yahoo, GitLab.com and broad Microsoft audiences | a bounded provider population such as one Entra tenant, self-managed GitLab or a controlled directory is an approved source of new firewall accounts |
| Admission policy | Administrator approval for a named profile; Strict for Generic; automatic choices unavailable for Apple, LinkedIn, ORCID, Yahoo, GitLab.com and broad Microsoft audiences | use Strict with manual bindings, Approval for public identities, or automatic matching only for an assessed controlled population |
| Groups for a new account | Empty | just-in-time creation is intentionally enabled and a bounded initial group set is required |
| Allow the built-in root account | Off | the recovery superuser should deliberately be controlled by the IdP |
| Group claim | Empty; memberships remain local | the provider should manage selected OPNsense memberships |
| Assignable groups | Empty; the provider can grant none | a Group claim is configured; list only bounded local groups |
| Allow every local group | Off | full privilege delegation to the provider is explicitly intended |

Enabling a Group claim does not make an empty allow-list mean “all”. This
prevents a typo from delegating every firewall privilege.

## Diagnostics, logout and appearance

| Setting | Safe/default behaviour | Change it when |
|---|---|---|
| Trace the exchange | Off | diagnosing one failed exchange; turn it off afterward |
| Redirect the Log Out menu entry | On for Auth0, authentik, FusionAuth, IBM Security Verify, Keycloak, Microsoft Entra, Okta, OneLogin, Oracle, Ping, Pocket ID, WSO2 and ZITADEL; Off otherwise | Lobby > Log Out should also end the provider SSO session when official documentation describes a compatible RP-initiated logout flow |
| Return here after logout | Off | the displayed post-logout URI is registered at the provider |
| Provider logout notifications | Both | accept only Back-Channel, only Front-Channel, or neither; disabling new logins does not disable notifications for existing sessions |
| Login button style | full-width button | the standard OPNsense link appearance is preferred |
| Login button wording | the localized OPNsense login sentence for Generic and installation-specific providers; the familiar short provider name for fixed global services | omit the sentence and show only an installation-specific provider label, or deliberately use one exact custom full text |
| Provider label on login button | Descriptive name; available for Generic, self-hosted and tenant-specific profiles | the name users should see differs from the technical authentication-server name; it remains compatible with the localized OPNsense sentence |
| Custom login button text | Empty; shown only for Custom full text | one literal complete wording should replace both the localized sentence and provider label for every WebGUI language |
| Icon URL | every named profile selects its real package-owned brand SVG; Generic uses the official OpenID mark | replace it with a local theme asset, image data URI or public HTTPS image for installation-specific branding; a remote image is fetched through the firewall rather than by the login browser |
| Icon markup | Empty | supported built-in markup is used; it takes precedence over Icon URL |
| Icon rendering | Single colour | choose Original colours when the provider's brand colours are preferred; bundled marks use real transparent cut-outs, while a custom icon must not simulate them with opaque white shapes |

The localized mode deliberately reuses the exact sentence translated by
OPNsense core. A custom full text cannot be translated automatically because it
is administrator-authored. Apple, Google, Microsoft, LinkedIn, ORCID, Slack and
Yahoo have one global public login identity and therefore use their conventional
short label without exposing unnecessary wording controls. Create separate
authentication-server entries when distinct Microsoft audiences need distinct
buttons; both still use the familiar `Microsoft` label.

**Test discovery**, **Connection health**, **Test sign-in**, **Download provider
setup** and **Open setup guide** are actions, not stored settings. None runs
during Save. Test discovery live-fetches Discovery and JWKS from OPNsense and
checks the selected Request Object key. It uses the current unsaved client
values for an authenticated PAR check when applicable and also works without
client credentials. Connection health becomes
available when the current form contains Exact issuer URL, Client ID and Client
Secret and adds form and WebGUI transport checks without requiring a save. Both
dialogs distinguish live OPNsense requests, metadata/configuration evaluation
and advertised paths that remain untested. The browser does not need to reach
Discovery. Test sign-in becomes available after the server has first been saved,
is complete and has no unsaved changes. It may be used while the provider
remains disabled and validates a real browser flow without changing the WebGUI
session or local identity state. The provider may retain its own SSO session.
OPNsense's generic **System > Access > Tester** is a username/password tester and
does not apply to OIDC. The setup
download and its independently reopenable guide are offered only where an
official, safely repeatable import format is implemented; see [provider
onboarding files](provider-onboarding.md).

In Automatic mode, the first temporary PAR availability failure falls back to a
normal browser authorization request and opens a provider-bound circuit. Later
logins bypass PAR immediately while the minutely scheduled recovery job sends
authenticated test PAR requests in the background. Success restores PAR. DNS,
connection and timeout failures, HTTP 429/5xx and explicitly temporary OAuth
errors may open this fallback; TLS, client authentication and protocol errors
never do. Required mode has no fallback. Disabled mode is rejected when
Discovery says `require_pushed_authorization_requests=true`.

Selecting **Request Object signing key** protects every authorization parameter
inside a signed RFC 9101 JWT. The browser receives only the matching Client ID
and `request`; with PAR, the PAR endpoint receives those two values and the
browser receives only its returned `request_uri`. Each Request Object binds the
Client ID as `iss`, the exact Discovery issuer as `aud`, uses the provider's
advertised compatible algorithm, expires after 60 seconds and carries a fresh
`jti`. A provider advertising `require_signed_request_object=true` cannot be
used until a key is selected. Encrypted JWE Request Objects are not supported.

Use a certificate dedicated to Request Object signing. Its OPNsense reference
is the JWS `kid`; register that exact value with the public key. To rotate, add
and register a second certificate under its new `kid`, select it, run Test
discovery and Test sign-in, and remove the former provider key only after the
new login succeeds. Replacing or deleting the selected certificate before the
provider is ready fails closed.

Validated OIDC and SSF Discovery and JWKS responses use `Cache-Control`, ETag and
`304 Not Modified`. Without an explicit lifetime they are fresh for one hour.
Bounded stale use is at most 24 hours for Discovery and one hour for an already
known signing key; `no-store` and `must-revalidate` are honoured. An unknown key
causes one throttled live refresh and then fails closed.

Changing a provider from public to pairwise subjects, changing its sector or
recreating its pairwise salt can change `sub`. Existing issuer/subject bindings
are not migrated automatically; verify and rebind affected identities
deliberately.

**Manage identities** is available on every saved OpenID Connect server. It
lists durable bindings, supports assisted creation/editing/removal and handles
pending approvals when the Administrator approval policy is active. It is not a
stored setting and requires OPNsense's **System: Authentication Servers**
privilege; write actions additionally honour **user-config-readonly**. Creating
a local account inside a new binding or approval also requires **System: Access:
Management**. The account starts with a scrambled password and no groups or
privileges, which remain explicit local choices. See the
[admission policy guide](admission-policy.md).

Back-channel and front-channel logout are notifications from the provider to
OPNsense. Both are accepted by default so a provider which supports an alternate
delivery has both available. OPNsense cannot itself turn a failed inbound
Back-Channel request into Front-Channel delivery; that retry decision belongs to
the provider. “Return here after logout” is the opposite direction: it asks the
provider to send the user's browser back after an OPNsense-initiated logout.
