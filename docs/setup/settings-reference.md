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
| Username claim | `preferred_username` | the provider guide specifies `email`, a vendor claim or a custom mapping |
| Claims source | Automatic | all required claims must come only from the ID Token, or UserInfo is explicitly required |
| Authorization response mode | Query | Apple with requested user scopes requires Form POST |
| Match by e-mail address | Only a verified address | username-only matching is required, or a provider omitting `email_verified` has been assessed |
| Scopes | profile preset, normally `openid,email,profile` | another scope such as `groups` is required; `openid` is always included |
| WebGUI address policy | Follow OPNsense WebGUI settings | select Custom origins for this provider only to replace the inherited set for a provider restriction, reverse proxy or different external port |
| Trusted reverse-proxy TLS offloading | Off and hidden while OPNsense itself serves HTTPS | only for an HTTP backend exclusively reachable through one trusted public HTTPS proxy; Custom origins and explicit public HTTPS addresses are mandatory, the proxy must preserve Host and add Secure to the session cookie, and source-network ACLs require trusted client-address propagation |
| Additional or overridden WebGUI origins | empty; Follow mode inherits configured names, actual local interface addresses and virtual IPs at the WebGUI port | add exact browser-facing HTTPS origins in Follow mode, or define the complete replacement set in Custom mode; never enter callback paths |
| Maximum authentication age | `14400` seconds (four hours) | use `3600` for one hour, `28800` for eight hours, or `0` to require active authentication at the provider for every new OPNsense login; this does not limit an OPNsense session that is already established |

## Local identity and privileges

| Setting | Safe/default behaviour | Change it when |
|---|---|---|
| Create an account on first login | Off; shown only for automatic admission policies | the provider is an approved source of new firewall accounts and default privileges are reviewed |
| Admission policy | Administrator approval for a named profile; Strict for Generic | use Strict with manual bindings, or use automatic username/e-mail matching only for an assessed, controlled claim source |
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
| Redirect the Log Out menu entry | Off | Lobby > Log Out should also begin provider logout |
| Return here after logout | Off | the displayed post-logout URI is registered at the provider |
| Login button style | full-width button | the standard OPNsense link appearance is preferred |
| Login button wording | the localized OPNsense login sentence for Generic and installation-specific providers; the familiar short provider name for fixed global services | omit the sentence and show only an installation-specific provider label, or deliberately use one exact custom full text |
| Provider label on login button | Descriptive name; available for Generic, self-hosted and tenant-specific profiles | the name users should see differs from the technical authentication-server name; it remains compatible with the localized OPNsense sentence |
| Custom login button text | Empty; shown only for Custom full text | one literal complete wording should replace both the localized sentence and provider label for every WebGUI language |
| Icon URL | a named profile selects its package-owned SVG; Generic leaves it empty | replace it with a local theme asset, image data URI or public HTTPS image for installation-specific branding; a remote image is fetched through the firewall rather than by the login browser |
| Icon markup | Empty | supported built-in markup is used; it takes precedence over Icon URL |
| Icon rendering | Single colour | use Original colours for a multicolour logo or one with a filled background |

The localized mode deliberately reuses the exact sentence translated by
OPNsense core. A custom full text cannot be translated automatically because it
is administrator-authored. Apple, Google, Microsoft, LinkedIn, ORCID, Slack and
Yahoo have one global public login identity and therefore use their conventional
short label without exposing unnecessary wording controls. Create separate
authentication-server entries when distinct Microsoft audiences need distinct
buttons; both still use the familiar `Microsoft` label.

**Test discovery**, **Test sign-in**, **Download provider setup** and **Open
setup guide** are actions, not stored settings. None runs during Save. Test sign-in becomes
available after the server has first been saved and may be used while the
provider remains disabled; it validates a real browser flow without changing
the WebGUI session or local identity state. The provider may retain its own SSO
session. OPNsense's generic **System > Access > Tester** is a username/password
tester and does not apply to OIDC. The setup
download and its independently reopenable guide are offered only where an
official, safely repeatable import format is implemented; see [provider
onboarding files](provider-onboarding.md).

**Manage identities** is available on every saved OpenID Connect server. It
lists durable bindings, supports assisted creation/editing/removal and handles
pending approvals when the Administrator approval policy is active. It is not a
stored setting and requires OPNsense's **System: Authentication Servers**
privilege; write actions additionally honour **user-config-readonly**. See the
[admission policy guide](admission-policy.md).

Back-channel and front-channel logout are notifications from the provider to
OPNsense. “Return here after logout” is the opposite direction: it asks the
provider to send the user's browser back after an OPNsense-initiated logout.
