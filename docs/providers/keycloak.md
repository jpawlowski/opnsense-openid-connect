# Keycloak

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

This walkthrough assumes that OPNsense is opened as
`https://firewall.example.com`, the Keycloak realm is `infrastructure`, and
**Application code** is `keycloak`. Replace all three example values. If the
application code remains `main`, every generated OPNsense endpoint ends in
`/main` instead.

## Quick setup

### Optional shortcut: import a generated client

Open OPNsense under the accepted HTTPS WebGUI FQDN to register, select the Keycloak profile,
enter the **Application code**, and select **Download provider setup**. The
issuer, Client ID and Client
Secret may still be empty while the OPNsense server remains disabled.

Use **Open setup guide** to reopen the Keycloak import steps later without
downloading the JSON file again.

In Keycloak select the intended realm, then **Realm settings > Action > Partial
import** and upload the JSON file. Choose **Skip** if the client already exists;
do not choose Overwrite merely to repeat the setup. Keycloak creates a
confidential client with a derived ID such as `opnsense-keycloak` and generates
its secret. Copy the secret from the client's **Credentials** tab, and copy the
realm's exact issuer into OPNsense.

The import sets **Root URL** to the accepted WebGUI origin from which it was
downloaded and **Home URL** to that origin's OPNsense login-start endpoint. This
makes Keycloak's application link start a normal local OIDC transaction instead
of sending the browser to a callback URL. The same origin's callback is first in
**Valid Redirect URIs**, and the client remains visible in the Account Console.
Its visible name is that FQDN, and its logo URI uses the package-owned OPNsense
mark from the same origin.

A repeated generated import does not update redirects or other client settings.
Apply a small change directly to the existing client. To replace it from a newly
generated file, delete that client first, import the new file with **Skip**, and
copy its newly generated secret back to OPNsense before testing.

The import keeps Keycloak's `basic` client scope as a default because current
Keycloak versions use it for the mandatory `sub` claim and the `auth_time`
evidence required by OPNsense maximum-age validation. It links the standard
`email` and `profile` client scopes only when the current OPNsense scope list
requests them. Keycloak's `email` scope maps the user's **Email verified** state
to `email_verified`; keep that state false until the realm's enrollment or
directory process has actually verified control of the current address.
The generated client also enables **DPoP Bound Access Tokens**. Keycloak
advertises ES256 DPoP realm-wide, so OPNsense uses that path automatically and
refuses a downgrade to an unbound Bearer token.

When **Return here after logout** is selected before generation, the import
also disables Keycloak's separate logout confirmation landing page. Otherwise
Keycloak 26.5 and newer can hold the browser on **You are logged out** until a
second click even though the exact post-logout redirect URI was accepted.

For pairwise subjects, first choose **Pairwise subject sector** in OPNsense and
save the server as a disabled draft. The generated import then adds Keycloak's
built-in `oidc-sha256-pairwise-sub-mapper` with the displayed sector identifier
URI. The mapper salt is deliberately absent from the file so Keycloak generates
and persists it. Do not change the sector or recreate the mapper after users are
bound: either can change `sub` and require deliberate rebinding.

The manual instructions below remain useful for checking the result and for
installations with custom client policies.

### 1. Create the OPNsense server without enabling login

Under **System > Access > Servers**, add an **OpenID Connect** server and enter
or change these values:

| Field | Value in this example |
|---|---|
| Offer on the login page | Off until the complete test below |
| Application code | `keycloak` |
| Provider profile | Keycloak |
| Exact issuer URL | May be empty in the disabled draft; later use `https://sso.example.com/realms/infrastructure` |
| Client ID | May be empty in the disabled draft; copy from Keycloak after creating the client |
| Client Secret | May be empty in the disabled draft; copy from Keycloak after creating the client |
| WebGUI address policy | Follow OPNsense WebGUI settings; open this form as `https://firewall.example.com` |
| Admission policy | Administrator approval for an unknown first identity, exact username matching for a controlled directory, or Strict with a subject binding |

Use the realm issuer, not the Keycloak account-console URL, base server URL,
Discovery document URL or an individual protocol endpoint. Discovery is below
that issuer at `/.well-known/openid-configuration`.

### 2. Create the Keycloak client

In the intended realm, go to **Clients > Create client** and use:

| Keycloak field | Value |
|---|---|
| Client type | OpenID Connect |
| Client ID | a unique value, for example `opnsense-webgui` |
| Client authentication | On |
| Authorization | Off; this is not Keycloak Authorization Services |
| Standard flow | On |
| Direct access grants | Off |
| Implicit flow | Off |
| DPoP Bound Access Tokens | On |
| Valid redirect URIs | `https://firewall.example.com/api/openidconnect/auth/callback/keycloak` |
| Web origins | `https://firewall.example.com` |
| Valid post logout redirect URIs | `https://firewall.example.com/` only when OPNsense **Return here after logout** will be enabled |

Use exact addresses, not `*`. The trailing slash in the post-logout address is
intentional. Do not put either OPNsense logout notification URL under **Valid
redirect URIs**.

On the **Credentials** tab, copy the generated client secret to OPNsense. Under
the client's advanced OpenID Connect settings, set **Proof Key for Code Exchange
Code Challenge Method** to `S256` if the installed Keycloak version exposes
that control. OPNsense sends PKCE S256 on every request in either case.

Under **Client scopes**, link `email` and `profile` as optional scopes when the
OPNsense scope list requests them. The standard `email` scope emits
`email_verified` from the user's **Email verified** state; do not replace it
with a mapper that unconditionally reports true.

Optional manual pairwise configuration uses Keycloak's **Pairwise subject
identifier** protocol mapper. Select a stable OPNsense **Pairwise subject
sector**, save the disabled draft, and configure the mapper's Sector Identifier
URI as:

```text
https://firewall.example.com/api/openidconnect/auth/sector/keycloak
```

Leave Keycloak to generate the pairwise salt. The URI is intentionally public,
contains only the client's exact callback URI array, and answers only through
the selected origin.

### Optional authentication-strength enforcement

This is a manual realm configuration. The generated partial realm import stops
when **Required authentication** is selected because a client import cannot
safely create and bind the realm flow which enforces the claimed method. Import
or create the client while **Provider policy only** is selected, then configure
the flow before enabling the stronger requirement in OPNsense.

1. Under **Authentication**, duplicate the realm's working Browser flow. Bind
   the copy as this client's Browser flow override; do not change the realm-wide
   flow merely for OPNsense.
2. For **Multi-factor authentication**, require a second-factor execution in
   the copied flow and give that successful execution the authenticator
   reference value `mfa`. Configure a Level of Authentication condition which
   the second factor satisfies.
3. For **Phishing-resistant authentication**, instead require a WebAuthn
   authenticator in a dedicated copied flow and give its successful execution
   reference value `fido`. Do not leave OTP as an alternative in that flow.
4. In the client's advanced OIDC settings map
   `https://refeds.org/profile/mfa` to the enforced MFA level, or map `phr` and
   optionally `phrh` to the enforced WebAuthn level. Set the corresponding
   minimum ACR value so a weaker request cannot select a lower level.
5. Ensure the realm's `acr` client scope and its ACR LoA Level mapper are linked
   to the client. Add Keycloak's Authentication Method Reference mapper so the
   successful execution reference is emitted as `amr` in the ID Token.
6. Select the matching **Required authentication** tier in OPNsense and run
   **Test sign-in**. Do not enable the login button unless the verified result
   contains the requested `acr` and the expected `amr` value.

The default OPNsense Keycloak values deliberately match those steps: MFA uses
the REFEDS context plus `mfa`; phishing-resistant authentication accepts
`phr`/`phrh` only together with a registered method such as `fido`. If the realm
uses different documented exact strings, change **Accepted authentication
contexts** and **Accepted authentication methods** to those values on both
sides. Adding a mapper without the enforcing flow is never sufficient.

### 3. Configure one Keycloak logout channel

Back-channel logout is the recommended default:

| Keycloak logout field | Value |
|---|---|
| Front channel logout | Off |
| Backchannel logout URL | `https://firewall.example.com/api/openidconnect/auth/backchannel/keycloak` |
| Backchannel logout session required | On |
| Backchannel logout revoke offline sessions | Off; this plugin does not request offline access |

The Keycloak server must be able to resolve and reach the WebGUI address and
trust its certificate. A self-signed leaf certificate is therefore unsuitable
for server-to-server logout unless that exact certificate is deliberately
trusted by Keycloak. Prefer an internal CA installed in both trust stores; do
not disable certificate verification.

Front-channel logout is the browser-dependent alternative. To use it, set
**Front channel logout** to **On**, set **Front-channel logout URL** to
`https://firewall.example.com/api/openidconnect/auth/frontchannel/keycloak`, and
enable **Front-channel logout session required**.

These two modes are alternatives in Keycloak, not two notifications which it
sends together. When **Front channel logout** is on, Keycloak uses that browser
path; the configured back-channel URL does not also receive the event. Browser
iframes can be blocked by content-security or cookie policy, and an
administrator terminating somebody else's Keycloak session has no matching
user browser in which to deliver it. Use front-channel only when Keycloak
cannot reach the WebGUI directly or when its limitations are acceptable.

The four endpoint roles are:

```text
Authorization redirect:
https://firewall.example.com/api/openidconnect/auth/callback/keycloak

Post-logout browser return (optional):
https://firewall.example.com/

Back-channel logout notification (recommended):
https://firewall.example.com/api/openidconnect/auth/backchannel/keycloak

Front-channel logout notification (alternative):
https://firewall.example.com/api/openidconnect/auth/frontchannel/keycloak
```

### 4. Finish and test OPNsense

1. Copy the Keycloak client ID, client secret and exact realm issuer into
   OPNsense.
2. Select **Test discovery**. Fix every reported error before continuing.
3. Ensure the Keycloak user's `preferred_username` equals the intended non-root
   local OPNsense username when using username bootstrap. With Strict mode,
   save the server, open **Manage identities**, and map the exact verified
   Keycloak `sub` to the intended existing local account.
4. Keep another local administrator session open.
5. Enable **Offer on the login page**, save, and test in a private window.
6. Test the selected logout channel from Keycloak as well as logout initiated
   from OPNsense.

## Defaults that are correct for Keycloak

The Keycloak profile selects these values; leave them unchanged for the first
login:

| Field | Value | Why |
|---|---|---|
| Authentication method | Follow the provider | current Keycloak Discovery advertises supported client-secret methods; force Basic or POST only for a known metadata mismatch |
| Username claim | `preferred_username` | emitted by Keycloak's standard `profile` client scope |
| Claims source | Automatic | accepts verified ID Token claims and asks UserInfo only for a configured missing claim |
| Authorization response mode | Query | normal Authorization Code response; current Keycloak also documents signed Query and Form POST JARM modes when that protection is required |
| Match by e-mail address | Only a verified address | prevents a first binding through an unverified address |
| Scopes | `openid,email,profile` | sufficient for sign-in and the standard identity claims |
| Pairwise subject sector | Off | select a stable accepted origin before client creation only when pairwise `sub` values are required |
| Maximum authentication age | `14400` | require the Keycloak authentication used for a new OPNsense login to be no older than four hours; `0` requests active authentication every time and does not shorten an established OPNsense session |
| Create an account on first login | Off | firewall accounts should normally be pre-created |
| Allow the built-in root account | Off | preserves a provider-independent recovery account |
| Group claim | Empty | keeps WebGUI authorization local for the first test |
| Trace the exchange | Off | enable only briefly while diagnosing; logs remain redacted |
| Redirect the Log Out menu entry | On | ends the local session first and then initiates Keycloak logout |

**Return here after logout** remains off by default. Enable it only after the
exact **Valid post logout redirect URI** above has been registered. The
logout-menu recommendation remains editable when ending the wider Keycloak SSO
session is not wanted for this firewall.

Keycloak's [response-mode API](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/utils/OIDCResponseMode.html)
documents `QUERY_JWT` and `FORM_POST_JWT`. Use either only when signed JARM
responses are deliberately required; Query remains the simpler default.

## Groups and advanced notes

Keycloak protocol mappers decide whether a custom claim appears in the ID
Token, UserInfo response or both. Automatic claims mode supports either. For
groups:

1. Create a Group Membership mapper with a stable claim name such as `groups`.
2. Emit it in the ID Token or UserInfo response.
3. Set that name as OPNsense **Group claim**.
4. List only dedicated local OPNsense group names under **Assignable groups**.
5. Keep **Allow every local group** off.

Avoid **Full group path** unless those exact paths are deliberately also the
local group names. Keycloak realm/client roles are not groups unless a mapper
explicitly turns them into the chosen claim.

The complete flow, including both logout alternatives, `form_post` and
`client_secret_post`, is exercised by this project's disposable
[browser-to-firewall test](../../tests/e2e/README.md) with an official Keycloak
container and a real OPNsense WebGUI.

References: [Keycloak step-up authentication](https://www.keycloak.org/docs/latest/server_admin/#_step-up-flow),
[ACR to Level of Authentication mapping](https://www.keycloak.org/docs/latest/server_admin/#_oidc-auth-flows),
and [Authentication Method Reference mapper](https://www.keycloak.org/docs/latest/server_admin/#adding-authentication-executions).

For every remaining OPNsense field, see the [settings
reference](../setup/settings-reference.md).

References: [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
and [Keycloak release notes for the `basic` client scope](https://www.keycloak.org/docs/latest/release_notes/).
