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

Open OPNsense under the WebGUI address to register, select the Keycloak profile,
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
| Authorization response mode | Query | normal Authorization Code response; Form POST is also implemented but unnecessary for Keycloak |
| Match by e-mail address | Only a verified address | prevents a first binding through an unverified address |
| Scopes | `openid,email,profile` | sufficient for sign-in and the standard identity claims |
| Pairwise subject sector | Off | select a stable accepted origin before client creation only when pairwise `sub` values are required |
| Maximum authentication age | `14400` | require the Keycloak authentication used for a new OPNsense login to be no older than four hours; `0` requests active authentication every time and does not shorten an established OPNsense session |
| Create an account on first login | Off | firewall accounts should normally be pre-created |
| Allow the built-in root account | Off | preserves a provider-independent recovery account |
| Group claim | Empty | keeps WebGUI authorization local for the first test |
| Trace the exchange | Off | enable only briefly while diagnosing; logs remain redacted |

**Redirect the Log Out menu entry** and **Return here after logout** are off by
default. Enable the first when the OPNsense Log Out entry should end the
Keycloak SSO session. Enable the second only after the exact **Valid post logout
redirect URI** above has been registered.

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

For every remaining OPNsense field, see the [settings
reference](../setup/settings-reference.md).

Reference: [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/).
