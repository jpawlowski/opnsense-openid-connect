# authentik

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

This walkthrough assumes that OPNsense is opened as
`https://firewall.example.com` and that **Application code** is set to
`authentik`. Replace the address with the real WebGUI address. If you keep
application code `main`, every generated URL must end in `/main` instead.

## Quick setup

### Optional shortcut: import a generated Blueprint

Open OPNsense under the accepted HTTPS WebGUI FQDN to register, select the authentik
profile, enter the **Application code**, and select **Download provider setup**.
Choose Back-channel only
if the authentik server trusts and can reach the WebGUI; otherwise choose
Front-channel. The current unsaved form is enough, so the issuer, Client ID and
Client Secret may still be empty.

Use **Open setup guide** whenever the import instructions are needed again; it
opens the authentik steps without downloading another Blueprint.

In authentik open **Admin interface > Customization > Blueprints > Import**, use
**File upload**, review the YAML and import it. The Blueprint creates a
confidential OAuth2/OpenID provider and linked application, exact Authorization
and optional Post Logout redirects, the standard OpenID and profile mappings, a
dedicated verified e-mail mapping and an asymmetric signing key. authentik
generates the Client ID and Client Secret. The Application's explicit Launch URL
is the OPNsense login-start endpoint under the accepted WebGUI origin from which
the Blueprint was downloaded, not its callback URL. That origin's callback is
also the first redirect entry. The application tile is named after that FQDN and
uses the reviewed, commit-pinned OPNsense Core mark from public GitHub hosting.
Replace or remove that external icon URL when the installation requires local hosting.

The dedicated `email` mapping sends `email_verified=true` only when the
authentik user's custom `email_verified` attribute is the JSON boolean `true`.
It sends `false` when that attribute is absent, false or another type. Populate
the attribute only from a directory or enrollment flow that actually verified
control of the current address; do not set it merely because an address exists.

A green import result means authentik validated and immediately applied the
file. This one-time **Import** operation deliberately does **not** create a
monitored entry under **Customization > Blueprints**, so no new Blueprint is
expected in that list. Confirm the result instead under **Applications >
Applications** and **Applications > Providers**. Creating a persistent Blueprint
instance is a different workflow intended for a file, OCI registry or YAML
stored inside authentik; it is not required for this onboarding shortcut.

The generated YAML declares the version-bound authentik `2026.8` JSON schema.
Its model fields and references are tested against authentik `2026.8.0`. The
provider `name` and application `slug` occur only under `identifiers`, in line
with the current Blueprint structure guidance; authentik merges identifiers
into the attributes when it creates each object.

After import, open the generated provider and copy those credentials to
OPNsense. The exact issuer is
`https://auth.example.com/application/o/opnsense-<application-code>/`; copy the
value shown by authentik rather than constructing it by hand. A repeated import
leaves the existing provider and its credentials unchanged; it does not add new
redirect addresses or apply other changed settings. Update a small change on the
existing provider. To replace it from a newly generated Blueprint, delete the
generated application, provider and application-specific verified e-mail scope
mapping first, import again, and copy the newly generated Client ID and Client
Secret back to OPNsense. Do not delete authentik's built-in scope mappings.

The Blueprint deliberately creates no authentik policy binding. Restrict the
generated application to the users or groups who may administer this firewall;
OPNsense's local account and privilege checks remain an additional boundary.
It already selects authentik's per-provider issuer mode and hashed user-ID
subject mode, so the OPNsense **Pairwise subject sector** setting is not needed
for this generated Blueprint and does not alter it.

**Required authentication** is limited to **Provider policy only** for the
authentik profile. authentik can enforce MFA, WebAuthn and Passkeys in a selected
authentication flow and reports authentication methods, but its retained
documentation does not establish the request-bound `acr` plus `amr` evidence
pair this plugin requires for either stronger tier. The Blueprint therefore
does not invent claims or treat an authenticator stage as portable evidence.
Generation and login both refuse a manually injected stronger setting.

The remaining sections describe every field and are also the fallback when a
custom authentik flow, signing key or policy assignment is required.

### 1. Create the OPNsense server without enabling login

Under **System > Access > Servers**, add an **OpenID Connect** server and enter
or change these values:

| Field | Value in this example |
|---|---|
| Offer on the login page | Off until the complete test below |
| Application code | `authentik` |
| Provider profile | authentik |
| Exact issuer URL | May be empty in the disabled draft; later use `https://auth.example.com/application/o/<slug>/` |
| Client ID | May be empty in the disabled draft; copy from authentik after creating the provider |
| Client Secret | May be empty in the disabled draft; copy from authentik after creating the provider |
| WebGUI address policy | Follow OPNsense WebGUI settings; open this form as `https://firewall.example.com` |
| Admission policy | Administrator approval for an unknown first identity, exact username matching for a controlled directory, or Strict with a subject binding |

The current WebGUI address has no callback path. The issuer normally has the shown
trailing slash; copy it exactly from authentik instead of typing it from memory.

### 2. Create the authentik application and provider

In authentik go to **Applications > Applications** and create an application
with an **OAuth2/OpenID Provider**, or create the provider and application
separately.

Use these provider values:

| authentik field | Value |
|---|---|
| Client type | Confidential |
| Signing Key | an asymmetric certificate/key; do not select an HMAC/HS signing setup |
| Grant type | Authorization Code; a Refresh Token grant is not required by this plugin |
| Scopes | `openid`, `email`, `profile` |
| Redirect matching mode | Strict, not Regex |
| Redirect URI/Origin type | Authorization |
| Redirect URI/Origin value | `https://firewall.example.com/api/openidconnect/auth/callback/authentik` |

In current authentik versions, each entry under **Redirect URIs/Origins** has a
type:

- Add the callback above as type **Authorization**.
- Do not add the back-channel or front-channel logout address as Authorization.
- Add `https://firewall.example.com/api/openidconnect/auth/logouttestcallback/authentik`
  as type **Post Logout**. This exact address returns the optional disposable
  lifecycle test to the saved OPNsense server page.
- Add `https://firewall.example.com/` as type **Post Logout** only if **Return
  here after logout** will be enabled in OPNsense. Keep the trailing `/` because
  that is the exact post-logout address displayed by the plugin.

Assign the authentik application only to users or groups who should be able to
reach this firewall.

When creating the provider manually, replace authentik's standard `email`
mapping with a custom scope mapping equivalent to the generated Blueprint:

```python
verified = request.user.attributes.get("email_verified", False)
return {
    "email": request.user.email,
    "email_verified": verified is True,
}
```

The strict boolean check deliberately treats missing values and strings such as
`"true"` as unverified.

### 3. Configure one authentik logout method

authentik's **Logout URI** is not the post-logout return address. It is the
notification endpoint used by the selected **Logout Method**. Choose exactly
one matching pair:

| authentik Logout Method | authentik Logout URI |
|---|---|
| Back-channel | `https://firewall.example.com/api/openidconnect/auth/backchannel/authentik` |
| Front-channel | `https://firewall.example.com/api/openidconnect/auth/frontchannel/authentik` |

Back-channel is more reliable because it does not depend on a browser iframe.
It requires the authentik server itself to reach `firewall.example.com` and
trust the OPNsense certificate. With a self-signed certificate, Front-channel
is easier unless that certificate or its CA is installed in authentik's trust
store. Do not disable certificate verification.

authentik currently marks its front-channel/back-channel logout feature as
**Preview**. Its documented back-channel Logout Token includes `iss`, `sub`,
`aud`, `iat`, unique `jti`, the logout event and optional `sid`. OPNsense also
requires an integer `exp` and keeps its replay entry through that signed expiry.
If the installed authentik release does not emit `exp`, use front-channel
logout instead of weakening token validation. Treat both notification methods
as optional until they have been tested with the installed authentik release;
ordinary login and RP-initiated logout do not depend on enabling either one.

These addresses have separate jobs:

```text
Authorization redirect:
https://firewall.example.com/api/openidconnect/auth/callback/authentik

Post-logout browser return (optional):
https://firewall.example.com/

Back-channel logout notification (choose this or front-channel):
https://firewall.example.com/api/openidconnect/auth/backchannel/authentik

Front-channel logout notification:
https://firewall.example.com/api/openidconnect/auth/frontchannel/authentik
```

### 4. Finish and test OPNsense

1. Copy the authentik client ID, client secret and exact issuer into OPNsense.
2. Select **Test discovery**. Fix every reported error before continuing.
3. Ensure an authentik `preferred_username` equals the intended non-root local
   OPNsense username when using username bootstrap. With Strict mode, save the
   server, open **Manage identities**, and map the exact verified authentik
   `sub` to the intended existing local account.
4. Keep another local administrator session open.
5. Enable **Offer on the login page**, save, and test in a private window.
6. After the first successful bootstrap, the durable issuer/subject binding is
   saved; later username changes do not reassign the identity.

## Defaults that are correct for authentik

The authentik profile selects these values; leave them unchanged for the first
login:

| Field | Value | Why |
|---|---|---|
| Authentication method | Follow the provider | Discovery advertises the supported secret method; force Basic or POST only for a known metadata mismatch |
| Username claim | `preferred_username` | authentik's standard profile mapping emits it |
| Claims source | Automatic | uses verified ID Token claims and asks UserInfo only for a configured missing claim |
| Authorization response mode | Query | authentik returns the authorization code in the normal query response |
| Match by e-mail address | Only a verified address | avoids first-binding takeover through an unverified address |
| Scopes | `openid,email,profile` | sufficient for sign-in and the standard identity claims |
| Pairwise subject sector | Off | the generated provider already uses per-provider issuer and hashed user-ID subject modes |
| Required authentication | Provider policy only | no compatible end-to-end context-and-method procedure is retained for this profile |
| Maximum authentication age | `14400` | require the authentik authentication used for a new OPNsense login to be no older than four hours; `0` requests active authentication every time and does not shorten an established OPNsense session |
| Create an account on first login | Off | firewall accounts should normally be pre-created |
| Allow the built-in root account | Off | preserves a local recovery account outside the IdP |
| Group claim | Empty | keeps OPNsense privilege membership local for the first test |
| Trace the exchange | Off | enable only briefly while diagnosing |
| Redirect the Log Out menu entry | On | ends the local session first and then initiates authentik logout |

authentik 2026.8 also documents the `bound_key` scope for a key-bound ID Token.
Its access token remains Bearer, so this profile does not request that extension
or mistake it for RFC 9449 sender-constrained access tokens. Keycloak's separately
documented DPoP access-token path remains enabled automatically.

**Return here after logout** remains off by default. Enable it only after the
Post Logout entry described above exists in authentik. The logout-menu
recommendation remains editable when ending the wider authentik SSO session is
not wanted for this firewall.

## Groups and advanced notes

The standard authentik profile scope mapping can emit `groups`. To delegate a
small part of OPNsense authorization after login works:

1. Set **Group claim** to `groups`.
2. Put only dedicated local OPNsense group names under **Assignable groups**.
3. Leave **Allow every local group** off.

Do not select an encryption key for the client: encrypted ID Tokens and
UserInfo responses are outside this plugin's supported profile. An asymmetric
**Signing Key** is required because the plugin intentionally rejects ID Tokens
signed with a shared client secret (`HS*`).

For an explanation of every remaining OPNsense field, see the [settings
reference](../setup/settings-reference.md).

References: [authentik OAuth2/OIDC provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/),
[front-channel and back-channel logout](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/frontchannel_and_backchannel_logout/),
and [Blueprint import](https://docs.goauthentik.io/customize/blueprints/working_with_blueprints/).
