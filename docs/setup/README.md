# Set up WebGUI sign-in

Install the package first if it is not already present; see [Install or remove
the beta package](install.md).

For authentik and Keycloak, the form can generate an optional provider-side
import file before Client ID, Client Secret or issuer exist. See [provider
onboarding files](provider-onboarding.md). The manual steps below remain the
authoritative route and work for every supported provider.

This is the common part of every provider setup. Keep a separate local
administrator session open until an OpenID Connect login and logout have both
worked. The local username/password form remains available.

## 1. Prepare the WebGUI address

Decide which HTTPS address administrators actually type into their browsers,
for example `https://firewall.example.com`. When an IPv4 example is useful,
this documentation uses the [reserved TEST-NET-1 address](https://www.rfc-editor.org/rfc/rfc5737.html)
`https://192.0.2.1`.

An **origin** contains only the scheme, host or IP address, and an optional
port. It never contains `/api/...` or another path. Normally leave **WebGUI
address policy** at **Follow OPNsense WebGUI settings**. The plugin then accepts
OPNsense's hostname and domain, short hostname, alternate hostnames, actual
local interface addresses and virtual IPs. Every origin uses the configured
WebGUI port, or the HTTPS standard port 443 when none is configured. The
provider setup download and endpoint preview put the currently opened origin
first only when it is one of these accepted origins.

**Additional or overridden WebGUI origins** is optional in Follow mode. Any
origins entered there supplement the automatically inherited set. Select
**Custom origins for this provider** when the entered origins must instead
replace that set: for example to restrict one provider to fewer addresses, or
when a reverse proxy or external port cannot be represented by OPNsense's
WebGUI settings. A value is `https://firewall.example.com`, not a callback URL.
Scheme and port are part of the exact origin; certificate trust remains a
separate matter. An arbitrary IP address is never accepted merely because it
is syntactically valid: it must belong to OPNsense or be entered explicitly.

An IP address is valid here. It can also be covered by a certificate when the
certificate contains that IP address as an IP Subject Alternative Name. With a
self-signed certificate:

- every administrator's browser must trust or explicitly accept it before the
  provider sends the browser back to OPNsense;
- an identity provider making a back-channel logout request must separately
  trust that certificate and be able to reach the address;
- OPNsense must trust the identity provider's certificate for Discovery, token
  and UserInfo requests.

There is intentionally no switch which disables TLS certificate verification.
For a private certificate authority, install that authority into the relevant
trust stores. A browser exception is adequate for an isolated test, but is not
a durable production setup.

### Native HTTP and TLS offloading

The safe and recommended setup is **System > Settings > Administration >
Protocol: HTTPS**. If OPNsense is configured as HTTP, an enabled OIDC server is
blocked, no automatic HTTPS origins are invented, its login button is omitted,
and Test sign-in cannot start. An unfinished server can still be saved while it
is disabled.

For an intentionally HTTP-only backend behind one trusted HTTPS reverse proxy,
the form exposes **Trusted reverse-proxy TLS offloading**. This is an advanced
exception, not a way to permit an HTTP login. All of these conditions are
required:

1. The browser-facing listener permits HTTPS only. The OPNsense HTTP listener
   is reachable only from that trusted proxy, using firewall rules as well as
   routing where possible.
2. Select **Custom origins for this provider** and enter every exact public
   HTTPS origin. Follow mode is deliberately unavailable because an HTTP
   listener cannot prove the external scheme or port.
3. Preserve the public `Host` header. If the public name is not OPNsense's main
   hostname, also add it to **Alternate Hostnames for DNS Rebinding and
   HTTP_REFERER Checks**; do not disable those checks globally.
4. Rewrite OPNsense's `PHPSESSID` response cookie to add at least `Secure`, while
   retaining `HttpOnly` and `SameSite=Lax`. OPNsense omits `Secure` when its own
   WebGUI protocol is HTTP.
5. Apply normal reverse-proxy limits and do not expose another path that reaches
   the backend with an attacker-chosen `Host`.
6. If OPNsense group privileges use source-network restrictions, propagate the
   real client address through either lighttpd's `mod_extforward` with a strict
   trusted-proxy allow-list or PROXY protocol. Otherwise OPNsense sees the
   proxy's address and evaluates those restrictions against the wrong client.

The plugin intentionally ignores `X-Forwarded-Proto` and related headers. A
client can manufacture them unless the complete proxy trust chain is configured
perfectly; the exact custom HTTPS origin and explicit exception are instead the
authority used to construct callbacks.

OPNsense's lighttpd build includes `mod_extforward`, and lighttpd can use HAProxy
PROXY protocol v1/v2 when it is manually enabled. This may preserve the real
client address for logging and source-network access policy without relying on
an HTTP client-IP header. It is **not** an
OIDC setting and the plugin does not enable it: PROXY framing is listener-wide,
so the proxy and every connection to that listener must agree. Version 1 carries
addresses but no TLS fact; version 2 has an optional SSL TLV, but its presence
and propagation into OPNsense's PHP request scheme are not dependable enough to
replace the explicit offloading policy. Neither version replaces the HTTP
`Host` value used for exact callback-origin matching. See the
[lighttpd `mod_extforward` documentation](https://redmine.lighttpd.net/projects/1/wiki/Docs_ModExtForward)
and [HAProxy PROXY protocol specification](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt).

## 2. Create the OPNsense authentication server

Go to **System > Access > Servers**, add a server of type **OpenID Connect** and
start with **Offer on the login page** disabled.

Choose an **Application code**. It is a short, unique identifier, not a URL.
For example, use `authentik` for one authentik connection. The default `main`
is also valid when there is only one connection. The examples in a provider
guide state which code they use. The form immediately names an existing server
that already owns the code, and Save performs the same authoritative check.
Capitalization does not make a code distinct; use simple lowercase names.

Enter the matching **Provider profile**. The form immediately fills all safe
provider defaults, locks documented invariants, and shows an issuer-shaped hint
where a tenant, realm or installation value is still required. **Restore profile
defaults** reverses later experiments without affecting provider-independent
authorization or WebGUI settings. The complete behaviour is documented in
[provider profiles and defaults](provider-profiles.md).

Leave **Required authentication** at **Provider policy only** until the provider
has been configured to return and enforce the corresponding ID Token evidence.
MFA and phishing-resistant policies fail closed when either their exact
authentication context or method evidence is missing. Provider-specific setup,
especially Microsoft Entra Conditional Access, is described in its provider
guide. Run **Test sign-in** before enabling such a requirement for normal login.

Named profiles expose a stronger choice only when this project retains a
complete provider-side procedure. Auth0 supports documented MFA, Keycloak needs
manual realm-flow setup, and Okta and one Entra tenant support both available
tiers. Other named profiles enforce **Provider policy only**; a crafted form or
manual `config.xml` value is refused at login rather than silently trusted.

While the server remains disabled, the exact **Issuer URL**, **Client ID** and
**Client Secret** may be empty so either side can be prepared first. Before
enabling login, the three provider values are required; a selected custom address
policy additionally requires at least one exact HTTPS origin. Follow mode needs
no duplicated origin entry when OPNsense itself serves HTTPS. With an HTTP
WebGUI, enabling also requires the complete trusted TLS-offloading exception
described above.

The endpoint reference constructs the addresses from the WebGUI origin and
application code. With origin `https://firewall.example.com` and application code
`authentik`, the callback is:

```text
https://firewall.example.com/api/openidconnect/auth/callback/authentik
```

Every callback, front-channel and back-channel URL for this connection ends in
the same application code. Do not append `/main` unless `main` is the selected
code.

With an authentik or Keycloak profile, **Download provider setup** can create
the provider-side import from the current form without saving or contacting the
provider. **Open setup guide** reopens the same provider-specific import steps
without downloading the file again. The [onboarding guide](provider-onboarding.md)
explains the import and the credential values copied back afterward.

## 3. Register the provider application

Create a confidential web/OIDC application at the provider. Register the
endpoint reference according to its labels:

| OPNsense reference | Register it as |
|---|---|
| Authorization redirect URI | the application's login/callback/authorization redirect URI |
| Post-logout redirect URI | a post-logout URI, only when **Return here after logout** is enabled |
| Back-channel logout URI | the provider's back-channel logout endpoint, when supported |
| Front-channel logout URI | the provider's front-channel logout endpoint, as an alternative |

The three logout-related addresses are not additional authorization redirect
URIs. A provider may offer only some of these fields. Follow its individual
[provider guide](../providers/README.md).

Use Authorization Code, PKCE `S256`, asymmetric token signing and exact redirect
addresses. When JARM is selected, register a supported asymmetric authorization
response signing algorithm and use signed Query or signed Form POST. Do not use
wildcard redirects. Public clients without a secret, encrypted ID Tokens and
encrypted JARM responses are outside this plugin's supported profile.

### Network directions and required reachability

OPNsense cannot operate as a fully isolated relying party. Even when validated
Discovery and signing keys are cached, every new Authorization Code login needs
the Token endpoint from OPNsense. The browser alone reaching the provider is not
enough.

| Path | Direction | Needed when | Checked by |
|---|---|---|---|
| Login page, callback | Browser → OPNsense | every login | Test sign-in |
| Authorization endpoint | Browser → IdP | every login | Test sign-in |
| Discovery | OPNsense → IdP | configuration and metadata refresh | Test discovery, live |
| JWKS signing keys | OPNsense → IdP | token/logout/SSF signature validation | Test discovery, live |
| PAR endpoint | OPNsense → IdP | PAR is offered and not disabled | Test discovery, authenticated live request |
| Token endpoint | OPNsense → IdP | every completed login | Test sign-in |
| UserInfo endpoint | OPNsense → IdP | selected or missing claims require it | Test sign-in |
| Revocation endpoint | OPNsense → IdP | best-effort provider-aware logout | real logout |
| End-session endpoint | Browser → IdP | RP-initiated provider logout | real logout |
| Back-channel logout | IdP → OPNsense | that notification channel is registered | provider logout |
| Front-channel logout | IdP → browser → OPNsense | that notification channel is registered | provider logout |
| Shared Signals management | OPNsense → transmitter | a discovered lifecycle operation is requested | Test Shared Signals plus Create/Read stream |
| Shared Signals push | transmitter → OPNsense | Push delivery is explicitly selected | Test Shared Signals plus a real event |
| Shared Signals poll | OPNsense → transmitter | Poll delivery is explicitly selected | connectivity status plus a real event |

There is no generic OIDC ping endpoint. A TCP or unauthenticated HTTP probe would
not prove TLS trust, client authentication or protocol compatibility. Endpoint-
native tests are used instead.

## 4. Check Discovery

Saving and **Test discovery** are deliberately independent. You may save a
disabled draft even while its provider is unreachable or the Discovery test
fails, return later, and continue editing it. Saving checks local field syntax
and security boundaries only; it never contacts the provider.

Select **Test discovery** before offering the server on the login page. It makes
fresh server-side requests for Discovery and JWKS and, when configured, an
authenticated PAR request using the current form values. The PAR `request_uri`
is discarded and no login transaction is created. The browser does not fetch or
need the Discovery URL. Exact issuer matching is a security boundary: enter the
`issuer` value returned by the provider, not an individual endpoint.

Resolve a failed check at the provider or in the entered value. A named profile
supplies compatible defaults and clearer diagnostics, but never turns off a
protocol check.

Every result keeps only the actor path beneath the check name. The arrow
distinguishes requests made by OPNsense from browser paths and provider
responses. Open the row's info control to see two deliberately separate facts:
the source used for the result and whether that endpoint was actually called.
An advertised endpoint can pass readiness because the validated live Discovery
document contains a compatible value without pretending that a browser, code,
token or logout path ran. Optional capabilities absent from Discovery are grouped
under **Not offered by the provider**; anything selected by the current
configuration remains under **Readiness** and needs attention instead. A silent `prompt=none` request may verify
that the public Client ID and exact callback are accepted, but it neither
authenticates a user nor exchanges a code. **Test sign-in** remains the action
that exercises the real browser and token paths.

Once Exact issuer URL, Client ID and Client Secret are present, **Connection
health** runs the same fresh Discovery, JWKS, authorization-registration and
applicable PAR preflight with the current unsaved form values. It additionally
checks form completeness and the current WebGUI transport. Authenticated PAR
validates the Client ID, Client Secret and callback together. Without PAR, the
silent authorization check can validate only the public Client ID and callback;
the result says plainly that only Test sign-in can validate the secret during a
real code exchange.

Validated runtime caches may still bridge provider outages for bounded periods,
but they are not presented as a live health result. Discovery may remain usable
for at most 24 hours and an already known signing key for at most one hour beyond
freshness, unless the provider forbids stale use through its HTTP cache policy.
This cannot replace the mandatory Token endpoint or admit an unknown key.

After the server has been saved, **Test sign-in** performs the complete browser
flow even while **Offer on the login page** remains disabled. It checks the
authorization response (including JARM when selected), PKCE binding, code
exchange, ID Token and configured claims source. Unsaved changes disable the
action so that the displayed form and the saved connector under test cannot
disagree. The result shows the exact issuer, subject and configured
username claim. It deliberately does not create a WebGUI login session or
change a local account, subject binding or group membership. It is available
only while the saved form is unchanged; save or exactly revert edits first.
This makes it safe to run before deciding the admission policy. The identity provider may
still retain its own SSO session, so use a private browser window when a later
test must begin without that provider session. Before leaving OPNsense, the test
runs the same reduced public-registration check when possible. If the provider
rejects the Client ID or callback there, the form shows the failure without a
browser redirect. If it accepts authorization but rejects the confidential
client during the token exchange, a dedicated diagnostic page explains the
credential failure and returns to the exact saved server row.

OPNsense's generic **System > Access > Tester** is built only for connectors
which accept a username and password in one request. It always requires those
two fields before calling a connector and therefore cannot exercise a browser-
redirect protocol such as OpenID Connect. Use **Test discovery** and **Test
sign-in** on the saved OIDC server instead.

## 5. Decide the admission policy

The durable identity is `(issuer, sub)`, not a username or e-mail address. It is
stored against the local numeric user ID after the first approved login.

On a fresh OPNsense installation, first create a normal non-root local
administrator and confirm that its password login works. The built-in `root`
account is intentionally not eligible for OIDC by default, because it is the
recovery path when the provider or its configuration is unavailable.

- **Strict** (the Generic profile default): save the server, open **Manage
  identities**, select **Add identity binding**, and map the exact verified
  issuer and `sub` to an existing or newly created local account before the
  first login.
- **Administrator approval** (the default for every named profile): a valid but
  unbound identity receives no WebGUI session. It is queued for an administrator
  to review and bind to an existing or newly created local account. This is
  recommended for social login and other unknown first identities.
- **Bootstrap by exact local username**: allow one initial match using the
  configured username claim. This is practical for a controlled first test.
- **Bootstrap by unique verified e-mail**: allow one initial match only when
  exactly one local account has the provider-verified address.
- **Bootstrap by exact username or unique verified e-mail**: try both rules.

After an approval, manual binding or successful bootstrap, the saved
issuer/subject binding is used instead of repeating claim-based matching. Open
**Manage identities** at any time to review, edit or remove it. Keep **Create an account on first login** and
**Allow the built-in root account** off unless their consequences are intended.

Public provider populations add a hard boundary to that recommendation. Apple,
Google, LinkedIn, ORCID, Slack and Yahoo never offer automatic local-account
creation. GitLab.com and Microsoft Organizations, Consumers or Common are
blocked dynamically, while self-managed GitLab and one Entra tenant retain the
choice. Apple, LinkedIn, ORCID, Yahoo, GitLab.com and broad Microsoft audiences
also limit Admission policy to Strict or Administrator approval.

See [Admission policy and identity approvals](admission-policy.md) for the
complete workflow, request retention and Apple Private Relay behaviour.

## 6. Test safely

1. Use a non-root local administrator account.
2. Keep an independent local administrator session open.
3. Save the provider and complete **Test sign-in** while it is still disabled.
4. Enable **Offer on the login page**, save and open a private browser window.
5. Test login, local logout and provider-aware logout.
6. Confirm that local password login still works.
7. Configure provider groups only after identity login is reliable.

Provider groups are authorization input. An empty **Group claim** leaves every
membership local. When it is configured, list the only local groups the
provider may control under **Assignable groups**; an empty list grants none.

Continue with the [complete settings reference](settings-reference.md) or
[troubleshooting](troubleshooting.md).
