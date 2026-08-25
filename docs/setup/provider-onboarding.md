# Provider onboarding files

The OPNsense form can create a reviewable setup file for provider platforms
whose official import format can safely add one client to an existing
installation. This is an optional shortcut; every provider guide also documents
the complete manual setup.

Provider setup and OPNsense configuration are deliberately independent:

1. Add an OpenID Connect authentication server and leave **Offer on the login
   page** off.
2. Enter a server name, **Application code** and provider profile. Open OPNsense
   under an accepted HTTPS WebGUI FQDN inherited from its WebGUI settings. If the provider must use
   a reverse proxy, a different external port or a restricted set, enter the
   relevant origins and optionally select **Custom origins for this provider**.
   Issuer, Client ID and Client Secret may still be empty.
3. Save the disabled draft, or select **Download provider setup** directly from
   the unsaved form. Downloading never contacts the provider and never stores a
   secret in the file. **Open setup guide** shows the provider-specific import
   steps again later without downloading another copy.
4. Review and import the file at the provider.
5. Copy the exact issuer, generated Client ID and generated Client Secret back
   to OPNsense.
6. Save, run **Test discovery** and **Test sign-in**, and enable login only when
   both tests are successful and local identity policy is complete.

The reverse order works too: create the provider client manually first and then
enter its values in OPNsense. No test is required merely to save either draft.

## Downloadable files

| Profile | File | Official import path | Repeat import |
|---|---|---|---|
| authentik | Blueprint YAML | **Admin interface > Customization > Blueprints > Import > File upload** | This applies once and does not create a visible Blueprint instance. The generated resources use `state: created`; an existing application and its generated credentials are left unchanged |
| Keycloak | Partial realm import JSON | Select the intended realm, then **Realm settings > Action > Partial import** | Select **Skip** for an existing resource; the file also declares `ifResourceExists: SKIP` for API or `kcadm` imports |

A newly downloaded file is therefore not an update mechanism. For a small
change such as another redirect address, edit the existing provider/client in
its administration interface. To recreate the generated configuration instead,
first remove the old generated application and provider in authentik, or the old
client in Keycloak, and then import the new file. Re-creation generates a new
client secret (and, in authentik, may generate a new Client ID), so copy the new
credentials to OPNsense before testing. If the authentik setup uses the generated
verified e-mail scope mapping, remove that application-specific mapping as well
before re-importing it; do not remove authentik's built-in scope mappings.

Both formats use exact redirect addresses, a confidential client, Authorization
Code flow and PKCE S256 where the provider exposes that setting. Neither uses a
wildcard. With the default address policy, the automatically inherited origins
and any additions become exact registered addresses. The currently opened
HTTPS origin must be an accepted FQDN and is placed first. A short hostname, IP
literal or origin absent from the effective policy stops generation. With a
custom policy, only the entered origins are registered. In either mode that
first origin is the canonical launch and front-channel or back-channel logout
address. All origins receive authorization redirects and the dedicated
lifecycle-test post-logout return; the ordinary origin-root post-logout entry
remains conditional on **Return here after logout**. The generated
authentik Application `meta_launch_url` and Keycloak client Home URL start the
local OPNsense login endpoint on that origin. They are intentionally different
from the callback that receives the provider's authorization response.

The FQDN becomes the visible authentik application or Keycloak client name. Both
imports also reference the reviewed package-owned OPNsense SVG from that exact
origin. The browser can retrieve the image without a WebGUI session, but the
firewall still has to be reachable from the browser's network; the URL does not
make a private WebGUI publicly routable.

The authentik file replaces its fail-closed standard e-mail mapping with an
application-specific mapping. It reports `email_verified=true` only when the
user's custom `email_verified` attribute is the JSON boolean `true`; an absent,
false or differently typed value remains unverified. The attribute must be fed
by the installation's actual address-verification authority. The Keycloak file
links only the standard scopes requested by the OPNsense form; its realm owns
the user-level `emailVerified` state behind the standard `email` scope.

The download is a projection of the current form, not a generic provider
template. Provider-side choices such as requested scopes, the claims OPNsense
expects, authentication-strength evidence, redirect addresses, logout delivery
and pairwise subjects have to agree with the generated resource. When a provider
adapter cannot safely express one of those choices, generation stops with a
specific error instead of producing a client which OPNsense will later refuse.
In particular, writing an `acr` or `amr` claim is never treated as equivalent to
configuring a provider flow which actually enforces that authentication method.

Settings that only decide what OPNsense does remain outside the provider file:
local identity bindings, account admission and creation, assignable local groups,
root access, tracing and login-button presentation. The generated file receives
no client secret, token or stored subject binding.

Pairwise subjects are the exception to unsaved generation. Select a stable
**Pairwise subject sector** and save the authentication server as a disabled
draft first, because the provider must fetch the public sector identifier URI
from that saved origin. A generated Keycloak client then includes Keycloak's
built-in SHA-256 pairwise-subject mapper and the sector URI; Keycloak generates
and persists its own mapper salt. The authentik Blueprint already uses its
per-provider issuer and hashed user-ID subject mode and is otherwise unchanged.

Choose **Back-channel** only when the provider server can resolve and reach the
canonical WebGUI address and trusts its certificate. Otherwise choose
**Front-channel** and understand its browser, cookie and iframe limitations.

Only import a file generated by the firewall you intended to configure, and
review its addresses before applying it. A provider import changes security
configuration even though the file carries no credential.

For authentik, a green import notification means the YAML was validated and
applied. Check the resulting objects under **Applications > Applications** and
**Applications > Providers**. The imported YAML is not expected to remain in
the **Customization > Blueprints** list: authentik reserves that list for
persistent Blueprint instances backed by internal content, a mounted path or an
OCI registry.

## Why the other profiles do not get a misleading import button

There is no universal OIDC client-import format. The plugin does not turn a
privileged cloud API call into a deceptively simple download:

| Provider family | Available automation | Why it is not generated here |
|---|---|---|
| Microsoft Entra ID | Microsoft Graph can create applications and credentials | It requires tenant-wide application permissions or an appropriate Entra role, and a generated secret is returned only once. A downloaded manifest is not a supported create/import operation. |
| Google / Google Workspace and Apple | Provider consoles create web clients; Google offers a credential JSON download *after* creation | That JSON is a credential export, not an onboarding import, and must be protected as a secret. |
| Okta and ZITADEL | Official Terraform providers and administrative APIs | They require a separately authorized automation identity and persistent Terraform state. A standalone fragment would not be safely repeatable. |
| Auth0 | Auth0 Deploy CLI and Auth0 CLI | Tenant import needs a deployment client with Management API access; the interactive CLI is safer for a one-off client. |
| AWS Cognito | API, AWS CLI and CloudFormation support user-pool clients | The operation needs the target user-pool ID, AWS account/region credentials and deployment ownership. A generic file cannot choose those safely. |
| Authelia and Dex | Static server configuration | Their client entries belong in the operator's deployment configuration and secret-management system; there is no provider-side upload transaction. |
| Remaining named profiles and **Generic** | Provider-specific admin UI or API | The plugin has no safe, officially documented, portable import transaction to target. Follow the matching manual provider guide. |

Dynamic Client Registration (RFC 7591) is intentionally not attempted merely
because a discovery document advertises it. Registration policy, initial access
tokens, software statements and client-secret lifecycle differ by provider, and
an unauthenticated public registration endpoint is not a reasonable assumption
for a firewall administration client. It can be reconsidered later as an
explicit, separately authorized feature for tested providers.

Official references: [authentik Blueprint import](https://docs.goauthentik.io/customize/blueprints/working_with_blueprints/),
[authentik Blueprint structure](https://docs.goauthentik.io/customize/blueprints/v1/structure/),
[Keycloak partial import](https://www.keycloak.org/server/importExport),
[Microsoft Graph application credentials](https://learn.microsoft.com/en-us/graph/api/application-addpassword),
[Google web-client credentials](https://developers.google.com/identity/protocols/oauth2/web-server),
[Auth0 Deploy CLI](https://dev.auth0.com/docs/deploy-monitor/deploy-cli-tool),
[Okta Terraform OAuth application](https://registry.terraform.io/providers/okta/okta/latest/docs/resources/app_oauth),
and [Amazon Cognito user-pool clients](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html).
