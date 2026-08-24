# Social-login compatibility

One saved OpenID Connect authentication server produces one login button. A
home-lab administrator can therefore offer one social provider, several
separate providers, or several deliberately different configurations of the
same provider. The admission policy remains the firewall's gate: possessing a
valid account at a global provider never grants WebGUI access by itself.

Every social provider requires a separate application/client registration;
there are no shared credentials built into this plugin. The table below records
whether an ordinary operator can realistically obtain those credentials. It is
based on the providers' published onboarding terms as checked on 23 August
2026; “no separate fee documented” is not a promise that a provider will never
change its terms.

The dropdown suffixes direct account providers with **Social login** and marks
providers spanning personal and organization identities as **Social /
workforce**. Identity platforms such as authentik, Keycloak or Auth0 are not
labelled social merely because they can federate social accounts internally.

## Registration availability

| Provider | Registration and cost | Important eligibility or review condition | Included |
|---|---|---|---|
| Apple | publicly available Apple Developer Program, USD 99 per membership year | a web Services ID must be associated with a primary Apple-platform App ID; this is not a stand-alone homelab web credential | yes, for operators who already meet Apple's app prerequisite |
| GitLab | self-service user-owned OAuth/OIDC application on GitLab.com; OIDC provider support is documented for GitLab.com, Self-Managed and Dedicated | a self-managed administrator can disable user-owned applications | yes |
| Google | self-service Google Cloud project and OAuth web client; no separate client-registration fee documented | basic `openid`, `email` and `profile` use is exempt from sensitive-scope verification; broader scopes change that | yes |
| LinkedIn | self-service developer app; no separate fee documented | requires a LinkedIn Page, privacy-policy URL and Page-admin approval; the OIDC product is an open permission available to all developers | yes, but not frictionless for a private homelab |
| Microsoft | self-service Entra app registration; Entra Free has no product charge | creating a free tenant/billing account may require a credit card; tenant policy can restrict who may register or consent | yes |
| ORCID | Public API client is free for non-commercial use by an individual | commercial/organizational Member API access is paid; production requires exact HTTPS redirects | yes |
| Slack | self-service Slack app in a workspace or free developer sandbox; no separate app-registration fee documented | own-workspace use needs no Marketplace listing; multi-workspace distribution has additional rules | yes |
| Yahoo | self-service Yahoo Developer Network application after creating/signing in with a Yahoo account; no separate fee or partner approval documented | operator must control the callback domain and comply with Yahoo's developer terms | yes |

References: [Apple membership](https://developer.apple.com/programs/whats-included/)
and [web configuration](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/),
[GitLab OIDC and tier availability](https://docs.gitlab.com/integration/openid_connect_provider/),
[Google app audience rules](https://support.google.com/cloud/answer/15549945),
[LinkedIn open permissions](https://learn.microsoft.com/en-us/linkedin/shared/authentication/getting-access)
and [Page requirement](https://www.linkedin.com/help/linkedin/answer/a1667239),
[Microsoft Entra Free](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/microsoft-entra-id-free),
[ORCID Public API registration](https://info.orcid.org/documentation/integration-guide/registering-a-public-api-client/),
[Slack app distribution](https://docs.slack.dev/app-management/distribution/),
[Yahoo application setup](https://developer.yahoo.com/oauth2/guide/openid_connect/getting_started.html).

## Supported OpenID Connect account providers

| Provider | Profile | Account population | Safe admission choice |
|---|---|---|---|
| Apple | Apple | personal Apple accounts | Strict or Administrator approval; account creation unavailable |
| GitLab | GitLab.com, Self-Managed or Dedicated | personal GitLab.com accounts or a controlled instance population | Strict/Approval and no account creation on GitLab.com; assessed automatic choices on a managed instance |
| Google | Google / Google Workspace | personal and managed Workspace accounts | Approval or controlled Workspace matching; account creation unavailable |
| LinkedIn | LinkedIn | personal LinkedIn accounts | Strict or Administrator approval; account creation unavailable |
| Microsoft | Microsoft Entra ID / Microsoft account | selectable tenant, all organizations, personal accounts, or both | Strict/Approval and no account creation for broad audiences; assessed automatic choices for one tenant |
| ORCID | ORCID | researcher identities | Strict or Administrator approval; account creation unavailable; `sub` is the useful identifier |
| Slack | Slack | members of Slack workspaces in which the app is usable | Approval or controlled workspace matching; account creation unavailable |
| Yahoo | Yahoo | personal Yahoo accounts | Strict or Administrator approval; account creation unavailable |

Apple Private Relay and every other unfamiliar first identity use the same
[administrator approval workflow](../setup/admission-policy.md). Do not turn
on automatic local-account creation simply to make a social login work. The
form removes that choice where the selected provider population cannot safely
support it.

## Excluded services

The following services are not selectable profiles. Their official user-login
interfaces are OAuth 2.0 authorization flows: they do not publish the OIDC
Discovery/ID Token contract this plugin requires.

| Service | Registration availability | Official user-login protocol | Why Generic OIDC cannot be used |
|---|---|---|---|
| GitHub.com, GitHub Enterprise Server and GitHub Enterprise Cloud on `*.ghe.com` | OAuth Apps/GitHub Apps are documented for cloud and Enterprise Server; data-residency enterprises use a dedicated `*.ghe.com` subdomain | OAuth Apps or the OAuth user flow of a GitHub App | changing the GitHub host changes OAuth/API URLs, not the protocol: the user flow returns an access token and requires a GitHub API call; GitHub Actions OIDC identifies workloads, not people |
| Discord | self-service application in the Developer Portal; no separate fee documented | Discord OAuth2 | the `identify` scope returns user data through the Discord API, not a validated OIDC ID Token |
| Login with Amazon | Amazon describes Developer registration as free and Security Profile creation as self-service | OAuth 2.0 | profile data is fetched with an access token; Amazon documents the service as OAuth 2.0 |

Adding these would require a separately designed OAuth-login subsystem with
provider-specific token validation and profile APIs. Treating an OAuth access
token as an OIDC ID Token would weaken the explicit standards boundary and is
not a compatibility exception.

References: [GitHub OAuth app authorization](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps),
[GitHub Enterprise Server OAuth authorization](https://docs.github.com/en/enterprise-server@latest/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps),
[GitHub Enterprise Cloud data residency](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/about-storage-of-your-data-with-data-residency),
[GitHub app registration](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app),
[Discord OAuth2](https://docs.discord.com/developers/topics/oauth2),
[Discord application registration](https://docs.discord.com/developers/quick-start/overview-of-apps),
[Login with Amazon](https://developer.amazon.com/docs/login-with-amazon/documentation-overview.html),
and [Amazon Security Profile registration](https://www.developer.amazon.com/docs/login-with-amazon/register-web.html).
