# Provider profiles and defaults

A named profile is more than a label. Selecting it applies a complete starting
point to every provider-dependent setting. Every such field is explicitly
classified, so adding a setting cannot silently inherit an unrelated old default:

- **Fixed by the selected provider profile** is read-only. The provider's public
  service does not allow a different value, so the relying party also enforces it
  when reading saved configuration.
- **Recommended by the selected provider profile; editable** is the documented,
  interoperable default. Change it for a tenant mapping or provider option that
  deliberately differs.
- **Available for this provider; no provider-specific default** is an operator
  choice. The safe starting value is filled, but the profile makes no capability
  claim for it.
- **Used only by another provider profile** stays out of the applicable flow.
- **Not supported by the selected provider profile** is reserved for a retained
  provider incompatibility, rather than merely missing evidence.
- **Enter the value issued by this provider** cannot be inferred from a product
  name. The field shows the expected issuer shape but remains empty in a draft.

Selecting a named profile applies its complete starting point. **Restore profile
defaults** repeats that operation after manual edits. Selecting **Generic OpenID
Connect** unlocks and preserves the current values; its restore action returns to
standards-only defaults.

On a new form, replacing the initial `main` profile also suggests the profile's
short name as **Application code**. This keeps callback addresses readable. The
code remains editable and must be unique when several connections use the same
provider.

Client ID and Client Secret are always specific to an application registration
and are therefore never invented. WebGUI addresses, group delegation, root access,
debugging and outbound logout remain installation policy. Button wording is also
installation policy for Generic, self-hosted and tenant-specific providers. The
fixed global Apple, Google, Microsoft, LinkedIn, ORCID, Slack and Yahoo services
instead use their familiar short public label and hide wording controls that would
only create inconsistent branding.

## Defaults shared by named profiles

Unless the table below says otherwise, every named profile starts with:

| Setting | Starting value |
|---|---|
| Authentication method | Follow the provider's Discovery metadata |
| Pushed authorization requests | Automatic with availability fallback |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Match by e-mail address | Only a verified address |
| Scopes | `openid,email,profile` |
| Required authentication | Provider policy only; no additional ID Token strength requirement |
| Always show account selection | Off |
| Redirect the Log Out menu entry | On when current official provider documentation describes a compatible RP-initiated logout flow; Off otherwise |
| Return here after logout | Off; its exact redirect must first be registered at the provider |
| Provider logout notifications | Off unless a retained provider guide reviews a channel |
| Receive Shared Signals | Off; transmitter details are always installation-specific |
| Admission policy | Administrator approval |
| Create an account on first login | Off; unavailable when the selected profile cannot prove a bounded account population |
| Login button wording | localized OPNsense sentence; an empty provider label follows Descriptive name |

Administrator approval is intentionally useful but not permissive. A valid unknown
identity receives no WebGUI session; an administrator must bind its exact
`(issuer, sub)` pair to an existing local account. Generic OpenID Connect instead
starts in Strict mode because the plugin has no provider knowledge at all.

For an installation-specific provider, **Provider label on login button** can
differ from the technical **Descriptive name** without losing localization. The
wording can alternatively contain only that label. **Custom full text** replaces
the whole visible string and is intentionally literal rather than translated.

## Profile-specific values

“Fixed” means the form locks the value. All other shown values are editable.

| Profile | Issuer behaviour | Other preset differences |
|---|---|---|
| Auth0 | enter tenant or custom-domain issuer, including its published trailing slash | redirect the Log Out menu through documented provider logout; older tenants may need RP-initiated logout discovery enabled |
| Authelia | enter configured public issuer | shared defaults |
| authentik | enter application issuer ending `/application/o/<slug>/` | redirect the Log Out menu through provider logout; prefer Back-channel logout notifications; its guide documents the Front-channel alternative |
| AWS Cognito | enter region and user-pool issuer | username claim `cognito:username` |
| Cisco Duo Single Sign-On | enter the per-application issuer | username `email`; require UserInfo |
| Dex | enter configured issuer | shared defaults; add `groups` only when group mapping is intended |
| FusionAuth | enter tenant issuer | redirect the Log Out menu through documented provider logout |
| GitLab | `https://gitlab.com` is filled but editable for self-managed GitLab | GitLab.com permits only Strict/Approval and no automatic account creation; a self-managed issuer retains assessed automatic choices |
| Google / Google Workspace | fixed `https://accounts.google.com` | username `email`; ID Token only; no automatic local-account creation because the form cannot prove an Internal Workspace audience |
| IBM Security Verify | enter tenant issuer | redirect the Log Out menu through documented provider logout; adjust the claim only when explicitly mapped differently |
| JumpCloud | enter the exact regional issuer | shared defaults |
| Keycloak | enter realm issuer | redirect the Log Out menu through provider logout; prefer Back-channel logout notifications; its guide documents the Front-channel alternative |
| LinkedIn | fixed `https://www.linkedin.com/oauth` | username `email`; ID Token only; fixed `client_secret_post`; only Strict/Approval and no automatic account creation |
| Microsoft Entra ID / Microsoft account | enter one tenant's v2 issuer; broader audience modes manage their authority automatically | broad audiences permit only Strict/Approval and no automatic account creation; one tenant retains assessed automatic choices; redirect the Log Out menu through documented provider logout; ID Token only; tenant audience recommended |
| Okta | enter organization or custom authorization-server issuer | redirect the Log Out menu through documented provider logout; MFA uses `urn:okta:loa:2fa:any`; phishing-resistant authentication uses `phr`/`phrh` when deliberately enabled; optional Shared Signals stays off until its separate stream is configured |
| OneLogin | enter exact v2 issuer | redirect the Log Out menu through documented provider logout |
| ORCID | fixed `https://orcid.org` | username `sub`; ID Token only; fixed `client_secret_post`; fixed sole scope `openid`; only Strict/Approval and no automatic account creation |
| Oracle Identity Cloud / OCI IAM | enter identity-domain issuer | redirect the Log Out menu through documented provider logout; adjust the claim only when explicitly mapped differently |
| Ping Identity | enter environment issuer | redirect the Log Out menu through documented provider logout; insist on Basic only when the application was configured that way |
| Pocket ID | enter the instance `APP_URL` issuer | redirect the Log Out menu through documented provider logout; add `groups` only when group mapping is intended |
| Apple | fixed `https://appleid.apple.com` | username `email`; fixed ID Token only, Form POST and `client_secret_post`; scopes `openid,email,name`; only Strict/Approval and no automatic account creation |
| Slack | fixed `https://slack.com` | username `email`; ID Token only; no automatic account creation because the form cannot prove a single-workspace population |
| WSO2 Identity Server | enter exact published issuer | redirect the Log Out menu through documented provider logout |
| Yahoo | fixed `https://api.login.yahoo.com` | username `email`; require UserInfo; only Strict/Approval and no automatic account creation |
| ZITADEL | enter instance or custom-domain issuer | redirect the Log Out menu through documented provider logout |

The Apple username and scopes remain editable even though the transport rules are
fixed. Using `sub` avoids depending on an e-mail address; removing `name` or `email`
reduces requested information. Apple's client secret is still an expiring,
developer-signed JWT and must be replaced before it expires.

The individual [provider guides](../providers/README.md) explain where to copy each
tenant-specific value and which provider-side application settings are required.

## Why Discovery still matters

Profiles do not replace Discovery. Discovery supplies endpoints, signing algorithms,
supported response types and advertised client-authentication methods at runtime. A
profile only supplies information that is safe to know before the provider can be
contacted and handles documented omissions such as LinkedIn's missing token endpoint
authentication metadata. **Test discovery** reports disagreements without making a
draft impossible to save.

Official references for the fixed special cases: [Sign in with Apple authorization](https://developer.apple.com/documentation/signinwithapple/incorporating-sign-in-with-apple-into-other-platforms),
[LinkedIn OpenID Connect](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2),
[LinkedIn authorization-code exchange](https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow),
[ORCID public client registration](https://info.orcid.org/documentation/integration-guide/registering-a-public-api-client/),
and [Okta authorization-server issuers](https://developer.okta.com/docs/concepts/auth-servers/).
