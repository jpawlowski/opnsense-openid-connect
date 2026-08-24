# Identity provider guides

Complete the [common setup](../setup/README.md), then use the matching guide.
Every guide has two levels:

1. **Quick setup** gives a first-time administrator the provider-side steps and
   every OPNsense value that must be entered or changed.
2. **Defaults and advanced notes** explain settings which can stay as selected
   by the named profile, plus provider-specific limitations.

“Checked against documentation” does not mean every hosted version and tenant
policy has received a live login test. Report practical differences with the
Discovery document and a redacted log reference.

The central [profile-default matrix](../setup/provider-profiles.md) shows what the
selection fills, what remains editable and what the provider fixes. Individual
guides concentrate on values that still have to come from the provider console.
The generated [provider capability matrix](../reference/provider-capabilities.md)
keeps documentation, retained live interoperability evidence and verified
standards conformance as three deliberately separate claims.

The first entry is named **Generic OpenID Connect**: “Generic” is the usual
technical term for a standards-only provider profile, whereas “General” would
describe a settings category rather than an interoperable fallback.

| Provider | Practical status | Important detail |
|---|---|---|
| [Microsoft Entra ID](entra-id.md) | checked against documentation; live test planned | tenant-specific v2 issuer; group overage |
| [Google / Workspace](google.md) | Discovery exercised; flow checked against documentation | e-mail claim; Google `sub` is the stable identity |
| [Okta](okta.md) | checked against documentation | organization versus custom authorization-server issuer |
| [Auth0](auth0.md) | checked against documentation | Regular Web Application; issuer keeps its trailing slash |
| [AWS Cognito](cognito.md) | checked against documentation | user-pool issuer, not hosted-login domain |
| [JumpCloud](jumpcloud.md) | Discovery exercised; flow checked against documentation | regional issuer and trailing slash |
| [Apple](apple.md) | checked against documentation; special credentials | Form POST and generated JWT client secret |
| [LinkedIn](linkedin.md) | Discovery exercised; flow checked against documentation | OpenID Connect product must be enabled |
| [Slack](slack.md) | Discovery exercised; flow checked against documentation | modern Sign in with Slack OIDC flow |
| [Yahoo](yahoo.md) | Discovery exercised; flow checked against documentation | Consumer Key/Secret; global account population |
| [ORCID](orcid.md) | Discovery exercised; flow checked against documentation | `sub` identity; only `openid` is required |
| [authentik](authentik.md) | primary live target | separate redirect types and one chosen logout method |
| [Keycloak](keycloak.md) | live E2E against a real OPNsense WebGUI | realm issuer; back-channel and front-channel are alternatives |
| [Authelia](authelia.md) | checked against documentation | confidential client plus PKCE S256 |
| [ZITADEL](zitadel.md) | checked against documentation | role claim is a JSON object keyed by role |
| [Ping Identity](ping.md) | checked against documentation | PingOne environment-specific issuer |
| [OneLogin](onelogin.md) | checked against documentation | no `offline_access` in authorization-code flow |
| [Dex](dex.md) | checked against documentation | request `groups` scope explicitly |
| [GitLab](gitlab.md) | checked against documentation | many profile/group claims come from UserInfo |
| [Pocket ID](pocketid.md) | checked against documentation | access denied until allowed groups are assigned |
| [FusionAuth](fusionauth.md) | checked against documentation | require client authentication and PKCE |
| [Cisco Duo Single Sign-On](duo.md) | checked against 2026 generic provider documentation | OAuth 2.1 requires PKCE; per-application issuer |
| [IBM Security Verify](ibm-verify.md) | checked against documentation | copy issuer, not Discovery URL |
| [Oracle Identity Cloud / OCI IAM](oracle-idcs.md) | checked against documentation | confidential application; avoid admin scopes |
| [WSO2 Identity Server](wso2.md) | checked against documentation | issuer can intentionally equal token endpoint |
| [Any other provider](general.md) | standards profile | no vendor exception; Discovery is authoritative |

See [Social-login compatibility](social-login.md) for the account-population
model, the Microsoft one-button/separate-button choices and the documented
reason GitHub, Discord and Login with Amazon are not selectable profiles.
