# Sign in with LinkedIn

Create an application in the LinkedIn Developer Portal and request the **Sign
in with LinkedIn using OpenID Connect** product. Add the exact OPNsense
authorization redirect URI under the application's authorized redirect URLs.
LinkedIn lists this OIDC product as an open permission available to all
developers rather than a closed partner API. App creation nevertheless requires
a LinkedIn Page, a privacy-policy URL and approval by that Page's administrator.
A Page can be created without a fee, but it must legitimately represent a
company, school, brand or service; this is therefore less convenient for a
purely private homelab than Google, Microsoft, Slack, Yahoo or ORCID.

| Field | Value |
|---|---|
| Provider profile | LinkedIn · Social login |
| Exact issuer URL | `https://www.linkedin.com/oauth` |
| Username claim | `email` |
| Claims source | ID Token only; the documented ID Token contains the sign-in claims |
| Authentication method | Insist on POST (fixed because LinkedIn's code-exchange guide requires credentials in the body while Discovery omits the method) |
| Scopes | `openid,email,profile` |
| Admission policy | Administrator approval |

LinkedIn publishes pairwise subjects. Bind the exact issuer/subject; do not
assume that an e-mail address is permanent. A broader automatic admission
policy could allow any LinkedIn account whose claim happens to match a local
account. The profile therefore offers only Strict or Administrator approval;
**Create an account on first login** is unavailable.

References: [LinkedIn OpenID Connect setup](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2)
and [authorization-code exchange](https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow).
[open permissions](https://learn.microsoft.com/en-us/linkedin/shared/authentication/getting-access),
[app and Page setup](https://www.linkedin.com/help/linkedin/answer/a1667239),
and [LinkedIn Discovery](https://www.linkedin.com/oauth/.well-known/openid-configuration).
