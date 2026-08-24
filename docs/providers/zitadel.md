# ZITADEL

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in ZITADEL

1. Create a **Web** OIDC application in the intended project.
2. Use the Authorization Code flow, client authentication and PKCE.
3. Add the exact OPNsense callback under Redirect URIs and the WebGUI origin
   under Post Logout URIs if return-after-logout is enabled.
4. Copy the client ID and secret. Require user assignment/role policy as needed.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | ZITADEL |
| Exact issuer URL | the instance/custom-domain issuer shown under application URLs |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Redirect the Log Out menu entry | On |

### Roles

To use ZITADEL application roles, enable **Assert Roles on Authentication** in
the project and/or **User Roles Inside ID Token** on the application. Request
the documented role scope if required. The usual role claim is
`urn:zitadel:iam:org:project:roles` (or its multi-project counterpart) and is a
JSON object keyed by role name. The plugin intentionally understands that shape
and extracts the keys as group names.

Put only those local names in **Assignable groups**. ZITADEL manager roles such
as organization/IAM owner are not the same as application roles and should not
be treated as OPNsense privileges.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [ZITADEL login/OIDC](https://zitadel.com/docs/guides/integrate/login/login-users),
[retrieve roles](https://zitadel.com/docs/guides/integrate/retrieve-user-roles),
and [OIDC endpoints](https://zitadel.com/docs/apis/openidoauth/endpoints).
