# Okta

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in Okta

1. Create an **OIDC - OpenID Connect** integration of type **Web Application**.
2. Keep the Authorization Code grant and add the exact OPNsense sign-in
   callback. Add the WebGUI origin as sign-out redirect only if used.
3. Assign only intended users/groups and copy client ID/secret.

## Choose the issuer

- For ordinary Okta SSO, the org authorization server issuer is
  `https://<your-okta-domain>`.
- A custom authorization server issuer is
  `https://<your-okta-domain>/oauth2/<authorization-server-id>` and requires the
  corresponding Okta product/plan in production.

Do not mix endpoints or signing keys between those issuers.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Okta |
| Exact issuer URL | one of the issuer forms above |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

For group authorization, add a filtered groups claim in Okta. Depending on the
authorization server and claim settings, include the `groups` scope. Avoid an
unbounded “all groups” claim and restrict OPNsense assignable groups as well.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Okta web application](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/),
[authorization servers](https://developer.okta.com/docs/concepts/auth-servers/),
[groups claim](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/).
