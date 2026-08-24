# Auth0

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in Auth0

1. Create an application of type **Regular Web Application**.
2. Add the exact OPNsense callback to **Allowed Callback URLs**.
3. If provider-aware logout returns to OPNsense, add the WebGUI origin to
   **Allowed Logout URLs**.
4. Ensure Authorization Code is enabled and copy client ID/secret. Enable and
   assign the intended database/enterprise/social connections.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Auth0 |
| Exact issuer URL | `https://<tenant-or-custom-domain>/` |
| Username claim | `preferred_username` (or `email` if your tenant does not emit it) |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Redirect the Log Out menu entry | On |

Keep the issuer's trailing slash exactly as discovery publishes it. Auth0
custom claims should use a collision-resistant URI namespace. If groups/roles
are added through an Action, configure that exact namespaced claim in OPNsense
and keep the local assignable group list narrow.

Do not add an API audience merely to obtain identity claims; it changes the
access token's intended resource and is unnecessary for `/userinfo`.

Auth0 documents OIDC RP-initiated logout and publishes its endpoint through
Discovery when that feature is enabled. It is the default for newer tenants;
for an older tenant, enable **RP-Initiated Logout End Session Endpoint Discovery**
if **Test discovery** does not report provider sign-out.

## Optional multi-factor authentication enforcement

Auth0 requires a post-login Action to turn OPNsense's documented step-up
request into an MFA challenge. Create an Action, bind it to the Login flow, and
restrict it to this application's client ID:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const requested = event.transaction?.acr_values || [];
  if (event.client.client_id === 'REPLACE_WITH_OPNSENSE_CLIENT_ID'
      && requested.includes('http://schemas.openid.net/pape/policies/2007/06/multi-factor')) {
    api.multifactor.enable('any', { allowRememberBrowser: false });
  }
};
```

Enable and enroll the intended Auth0 MFA factors. Then select **Multi-factor
authentication** in OPNsense. The profile sends the exact documented
`acr_values` value and accepts the login only when the signed ID Token contains
that context and `amr` value `mfa`. Run **Test sign-in** before offering the
connection on the login page.

**Phishing-resistant authentication** is unavailable for this profile. Auth0's
documented step-up result reports the general `mfa` method and does not provide
the distinct context-and-method evidence this plugin requires for that tier.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Auth0 Authorization Code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow),
[Regular Web Applications](https://auth0.com/docs/get-started/architecture-scenarios/sso-for-regular-web-apps),
[step-up authentication](https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication/configure-step-up-authentication-for-web-apps),
and [RP-initiated logout](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0).
