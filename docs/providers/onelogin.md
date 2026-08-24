# OneLogin

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in OneLogin

1. Add an OpenID Connect application and choose the Authorization Code flow.
2. Register the exact OPNsense callback and copy client ID/secret.
3. Configure the token endpoint authentication method to Basic or POST.
4. Assign the intended users/roles.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | OneLogin |
| Exact issuer URL | the exact v2 issuer from the application's Discovery document |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider, or insist on the method selected for the application |
| Redirect the Log Out menu entry | On |

OneLogin documents that `offline_access` is not supported for Authorization
Code and returns an error there, so do not request it. To consume roles/groups,
configure the application's Groups parameter, request the `groups` scope and
set **Group claim** to `groups` with a restrictive OPNsense allow-list.

OneLogin has historical endpoint/issuer variants. Never assemble them from
memory; copy the current application's exact issuer and confirm it through the
OPNsense discovery test.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [OneLogin Authorization Code](https://developers.onelogin.com/openid-connect/api/authorization-code),
[scopes and groups](https://developers.onelogin.com/openid-connect/scopes),
and [RP-initiated logout](https://developers.onelogin.com/openid-connect/api/logout).
