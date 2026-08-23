# JumpCloud

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in JumpCloud

1. Add a **Custom OIDC App** in the JumpCloud Admin Portal.
2. Authorization Code is enabled by default. Add the exact OPNsense callback.
3. Choose **Client Secret Basic** or **Client Secret POST**, then select the same
   method in OPNsense if metadata-following is not sufficient.
4. Assign intended user groups and configure any required attribute mappings.

## Region and values to enter in OPNsense

| Region | Exact issuer |
|---|---|
| US | `https://oauth.id.jumpcloud.com/` |
| EU | `https://oauth.id.eu.jumpcloud.com/` |
| IN | `https://oauth.id.in.jumpcloud.com/` |

Keep the trailing slash. Use the matching regional client and endpoints.

| Field | Value |
|---|---|
| Provider profile | JumpCloud |
| Username claim | `preferred_username` (or your mapped claim) |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

JumpCloud documents RP-initiated login. Configure the login URL shown by
OPNsense if the application tile needs one. Do not select Public/None: this
plugin intentionally uses a confidential client even though it also sends PKCE.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

Reference: [JumpCloud SSO with OIDC](https://jumpcloud.com/support/sso-with-oidc).
