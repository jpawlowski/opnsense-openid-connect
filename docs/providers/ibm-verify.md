# IBM Security Verify

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in IBM Security Verify

1. Create a web/OIDC application in the intended Verify tenant.
2. Register the exact callback displayed by OPNsense and select Authorization
   Code with a confidential client ID and secret.
3. Assign only the users or groups which may administer this firewall.
4. Open the application's Discovery endpoint, then copy its exact `issuer`
   value into OPNsense. The Discovery document URL itself is not an issuer.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | IBM Security Verify |
| Exact issuer URL | exact `issuer` from the tenant Discovery document |
| Username claim | the mapped `preferred_username`, or `email` if explicitly mapped |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Redirect the Log Out menu entry | On |

Run **Test discovery** before enabling the server. Verify tenant/application
attribute mappings vary, so inspect which claim actually carries the immutable
local login name. The persistent issuer/subject binding means that claim is
used only for an approved first match, not as the durable identity.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [IBM Security Verify OIDC configuration](https://docs.verify.ibm.com/gateway/docs/tasks-oidc-rp-verify)
and [OIDC single logout](https://www.ibm.com/docs/en/security-verify?topic=applications-single-logout-oidc).
