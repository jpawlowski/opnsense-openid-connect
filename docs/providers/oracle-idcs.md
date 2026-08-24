# Oracle Identity Cloud Service / OCI IAM Identity Domains

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Oracle's older Identity Cloud Service and current OCI IAM Identity Domains use
tenant/domain-specific endpoints. Treat the Discovery response as authoritative
instead of assembling endpoint URLs from an older example.

## Quick setup in Oracle

1. Add a **Confidential Application** and configure it as an OAuth/OIDC client.
2. Enable Authorization Code, add the exact OPNsense callback and keep HTTPS
   enforcement enabled.
3. Leave ID Token encryption at `none`; this plugin verifies signed tokens but
   does not decrypt JWE.
4. Assign the intended users/groups and activate the application.
5. Fetch the identity domain's OpenID configuration and copy its exact `issuer`.
   Do not grant Oracle administration API scopes merely for WebGUI login.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Oracle Identity Cloud / OCI IAM |
| Exact issuer URL | exact `issuer` from the identity-domain metadata |
| Username claim | mapped `preferred_username` or `email` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Redirect the Log Out menu entry | On |

If Oracle is configured for TLS client authentication or private-key JWT only,
that client is outside this release. Select a secret-authenticated confidential
client using Basic or POST.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [add an Oracle confidential application](https://docs.oracle.com/en/cloud/paas/identity-cloud/uaids/add-confidential-application.html),
[Oracle authorization-code grant](https://docs.oracle.com/en/cloud/paas/identity-cloud/idcsa/AuthCodeGT.html),
and [OpenID Discovery](https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/op-admin-v1-users-id-patch.html).
