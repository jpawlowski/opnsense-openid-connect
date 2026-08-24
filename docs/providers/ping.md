# Ping Identity / PingOne

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Ping products and deployment models use different issuer shapes. This guide
uses PingOne; for PingFederate enter the exact issuer published by that server's
OIDC Discovery and otherwise use the same confidential-client profile.

## Quick setup in PingOne

1. Create an **OIDC Web App** in the correct PingOne environment.
2. Enable Authorization Code and add the exact OPNsense callback URI.
3. Select **Client Secret Basic** (the straightforward documented option) and
   copy the client ID/secret.
4. Configure attribute mappings and user/group access policy.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Ping Identity |
| Exact issuer URL | the PingOne environment issuer shown by Discovery |
| Username claim | `preferred_username` or the mapped PingOne username claim |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Insist on Basic when that method is selected in PingOne |
| Redirect the Log Out menu entry | On |

Do not copy endpoints from another region/environment. Discovery must return
the same issuer configured here and its key set must belong to this environment.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, **Redirect the Log Out menu
entry** on, **Return here after logout** off, and provider logout notifications
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [PingOne web-app tutorial](https://docs.pingidentity.com/pingone/pingone_tutorials/p1_tutorial_integrate_nodejs_express_app.html),
[token endpoint authentication methods](https://docs.pingidentity.com/pingone/applications/p1_token_endpoint_authentication_methods.html),
and [Discovery-published end session](https://docs.pingidentity.com/pingoneaic/am-oidc1/rest-api-oidc-endsession-endpoint.html).
