# FusionAuth

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in FusionAuth

1. Create/select an Application and open its OAuth settings.
2. Keep **Authorization Code** enabled, set **Client Authentication** to
   Required, and set **PKCE** to Required.
3. Use **Exact match** URL validation and add the exact OPNsense callback under
   Authorized redirect URLs.
4. Copy client ID/secret and require registration/application access for the
   users intended to administer the firewall.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | FusionAuth |
| Exact issuer URL | the tenant issuer configured in FusionAuth and published by Discovery |
| Username claim | `preferred_username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider, or insist on the method selected in FusionAuth |

FusionAuth can populate custom UserInfo claims through a lambda. If used for
groups/roles, choose a bounded list/string claim and keep OPNsense's assignable
groups restricted. Do not enable its optional wildcard redirect validation for
this application.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

Reference: [FusionAuth OAuth application settings](https://fusionauth.io/docs/lifecycle/authenticate-users/oauth/).
