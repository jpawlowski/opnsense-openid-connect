# WSO2 Identity Server

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

WSO2 has an unusual but valid default: in current documentation the issuer can
be the token endpoint itself, such as `https://id.example.com/oauth2/token`.
Do not shorten it to the server origin. The corresponding Discovery document is
then `<issuer>/.well-known/openid-configuration`.

## Quick setup in WSO2

1. Register a confidential **Web Application** using OpenID Connect.
2. Enable Authorization Code and PKCE with `S256`, then add the exact OPNsense
   callback as an authorized redirect URL.
3. Copy client ID/secret and the issuer shown by the application/Discovery
   view. For a tenant it may also contain a tenant path.
4. Use an asymmetric ID Token signing algorithm and no ID Token encryption.
5. Map the username and optional groups claim deliberately.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | WSO2 Identity Server |
| Exact issuer URL | the exact WSO2 issuer, commonly ending `/oauth2/token` |
| Username claim | your mapped `preferred_username` claim |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

Older WSO2 releases expose metadata at a separately configured discovery path.
This plugin intentionally follows the OIDC rule `<issuer>/.well-known/...` and
requires exact issuer equality. Configure WSO2's resident IdP/discovery URL to
that form rather than adding an endpoint override that could weaken mix-up
protection.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [WSO2 OIDC flow configuration](https://is.docs.wso2.com/en/latest/guides/authentication/oidc/),
[WSO2 Discovery and its token-endpoint issuer](https://is.docs.wso2.com/en/7.0.0/guides/authentication/oidc/discover-oidc-configs/).
