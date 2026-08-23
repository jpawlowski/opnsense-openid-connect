# Sign in with Yahoo

Create a web application in the Yahoo Developer Network and register the exact
OPNsense callback. Copy the Consumer Key as Client ID and Consumer Secret as
Client Secret.

Yahoo documents this as a self-service application registration after signing
in with a Yahoo account. Its getting-started material states no separate fee or
partner-approval requirement. The callback domain must be controlled by the
operator.

| Field | Value |
|---|---|
| Provider profile | Yahoo · Social login |
| Exact issuer URL | `https://api.login.yahoo.com` |
| Username claim | `email` |
| Claims source | Require UserInfo |
| Scopes | `openid,email,profile` |
| Admission policy | Administrator approval |

Yahoo accounts are globally available. A successful Yahoo authentication does
not imply permission to administer the firewall; approve the exact subject or
pre-link it explicitly.

References: [Yahoo OpenID Connect](https://developer.yahoo.com/oauth2/guide/openid_connect/),
[getting started](https://developer.yahoo.com/oauth2/guide/openid_connect/getting_started.html),
and [Yahoo Discovery](https://api.login.yahoo.com/.well-known/openid-configuration).
