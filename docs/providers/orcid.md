# ORCID

Register a redirect URI and obtain client credentials through ORCID's developer
tools or member API process. The redirect URI must exactly equal the OPNsense
authorization redirect URI.

An individual can obtain Public API client credentials free of charge for
non-commercial use after creating an ORCID record, verifying its e-mail address
and accepting the public-client terms. Commercial organizational use requires
the paid Member API path. ORCID recommends its freely available sandbox before
production.

| Field | Value |
|---|---|
| Provider profile | ORCID · Social login |
| Exact issuer URL | `https://orcid.org` |
| Username claim | `sub` |
| Claims source | ID Token only |
| Scopes | `openid` |
| Authentication method | Insist on POST (fixed; ORCID Discovery advertises only `client_secret_post`) |
| Admission policy | Administrator approval |

ORCID's Basic OpenID Provider profile exposes a stable ORCID identity but does
not promise an e-mail claim. Use the exact subject shown by Test sign-in or the
approval workflow rather than inventing an e-mail/username mapping.

References: [ORCID authenticated iD tutorial](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/)
[Public API client registration](https://info.orcid.org/documentation/integration-guide/registering-a-public-api-client/),
[ORCID OpenID Connect support](https://github.com/ORCID/ORCID-Source/blob/main/orcid-web/ORCID_AUTH_WITH_OPENID_CONNECT.md),
and [ORCID Discovery](https://orcid.org/.well-known/openid-configuration).
