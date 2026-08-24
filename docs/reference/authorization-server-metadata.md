# Authorization-server metadata profile

Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

The plugin retrieves OpenID Provider Configuration from
`/.well-known/openid-configuration`. Within that OIDC document, the RFC 8414
metadata below is the applicable profile for this confidential web relying
party. Every value used by a login is validated and frozen into its one-time
transaction. Unknown extension members are retained in the bounded snapshot
but never become protocol decisions.

| RFC 8414 metadata | Treatment in this RP profile |
|---|---|
| `issuer` | required HTTPS issuer without query or fragment; exact match with the configured authority |
| `authorization_endpoint` | required validated HTTPS URL; used for the code authorization request |
| `token_endpoint` | required validated HTTPS URL; used for the code exchange |
| `jwks_uri` | required by the enclosing OIDC profile; validated HTTPS URL used for signature keys |
| `registration_endpoint` | ignored; clients are registered administratively |
| `scopes_supported` | optional non-empty string list; when present it must include `openid`, but omission of another requested scope is not treated as refusal because RFC 8414 permits incomplete advertisement |
| `response_types_supported` | required non-empty string list containing the selected `code` response type |
| `response_modes_supported` | optional non-empty string list; omission means `query` and `fragment`, so selected `form_post` requires an explicit advertisement |
| `grant_types_supported` | optional non-empty string list; omission includes `authorization_code`, otherwise that grant must be advertised |
| `token_endpoint_auth_methods_supported` | optional non-empty string list; omission means `client_secret_basic`; automatic or configured selection is limited to an advertised method with a usable client secret or signing certificate: `client_secret_basic`, `client_secret_post` or `private_key_jwt` |
| `token_endpoint_auth_signing_alg_values_supported` | optional non-empty string list used to negotiate the asymmetric `private_key_jwt` signature; no algorithm is inferred when omitted, except for the Microsoft profile's documented PS256 certificate-credential behavior |
| `service_documentation`, `ui_locales_supported`, `op_policy_uri`, `op_tos_uri` | ignored presentation and registration information |
| `revocation_endpoint` | optional validated HTTPS URL used for logout cleanup |
| `revocation_endpoint_auth_methods_supported` | optional non-empty string list; omission means `client_secret_basic`; negotiated independently from token-endpoint authentication |
| `revocation_endpoint_auth_signing_alg_values_supported` | optional non-empty string list used to negotiate a separate `private_key_jwt` assertion for revocation |
| `introspection_endpoint` and its authentication metadata | optional HTTPS endpoint and non-empty authentication lists are validated; the shared client-authentication boundary can negotiate an endpoint-specific assertion, although this RP does not currently introspect tokens |
| `code_challenge_methods_supported` | required by this RP profile to contain `S256`; omission means PKCE is unsupported |
| `signed_metadata` | ignored as RFC 8414 permits when signed metadata is unsupported; the exact HTTPS response remains authoritative |

OIDC-only metadata such as `subject_types_supported`, ID Token signing
algorithms and `userinfo_endpoint`, plus later extension metadata for PAR and
authorization-response issuer identification, remain validated by the same
`ProviderMetadata` boundary. Unused known metadata and unknown future
extensions cannot enable a mechanism by their mere presence.
