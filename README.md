# OpenID Connect sign-in for the OPNsense WebGUI

This pre-release plugin adds OpenID Connect sign-in to the OPNsense web
interface while keeping the local username/password form available. Its scope is
deliberately narrow: **WebGUI administration only**. It does not implement
Captive Portal or OPNWAF authentication.

## Security and protocol profile

The plugin contains its own small relying-party implementation. It bundles no
general-purpose OIDC client and uses OPNsense's existing phpseclib package for
cryptographic primitives.

- Authorization Code flow only, always with transaction-specific `state`,
  `nonce`, and PKCE `S256`.
- Pushed Authorization Requests (PAR) are used automatically when Discovery
  publishes an endpoint; a failed push never falls back to browser parameters.
- Exact issuer validation from OIDC Discovery; endpoints and the metadata
  snapshot are bound to the pending browser transaction.
- A distinct callback per provider plus RFC 9207 `iss` validation when offered,
  protecting multi-provider installations from mix-up attacks.
- Asymmetric ID Token verification with RSA PKCS#1, RSA-PSS and ECDSA:
  `RS256/384/512`, `PS256/384/512`, and `ES256/384/512`.
- Strict `iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `nbf`, `nonce`, `auth_time`
  and `at_hash` checks. Token-supplied keys and critical JWT extensions are
  rejected.
- Optional plain or signed UserInfo, always bound to the verified ID Token by
  exact `sub` equality.
- HTTPS with normal certificate validation for discovery and every provider
  endpoint. Responses, redirects, sizes and timeouts are bounded. Credentials
  are never followed through redirects.
- The PHP session identifier is replaced after login. Login transactions are
  one-time, expire after ten minutes, and coexist safely across browser tabs.
  `form_post` uses a bounded server-side transaction index so OPNsense's
  `SameSite=Lax` session cookie remains unchanged.
- RP-Initiated, Front-Channel and Back-Channel Logout are supported. Signed
  back-channel logout messages require integer `exp`, a unique `jti` and are
  replay-protected until their signed expiry.
- Optional account selection and an exact-origin sector identifier endpoint
  support multi-account sign-in and provider-issued pairwise subjects.

The exact supported standards and intentionally unsupported optional extensions
are listed in [the security and conformance document](docs/reference/security.md).
The generated, evidence-backed security validation is in the
[security validation report](docs/reference/audit-report.md).

## Local identity and privileges

An accepted OIDC identity is bound to a local OPNsense account by the stable
pair `(exact issuer, subject)`. A rename of the local account or a later change
to an e-mail address therefore cannot silently redirect the identity to another
account.

The admission decision is deliberately conservative:

1. An existing binding wins.
2. Without one, strict mode refuses the login.
3. Administrator approval can queue the unknown identity without a session and
   bind it explicitly to an existing or newly created local account.
4. An administrator may instead allow a first match by exact username, unique
   verified e-mail, or either. The resulting stable binding is saved.
5. Optional just-in-time creation uses OPNsense's own account mechanism and
   also saves the binding.

Every saved OIDC server has a **Manage identities** action. It combines durable
binding creation/editing/removal with pending administrator approvals, uses the
existing **System: Authentication Servers** privilege and honours OPNsense's
read-only administrator restriction for every mutation. Inline local-account
creation additionally requires **System: Access: Management** and grants no
groups or privileges by itself.

Disabled and expired accounts remain disabled; UID 0 is refused unless an
administrator explicitly opts in. Provider-controlled groups are off by
default. When enabled, the provider may affect only the explicit local group
allow-list, unless the administrator separately chooses to allow all groups.
Before creating a session, the plugin also applies OPNsense's effective local
WebGUI ACL, including direct privileges, group privileges and group
source-network restrictions. An account without a usable WebGUI page receives
an explicit 403 explanation instead of being sent through a silent logout loop.

## Compatibility

The target lines are OPNsense Community Edition **26.1 and 26.7**. The package
does not replace core files. A nightly watchdog checks the real login page and
fingerprints the OPNsense interfaces on which the plugin depends.

Named profiles provide a complete provider-dependent starting point, mark public
provider invariants as read-only, and add provider-specific diagnostics without
weakening validation:

- Microsoft Entra ID and personal Microsoft accounts, Google / Google
  Workspace, Okta, Auth0, AWS Cognito, JumpCloud and Apple
- LinkedIn, Slack, Yahoo and ORCID social login
- authentik, Keycloak, Authelia, ZITADEL, Dex, GitLab, Pocket ID and FusionAuth
- Ping Identity, OneLogin, Cisco Duo Single Sign-On, IBM Security Verify,
  Oracle Identity Cloud / OCI IAM and WSO2 Identity Server
- **Generic OpenID Connect** for every standards-compliant provider not listed

See the [profile-default matrix](docs/setup/provider-profiles.md) and
[provider guide index](docs/providers/README.md). The guides state which parts are
verified from vendor documentation and which still need real-world confirmation.
GitHub, Discord and Login with Amazon are documented in the
[social-login compatibility guide](docs/providers/social-login.md), but are not
selectable because their official user-login flows are OAuth 2.0 rather than
OpenID Connect.

## Install

Download the package on an administrator workstation and verify that GitHub's
attested workflow for this repository built those exact bytes:

```sh
gh attestation verify /tmp/os-openid-connect-<version>.pkg \
  -R jpawlowski/opnsense-openid-connect \
  --signer-workflow jpawlowski/opnsense-openid-connect/.github/workflows/build.yml \
  --deny-self-hosted-runners
```

Then copy the verified package to the firewall, compare it with the checksum
shown by the immutable release, and install it:

```sh
sha256 -c <expected-checksum> /tmp/os-openid-connect-<version>.pkg
pkg add /tmp/os-openid-connect-<version>.pkg
```

GitHub's keyless Sigstore attestation binds the package digest to this public
repository, the exact release-workflow path and source commit. Verification
also refuses provenance issued on a self-hosted runner. Published releases are
immutable, so their tag and assets cannot later be replaced. Direct `pkg add`
understands neither proof; verification deliberately happens before the file
reaches `pkg`. An optional detached RSA signature remains available for an
offline installation once a project release key is configured. This is
documented in [packaging/README.md](packaging/README.md).

The beta remains a manually installed package. It does not register a package
repository and does not opt the firewall into automatic `pkg install` updates.

No restart is required. To remove the plugin:

```sh
pkg delete os-openid-connect
```

Settings remain in `/conf/config.xml`; the local password login remains usable.

## Configure

Under **System > Access > Servers**, add a server of type **OpenID Connect**.
Start with these fields:

| Field | Value |
|---|---|
| Provider profile | the named provider, or Generic OpenID Connect |
| Application code | a unique URL-safe identifier such as `authentik-main` |
| Exact issuer URL | the exact issuer, including any trailing slash |
| Client ID / Client Secret | credentials of a confidential web client |
| WebGUI address policy | follows OPNsense names, actual local addresses, virtual IPs and WebGUI port by default; optional additions or an exact provider-specific replacement remain available |
| WebGUI transport | native HTTPS required by default; an HTTP backend needs an explicit trusted-proxy exception with exact custom public HTTPS origins |
| Username claim | keep the profile default unless the provider guide differs |
| Claims source | Automatic normally; force ID Token or UserInfo only when needed |
| Required authentication | Provider policy only by default; optionally require verified MFA or phishing-resistant context and method claims |
| Admission policy | Administrator approval for named profiles; Strict for Generic |
| Identity manager | after saving, map exact issuer/`sub` identities to existing local accounts and review pending approvals |
| Shared Signals | optional push receiver; enter the transmitter issuer and assigned audience, then generate a delivery secret |
| Login button wording | localized OPNsense sentence, provider label only or an exact custom text; fixed global services use their familiar short name |
| Icon URL | every profile starts with a package-owned SVG, including a neutral OIDC mark for Generic; replace it only for installation-specific branding |

The form displays the exact URLs to register. For application code `main` they
have this shape:

```text
https://firewall.example.com/api/openidconnect/auth/callback/main
https://firewall.example.com/
https://firewall.example.com/api/openidconnect/auth/backchannel/main
https://firewall.example.com/api/openidconnect/auth/frontchannel/main
https://firewall.example.com/api/openidconnect/ssf/push/main
```

Use exact callback URLs at the provider; do not use wildcards. Saving is
independent of testing. Keep the server disabled, save it, run **Test
discovery** and the non-mutating **Test sign-in**, then complete local identity
policy before offering it on the login page. OPNsense's generic **System >
Access > Tester** accepts username/password connectors only and cannot exercise
OIDC browser redirects.

## Architecture

Network and protocol handling, verified claims, local identity resolution,
session creation, logout indexing, UI integration and package monitoring are
separate components. [Architecture](docs/reference/architecture.md) describes their trust
boundaries and data flow.

## Commercial OPNsense comparison

The official implementation is a Business Edition feature and covers WebGUI,
Captive Portal and OPNWAF. This plugin intentionally covers only the WebGUI and
goes deeper there with provider profiles, explicit origin policy, stable
issuer/subject bindings and documented protocol controls. The evidence-based
comparison is in [commercial-comparison.md](docs/reference/commercial-comparison.md); an
undocumented commercial feature is marked “not documented”, never assumed
absent.

## Test and build

```sh
./tests/run.sh
python3 packaging/build.py
```

The suite checks syntax, protocol behaviour, identity and group policy, package
contents and release conventions without Composer or network access. Real
OPNsense integration remains a separate release gate; see
[tests/README.md](tests/README.md) and [SUPPORT.md](SUPPORT.md).

## Licence

BSD-2-Clause, see [LICENSE](LICENSE). No third-party OIDC library is bundled.
Runtime signature verification uses the phpseclib package already supplied by
OPNsense.
