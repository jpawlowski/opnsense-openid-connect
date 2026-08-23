---
name: oidc-protocol
description: Change or review the built-in OpenID Connect protocol implementation. Use for discovery, provider HTTP, authorization and token exchange, JWT or claim validation, state, nonce, PKCE, callbacks, sessions, revocation, or logout behavior.
---

# Changing the OpenID Connect protocol

This repository owns a small, focused relying-party implementation under
`src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/`. There is no vendored OIDC
client and no Composer dependency to update. Keep protocol policy locally
reviewable and leave cryptographic arithmetic to OPNsense's phpseclib runtime.

Before changing behavior, read `docs/reference/architecture.md` and the relevant
part of `docs/reference/security.md`. Identify the trust boundary and component
that owns the decision:

- `RelyingParty` owns authorization transactions, code exchange, claim-source
  composition, and provider logout or revocation requests.
- `ProviderMetadata` validates Discovery and freezes the exact metadata used by
  a login.
- `HttpClient` is the only provider transport and owns HTTPS, response bounds,
  media types, timeouts, and redirect policy.
- `JwtVerifier` owns JWS and OIDC/logout claim validation while phpseclib
  performs signature operations.
- `TransactionRegistry` handles bounded, single-use `form_post` transactions;
  `SessionRegistry` and `PendingIdentityRegistry` hold their narrowly scoped
  runtime indexes.
- Controllers expose browser endpoints, generic public failures, audit records,
  and local session changes. They do not decide JWT validity or account policy.
- `Auth/OpenIDConnect.php` owns stable identity binding and local account/group
  policy, not the wire protocol.

Do not weaken an invariant by turning it into an administrator setting.
Algorithms, exact issuer and audience checks, state, nonce, PKCE, time claims,
subject binding, HTTPS, and redirect restrictions are protocol policy. A
provider that requires an unsupported feature must fail as incompatible until
that feature is deliberately implemented and tested.

## Preserve the failure model

- Consume and validate server-side transaction state before using an
  authorization response.
- Keep endpoints and keys bound to the exact validated issuer and frozen login
  metadata; never infer endpoints or accept token-selected trust material.
- Never log tokens, secrets, complete provider responses, or unnecessary claim
  values.
- Keep public protocol failures generic with a random reference; put the exact
  reason only in the safe audit/system log.
- Destroy or refuse local state on security-critical failure. Logout destroys
  the local session before best-effort provider communication.
- Preserve the local password form and recovery path.

## Test the decision, not the method

Add a behavior check for every protocol decision and its relevant refusal path.
Use the focused suites as a map:

- `tests/unit/exchange.php` for Discovery, transport, PKCE, transactions,
  mix-up protection, ID Token validation, and logout tokens;
- `tests/unit/claims.php` for verified claim-source composition;
- `tests/unit/redirects.php` for callback, origin, and local-target policy;
- `tests/unit/accounts.php`, `groups.php`, and `webgui-access.php` when verified
  claims cross into local identity, authorization, or session access policy.

Run `./tests/run.sh` and `python3 packaging/build.py --check`. Host-independent
tests cannot validate OPNsense's real phpseclib, session storage, dispatcher, or
WebGUI. When those boundaries change, run `tests/integration/opnsense.php` on a
supported OPNsense installation; use the disposable E2E flow described in
`tests/e2e/README.md` when browser/session behavior changes.

If the implementation starts depending on new OPNsense core behavior, also
follow the `core-dependency` skill and add the dependency to the watchdog's
`TOUCHPOINTS`.
