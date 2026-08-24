# OpenID Foundation relying-party conformance pilot

This is a deliberately manual external check against the hosted OpenID
Foundation Conformance Suite. The suite acts as an OpenID Provider that can
return valid and deliberately invalid protocol messages. That exercises the
installed plugin, its real HTTP boundary and OPNsense's phpseclib runtime
independently of the repository's stubs.

The pilot complements rather than replaces the Keycloak browser E2E test. It
does not validate local account and group policy, password recovery, the real
OPNsense session lifecycle or logout integration. It is not part of the fast
test gate, does not establish OpenID certification and must never be started by
an agent Stop hook or ordinary CI job.

## Requirements and safety boundary

- Use a newly installed or otherwise disposable OPNsense host with the package
  built from a clean, recorded source revision.
- Keep a separate local administrator session open throughout the run and keep
  the native password form available.
- The browser must reach both the OPNsense HTTPS origin and
  `https://www.certification.openid.net/`. OPNsense must be able to make outbound
  HTTPS requests to the suite. The firewall does not need to be publicly
  reachable: the browser follows the redirect back to its private management
  address.
- Do not publish or commit hosts, users, claims, authorization requests,
  tokens, cookies, client secrets, failure references or unredacted suite
  exports. Use test-only client credentials and remove the test server after
  the run.
- Run one module at a time. Every module exposes its own issuer, so parallel
  modules would race over the saved OPNsense server configuration.

The current suite instructions are at
[Conformance Testing for OpenID Connect RPs](https://openid.net/certification/connect_rp_testing/).
The plan and module definitions are maintained in the
[OpenID Foundation conformance-suite](https://gitlab.com/openid/conformance-suite).

## One-time configuration

1. Sign in to the hosted suite and create the **OpenID Connect Core: Basic
   Certification Profile Relying Party Tests** plan.
2. Select the Authorization Code response type, default response mode, plain
   HTTP request type, static client registration and `client_secret_basic`.
   Choose a unique, non-sensitive alias. Do not enable Dynamic Client
   Registration, request objects, implicit or hybrid flows.
3. Configure a test-only client ID and random secret in the suite. Register
   exactly this redirect URI, using the HTTPS origin by which the test browser
   reaches the firewall:

       https://firewall.example.test/api/openidconnect/auth/callback/oidf-conformance

4. In **System > Access > Servers**, save a disabled server with these values:

   | Field | Value |
   |---|---|
   | Descriptive name | `OIDF Conformance Pilot` |
   | Type | OpenID Connect |
   | Application code | `oidf-conformance` |
   | Provider profile | Generic OpenID Connect |
   | Exact issuer URL | the current module's exported `issuer` |
   | Client ID / Client Secret | the test-only static client values |
   | Authentication method | Client secret in the HTTP Basic header |
   | Response mode | Redirect query |
   | Scopes | `openid`, `email`, `profile` |
   | Username claim | `sub` |
   | Offer on the login page | disabled |

   Keep the normal WebGUI address policy when it already accepts the browser's
   HTTPS origin. Otherwise add only that exact test origin. The server remains
   disabled because **Test sign-in** deliberately supports testing before a
   provider is offered on the public login page.

## Running one module

1. Start the module in the suite and wait for `WAITING`.
2. Copy its exported `issuer` into the saved OPNsense server. Treat the issuer
   as an opaque exact value, including any path or trailing slash.
3. Save the server. Run **Test discovery** unless the module intentionally
   returns mismatching Discovery metadata.
4. Select **Test sign-in**. Use the same browser that can reach the firewall;
   the suite supplies the test identity and controls the authorization result.
5. Wait for the suite to reach its terminal state before starting another
   module. Negative modules normally wait a few seconds to confirm that the RP
   made no forbidden follow-up request.
6. Record only the module name, suite result and the expected local outcome in
   the pull-request description. A raw suite export stays outside the
   repository.

For every rejected response, confirm that no local WebGUI session or account is
created, that the browser receives only the plugin's generic protocol failure,
and that detailed diagnostics remain confined to the safe log without tokens
or secrets.

## Pilot matrix

Run these modules in order. The success and rotation cases must pass. A
negative case may finish as `PASSED`, `REVIEW`, `WARNING` or `SKIPPED` when the
module explicitly permits refusal; `FAILED` and `INTERRUPTED` are never accepted
as a successful pilot result.

Basic RP modules:

- `oidcc-client-test`: the sign-in test succeeds without changing a local
  account or session.
- `oidcc-client-test-invalid-sig-rs256`: the invalid signature is refused
  before identity use.
- `oidcc-client-test-idtoken-sig-none`: the unsigned ID Token is refused; the
  suite may mark deliberate refusal as `SKIPPED`.
- `oidcc-client-test-invalid-iss`: the mismatching token issuer is refused.
- `oidcc-client-test-invalid-aud`: the token issued to another client is
  refused.
- `oidcc-client-test-nonce-invalid`: the response bound to another nonce is
  refused.
- `oidcc-client-test-userinfo-invalid-sub`: UserInfo with a different subject
  is refused.

Configuration RP modules:

- `oidcc-client-test-discovery-issuer-mismatch`: Discovery or sign-in fails
  before an authorization transaction is trusted.
- `oidcc-client-test-signing-key-rotation-just-before-signing`: the sign-in
  test succeeds with the key published immediately before signing.
- `oidcc-client-test-signing-key-rotation`: two sign-in tests in the same
  module both succeed across provider key rotation.

Create **OpenID Connect Core: Configuration Certification Profile Relying Party
Tests** before the final three modules, using the same static client and code
flow choices. For `oidcc-client-test-discovery-issuer-mismatch`, skip **Test
discovery** and start **Test sign-in** directly so the module observes the
fail-closed Discovery request. For `oidcc-client-test-signing-key-rotation`, do
not start a new suite module after the first successful result: trigger **Test
sign-in** a second time against the same saved issuer and wait for the module to
finish.

## Interpreting a failure

First verify the exact exported issuer, callback URI, client credentials,
authentication method and current module. Repeat an unexpected result once
from a freshly saved server configuration. If it repeats, retain the suite
export outside version control, reduce it to a description containing no
sensitive values and add the smallest local regression check that expresses
the failed decision. Protocol validation must not be weakened or exposed as an
administrator setting merely to make an external test pass.

After the pilot, delete the OPNsense test server and the suite test plan or
test-only client credentials. A future automated evidence tier must generate
sanitized, revision-bound evidence; this manual checklist is intentionally not
accepted as evidence for the unified security and conformance report.
