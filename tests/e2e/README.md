# Disposable browser-to-firewall tests

This directory contains the destructive end-to-end tests. They install the package on a disposable OPNsense system,
configure an authentication server through the real WebGUI, start a real identity provider and complete the sign-in in
Chromium. The normal host-independent checks in `../run.sh` never start a VM, Docker or a browser.

## Local OPNsense VM on macOS

On an Apple Silicon Mac, the shortest complete run is:

    tests/e2e/local.sh

`local.sh` finds Homebrew QEMU and UTM. An OPNsense amd64 guest cannot use Apple Virtualization on arm64, so both
variants use QEMU's native-arm64 TCG emulator; Rosetta is not involved. Direct QEMU is the automatic default when both
are installed because it avoids UTM's frontend and automation overhead. Select a backend explicitly when diagnosing a
backend-specific problem:

    tests/e2e/local.sh --backend qemu
    tests/e2e/local.sh --backend utm

The first run downloads the current official OPNsense Nano image, verifies the signed checksum list, verifies the
signature of the unpacked image and bootstraps a reusable base disk through the serial console. The repository pins the
26.7 public key and image checksum in `vm/trust.json`. A future release key is accepted only when its `.pub.sig` chains
to that anchor; otherwise the run stops and asks for a reviewed trust-manifest update. Downloads and prepared disks are
kept under `~/Library/Caches/opnsense-openid-connect/e2e`, while every test gets a new qcow2 overlay.

The Nano image is deliberately used as the preinstalled, persistent serial image: it grows to the 8 GiB virtual disk
on first boot and avoids automating the interactive installer. The bootstrap assigns WAN to `vtnet0`, LAN to `vtnet1`,
enables key-only root SSH using a cache-local test key and preserves the normal local `root` / `opnsense` WebGUI login.
Both forwarded management ports bind only to loopback. Refresh the authenticated image and rebuild the base with:

    tests/e2e/local.sh --refresh-opnsense

Use `tests/e2e/vm.py status` to see the cache and available backends. `--keep` retains a failed VM and provider stack and
prints the exact stop command. Otherwise cleanup removes only the random run overlay, its generated SSH host-key file
and the provider containers.

## Provider matrix

Every invocation selects an identity implementation and only the network
boundary it needs:

    tests/e2e/local.sh --provider keycloak --source local --cluster direct
    tests/e2e/local.sh --provider entra --source emulated --cluster direct
    tests/e2e/local.sh --provider okta --source live --cluster direct

`--source auto` selects the real local Keycloak, authentik, Authelia and Pocket
ID images, and the reviewed emulator for Entra, Okta and Apple. `live` is valid
only with one explicit SaaS provider. `--cluster direct` is the default and
never starts a public listener. `all` finishes every direct selection first and
then runs only applicable `public-inbound` selections. An unsupported explicit
combination fails; a suite reports it as `not applicable` and continues.

The default `core` suite runs the two high-value implementations:

- **Keycloak** is the deep interoperability suite. It imports the exact partial realm file downloaded from the unsaved
  OPNsense form and covers Discovery, PKCE, enforced DPoP-bound tokens, state/nonce, true, false and missing verified
  e-mail evidence, JIT and approval workflows,
  stable subject binding, local fallback, session rotation, callback replay, `form_post`, both client-secret transport
  methods, RP/front-channel/back-channel logout and passive response-header checks with ZAP.
- **authentik** exercises the second primary deployment target, imports the exact Blueprint downloaded from the
  unsaved OPNsense form and proves that true, false and missing trusted user attributes become fail-closed
  `email_verified` values in real sign-in tests before completing a login.

The `full` suite adds two low-cost implementations whose official arm64 container images are small or self-contained:

- **Authelia** checks a file-backed provider, group claims, local SQLite state and a different Discovery/userinfo shape.
- **Pocket ID** checks an API-provisioned, passkey-only provider with a virtual WebAuthn authenticator and group-restricted
  client access.

It also adds three SaaS-shaped emulators. [entra-local](https://github.com/cmaneu/entra-local)
checks Entra's tenant issuer and baseline claims. Vercel Labs
[`emulate`](https://github.com/vercel-labs/emulate) checks Okta authorization
server paths, groups and Form Post, plus Apple's Form Post and first-login claim
shape. The Apple driver names its bounded adaptation in the result: `emulate`
uses a generic issuer profile, while a local adapter adds the PKCE and
`form_post` Discovery metadata that the emulator currently omits. These results
are useful compatibility evidence, never evidence that the
real hosted service, MFA, Conditional Access, consent or multitenancy works.

Dex was evaluated as another lightweight candidate but is not in the matrix yet. Its current stable release does not
return the required `auth_time` claim when OPNsense requests `max_age`; the firewall therefore correctly refuses the
login. Revisit it after Dex ships its authentication-session implementation in a stable release.

Every reviewed container is pinned by both tag and digest in `providers/images.json`. A canary run resolves the latest
official GitHub release once and then resolves its registry digest before starting it:

    tests/e2e/local.sh --suite full
    tests/e2e/local.sh --provider authentik
    tests/e2e/local.sh --provider pocketid --canary

## Public inbound cluster

Normal authorization redirects stay direct: the browser resolves the registered
HTTPS origin to the disposable VM. A public listener exists only for a
provider-originated POST that cannot reach the lab network. The Keycloak
`local/public-inbound` run starts a pinned Cloudflare Quick Tunnel immediately
before that cluster and removes it on success, failure or interruption. A Quick
Tunnel can log its random hostname shortly before the public DNS record exists;
the harness therefore lets that record propagate before its first system DNS
lookup instead of caching a transient negative answer for the whole run.

The tunnel reaches a private, access-log-free nginx container rather than the
WebGUI. That proxy accepts only exact `POST` requests to the selected
back-channel logout and Shared Signals push routes. It rejects every other path
or method and bounds request bodies, rates and timeouts. The random origin is
never used as a general OIDC redirect URI. [Microsoft Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/)
remain an alternative. Their anti-phishing page does not intercept these
provider-originated non-GET requests, but hosting still requires a signed-in
CLI, so they add an account dependency without improving this ephemeral path.

The Keycloak public cluster first proves the logout POST from Keycloak itself.
It then starts a pinned, ephemeral local SSF transmitter with a per-run RSA key,
serves its discovery metadata and JWKS over the lab CA, and sends one signed
session-revoked SET through the same tunnel. The run succeeds only when the
OPNsense receiver returns `202`; the transmitter emits neither tokens nor the
random tunnel origin.

Live Entra and Okta public-inbound profiles prepare the same narrow handoff and
invoke an owner-only driver outside the repository. The driver receives only
the provider, live-config path, public origin, application code and selected
capability through `E2E_LIVE_*` variables. It implements `prepare`, `register`,
`trigger` and idempotent `cleanup` actions and must return success from
`trigger` only after the hosted provider accepted the receiver response. Driver
output is discarded so it cannot become test evidence. The local Keycloak run
is the automatic tunnel canary.

## Optional SaaS profiles

Set `E2E_LIVE_CONFIG` to an absolute, owner-owned JSON file with mode `0600`.
The file stays outside the repository:

    {
      "schema": "opnsense-openid-connect.live-config/v1",
      "profiles": {
        "okta": {
          "issuer": "https://example.okta.com/oauth2/default",
          "client_id": "...",
          "client_secret": "...",
          "provider_revision": "service:2026-08-25",
          "application_code": "stable-lab-code",
          "webgui_port": 48443,
          "interaction": "manual",
          "public_inbound": {
            "capabilities": ["shared_signals"],
            "driver": "/absolute/owner-only/provider-driver",
            "ssf_issuer": "https://example.okta.com/ssf/default",
            "ssf_audience": "opnsense-live-lab",
            "ssf_push_secret": "..."
          }
        }
      }
    }

Entra and Okta can use `automatic` with an owner-only `username` and `password`;
the visible browser remains available when MFA or consent needs a person. Apple
normally uses `manual`. For `local.sh`, `webgui_port` makes the disposable VM use a stable callback origin that can be
registered in advance. The callback is `https://opnsense.opnsense.test:<webgui_port>` plus
`/api/openidconnect/auth/callback/<application_code>`. A prepared lab may supply its already stable origin directly.
The public-inbound proxy retains that origin's DNS route by default. Set
`E2E_OPNSENSE_PROXY_ADDRESS` to a literal reachable address only when the Docker runner needs an explicit override;
the local VM wrapper supplies Docker's `host-gateway` mapping automatically.

A live direct Entra or Okta result records `login=pass` only after the provider-backed flow reaches the WebGUI
dashboard and rotates the PHP session. Apple's public profile deliberately requires administrator approval for a new
subject, so the reusable live run proves PKCE through the test callback but does not publish WebGUI-login evidence.

The matrix wrapper reports all provider failures rather than hiding later results after the first failure. Provider
stacks use a per-run CA and TLS proxy. `provider.opnsense.test` is mapped to the Mac only for the browser and is pinned
to QEMU's host gateway inside OPNsense. `opnsense.opnsense.test` is mapped separately to the VM's forwarded HTTPS port
for the browser and to Docker Desktop's host gateway for logout callbacks. The reserved `.test` suffix avoids the
special loopback and proxy handling that HTTP clients apply to `.localhost`.

## Prepared lab or CI runner

CI must not construct an amd64 firewall VM. Point the same provider runner at a disposable, pre-provisioned OPNsense
machine instead:

    set -a
    . /secure/path/opnsense-oidc-e2e.env
    set +a
    tests/e2e/run.sh --suite core

The required variables are shown in `.env.example`. `E2E_KEYCLOAK_URL` or `E2E_PROVIDER_HOST` must name this Docker host
and be reachable from OPNsense and the browser runner. Root SSH must use certificate or public-key authentication. The
WebGUI certificate may remain self-signed; the provider-facing connection always uses the per-run trusted CA.

The tests generate provider passwords, client secrets and database keys for each run. They are passed through process
environments and temporary files with restrictive permissions and are never written to the repository. Cleanup removes
only resources carrying that run's random identifier. The package remains installed because it is the system under test.

To retain machine-readable evidence for the security audit, supply an absolute path outside the disposable working
directory before starting the deep Keycloak run:

    export E2E_AUDIT_EVIDENCE=/secure/audit/browser-e2e.json
    tests/e2e/run.sh --provider keycloak

The runner removes an older file at that exact path before starting and writes a mode-`0600` replacement only after
Playwright and passive ZAP both succeed. The evidence binds the result to the Git revision, deterministic package
SHA-256 and audit-harness SHA-256. It records only versioned test subjects and capability slugs, never target or provider
hosts, usernames, realm names, subjects, cookies, request data, tokens or secrets.

For any single provider and cluster, `E2E_PROVIDER_RESULT=/absolute/result.json`
writes a separate mode-`0600` provider result. It binds provider/source/cluster,
repository revision, harness digest, pinned test subject and capability outcomes
without retaining tenant, account, host, cookie, token, claim or secret values.
Import only deliberately reviewed cells:

    python3 tests/import-provider-result.py /absolute/result.json --feature login --feature pkce

The importer rejects dirty or different revisions, changed harnesses, unknown
fields, unpinned subjects and unknown capabilities. Real local or SaaS evidence
may make a cell ✅; an emulator result appears additionally as 🧪 and never
replaces or upgrades real evidence.

## ZAP boundary

ZAP remains part of the deep Keycloak test only. It passively observes traffic that Playwright deliberately sends through
its random loopback proxy; it does not spider or actively scan the firewall. The sanitized report records paths and rule
names but no hosts, query strings, tokens, cookies or bodies. Exact assertions in `oidc.spec.mjs` remain authoritative for
plugin-owned cache, content-type, clickjacking, referrer and CSP headers.
