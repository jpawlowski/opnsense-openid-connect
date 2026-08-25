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

### Documentation screenshots

The deep Keycloak flow can also capture the five maintained documentation images after their normal assertions pass:

    tests/e2e/local.sh --provider keycloak \
        --screenshots "$(pwd)/docs/assets/screenshots"

This mode uses stable synthetic labels such as `Company identity` and `alex`; it never exposes generated credentials.
It still creates a fresh disposable VM overlay, randomly named containers and independent loopback ports, so another
local E2E run cannot share its firewall, provider or logout callback. The output directory must be absolute. A
successful run replaces `login-and-recovery.png`, `connection-health.png`, `test-sign-in.png`,
`bound-identities.png` and `pending-approvals.png` at their exact paths. Captures remain staged in the disposable run
directory until all five UI states pass, so a failed run leaves the maintained set untouched.

The screenshot browser connects directly to its disposable VM; the separate API checks still use ZAP. Functional
Playwright assertions remain active, while the passive ZAP report stays part of the ordinary deep Keycloak run instead
of an image-generation prerequisite.

## Provider matrix

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

Dex was evaluated as another lightweight candidate but is not in the matrix yet. Its current stable release does not
return the required `auth_time` claim when OPNsense requests `max_age`; the firewall therefore correctly refuses the
login. Revisit it after Dex ships its authentication-session implementation in a stable release.

Every reviewed container is pinned by both tag and digest in `providers/images.json`. A canary run resolves the latest
official GitHub release once and then resolves its registry digest before starting it:

    tests/e2e/local.sh --suite full
    tests/e2e/local.sh --provider authentik
    tests/e2e/local.sh --provider pocketid --canary

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

## ZAP boundary

ZAP remains part of the deep Keycloak test only. It passively observes traffic that Playwright deliberately sends through
its random loopback proxy; it does not spider or actively scan the firewall. The sanitized report records paths and rule
names but no hosts, query strings, tokens, cookies or bodies. Exact assertions in `oidc.spec.mjs` remain authoritative for
plugin-owned cache, content-type, clickjacking, referrer and CSP headers.
