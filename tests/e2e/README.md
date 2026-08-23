# Disposable browser-to-firewall test

This is the destructive integration test for a disposable OPNsense instance.
It creates an isolated Keycloak realm in Docker, installs a two-day test CA and
the current package on OPNsense, configures the authentication server through
the real WebGUI, and drives the browsers with Playwright.

It verifies the authorization code flow, Discovery, PKCE S256, nonce and state,
JIT account creation, the `admins` bootstrap group, stable subject binding with
JIT subsequently disabled, assisted create/edit/remove operations in the
combined identity manager, the administrator-approval queue and subsequent
approved sign-in, session-ID rotation, callback replay rejection,
local-password fallback, explicit denial without a session after the admitted
local account loses its effective WebGUI privileges, RP-initiated logout,
Keycloak back-channel logout,
Keycloak front-channel logout, `form_post`, and `client_secret_post`. It also
checks the social-login labels, complete named-profile presets, fixed versus
editable fields, profile-default restoration and Microsoft-only conditional
settings in the real form. A pinned local OWASP ZAP instance passively observes
the OPNsense traffic created by these flows and independently parses cache,
content-type, clickjacking and CSP headers. Runtime cryptography, registry
permissions, package checks and the watchdog remain in
`../integration/opnsense.php` and `../run.sh`.

Before contacting Keycloak, it downloads and inspects the generated partial
import from the unsaved form, then saves and reopens a disabled draft with no
issuer, Client ID or Client Secret. This guards both the no-secret onboarding
contract and the UX rule that Discovery is an optional preflight, never a hidden
prerequisite for preserving work.

The container image is the official Keycloak 26.7.2 image pinned by digest;
the small TLS proxy is likewise pinned. The test switches the same Keycloak
client between back-channel and front-channel logout because Keycloak treats
them as alternatives. Keeping **Front channel logout** enabled prevents the
back-channel URL from receiving the same event.

## Requirements

- A newly installed or otherwise disposable OPNsense host reachable by HTTPS
  and certificate-authenticated root SSH.
- A Docker host address reachable from OPNsense and from the browser runner.
- Docker, Node.js, npm, OpenSSL, `jq`, SSH and SCP on the runner.
- Two unused host ports, normally 18443 for Keycloak and 19443 for the isolated
  back-channel TLS proxy.

The ZAP API and proxy use a random loopback-only port. ZAP runs locally in its
pinned official container, can reach private firewall addresses and accepts the
self-signed WebGUI certificate as part of this isolated test. The Playwright
browser sends only OPNsense traffic through ZAP; provider traffic is bypassed.

Copy `.env.example` to a file outside version control, replace the documentation
addresses and password, load it into the shell, then run:

    set -a
    . /secure/path/opnsense-oidc-e2e.env
    set +a
    tests/e2e/run.sh

`E2E_KEYCLOAK_URL` must be an HTTPS origin whose host resolves to this Docker
machine and is reachable from OPNsense. The runner creates a private CA with
that host in the certificate SAN; it never turns TLS verification off in the
plugin. The WebGUI certificate may remain self-signed and does not need to name
its management IP: the back-channel test uses a disposable TLS reverse proxy.

Secrets are random per run and are passed only in the process environment.
No internal address, password, realm, client secret or subject is stored in the
repository. Cleanup targets only the random `oidc-e2e-*` user and `e2e-*`
application code, removes the temporary CA, and removes all disposable
containers. The package remains installed because it is the system under test.
Set `E2E_KEEP=1` only on an isolated machine when failed resources must remain
for diagnosis; then remove them manually afterwards.

## Passive response-header validation

ZAP is not used as a spider and performs no active scan. Playwright remains
responsible for reaching authenticated APIs, single-use callbacks and each
browser outcome in a valid order; ZAP inspects the resulting responses. The
final report fails when any required response class was not observed, or when
the curated passive rules find an unexpected missing content type, unsafe
caching, missing MIME protection, missing anti-clickjacking protection, a
missing enforceable CSP, or a malformed/unsafe CSP on a plugin-owned response.

The policy deliberately does not turn a generic scanner grade into the
contract. It records rather than fails expected findings for host-owned HSTS,
non-HTML JSON APIs, the required front-channel iframe, reviewed inline styling
and cacheable validated icons. A missing response media type is accepted only
on a `3xx` produced by core authentication before an API controller runs; the
same finding on a successful API response remains blocking. Exact endpoint
assertions in `oidc.spec.mjs` remain authoritative for `no-store`,
`no-referrer`, `nosniff` and every CSP directive. A sanitized JSON report is
written inside the temporary E2E directory; it contains paths and rule names,
but no hosts, query strings, tokens, cookies or response bodies. It is retained
only with `E2E_KEEP=1`.
