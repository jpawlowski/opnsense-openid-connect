# Tests

    ./tests/run.sh

The unified security and conformance report is generated from versioned
standards, provider and control catalogs plus machine-readable evidence. Refresh
its host-independent statements with:

    python3 tests/update-security-report.py --update

`--check` runs the same suite without changing the unified report and fails when the
report is stale. A failing suite makes generation fail and leaves the existing
report untouched; CI already presents the failure. The report contains only
positive security properties whose complete evidence requirement is met. It
has no finding backlog, audit IDs or test-count dashboard.

The standards and provider section has a stricter, normative gate and an
intermediate generated fragment:

    python3 tests/update-capability-matrix.py --check

Its source catalogs are `tests/standards/catalog.json` and
`tests/providers/capabilities.json`. A standard can be marked verified only
after the exact RP profile and specification revision are pinned, every
applicable normative requirement has a stable ID, and each mandatory or claimed
behaviour points to distinct accepting and refusing checks in a test suite run by
the host-independent gate. Each exact check name starts with the requirement ID
and evidence direction. The PHP and Python harnesses record the checks actually
reached by `./tests/run.sh`; a check merely present in source is not evidence.
Recommendations need the same evidence or a dated, reviewed rationale for
deviating. Verified source-review pins require a canonical date and non-empty
revision, profile and section inventory. The validator also requires every
provider profile and matrix dimension to be represented. Run the complete gate,
not only the standalone generator, when validating a verified claim.

Every `documented` or `conditional` provider cell names one feature-specific
HTTPS source that is also cited in that provider's guide. The generated matrix
links the cell directly to that source; an unrelated URL elsewhere in the guide
cannot support another feature.

Installed and browser evidence is optional but required for statements that
cannot be proven on the host alone. Keep a sanitized result under
`tests/evidence/*.json`, or pass it explicitly with a repeatable
`--evidence /absolute/path.json` option. The generator accepts it only when it
is bound to a clean source revision and none of that statement's implementation
or validation files have changed since the recorded run.

Each evidence tier inventories its capability names in
`tests/audit-controls.json`. Generation fails if an evidence producer and that
inventory diverge, if a control names an unknown capability, or if a produced
capability has no control. This keeps a newly programmed check from becoming
unused evidence silently.

This is the fast, host-independent gate used by hand, by an agent Stop hook and
by the pipeline, so a failure looks the same in all three places. Nothing in it
needs Composer, PHPUnit, containers, a browser, a network or an OPNsense.

There are deliberately four test tiers:

| Tier | Command | When it runs |
|---|---|---|
| Host-independent | `./tests/run.sh` | On every relevant change and in CI |
| Installed integration | `php tests/integration/opnsense.php` | Explicitly, on an installed OPNsense |
| Destructive browser E2E | `./tests/e2e/run.sh` | Explicitly, with a disposable firewall and containers |
| OIDF RP pilot | [Hosted procedure](conformance/README.md) | Explicitly and manually |

Only the first tier belongs in an automatic Stop hook. The other three require a
deliberate decision and must never be started merely because an agent is done.

## What is covered

**`tests/unit/`** exercises the parts that decide things, through stand-ins for
the OPNsense classes (`tests/stubs/`):

| | |
|---|---|
| `settings.php` | reading a settings field: list parsing, the shapes a group claim arrives in, Microsoft account audiences and issuer rules, finding the issuer in whatever was typed, every default, which addresses may be fetched, and what the settings form refuses |
| `authentication-strength.php` | provider-aware MFA and phishing-resistant requests, complete registered AMR classification, exact `acr`/`acrs` plus `amr` enforcement, Microsoft authentication contexts, and transaction serialization |
| `redirects.php` | choosing the address the provider returns to — the allow list, near-miss names, the empty-list fallback, a Host header that is not a host name, and whom a token was issued for |
| `claims.php` | reading claims from the id_token as well as UserInfo, and keeping protocol claims out |
| `exchange.php` | discovery, bounded HTTPS, PKCE, one-time transactions, mix-up protection, ID Token claims and logout-token claims |
| `accounts.php` | which local account a login is, and whether it may be used at all: disabled, expired, root, verified-address matching, first-login creation, strict admission, and the bounded administrator-approval workflow |
| `groups.php` | what is handed to core when group membership is synced — the spelling it compares against, and the scope it is allowed to act in |
| `loginpage.php` | what the login page is handed: which icon, which markup, and that a provider name cannot open a tag |
| `provider-setup.php` | no-secret authentik and Keycloak imports, exact redirects, idempotent policy and input boundaries |

**`tests/convention.py`** checks the rule that decides what a commit message
may be, and what a release note makes of one. It is checked because the two
sides fail in opposite directions: a rule too strict refuses a message somebody
is trying to write, and a rule too loose lets a change reach a release with
nothing said about it in the note. The second is the one nobody notices.

**`tests/package.py`** builds the package and checks the result: the archive
shape `pkg` expects, that every file is listed with a matching checksum,
permissions and ownership, that no retired third-party client ships and
documentation does not — and that nothing carries the naming, addresses or
hosts of whoever built it, that everything is English, and that every file of
ours says who wrote it.

That last part is there because this package is meant to be handed to strangers.
It is a check, not a courtesy.

**It names nothing.** A check written as a list of the names to keep out is
itself a list of those names, published with the package — which is worse than
the thing it prevents. So it tests properties instead: an address literal that
is not the loopback or a documentation range, a host that is not the one the
manifest already declares, a mailbox that is not the declared maintainer. The
copyright line it looks for is read from `LICENSE` rather than written out.

That is also the stronger check. It catches whatever a future author leaves
behind, not only what this one happened to think of.

**`tests/capability-matrix.py`** attacks the publication gate itself. It proves
that an empty normative inventory, one-sided mandatory evidence, a live provider
claim without a dated retained artifact and an unnamed vendor adaptation are
all refused. It also proves that a pinned complete fixture with two-sided test
markers is the only shape that can become green.

## What is deliberately not covered

Anything that only exists inside OPNsense: session handling, the dispatcher, the
real login page, and what core does with a group sync once it has been handed
one. A stub that grew far enough to test those would start passing tests the
real thing would fail.

After installing on an actual firewall, `tests/integration/opnsense.php` checks
the OPNsense-supplied phpseclib implementation with RSA, RSA-PSS and ECDSA, plus
the real session directory, logout replay index, one-time form-post index and
administrator-approval registry. `--network` additionally checks exact
Discovery against the public providers whose metadata is available without an
account. It is not part of the host-independent CI command.

An installed run can explicitly produce sanitized machine-readable audit
evidence alongside its unchanged human output:

    php tests/integration/opnsense.php --evidence=/tmp/openid-connect-integration.json

The output path must be absolute. The mode-`0600` JSON names only the validated
runtime capabilities and, where `pkg` and `opnsense-version` expose them, binds
them to the installed package version, its `built_from` source revision and the
OPNsense version. Missing identity fields remain visible as limitations. It
contains no firewall address, hostname, configured account, claims or other
runtime values. Add `--network` to the same command only when public Discovery
requests are intended. The report generator accepts retained integration
evidence only when all three identities are present and valid.

An administrator can also prove mutual-TLS interoperability against one
deliberately prepared provider client without completing a browser login. The
probe sends a random invalid authorization code through the discovered mTLS
token endpoint and passes only when the provider first accepts the certificate
and then returns `invalid_grant` rather than `invalid_client`:

    php tests/integration/opnsense.php \
      --mtls-issuer=https://id.example.net/realms/firewall \
      --mtls-client-id=opnsense \
      --mtls-certificate-ref=0123456789abc \
      --mtls-redirect-uri=https://firewall.example.net/api/openidconnect/auth/callback/main

All four values are required together. The certificate reference names an
existing OPNsense certificate with its private key; no secret, certificate,
key, provider response or address is written into audit evidence.

For a disposable firewall, [`e2e/run.sh`](e2e/README.md) goes further: it
creates an isolated Keycloak realm in pinned official containers, installs the
current package and a short-lived CA, configures the server through the real
OPNsense WebGUI, and drives the complete browser flow with Playwright. A pinned
local OWASP ZAP proxy passively validates the response headers emitted along
that authenticated traffic without requiring a publicly reachable firewall or
a publicly trusted certificate. It covers
the non-mutating sign-in tester, login, PKCE, automatic first binding,
administrator approval, conditional provider fields, social-login labels,
session rotation, replay rejection, both Keycloak logout channels, Form POST,
POST client authentication and the local-password recovery path. This deliberately
destructive test is manual because it needs a fresh OPNsense host and a Docker
address reachable from it.

The external [OpenID Foundation relying-party conformance
pilot](conformance/README.md) uses the Foundation's hosted fake provider for a
small, fixed set of successful and deliberately invalid protocol responses. It
adds an independent end-to-end check of signature, claim, Discovery and signing
key rotation decisions without claiming certification. It remains manual,
serial and outside the audit report until a future runner can produce sanitized,
revision-bound evidence.

The stubs do keep a list of local accounts and record what was asked of core,
because *what this plugin decides* about an account — which one a claim is,
whether it may be used, which groups core is allowed to touch — is exactly the
part worth checking, and none of it needs an OPNsense to be true.

That side is watched where it is real. `openid-connect-watch` runs on the
firewall every night and fetches the actual login page — see
[`../packaging/README.md`](../packaging/README.md).

## Adding a check

The Python checks share `tests/harness.py`, which is the same three things
`harness.php` is: a name per check, a readable failure, a non-zero exit code.

`Checks::that(what, actual, expected)` and `Checks::throws(what, callable)`.
`inspect($object, 'method', ...)` reaches a private one, `connector([...])`
builds a configured authentication server without a config file,
`directory([...], [...])` gives the machine some local accounts, and
`claims([...])` is the shape a verified answer arrives in. Name the check
after the behaviour, not the method — a failure should read like a sentence
about what broke.

Regression checks are worth their weight here. Two of the bugs this suite
covers — Entra ID's claims living only in the id_token, and a group claim
arriving as a map rather than a list — were found by writing documentation, not
by running code.
