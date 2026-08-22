# opnsense-openid-connect

OpenID Connect sign-in for the OPNsense web interface, as a FreeBSD package
that installs beside the core package and replaces nothing in it. PHP for what
runs on the firewall, Python for what builds and checks it, shell for the
watchdog. No Composer, no PHPUnit, no framework beyond what OPNsense itself
ships.

**This module decides who reaches a firewall's web interface.** Almost every
rule below follows from that one sentence.

## Where things are

| | |
|---|---|
| `src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php` | the connector: the settings surface, and which local account a set of claims is |
| `src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/RelyingParty.php` | the seam between the bundled OIDC client and OPNsense, and every check the library leaves to its caller |
| `src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/OpenIDConnectClient.php` | **vendored, never edited** — see `packaging/VENDOR.md` |
| `src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/` | the HTTP endpoints: the browser's side of a login, and the discovery probe |
| `src/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/` | what the login page is handed |
| `packaging/` | the build, the vendoring, the commit convention, the release note, the watchdog |
| `tests/` | everything `./tests/run.sh` runs |
| `docs/` | one page per identity provider, plus what every provider has to offer |

Nothing here shares a name, a file path, an API route or an authentication
server type with any other OpenID Connect module for OPNsense: the type is
`openidconnect`, the module namespace is `OPNsense\OpenIDConnect`, the endpoints
live under `/api/openidconnect/`, and every field in `config.xml` carries the
`openidconnect_` prefix. Two packages cannot own the same file, so that
separation is not decoration — keep it.

## Commands

    ./tests/run.sh                                    everything, and what CI runs
    php tests/run.php                                 the behaviour checks alone
    python3 packaging/build.py --check                does it still build
    python3 packaging/vendor-check.py                 has upstream moved
    python3 packaging/release-notes.py --tag vX.Y.Z   what a release would say
    python3 packaging/commit-lint.py --range main..HEAD

There is no linter beyond `php -l`; keep to 120 columns and to the style of the
file being edited.

## Rules that are not preferences

1. **Signing in locally always works.** `authgui.inc` renders the password form
   before the single sign-on block, and nothing here may change that. Every
   failure mode has to end with somebody still being able to get in.
2. **The vendored client is never edited.** Everything wanted differently is an
   override in `RelyingParty.php`, so that updating it stays a copy and never
   becomes a merge. `packaging/VENDOR.md` lists the overrides and the two
   assumptions that are about behaviour rather than signatures.
3. **A refusal says one thing.** Every local-account outcome — no account,
   disabled, expired, root, an address the provider would not vouch for — ends
   in the same sentence and status code. The reason goes to the log alone.
   Splitting them would answer "which accounts exist here" to anyone who can
   sign in at the provider.
4. **A trace carries no tokens, secrets or claim values** beyond what is needed
   to follow the flow. Traces end up in support mail.
5. **Nothing is a setting that the protocol decides.** Algorithms, `exp`,
   `nonce`, `azp`, the subject binding, the redirect allow list: those are what
   OpenID Connect asks for, and an installation does not get to differ. What an
   installation genuinely differs on is a field under *System > Access >
   Servers*.
6. **Privileges stay local unless asked otherwise.** No group claim is consumed
   until one is configured. Anything that would widen this needs a deliberate
   decision, off by default.
7. **The package is named `os-openid-connect`, and ships no file under
   `/usr/local/opnsense/version/`.** The name is the only thing that puts it on
   *System > Firmware > Plugins*, which is where somebody notices their login
   depends on it. A version file is the separate mechanism that would also
   register it in `system.firmware.plugins`, and every plugin sync would then
   try to install it from a repository that does not have it. Name yes, register
   no.
8. **Depending on core means watching core.** Core is somebody else's code and
   moves without warning. Anything newly depended on goes into `TOUCHPOINTS` in
   `packaging/watch/openid-connect-watch`.

## Style

Comments explain **why**, not what — this project's comments are long on
purpose and are not clutter to remove. English throughout, a copyright line on
every file, no host, address or mailbox of whoever wrote it (`tests/package.py`
checks all three, and deliberately names none of them).

Commit messages follow Conventional Commits because the release note is written
out of them; see `CONTRIBUTING.md`. A change that can turn a login that worked
into one that does not is marked `!` with a `BREAKING CHANGE:` footer saying
what to set — not that something changed.

## What this deliberately does not do

Captive Portal and OPNWAF: the first because an integration nobody here can
exercise would be guesswork, the second because it is a Business Edition
product. The Log Out link in the page header: it lives in core's `authgui.inc`,
out of a plugin's reach.

## Skills

`.claude/skills/` holds the procedures worth following exactly: changing a
setting, updating the vendored library, depending on something new in core, and
cutting a release. Read the matching one before starting that kind of work.
