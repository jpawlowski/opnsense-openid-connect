# The bundled third-party file

    OpenIDConnectClient.php

| | |
|---|---|
| Origin | https://github.com/jumbojett/OpenID-Connect-PHP |
| Licence | Apache-2.0 — `LICENSE.jumbojett` sits next to it, notice in the file header |
| Copyright | MITRE 2020, Michael Jett |
| State | see `vendor.json` next to this file |
| Changes | **none** — taken unaltered |

## Why bundled

OPNsense has no Composer at runtime. Whatever a plugin needs in third-party
code, it brings along itself. This one needs `phpseclib3` and nothing else,
and OPNsense already ships that (`php85-phpseclib`, under
`/usr/local/share/phpseclib`, a dependency of the core package). Hence exactly
**one** file rather than a dependency tree — and hence the choice of a library
that manages with that single dependency.

## What that means

A bundled copy receives no security updates — not through Composer, not
through the system's package manager. If something is found over there, nobody
here learns of it by itself.

The countermeasure is `vendor-check.py` next to this file. It compares the
bundled file with what upstream has today and reports both directions: "the
origin has moved on" as well as "our copy has been altered". The pipeline runs
it on every push, deliberately without holding a release up.

It runs on the **build host, not on the firewall**: a watchdog that reaches out
to the internet from a firewall would be the wrong trade, and at build time
somebody is sitting in front of it who can act on what it says.

    python3 packaging/vendor-check.py           # check
    python3 packaging/vendor-check.py --update  # pull in and record

`LICENSE.jumbojett` deliberately stays **in the source tree** and ships with
the package: Apache-2.0 asks that every recipient of a distribution gets the
licence text, and the package is a distribution. This note here belongs to the
build host and is not installed.

## The rule when pulling in a newer version

The file is taken **unaltered**. Everything we want differently lives as an
override in `RelyingParty.php` — `authenticate`, `verifyJWTSignature`,
`verifyJWTClaims`, `requestUserInfo`, `fetchURL`, `redirect` and
`supportsAuthMethod` are overridden there. That keeps the comparison a copy and
never a merge, and keeps the deviations readable in one place.

After every update, check those overrides: if upstream changes the signature of
an overridden method, nothing says so until it fails at runtime.

A signature is the easy half. Two of the overrides depend on how the file
*behaves*, and behaviour moves without a word:

* `authenticate` checks the state before calling upstream's version, because
  upstream checks it only after handing the code to the token endpoint. It
  recognises an answer the same way upstream does, by `code` or `id_token` in
  the request. If upstream ever answers to something else, the check stops
  firing and nothing fails; if upstream stops keeping the state where
  `getState()` finds it, every login is refused. `tests/unit/exchange.php`
  covers both directions — run it after an update and read what it says.
* `setSessionKey` and `unsetSessionKey` can be sealed, so that nothing writes a
  session back into being after the sign-out path destroyed it. Together with
  the `startSession`/`commitSession` no-ops that is upstream's complete session
  interface today. A version that reaches `$_SESSION` by some other route would
  slip past the seal.
