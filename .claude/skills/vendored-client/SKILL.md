---
name: vendored-client
description: Update or reason about the bundled Jumbojett OpenID Connect client (src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/OpenIDConnectClient.php). Use when vendor-check.py reports upstream has moved, when a security advisory names the library, or when anything tempts you to edit that file - the answer is always an override in RelyingParty.php instead.
---

# The bundled client

One third-party file, Apache-2.0, taken **unaltered**. OPNsense has no Composer
at runtime, so a plugin brings what it needs; this library was chosen because it
needs only `phpseclib3`, which OPNsense already ships.

A bundled copy gets no security updates from anywhere. `vendor-check.py` is the
whole of the countermeasure, and it only reports — somebody has to act on it.

## Never edit that file

Everything wanted differently is an override in `RelyingParty.php`. That keeps
an update a copy and never a merge, and keeps every deviation readable in one
place. If something cannot be expressed as an override, say so and stop rather
than patching the file — the answer is usually a different override, or a check
in the controller.

`vendor.json` records a sha256 of the file, and `vendor-check.py` reports "the
bundled file has been altered" in exactly this case.

## Updating

    python3 packaging/vendor-check.py            # what is the state
    python3 packaging/vendor-check.py --update   # pull it in and record it
    git diff                                     # then read what changed

It runs on the build host, never on the firewall: a firewall that reaches out
to the internet on its own would be the wrong trade, and at build time somebody
is sitting there who can act on what it says.

## After every update, check the overrides

`RelyingParty.php` overrides `authenticate`, `verifyJWTSignature`,
`verifyJWTClaims`, `requestUserInfo`, `fetchURL`, `redirect` and
`supportsAuthMethod`. A changed signature fails loudly at runtime and nothing
warns first — read the diff for all seven.

**A signature is the easy half.** Two overrides depend on how the file behaves,
and behaviour moves without a word:

- `authenticate` checks the state *before* calling upstream's version, because
  upstream checks it only after handing the code to the token endpoint. It
  recognises an answer the way upstream does, by `code` or `id_token` in the
  request. If upstream answers to something else, the check stops firing and
  nothing fails. If upstream stops keeping the state where `getState()` finds
  it, every login is refused.
- `setSessionKey` / `unsetSessionKey` can be sealed, so that nothing writes a
  session back into being after the sign-out path destroyed it. With the
  `startSession` / `commitSession` no-ops that is upstream's complete session
  interface *today*. A version reaching `$_SESSION` another way slips past.

`tests/unit/exchange.php` covers the first in both directions. Run it and read
what it says rather than assuming:

    php tests/run.php

Then check what the library still refuses on its own, because the overrides are
written on the assumption that it does: `alg: none`, a key smuggled in through
the token header (`verifyJWKHeader` throws), the implicit flow, and TLS peer and
host verification.

## Then

- `vendor.json` carries the new ref, date and sha256 — `--update` writes them.
- `packaging/VENDOR.md` says what the overrides assume; correct it if an
  assumption moved.
- The package annotation `bundled_library` picks the new ref up by itself.
- Commit as `build(vendor): ...`, or `fix(oidc)!:` when behaviour an
  installation can notice changed with it.
