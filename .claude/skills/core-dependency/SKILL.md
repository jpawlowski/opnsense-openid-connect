---
name: core-dependency
description: Use when code here starts relying on something in the OPNsense core package - a class under OPNsense/Auth, session handling, the dispatcher, a configd action, a rule copied out of core, the login page. Core is somebody else's code and moves without warning; this says how to depend on it so that the next core update cannot break a login in silence.
---

# Depending on core

This plugin hooks into interfaces the core package is free to change at any
time. When one moves, the login button can disappear — or the login page can
stop loading. Two habits keep that from being discovered by whoever is locked
out.

## Read the real thing, not the stub

`tests/stubs/opnsense.php` is deliberately minimal and would happily pass a
test the real thing fails. Before relying on a core method, read core's own
source for the version being targeted:

    https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/library/OPNsense/...

Check the signature *and* what it does with each argument. `setGroupMembership`
is the cautionary tale: it compares group names against `strtolower()` of the
local name, so a scope handed to it with a capital letter matches nothing and
the sync silently does nothing at all.

## Add it to the watchdog

`TOUCHPOINTS` in `packaging/watch/openid-connect-watch` is a list of the core
files this package hangs off. `openid-connect-watch` fingerprints them nightly
and reports when the ground moves, even while everything still works.

**A new dependency that is not in that list is a dependency nothing watches.**
Add the file, and update the count in `packaging/README.md` where the watchdog
is described.

This matters most for rules *copied* out of core rather than called: the
account expiry arithmetic in `accountMayBeUsed()` is core's `Local` rule
written out again, so `Local.php` is a touchpoint even though nothing here
calls it. If core changes how it judges an expired account, the two ways in
diverge with no symptom but somebody getting in who should not.

## Fail the way core fails

Where core already answers a question — may this account sign in, what is this
user actually called, which groups may be touched — answer it the same way and
in the same direction. A connector that is more permissive than the password
form is a way around the password form.

## Never edit core

Not a file, not a line. This package adds files under
`/usr/local/opnsense/mvc/` and nothing else; `tests/package.py` checks that
what ships replaces nothing. Where core offers no hook, the honest options are
an override in this tree, a documented limitation, or nothing — the Log Out
link in the page header is the documented-limitation case.

## Check what a session actually is

Core's `Mvc\Session` copies the payload and closes the php session at once, and
writes changes back on `close()`. Two consequences that have already caught
somebody here:

- after the sign-out path destroys the session, **nothing** may write through
  the wrapper, or the dispatcher opens a fresh session on the way out and hands
  the browser a new cookie. `RelyingParty::sealSession()` exists for this.
- the session id is rotated after the wrapper has written its payload, so that
  `session_regenerate_id(true)` carries the login across and removes the old
  file.
