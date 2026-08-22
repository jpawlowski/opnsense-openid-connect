---
name: oidc-release
description: Cut a release of opnsense-openid-connect, or work out why a release came out wrong. Use when asked to tag, publish, bump the version, or check what a release note would say. The version lives in the git tag alone and the note is written out of the commits, so most of the work happens before the tag exists.
---

# Cutting a release

Two things are generated and neither can be fixed afterwards without moving a
tag: the **version**, which is the tag, and the **note**, which is the commits.
So the work is in what is already committed.

## Before tagging

    ./tests/run.sh
    python3 packaging/vendor-check.py
    python3 packaging/release-notes.py --tag vX.Y.Z

The last one prints the note the tag *would* produce — read it as an operator
would. Things worth catching there:

- **Is everything that can lock somebody out at the top?** A default that
  changed, a field that became required, an account that stops being reachable.
  If one is missing, its commit lacks the `!` or the `BREAKING CHANGE:` footer,
  and the fix is to amend the commit, not to write prose into the release.
- **Does each breaking entry say what to set?** The footer is quoted verbatim.
  "Behaviour changed" helps nobody; "set *Match by e-mail address* to *Any
  address the provider reports*" does.
- **Does anything land under "Other"?** Then a message was not readable, which
  `commit-lint.py` should have refused.

`vendor-check.py` is not blocking in the pipeline on purpose — an urgent
release should not wait for upstream. But a release that ships a bundled client
months behind is worth knowing about while deciding.

## The tag is the version

    git tag -a v1.2.3 -m "..." && git push --tags

`build.py` reads it and nothing else states it. A tag with a suffix is a
pre-release: `v1.0.0-beta1` becomes package version `1.0.0.beta1` (a hyphen is
what `pkg` reads as the end of a package's name, so it cannot survive), and
both pipelines mark the release itself as a pre-release.

Anything not sitting on a tag builds as `1.2.3.4.gabc1234`, so work in progress
never looks like a release.

## What the pipelines do

`.forgejo/workflows/build.yml` and `.github/workflows/build.yml` run the same
checks by the same commands; only the release step differs, because the two
forges do not offer releases the same way. Both attach:

- the `.pkg`
- a `.sha256` beside it
- a `.sig`, when a `PKG_SIGNING_KEY` secret exists — without it the pipeline
  says so in its log and carries on

A re-run of the same tag refreshes the release rather than failing, so a tag
deleted and pushed again is safe.

## After

Check the release page: the note reads as intended, the three assets are there,
and the install line in the note points at the file that is actually attached.

Then install it once on a real OPNsense if anything touched the login path —
`tests/` deliberately covers none of what only exists inside OPNsense, and
`openid-connect-watch --status` on that machine is the quickest way to see the
login page is still whole.

## If a release came out wrong

Delete the tag, fix the commits, tag again. The pipelines are written to be
repeatable for exactly this. What cannot be undone is a release somebody has
already installed — so a version that was wrong gets a new number, never a
quietly replaced file.
