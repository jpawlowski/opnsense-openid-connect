---
name: oidc-release
description: >-
  Prepare, validate, or troubleshoot an opnsense-openid-connect release or its CI workflow. Use when asked to tag,
  publish, choose a version, inspect generated release notes, or change GitHub/Forgejo release automation.
---

# Cutting a release

Two things are generated and neither can be fixed afterwards without moving a
tag: the **version**, which is the tag, and the **note**, which is the commits.
So the work is in what is already committed.

## Before tagging

    ./tests/run.sh
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

## The tag is the version

    git tag -a v1.2.3 -m "..." && git push --tags

`build.py` reads it and nothing else states it. A tag with a suffix is a
pre-release: `v1.0.0-beta1` becomes package version `1.0.0.beta1` (a hyphen is
what `pkg` reads as the end of a package's name, so it cannot survive), and
the workflow marks the release itself as a pre-release on both forges.

Anything not sitting on a tag builds as `1.2.3.4.gabc1234`, so work in progress
never looks like a release.

## GitHub publishes, Forgejo mirrors

`.github/workflows/build.yml` is the single source for GitHub and Forgejo.
Forgejo reads it as a fallback while `.forgejo/workflows` is absent, so every
check workflow change must still parse and run on both platforms. The Forgejo
repository is a read-only pull mirror, however: mirror synchronization is not a
release event and its result is not a required status check.

GitHub is the source of truth for pull requests, protected `main`, tags and
releases. Only a GitHub `push` event for a `v*` tag may publish. A manual run,
Forgejo run or ordinary branch push may build and check but must not create a
release.

The GitHub release attaches:

- the `.pkg`
- a `.sha256` beside it
- a `.sig`, when a `PKG_SIGNING_KEY` secret exists — without it the pipeline
  says so in its log and carries on

A re-run refreshes the note and first removes every previous attachment, so a
removed signing key cannot leave an obsolete signature behind.

Release notes come from the squashed commits between tags. Pull request titles
therefore follow Conventional Commits and their descriptions carry any
`BREAKING CHANGE:` instruction; `commit-lint.py --pull-request` checks the exact
message GitHub will create before merge.

## After

Check the release page: the note reads as intended, the three assets are there,
and the install line in the note points at the file that is actually attached.

Then install it once on a real OPNsense if anything touched the login path —
`tests/` deliberately covers none of what only exists inside OPNsense, and
`openid-connect-watch --status` on that machine is the quickest way to see the
login page is still whole.

## If a release came out wrong

Delete the tag, fix the commits, tag again. The workflow is written to be
repeatable for exactly this. What cannot be undone is a release somebody has
already installed — so a version that was wrong gets a new number, never a
quietly replaced file.
