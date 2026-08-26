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

    python3 packaging/release-notes.py --tag vX.Y.Z
    gh api repos/jpawlowski/opnsense-openid-connect/immutable-releases

The publishing workflow is the authoritative gate for checks it already runs.
Do not repeat those commands locally merely because a release is being cut when
the revision and inputs are the same and no different result is expected; the
workflow refuses to publish when one fails. Before pushing the tag, wait for
successful required CI on its exact commit instead of rerunning the same checks
locally. Run a CI-covered check locally only to investigate a failure or when
the local environment provides distinct required evidence. This includes the
host-independent product gate and package build checks. It does not replace the
release-specific inspection below or any manual evidence that CI cannot
produce.

The release-notes command prints the note the tag *would* produce — read it as
an operator would. Things worth catching there:

- **Is everything that can lock somebody out at the top?** A default that
  changed, a field that became required, an account that stops being reachable.
  If one is missing, its commit lacks the `!` or the `BREAKING CHANGE:` footer,
  and the fix is to amend the commit, not to write prose into the release.
- **Does each breaking entry say what to set?** The footer is quoted verbatim.
  "Behaviour changed" helps nobody; "set *Match by e-mail address* to *Any
  address the provider reports*" does.
- **Does anything land under "Other"?** Then a message was not readable, which
  `commit-lint.py` should have refused.
- **Does the GitHub API say immutable releases are enabled?** Do not push a tag
  until it does. The workflow checks the published result too, but by then the
  release boundary has already been crossed. Once this attesting workflow is on
  the publishing branch, an administrator can enable the policy with
  `gh api --method PUT repos/jpawlowski/opnsense-openid-connect/immutable-releases`.

## The tag is the version

    git tag -a v1.2.3 -m "..." && git push --tags

`build.py` reads it and nothing else states it. A stable tag uses
`vMAJOR.MINOR.PATCH`. Future pre-releases use exactly one of these forms:

    v1.2.3-alpha.1
    v1.2.3-beta.1
    v1.2.3-rc.1

The readable SemVer tag becomes FreeBSD package version `1.2.3.a1`, `1.2.3.b1`
or `1.2.3.r1`. `pkg` sorts those before `1.2.3`, so the stable package remains
an upgrade from every pre-release. Number the first pre-release of each stage
with `1`; zero and leading zeroes are refused along with every other release-tag
suffix. The workflow marks an accepted suffixed tag as a GitHub pre-release.
Earlier immutable tags that used `v1.0.0-betaN` remain historical; never rename,
delete or reuse them. Their legacy package versions sort after `1.0.0`, so the
generated `v1.0.0` release note must retain its one-time `pkg add -f` migration
instruction. Installed paths and settings are unchanged; no later release needs
this exception.

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

A successful GitHub `main` push or manual run also keeps a **CI snapshot** for
14 days: the commit-versioned `.pkg` and its `.sha256`. Successful pull-request
runs keep clearly named, untrusted snapshots for 3 days so their exact result
can be tested manually. Each revision has a separate artifact; concurrency
cancels only an older run that is still in progress, while completed artifacts
expire normally.

A pull-request snapshot contains contributor-controlled code and carries no
release signature or attestation. Its artifact name and included notice must
say so. Tag runs use the separately attested release path instead. Forgejo runs
the shared checks but keeps no duplicate snapshot. A CI snapshot is for testing
only and is never promoted into a release.

The GitHub release attaches:

- the `.pkg`
- a `.sha256` beside it
- a `.sig`, when a `PKG_SIGNING_KEY` secret exists — without it the pipeline
  says so in its log and carries on
- a keyless Sigstore build-provenance attestation bound to the exact package,
  repository workflow and commit

The workflow creates an unpublished draft, uploads and checks its complete asset
set, then publishes exactly once. Repository release immutability locks the tag
and assets at that boundary and creates GitHub's separate release attestation.
A re-run may discard an incomplete draft, but it must refuse an already
published tag. A new package always gets a new version.

Release notes come from the squashed commits between tags. Pull request titles
therefore follow Conventional Commits and their descriptions carry any
`BREAKING CHANGE:` instruction; `contribution-lint.py --pull-request-event`
checks the exact message GitHub will create before merge.

## After

Check the release page: the note reads as intended, the expected assets are
there, GitHub labels the release immutable, and the install line points at the
file that is actually attached. Verify provenance once as a consumer would:

    gh attestation verify os-openid-connect-<version>.pkg \
      -R jpawlowski/opnsense-openid-connect \
      --signer-workflow jpawlowski/opnsense-openid-connect/.github/workflows/build.yml \
      --deny-self-hosted-runners

Do not install or functionally test the published package unless the human
explicitly requests that work. A request to cut or publish a release does not
authorize post-release package testing, including when the login path changed;
finish and report the release promptly after the publication checks above.

## If a release came out wrong

An unpublished draft may be deleted and the same run retried. Once published,
fix the commits and use a new version. Never delete and reuse a released tag:
GitHub intentionally locks it and the workflow intentionally refuses it.
