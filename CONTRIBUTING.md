# Working on this

    ./tests/run.sh

For changes limited to agent instructions, contribution policy, agent hooks and
their focused tests, use this smaller gate instead:

    ./.agents/check-control-plane.sh

Syntax for every language in the tree, the behaviour checks, what a commit
message may be, and checks on the package that gets built. No Composer, no
PHPUnit, no network, no OPNsense. See [`tests/README.md`](tests/README.md).
Do not run the full product gate for a control-plane-only diff. The focused gate
still validates syntax, contribution policy and hook behavior. Any product
source, packaging/runtime logic or unclassified path keeps the full gate.

## Pull requests

GitHub is the source of truth; the Forgejo repository is a read-only code
mirror and accepts no contributions. With write access, push a topic branch to
this repository. Without write access, push it to a personal fork and open the
pull request against `jpawlowski/opnsense-openid-connect:main`. Both paths use a
branch, and every pull request targets `main`.

Pull requests are squash-merged, so their title and description become the one
commit that reaches `main`. Give the title the Conventional Commit shape below,
at most 100 characters. The description does not restate the problem: put that
in an issue, then describe the change and how it resolves that issue. An
agent-authored pull request must close exactly one same-repository issue which
was opened first with `Fixes #N`. A human-authored pull request without a
preceding issue may use `None` instead. `Fixes #N` creates the Development link
for every pull-request author, including authors working from forks; the manual
Development picker is only a convenience for maintainers with write access.

Use the template sections, check an actual validation or say `Not run: <reason>`,
and keep the pull-request body to at most 125 counted prose words. When
applicable, put the exact `BREAKING CHANGE:` operator instruction under upgrade
impact. Intermediate branch commits may be ordinary work in progress; the
pipeline judges the future squash commit shown by the pull request. A title or
description edit triggers that check again.

When important supporting context does not fit, use the maintained detail
comment described below. Keep the pull-request body self-contained: its change,
resolution, actual validation and upgrade impact still belong in the template
sections.

The `Area` section is a visible label request. Use `Same as issue` only when the
implementation belongs to the linked issue's areas; otherwise list one or two
exact `area:*` labels. This lets a fork contributor classify the implementation
without label permission.

GitHub may hold the workflow of a first-time fork contributor for maintainer
approval. That is an expected security review, not a failed check; do not close
and recreate the pull request while it waits.

For a fork clone, keep `origin` as the writable fork and use the canonical
repository as a read-only `upstream`. Agent startup recognizes the fork from
the `origin` fetch URL, creates that `upstream` with pushing disabled, and uses
`upstream/main` as the base. A direct canonical clone needs no extra remote and
uses `origin/main`. An existing `upstream` with another destination is never
overwritten. GitHub's Sync fork button and a current fork `main` are optional:
create and push the topic branch through `origin`, but derive and refresh it
from the canonical ref.

### If an agent does the work

Most changes here are written by an agent, and the rules it follows are longer
than the ones above: worktrees and writer leases, an exclusive issue claim,
canonical-base freshness, stewardship of an open pull request, the review cycle
and its severities, merge order between overlapping pull requests, and what a
cloud checkout without a remote may claim to have done.

Those rules live in [`AGENTS.md`](AGENTS.md) and, for everything that becomes
public on GitHub, in the `github-contribution` skill under `.agents/skills/`.
They are deliberately not repeated here. This file and `AGENTS.md` used to
restate the same procedure, and three copies that were each only checked for
containing the right keywords drifted apart without any test noticing.

What matters when you review one of these pull requests is the visible part. An
agent-authored pull request stays draft while it is implemented, validated and
reviewed. It becomes ready for review only once it is finished, green, mergeable
and every review thread has an answer — that transition is the handoff to you.
No agent merges anything, enables auto-merge or queues a merge without an
explicit instruction naming that pull request.

Before opening a pull request an agent validates the exact proposed title and
body locally, and you can run the same check yourself:

    python3 packaging/contribution-lint.py \
        --title "fix(auth): keep local login available" \
        --body-file /path/to/pr-body.md \
        --repository jpawlowski/opnsense-openid-connect

## Issues and public conversation

Every implementation starts with a visible issue before its first source write.
Search open issues and pull requests first. Extend an existing open issue and its
active pull request when follow-up work belongs to the same continuous request,
serves the same outcome, and can be reviewed and accepted or rejected together.
Update the issue title and body when its coherent scope grows. A shared area
alone is not enough; create a separate issue when the work is independently
decidable, needs a separate security path, or requires another real decision.
When no suitable issue exists, create one for the actual requested outcome;
never create a placeholder merely to satisfy the issue-first rule. Ask the user
before splitting an ambiguous continuous request.

When work begins now rather than at some later date, first check assignees,
Development links, recent comments and temporary `wip:*` labels. The repository
helper requires label-management permission, atomically creates one fixed
per-issue lock definition, assigns the publishing account, creates a unique
`wip:<epoch>-<random>` label on the issue, and leaves a matching hidden-marker
comment. The fixed definition serializes cross-clone claimants even when one is
paused mid-operation; a contributor without that permission coordinates with a
maintainer instead of starting an unguarded agent implementation.

Use `python3 .agents/issues.py claim N` before implementation. Delete only that
task's own temporary comment, issue label and both label definitions as soon as the
pull request appears through `Fixes #N`, using
`python3 .agents/issues.py linked PR`. The pull request and its head branch then
become the work signal; do not copy a WIP label to the pull request. If work
stops first, use `python3 .agents/issues.py release`, which also removes the
self-assignment when permitted. Never delete another task's claim. A timestamped
claim that appears abandoned is inspected and handed over deliberately, never
silently stolen.

Bug and Change forms ask for `TL;DR`, `Where`, `Now`, `Want`, and `To decide`.
Keep the complete issue to at most 175 counted prose words. The last field names
one decision and suggests a direction at a high level; implementation detail
belongs in the eventual change. Suspected vulnerabilities go through a private
security advisory, never a public issue.

### Maintained detail comments

The issue and pull-request word limits apply to their main bodies. When a
focused contribution has important supporting context that cannot fit there,
publish one supplemental comment beginning with `## Details`. Link it from the
most relevant main-body field or section as
`Details: [maintained comment](permalink)`. Examples of suitable detail are a
longer rationale, evaluated alternatives, logs, examples, or a validation
matrix.

The main body remains the self-contained, scan-friendly overview. Do not move a
required decision, the pull request's change or resolution, actual validation,
upgrade action, unrelated scope, or a second issue into the detail comment.
The supplemental comment has no separate word limit, but keep it structured and
as concise as its subject permits.

Treat the main body and its detail comment as one maintained contribution.
Whenever facts, scope, decisions, implementation, validation, or upgrade impact
change, review both and edit the existing detail comment in place in the same
update. Remove stale contradictions instead of adding correction comments or a
replacement detail comment. Ordinary discussion continues in ordinary comments.

### Labels and triage

Issues and pull requests share a small vocabulary without mirroring one another.
Every issue has exactly one `type:*`: `bug`, `change`, `docs`, or `question`.
Every pull request instead has exactly one title-derived `change:*`: `feature`,
`fix`, `performance`, `docs`, or `maintenance`. A breaking title also carries
`impact: breaking`; issue `type:*` labels never belong on a pull request.

One or two `area:*` labels locate either item in `oidc`, `opnsense`, `ui`,
`packaging`, or `contribution`. Pull requests deliberately confirm the issue
areas or name their implementation areas; automation reconciles both paths,
including fork contributions. `accessibility` follows a linked issue when
relevant, but workflow labels such as `needs decision` are not copied.

`needs revision` belongs to the hygiene workflow. Maintainers use `needs decision`,
`needs reproduction`, or `blocked` only while that action is needed; `help wanted`
and `good first issue` are deliberate invitations. `accessibility` records an
impact, while `duplicate` and `not planned` record a reasoned close. There are no
priority or permanent agent-authorship labels. Temporary `wip:<epoch>-<random>`
labels expose exclusive issue locks; their dynamic definition and the fixed
per-issue mutex definition are deleted when released. They are never
classification labels or pull-request labels. Contributors
without triage access make their classification through the forms rather than
applying labels directly.

English and German are accepted; prefer English when in doubt. Replies follow
the language of the issue or pull request, and use English for a mixed-language
conversation. Be concise, friendly, factual and focused. Insults, threats,
sarcasm directed at another person, and speculation about competence or motives
are not acceptable; the complete community standard is in
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

Every issue, pull request, review or comment an agent writes in a person's name
ends with exactly one matching italic notice as its own final paragraph:

*An AI agent wrote this text on my behalf; I am responsible for its content.*

*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*

Code, commands, paths, URLs and link destinations, closing references such as
`Fixes #123`, template boilerplate, exact `None` values and those notices do not
count toward the prose limits. Visible custom link text and any additional prose
do count. Undisclosed agent use under a human account cannot be detected
reliably; the publisher remains responsible for it.

## Commit messages

The release note of a version is written out of the commits that version
contains, so a message is not only for whoever reads the history — it is the
text an operator reads before deciding to upgrade a firewall. Hence a shape:

    type(scope)!: what it does

    Why, in whatever length that takes.

    BREAKING CHANGE: what an installation has to do about it.

[Conventional Commits](https://www.conventionalcommits.org), with the types
`feat` `fix` `perf` `refactor` `docs` `build` `ci` `test` `chore` `style`
`revert`. The scope in brackets is optional and free-form — it is decoration
for a reader, not a vocabulary to memorise; `auth`, `oidc`, `api` and `watch`
are the ones in use.

**The `!` and the `BREAKING CHANGE:` footer mean the same thing**, and either
one puts an entry at the top of the release note under its own heading. On a
firewall that matters more than usual: this module decides who reaches the web
interface, and a change that turns a login which worked into one that does not
has to arrive with a sentence saying so. Mark it, and say in the footer what to
set — not that something changed, but what to do about it.

The subject is a sentence, lower case after the colon, no full stop. A pull
request title is at most 100 characters; ordinary commit bodies remain as long
as the change needs.

### Local commit setup

    git config commit.template "$(git rev-parse --show-toplevel)/.gitmessage"
    git config core.hooksPath packaging/hooks

A local Codex or Claude task applies both settings automatically when its host
supports repository hooks; other contributors run the commands once per clone.
Cloud agents still follow `AGENTS.md`, and Claude cloud also runs the shared
configuration through its repository settings. The agents read the same
tracked hook configuration and implementation under `.agents/`. The template
puts the expected shape and the available types into the commit editor; its
guidance consists only of comments and does not become part of the commit. The
hook refuses a message the release note could not read, before the commit
exists rather than after. Neither Git config nor hooks are part of what Git
clones, so the pipeline remains authoritative.

For parallel local agents, Git's ordinary repository configuration would be
shared between linked worktrees. The agent hook therefore enables
worktree-specific configuration and stores the absolute template path
separately for each tree.
It also serializes periodic fetches of the selected canonical ref, keeps local
`main` as a safe fast-forward mirror, and reports lag and overlap with work
already in progress. It never rebases, merges, or pushes an agent branch
automatically. Before publishing, an agent runs:

    python3 .agents/hooks/fast_gate.py refresh

When no remote exists, the command reports a snapshot handoff instead of a safe
`main` mirror. The cloud platform must update the existing pull request, or the
agent must provide its commit and patch to the integrating session.

For a pull request, the pipeline checks its title, description and linked issue
instead. On `main` and tag pushes it checks the commits that arrived, so the
protected branch cannot contain a message the release note cannot read.

    python3 packaging/commit-lint.py --range main..HEAD    # by hand, any time

Merges and the messages git writes itself (`fixup!`, `Revert "..."`) are left
alone.

### Seeing the note before tagging

    python3 packaging/release-notes.py --tag v1.2.3

Prints what the note for that tag would say. Worth a look before pushing the
tag: an empty section or an entry that reads badly is easier to fix while the
tag does not exist yet.

## Releasing

Tag the reviewed commit on GitHub. The version lives in the tag and nowhere
else, the pipeline builds the package, writes the note out of the commits and
attaches both — see
[`packaging/README.md`](packaging/README.md).

    git tag -a v1.2.3 -m "..." && git push --tags

## Where the rules are written down

[`AGENTS.md`](AGENTS.md) has the map of the tree, the commands, and the rules
that are not preferences — what may never change about a login, what is a
setting and what is not, and why a refusal says only one thing. It is written
for an agent working here, and reads as well for a person.

`.agents/skills/` holds the procedures worth following exactly rather than from
memory: making a public contribution, changing a setting or protocol behavior,
depending on something new in OPNsense core, and cutting a release. Each one is
a checklist of the places that go stale silently, which is most of the work.
`.claude/skills` points to the same directory so Claude and other agents use one
canonical copy.

## Protocol changes

The OpenID Connect implementation is intentionally small and lives under
`OPNsense/OpenIDConnect`. Add a behaviour test for every protocol decision and
run the real cryptographic fixtures on OPNsense before release. Cryptographic
primitives remain the responsibility of OPNsense's phpseclib runtime.
