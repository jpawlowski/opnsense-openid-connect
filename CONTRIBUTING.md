# Working on this

    ./tests/run.sh

Syntax for every language in the tree, the behaviour checks, what a commit
message may be, and checks on the package that gets built. No Composer, no
PHPUnit, no network, no OPNsense. See [`tests/README.md`](tests/README.md).

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

The primary local checkout is read-only for agents. Pure inspection needs no
extra worktree; every implementation, build or test that may write uses a
dedicated worktree. Codex-managed worktrees may remain detached until a branch
is needed, while manually created Codex, Claude and CLI worktrees start with a
topic branch. Parallel subagents are read-only; parallel implementations use
separate top-level tasks and worktrees. Cloud sessions already run in isolated
checkouts and do not add another worktree. Claude Code cloud exposes
`CLAUDE_CODE_REMOTE=true`; Codex cloud uses the repository-defined
`AGENT_EXECUTION=codex-cloud`, and GitHub Copilot coding agent is recognized
from its scoped `GITHUB_COPILOT_GIT_TOKEN` by the adapter under `.github/hooks/`.
Regardless of vendor, a checkout without `origin` is treated as an isolated
snapshot: it can test and create a handoff commit, but cannot claim remote
freshness or a successful push. Do not place a personal access token in a cloud
setup script. Use the platform's existing pull request update facility, or hand
a commit and patch to the agent that owns the pull-request branch. Do not open
a replacement pull request for the same work.

Agent hooks refresh the canonical branch throughout active work and report
path overlap with new `main` commits or other open pull requests. They also
observe a published pull request by number, verify one coherent current-head
snapshot, and include checks, submitted reviews, threads and merge state. They
never merge or rebase automatically. A foreign remote head must be reconciled
before another write or publication, and a changed head needs a new review.

Freshness does not require live synchronization. An agent may protect a costly
or stateful operation until a named safe checkpoint while any number of `main`
commits accumulate visibly. It then assesses the complete drift once. Branch
lag alone is not a conflict, and a conflict found during review waits for the
next review or finalization checkpoint rather than invalidating the running
review immediately. A read-only monitor retains the PR number until review,
failure, conflict, merge, closure or another actionable transition; it never
comments, pushes, requests review or merges.

Material overlap between open PRs gets one machine-readable recommendation
mirrored in each PR. It gives the human one exact merge order, never
alternatives. The later PR may keep working but does not merge first or chase
the earlier PR's changing head; after its predecessor merges, it integrates
once at a safe checkpoint. A replacement is also mirrored to PRs present only
in the superseded order, preventing them from retaining obsolete coordination.
Its marker retains that complete target set for retry and fulfillment even when
one of those PRs closes. Active orders sharing any participant form one
transitive group and must be replaced by a single order covering all of its open
PRs; former participants remain mirroring targets but never re-enter the order.
A predecessor closing unmerged invalidates that order immediately. Only
repository-associated publishers are trusted;
an interrupted mirroring resumes under its printed identifier without duplicate
comments. Recommendation and fulfillment hold an atomic repository mutex across
their remote snapshot and all mirrored writes; a concurrent publisher waits, and
a lock left by a failed process is inspected rather than stolen. No agent merges, enables auto-merge or queues a
merge without an explicit human instruction naming that PR. Review,
coordination and making a PR ready do not imply merge permission.

Agent worktrees have an event-driven cleanup queue rather than a background
scheduler. SessionEnd retains dirty work and open pull requests, while a clean
finished worktree becomes eligible after a 24-hour grace period. A later
session removes only
a registered worktree with no lease, tracked, untracked or ignored files, open
or closed-unmerged pull request, foreign head or unknown GitHub state. The local
branch remains for a seven-day grace period and is deleted only when canonical
`main`
contains it or GitHub confirms that its exact head was merged. Remote branches
are never deleted by this cleanup. `python3 .agents/worktrees.py audit` explains
every retained or removable item before `retire` or `sweep` is used.

Before opening a pull request, an agent validates the exact proposed title and
body locally:

    python3 packaging/contribution-lint.py \
        --title "fix(auth): keep local login available" \
        --body-file /path/to/pr-body.md \
        --repository jpawlowski/opnsense-openid-connect

Keep the pull request in draft while it is changing. Before merge, wait for
Codex to review the current head commit, not an earlier revision. P0, P1 and P2
do not have one blanket disposition: P0 and P1 always block until fixed or
technically rebutted. A P2 blocks when independently reproduced in a
security-, recoverability-, ownership-, freshness-, publication-, or
cleanup-critical path; other P2 and all P3 findings are answered and tracked.
The pull request's author or integrating agent owns every review thread through
completion: document its disposition and resolve it when addressed before
requesting another review. Once the current head has no blocking finding, do
not repeat reviews merely to obtain zero suggestions. The required-thread rule
prevents unresolved findings from merging, while this wait prevents a late
Codex review from arriving only after merge.

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
