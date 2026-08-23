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

Before opening a pull request, an agent validates the exact proposed title and
body locally:

    python3 packaging/contribution-lint.py \
        --title "fix(auth): keep local login available" \
        --body-file /path/to/pr-body.md \
        --repository jpawlowski/opnsense-openid-connect

Keep the pull request in draft while it is changing. Before merge, wait for
Codex to review the current head commit, not an earlier revision. P0, P1 and P2
findings block merge until fixed or technically rebutted in their thread; P3
findings are answered or tracked. Document the disposition before resolving a
thread. The required-thread rule prevents unresolved findings from merging,
while this wait prevents a late Codex review from arriving only after merge.

## Issues and public conversation

Search before opening another issue. Extend an existing open issue and its
active pull request when follow-up work belongs to the same continuous request,
serves the same outcome, and can be reviewed and accepted or rejected together.
Update the issue title and body when its coherent scope grows. A shared area
alone is not enough; create a separate issue when the work is independently
decidable, needs a separate security path, or requires another real decision.
An agent never creates an issue merely to satisfy the issue-first rule and asks
the user before splitting an ambiguous continuous request.

When work begins now rather than at some later date, first check assignees,
Development links, and recent comments. A contributor with write access assigns
their own account to the issue. Until a pull request is linked, the contributor
also leaves one short temporary comment saying that work has started; this is
the only signal available to a contributor without assignment permission. An
agent uses the issue's language and includes its authorship notice.

Delete only the contributor's own temporary work comment as soon as the pull
request appears through `Fixes #N`. Never delete another person's comment, even
if it copies the same marker or wording. If work stops before a pull request
exists, remove the contributor's own comment and self-assignment. When the pull request is
opened immediately, its Development link makes a temporary comment unnecessary.

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
priority or agent-authorship labels. Contributors without triage access make
their classification through the forms rather than applying labels directly.

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

A Codex or Claude task applies both settings automatically when it starts;
other contributors run the commands once per clone. Both agents read the same
tracked hook configuration and implementation under `.agents/`. The template
puts the expected shape and the available types into the commit editor; its
guidance consists only of comments and does not become part of the commit. The
hook refuses a message the release note could not read, before the commit
exists rather than after. Neither Git config nor hooks are part of what Git
clones, so the pipeline remains authoritative.

For parallel agents, Git's ordinary repository configuration would be shared
between linked worktrees. The agent hook therefore enables worktree-specific
configuration and stores the absolute template path separately for each tree.
It also serializes periodic fetches of the selected canonical ref, keeps local
`main` as a safe fast-forward mirror, and reports lag and overlap with work
already in progress. It never rebases, merges, or pushes an agent branch
automatically. Before publishing, an agent runs:

    python3 .agents/hooks/fast_gate.py refresh

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
