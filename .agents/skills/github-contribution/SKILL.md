---
name: github-contribution
description: >-
  Prepare or publish an issue, pull request, review, or comment for opnsense-openid-connect. Use before an agent
  writes publicly on GitHub in a contributor's name; do not use for read-only inspection.
---

# Contributing on GitHub

Keep the public conversation easy to scan. Be concise, friendly, factual and
focused on the work. Do not insult, threaten, use sarcasm at another person's
expense, or speculate about anybody's competence or motives.

Write in the language of the issue or pull request. Prefer English when opening
a contribution or when the existing conversation is mixed.

## Issues before pull requests

Reuse before creating. Before the first implementation write in every new task,
search open issues and pull requests for the same user-requested outcome. Reuse
the matching issue; if none exists, create a focused issue for the actual work,
never a placeholder merely to satisfy the issue-first rule. During one
continuous user task, update the current issue's title and body
and extend its active pull request when the added work can be understood,
reviewed, and accepted or rejected as one change.

Create another issue only when the work is independently decidable, needs a
separate security path, or would force more than one real decision into `To decide`.
If the current issue or pull request is becoming too broad, pause before
creating another one and ask the user once. Propose a concrete boundary and
recommend handling the separated work in a new session. Do not ask repeatedly
after the user has decided the boundary.

When an approved split produces thematically related issues, prefer GitHub's
native sub-issue relationship over another top-level issue. The parent must
truthfully describe the shared outcome, and every child must remain independently
decidable. Link an existing suitable issue as a child instead of creating a new
one merely to build a hierarchy. Never create a placeholder parent or a
sub-issue solely because the work happened in the same session.

Managing sub-issues requires repository triage permission. When the publishing
account lacks it, identify the intended parent as `Sub-issue of #N` under
`Where`; this is a suggestion for a maintainer to apply, not a reason for an
extra comment. A separate top-level issue remains valid when there is no honest
parent-child relationship, but it is not the first choice for a coherent split.

An agent-authored pull request must close one same-repository issue that already
exists before the pull request is opened. Create the issue first only when no
suitable one exists. Use the Bug or Change form and retain these headings in
order: `TL;DR`, `Where`, `Now`, `Want`, `To decide`. Keep implementation detail
out; `To decide` names one decision and recommends a direction at a high level.

Keep counted issue prose to 175 words. The issue workflow helps with structure
and length but does not close an issue or grant permission to start work.

## Claiming active work

Before starting, inspect the issue's assignees, Development links, and recent
comments and `wip:*` labels. Coordinate instead of creating a second claim when
somebody is already working on it. Claim work only when implementation begins
now, not when it is merely planned for later. The write guard requires a local
record of the public claim before it permits source, build or Git mutations.

Run `python3 .agents/issues.py claim N`. It requires label-management permission
and first creates a fixed per-issue label definition through GitHub's atomic
create operation. Only its owner proceeds to assign the publishing account,
create the visible temporary `wip:<epoch>-<random>` issue label, and publish the comment.
This serializes claimants across clones even when one pauses mid-operation. An
agent without that permission coordinates with a maintainer instead of starting
unguarded work. Add `--language de` when the issue conversation is German. The
hidden marker uses the same dynamic identifier:

    <!-- contribution-work-claim:<epoch>-<random> -->

The helper includes the issue-language work note and required authorship notice,
then re-reads the issue under the atomic lock. A claimant that cannot acquire
the fixed definition stops before it publishes anything.

As soon as a pull request with `Fixes #N` is linked, run
`python3 .agents/issues.py linked PR`. It deletes only this task's comment,
removes its issue label, deletes both now-unused repository label definitions and
retains a local state bound to the pull-request branch and linked head ancestry.
Never delete another author's marker. The pull request and bound branch are the
exclusive work signal from then on;
do not put the WIP label on the pull request. If work stops before a pull request
exists, run `python3 .agents/issues.py release` to remove the comment, label,
label definition and, when permitted, self-assignment. Inspect and deliberately
hand over an apparently stale timestamped claim; never steal it automatically.

When the user explicitly asks to continue an existing pull request in its own
branch, use `python3 .agents/issues.py adopt-pr PR`. Do not use adoption to evade
the issue search or to join another task's active pull request.

## Pull requests

### Execution context and parallel local work

Treat the primary local checkout as read-only for agents. Pure inspection needs
no branch or extra worktree. Any implementation, build or test that may write
uses a dedicated worktree. A Codex-managed worktree may remain detached until
its work needs a commit or pull request; a manual Codex, Claude or CLI worktree
starts with its own topic branch. A cloud session already has an isolated
checkout and does not create another worktree merely to satisfy this rule.

Parallel subagents are read-only and their delegated prompt begins with
`[read-only]`. Run parallel implementations as separate top-level tasks in
separate worktrees. When several agents support one pull request, exactly one
agent owns its publishing branch; the others hand over findings, focused
commits or patches for that agent to integrate. For a manual local task use:

    python3 .agents/worktrees.py create task-slug --client codex
    python3 .agents/worktrees.py list

The startup hook compares the `origin` fetch URL with the canonical repository.
For a direct clone, it treats `origin/main` as the source of truth and adds no
remote. For a GitHub fork, `origin` remains the writable publishing remote and
the hook creates `upstream` for the canonical repository with pushing disabled;
`upstream/main` is then the source of truth. It refuses to overwrite an existing
`upstream` that points elsewhere. Resolve that name conflict deliberately.

The hook serializes fetches across worktrees, refreshes the canonical base and
the publishing remote at session start, at most every five minutes before a
write, at turn stop, and unconditionally before publication. It fast-forwards
clean local `main` only. It never changes an agent's topic branch or pushes
canonical main to a fork. GitHub's Sync fork button is not required. Start new
work from the reported canonical ref, not from a possibly stale fork `main`.
Freshness is an observation obligation, not an immediate synchronization
obligation. Commit count, branch distance and elapsed time are informational.
Canonical overlap blocks another write only until the agent integrates it or
starts a protected continuity phase:

    python3 .agents/hooks/fast_gate.py defer-main \
        --reason "why interruption is materially costly" \
        --checkpoint "the earliest observable safe checkpoint"

Use this for a stateful or expensive operation whose interruption would discard
setup, evidence or coherent progress. The observer continues to accumulate any
number of later canonical heads without requiring another acknowledgement. The
operation and its evidence remain pinned to their source revision. At the named
checkpoint run `python3 .agents/hooks/fast_gate.py checkpoint-main`, review all
accumulated drift once and integrate only what affects the next phase. Close the
phase before any push, PR update, review request or handoff.

Once a branch has a pull request, its integrating agent remains steward until
merge, closure or explicit handoff. Observation is bound to repository and PR
number, not a commit SHA. A snapshot reads the current head, submitted reviews
including `COMMENTED`, review threads, checks and merge state, then verifies the
head and open state again; discard and retry a mixed-head result, and report a
terminal transition immediately. Old-head reviews do not satisfy the current-head
gate, but every unresolved old thread still needs disposition.
A remote head for that PR that is not contained locally remains an immediate
block until reconciled.

Wait for a review submission to finish, inventory every thread and address one
coherent batch. Synchronize relevant canonical drift at that same checkpoint,
validate and push once, then request one current-head review. `behind` is not a
conflict. Do not change a head under active review merely to chase `main`; record
a confirmed conflict and restore mergeability before initial review, after the
review batch or at finalization.

Claude Code cloud identifies itself with `CLAUDE_CODE_REMOTE=true`. In Codex
cloud, set the repository-defined `AGENT_EXECUTION=codex-cloud` in the cloud
environment. GitHub Copilot cloud exposes a scoped `GITHUB_COPILOT_GIT_TOKEN`;
its `.github/hooks/` adapter sets `AGENT_EXECUTION=copilot-cloud` while calling
the same shared hook implementation. The shared hook also recognizes the
behavior that matters without a vendor marker: a checkout without `origin` is
an isolated snapshot, not a direct canonical clone. Do not fabricate a remote,
install a personal token, or describe a snapshot-only commit as pushed.

Cloud sessions start from the existing pull request's current head branch when
the task is a pull-request update. Use the platform's existing-PR update action
or authenticated Git proxy when available. If the platform exposes neither a
writable branch nor an update action, run the tests, create a focused commit,
and hand its hash plus a patch to the integrating agent. Never create a second
issue, branch, or pull request merely to escape that limitation.

Immediately before a push, pull request update, or review handoff, require a
fresh remote view:

    python3 .agents/hooks/fast_gate.py refresh

In a remote-less snapshot this command reports that freshness cannot be
verified instead of pretending that `main` is current. That report changes the
handoff path above; it is not permission to hide the limitation.

Rebase an unpublished private branch onto the reported `origin/main` or
`upstream/main`. Do not routinely rewrite a published branch; merge the
canonical ref only when its changes are relevant or GitHub requires an
up-to-date branch. Either operation changes the head and invalidates an earlier
review.

When no local action remains and CI, review, approval or merge is pending, retain
a read-only monitor until an actionable event or terminal PR state. Its single
observation command is:

    python3 .agents/hooks/fast_gate.py watch

Use the platform's recurring monitor or wait facility around that observation;
do not invent a repository scheduler. Report only changed state or concrete
action needed. The monitor never writes code, comments, pushes, requests review
or merges. A submitted review, new thread, CI failure, confirmed conflict,
foreign head, coordination predecessor transition, approval, merge or closure
ends pure waiting and returns the PR to its steward. If the platform cannot
retain a monitor, hand off the PR number and exact pending conditions; waiting
work is not complete.

### Coordinating overlapping pull requests

Observe exact changed-path overlap, shared interfaces and semantic dependencies
with other open PRs. At the next safe opportunity, turn a material overlap into
one final recommendation mirrored in every involved PR:

    python3 .agents/pr-coordination.py recommend \
        --prs 42 57 --order 42 57 \
        --overlap "the concrete shared paths or contract" \
        --reason "why this exact order minimizes repeated work" \
        --reconsider "the concrete condition that invalidates the order"

Read the complete `github-contribution` skill before that public write. The
helper supplies the machine marker, concise human explanation and authorship
notice. It publishes one total order, never alternatives: prerequisite first,
then the current-head reviewed or more merge-ready PR, then least total rework,
then lower PR number as a deterministic tie-breaker. A replacement names every
record it supersedes and is mirrored to every PR in both the new and superseded
sets. The machine marker retains that complete target set so a retry or later
fulfillment also reads and updates old-only or already closed PRs. The helper
requires every active record sharing a participant to be superseded by one order
covering every open PR in the complete transitive group. Closed or merged former
participants remain publication targets only. It refuses an order that would create a cycle and
accepts machine markers only from GitHub authors associated as owner, member or
collaborator. It prints the coordination identifier before its first public
write. If one mirrored write fails, rerun the same command with `--id ID`; the
helper verifies and skips matching copies instead of duplicating them. It writes
the current open PR set before old-only targets, and a retry recovers hidden
superseded IDs plus the complete target set from its already-published marker.
If that marker's first target has closed, publish a new remaining-open-PR order
with the partial ID in `--supersedes`. The ID directs the helper to read the
closed PR and mirror the successor there, so reopening cannot revive it.
Fulfillment also derives the original PRs from its ID and uses consistent
fulfilled copies as recovery metadata, allowing it to complete an old-only
target after every original PR has closed or already received fulfillment.
Recommendation and fulfillment each acquire one atomic repository-label mutex
before reading the remote coordination snapshot and retain it through all
mirrored comments. A competing publisher stands down until release. If a failed
process leaves the label behind, inspect its owner and remove it deliberately;
never steal it automatically. If ownership cannot be read during release,
preserve the publication failure and report the retained lock for inspection.
Recommendation and fulfillment are public mutations: the guard requires a topic
branch as well as an uncached remote observation before either command runs.

The recommendation is active immediately and controls merge order, not current
execution. The later steward may finish a coherent or protected phase, but does
not merge first or repeatedly chase anticipated conflicts. After its predecessor
merges, it integrates the predecessor once at its next checkpoint, validates and
obtains any newly required current-head review. Every steward must inspect and
obey a mirrored record on its PR. A predecessor closing without merge invalidates
the sequence immediately, regardless of other open predecessors. Mark a completed sequence with
`.agents/pr-coordination.py fulfill --id ID`.

The public recommendation tells the human exactly what to merge first and what
must follow. It never grants merge authority. No agent merges, enables
auto-merge or enters a merge queue without an explicit human instruction naming
the PR. Monitoring, review, repair, coordination and a request to make the PR
ready do not imply permission to merge.

### Worktree retirement

Treat cleanup as a separate, event-driven lifecycle; never add a scheduler.
SessionEnd retains dirty work and work waiting on an open pull request. It
queues a clean finished worktree because a task must not try to remove its own
current directory. A later SessionStart may remove at most one registered
candidate after a 24-hour grace period. Audit or operate the queue with:

    python3 .agents/worktrees.py audit
    python3 .agents/worktrees.py retire task-slug
    python3 .agents/worktrees.py sweep

Deletion is blocked by a live lease, tracked, untracked or ignored files, an
open pull request, a closed unmerged pull request, a foreign head or unknown
GitHub state. Worktree removal retains its local branch. Delete that branch only
after a seven-day grace period and proof that canonical `main` contains it or
that it is the exact head of a merged pull request. Never delete a remote branch.
End every handoff with one cleanup status: completed, queued, or retained with
the exact reason.

### Publishing

Resolve the publishing path before pushing. Query the upstream repository's
viewer permission with `gh` locally or with the cloud platform's GitHub tools.
With write access, push a topic branch there.
Without write access, reuse or create a personal fork and push the branch to
that writable head. In either case, open the pull request against
`jpawlowski/opnsense-openid-connect:main`.
For a cross-repository head, identify it as `<fork-owner>:<branch>`.
Push only the topic branch to `origin`; keeping the fork's own `main` synchronized
is optional and is not part of the contribution procedure.

    gh repo view jpawlowski/opnsense-openid-connect \
        --json viewerPermission --jq .viewerPermission

Do not install or inject a personal access token solely to make that command
work in a cloud sandbox. A cloud Git proxy or connector is the publishing
authority; without one, use the commit-and-patch handoff instead.

The title is the squash commit and a release-note entry. Choose it before
opening the pull request:

    type(scope)!: lower-case description without a full stop

It is at most 100 characters. The scope and `!` are optional; the allowed types
are `feat`, `fix`, `perf`, `refactor`, `docs`, `build`, `ci`, `test`, `chore`,
`style`, and `revert`. A breaking change uses both `!` and a concrete
`BREAKING CHANGE:` instruction saying what an operator must do.

Put exactly `Fixes #N` under `Issue`. Do not repeat the issue's problem. Describe
the change under `Change`, how it resolves the issue under `Resolution`, actual
checks under `Validation`, and any operator action under `Upgrade impact`. Keep
counted pull-request prose to 125 words. The closing reference creates the
Development link even from a fork; do not depend on the write-only manual
Development picker.

Under `Area`, use `Same as issue` only after confirming that the implementation
belongs to the issue's one or two `area:*` labels. Otherwise list the actual
areas explicitly. Issue `type:*` labels describe requests and never belong on a
pull request. Automation derives exactly one `change:*` label from the title:
`feat` is `feature`, `fix` is `fix`, `perf` is `performance`, `docs` is `docs`,
and every other allowed type is `maintenance`. A `!` also adds
`impact: breaking`. Verify the resulting labels after publication.

Before publishing, save the proposed body and validate the exact title and body:

    python3 packaging/contribution-lint.py \
        --title "type(scope): lower-case description" \
        --body-file /path/to/pr-body.md \
        --repository jpawlowski/opnsense-openid-connect

Do not open the pull request until this passes. A title or body edit triggers
the required check again after publication. A first-time fork contribution may
wait for a maintainer to approve its workflow; treat that as pending review,
not as a reason to recreate the pull request.

## Review before merge

Keep an agent-authored pull request in draft until its intended change and
validation are complete. Before merging, wait for Codex to review the current
head commit; compare the reviewed commit shown by Codex with the pull request's
current head. A review of an older head does not count.

Every P0 and P1 finding blocks the merge until it is fixed or technically
rebutted in its review thread. Independently reproduce each P2: it blocks only
when it affects security, recoverability, worktree or issue ownership, remote
or pull-request freshness, publication correctness, or cleanup safety. Answer
and track every other P2 and every P3. Do not dismiss or silently resolve a
finding: document its disposition in the thread, then resolve it. The ruleset's
required thread resolution is the hard backstop, but it does not replace
waiting for a late review or checking the reviewed commit.

The integrating agent that owns the publishing branch owns every review thread
through completion; the reviewing agent does not. After each review:

1. Inventory every unresolved thread, including outdated threads from earlier
   heads.
2. Fix the finding, technically rebut it, or track it when the P2/P3 rule permits.
3. Push the change and run the relevant validation before claiming it is fixed.
4. Reply in the thread with the disposition and, when applicable, the commit
   and validation that demonstrate it.
5. Resolve the thread once that disposition is complete. Never leave this
   cleanup for the reviewer or silently resolve an unaddressed finding.

Only after all existing threads have a disposition, all addressed threads are
resolved, and no blocking finding remains unaddressed may the integrating agent
request exactly one new review for the current head. A new Codex review is a
separate snapshot; it does not update or close an earlier review's threads.
Once that current-head review has no blocking finding, stop: do not request
another review merely to obtain zero suggestions.

## Agent notice

Every issue, pull request, review, or comment written by an agent in a person's
name ends with exactly one matching italic notice as its own final paragraph:

*An AI agent wrote this text on my behalf; I am responsible for its content.*

*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*

Use only the notice matching the contribution's language. The notice discloses
authorship; the person publishing remains responsible for the content.
