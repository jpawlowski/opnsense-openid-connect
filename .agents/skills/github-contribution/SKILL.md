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

Reuse before creating. Search open issues and pull requests for the same
user-requested outcome. Never open an issue merely to satisfy the issue-first
rule. During one continuous user task, update the current issue's title and body
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
comments. Coordinate instead of creating a second claim when somebody is
already working on it. Claim work only when implementation begins now, not when
it is merely planned for later.

With write access, assign the publishing account to the issue when work starts.
Without write access, do not attempt to change assignees. If no pull request is
linked yet, also leave one concise temporary comment in the issue's language:

    <!-- contribution-work-claim -->
    I am working on this now. This note will be removed when the pull request is linked.

An agent adds the required authorship notice as the final paragraph. Keep the
comment URL or ID. As soon as the pull request's `Fixes #N` link appears, delete
only that account's own marked comment; never delete another author's comment,
even when it contains the marker. If work stops before a pull request exists,
delete the claim and, when permitted, remove the self-assignment. A pull request
opened immediately needs no temporary comment because its Development link is
the work signal.

## Pull requests

### Execution context and parallel local work

Use one topic branch and one linked worktree per concurrent local agent session.
Never let two local agents write the same worktree or branch. A cloud session
already has an isolated checkout and does not create another worktree merely to
satisfy this rule. When several agents support one pull request, exactly one
agent owns its publishing branch; the others hand over focused commits or
patches for that agent to integrate.

The startup hook compares the `origin` fetch URL with the canonical repository.
For a direct clone, it treats `origin/main` as the source of truth and adds no
remote. For a GitHub fork, `origin` remains the writable publishing remote and
the hook creates `upstream` for the canonical repository with pushing disabled;
`upstream/main` is then the source of truth. It refuses to overwrite an existing
`upstream` that points elsewhere. Resolve that name conflict deliberately.

The hook serializes fetches across worktrees, refreshes the canonical base and
the publishing remote at most once per interval, and fast-forwards clean local
`main` only. It never changes an agent's topic branch or pushes canonical main
to a fork. GitHub's Sync fork button is not required. Start new work from the
reported canonical ref, not from a possibly stale fork `main`. If the hook
reports lag or overlapping paths, integrate deliberately before publishing.

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

Every P0, P1 and P2 finding blocks the merge until it is fixed or technically
rebutted in its review thread. Answer or track every P3 finding. Do not dismiss
or silently resolve a finding: document its disposition in the thread, then
resolve it. The ruleset's required thread resolution is the hard backstop, but
it does not replace waiting for a late review or checking the reviewed commit.

The integrating agent that owns the publishing branch owns every review thread
through completion; the reviewing agent does not. After each review:

1. Inventory every unresolved thread, including outdated threads from earlier
   heads.
2. Fix the finding, technically rebut it, or track it when the P3 rule permits.
3. Push the change and run the relevant validation before claiming it is fixed.
4. Reply in the thread with the disposition and, when applicable, the commit
   and validation that demonstrate it.
5. Resolve the thread once that disposition is complete. Never leave this
   cleanup for the reviewer or silently resolve an unaddressed finding.

Only after all existing threads have a disposition, all addressed threads are
resolved, and no P0, P1 or P2 remains unaddressed may the integrating agent
request exactly one new review for the current head. A new Codex review is a
separate snapshot; it does not update or close an earlier review's threads.

## Agent notice

Every issue, pull request, review, or comment written by an agent in a person's
name ends with exactly one matching italic notice as its own final paragraph:

*An AI agent wrote this text on my behalf; I am responsible for its content.*

*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*

Use only the notice matching the contribution's language. The notice discloses
authorship; the person publishing remains responsible for the content.
