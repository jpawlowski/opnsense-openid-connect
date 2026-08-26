# opnsense-openid-connect

OpenID Connect sign-in for the OPNsense web interface, as a FreeBSD package
that installs beside the core package and replaces nothing in it. PHP for what
runs on the firewall, Python for what builds and checks it, shell for the
watchdog. No Composer, no PHPUnit, no framework beyond what OPNsense itself
ships.

**This module decides who reaches a firewall's web interface.** Almost every
rule below follows from that one sentence.

## Where things are

| | |
|---|---|
| `src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php` | the connector: the settings surface, and which local account a set of claims is |
| `src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/` | the focused protocol implementation: bounded HTTPS, discovery, JWT verification, transactions and session logout |
| `src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/` | the HTTP endpoints: the browser's side of a login, and the discovery probe |
| `src/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/` | what the login page is handed |
| `packaging/` | the build, the commit convention, the release note and the watchdog |
| `tests/` | everything `./tests/run.sh` runs |
| `docs/` | one page per identity provider, plus what every provider has to offer |

Nothing here shares a name, a file path, an API route or an authentication
server type with any other OpenID Connect module for OPNsense: the type is
`openidconnect`, the module namespace is `OPNsense\OpenIDConnect`, the endpoints
live under `/api/openidconnect/`, and every field in `config.xml` carries the
`openidconnect_` prefix. Two packages cannot own the same file, so that
separation is not decoration — keep it.

## Commands

    ./tests/run.sh                                    fast host-independent product gate; CI
    ./.agents/check-control-plane.sh                  focused agent-policy and automation gate
    python3 tests/update-security-report.py --update regenerate the unified security and conformance report
    php tests/run.php                                 the behaviour checks alone
    python3 packaging/build.py --check                does it still build
    python3 packaging/release-notes.py --tag vX.Y.Z   what a release would say
    python3 packaging/commit-lint.py --range main..HEAD
    python3 .agents/hooks/fast_gate.py refresh        refresh remote main before publishing
    python3 .agents/hooks/fast_gate.py defer-main --reason WHY --checkpoint WHEN
    python3 .agents/hooks/fast_gate.py checkpoint-main
    python3 .agents/hooks/fast_gate.py reconcile-pr --sha SHA --strategy merge
    python3 .agents/pr-coordination.py status --pr PR
    python3 .agents/review-requests.py request --pr PR
    python3 .agents/review-requests.py cleanup --pr PR
    python3 packaging/contribution-lint.py --help     what an issue or PR may contain
    python3 .agents/test-impact.py                    explain the minimum manual validation for this diff

Installed integration and destructive browser E2E are deliberate manual runs;
they never belong in an automatic agent Stop hook. See `tests/README.md`.

When the complete diff changes only agent instructions, contribution policy,
agent hooks or their focused tests, run `./.agents/check-control-plane.sh` and
do not run `./tests/run.sh`. The Stop hook makes the same selection. The full
host-independent gate is required when any product source, packaging/runtime
logic or other unclassified path changes. A control-plane change still runs its
own syntax, contribution and hook tests; "no full product suite" never means
"no validation".

Before finalizing a validation plan, run the read-only test-impact helper and
then check its path-based recommendation against the semantic boundary actually
changed. Keycloak `local/direct` is the canonical browser/session gate;
authentik is additional only for its claim, Blueprint or logout behavior.
Provider-profile changes for Entra, Okta or Apple use that provider's
`emulated/direct` run, while behavior absent from the emulator needs an explicit
`live` run. Public provider-to-firewall callbacks use `public-inbound`; ordinary
browser redirects remain `direct`. The helper never starts a test.

An agent-owned issue's maintained `## Details` comment records a `Validation
plan` before implementation: boundary, tier, provider/source/cluster, why the
lower tier is insufficient, and whether tunnel, live credentials or browser
handoff is required. Scope acceptance authorizes announced repeats of that
plan. A later scope change that raises the tier requires one updated plan and
new approval. Required manual evidence cannot be silently made optional; an
unavailable environment leaves the technical gate open and the pull request
draft. Pull-request validation names exact runs and gives a concrete `Not run`
reason for optional breadth.

There is no linter beyond `php -l`; keep to 120 columns and to the style of the
file being edited.

## Parallel agent work

The primary local checkout is an agent read-only control surface. Pure searches
and inspection need neither a branch nor another worktree. Any implementation,
build or test that may write files uses a dedicated worktree. A Codex-managed
worktree may remain detached until its work needs a commit or pull request; a
manual Codex, Claude or CLI worktree starts with its own topic branch. Cloud
sessions already have an isolated checkout and must not add another worktree
merely to satisfy this rule.

Parallel subagents are read-only and mark their delegated prompt with
`[read-only]`. Parallel writing happens in separate top-level tasks and
worktrees. One integrating agent owns a pull-request branch; supporting agents
hand over findings, commits or patches instead of editing or pushing that
branch. The shared PreToolUse hook enforces the control checkout, one writer
lease per worktree and the read-only subagent marker. For a manual worktree use:

    python3 .agents/worktrees.py create task-slug --client codex
    python3 .agents/worktrees.py list
    python3 .agents/worktrees.py audit

Before the first implementation write in a new task, search open issues and
pull requests for the requested outcome. Reuse its issue, or create a focused
issue when none exists, then acquire its exclusive public work claim:

    python3 .agents/issues.py claim 123

The claim first acquires a fixed per-issue label definition as an atomic
cross-clone mutex, then publishes one temporary `wip:<epoch>-<random>` issue
label and a matching machine-readable comment. A racing agent must stand down.
When `Fixes #123` links the pull request, run
`python3 .agents/issues.py linked 456`; this removes the comment and both label
definitions. The pull request, branch and linked head ancestry then carry
ownership, so no WIP label belongs on the pull request. Run
`python3 .agents/issues.py release` when work stops before a pull request. Use
`adopt-pr` only when the user explicitly asks to continue an existing pull
request. The guard blocks implementation writes without one of these verified
states.

The shared startup hook identifies the canonical base from the `origin` fetch
URL. A direct clone uses `origin/main`; a GitHub fork keeps `origin` for
publishing and gains a push-disabled `upstream`, then uses `upstream/main`.
In the read-only control checkout, prefix Git inspection with
`GIT_OPTIONAL_LOCKS=0`; otherwise Git may refresh its index while reporting.
It serializes fetches, keeps clean local `main` as a fast-forward mirror, and
checks the canonical ref at session start, at most every five minutes before a
write, at turn stop, and unconditionally before publication. It reports lag and
path overlap without changing the topic branch. Freshness is an observation
obligation, not an immediate synchronization obligation. Commit count, branch
distance and elapsed time are informational only; none requires an in-progress
operation to restart.

When interruption would discard expensive setup, transient state or useful
evidence, start a continuity deferral with the command above. Give the concrete
reason and the earliest observable checkpoint at which work becomes cheaply
resumable. Any number of canonical commits and local path changes may accumulate
while the hook keeps observing them as one pending drift set. Finish the protected
operation against its pinned source revision and label its evidence with that
revision. Interrupt only for a concrete safety, destructive-action, exclusive-
ownership or revision-identification risk; possible future conflict is not one.
At the safe checkpoint, run `checkpoint-main`, compare the complete drift once and
integrate only what invalidates the next phase or its evidence. Before every push,
pull-request update, review request or handoff the deferral must be closed and the
explicit refresh command above must run. Never push an automatic `main`
synchronization to a contributor fork.

The integrating agent remains steward of every pull request it creates or adopts
until merge, closure or explicit handoff. The read-only observer identifies it by
repository and pull-request number, never by a commit SHA. Each fresh snapshot
reads the current head, reviews including `COMMENTED` submissions, all review
threads, checks and merge state, then verifies both the head and open state
again; a mixed-head snapshot is discarded and a terminal transition is reported
immediately. Reviews from older heads and their unresolved threads
remain visible, but only review of the current head satisfies the merge gate. A
remote head not contained locally remains an immediate coordination block and is
reconciled only through the exact-SHA helper above.

Keep the pull request draft throughout the automatic review cycle. Prefer the
execution surface's dedicated local read-only reviewer against the complete diff
from the canonical base: Codex `/review` or `codex review --base BASE`, and Claude
Code `/review`. A local result counts for the current head only when the worktree
is clean and both `HEAD` and the canonical base remain the revisions recorded for
that review. Use a GitHub-triggered Codex review only when no suitable local
reviewer is available or a human explicitly requests public bot evidence.

Wait for one review to finish before repairing its first finding. Inventory every
finding or GitHub thread, apply one coherent batch, synchronize canonical changes
at the same checkpoint, validate once, commit and push once, then automatically
run another current-head local review or request the GitHub fallback. Repeat until
the review reports no findings, or the steward records why every remaining
non-blocking finding is too granular or immaterial to justify another code change.
A technically rebutted finding with complete evidence and a resolved thread is
also disposed without requiring a duplicate same-head review. P0, P1 and
critical-path P2 findings can never be waived as granular or immaterial. Branch
lag is not conflict. While a GitHub review of the current head is pending, record
an actual conflict but do not rewrite the head merely to remove it. Restore
mergeability before the first review, after a completed review batch, or during
finalization. If `main` advances again during review, accumulate it until the next
checkpoint instead of starting a live conflict-resolution loop.

Native review-follow-up commands are implementation aids, not policy. If Codex
exposes `/reviewfollowup`, use it to collect or recheck GitHub feedback; otherwise
continue in the same review context or run a narrowly instructed review. Claude
has no required named follow-up command: continue the PR-linked session or rerun
`/review`. In every case the repository rules for exact revisions, severity,
validation, thread disposition and Draft/Ready state remain authoritative.

For a published PR, keep a read-only monitor active until an actionable event or
terminal state. A synchronous local review needs no GitHub polling. While a
GitHub-triggered automatic review is pending, choose a new exact delay of 180
through 480 seconds after every unchanged observation with
`.agents/review-requests.py wait --phase review`, then arrange one platform wait
or recurring wake-up for that delay. Once ready for human review, use
`.agents/review-requests.py wait --phase ready` and observe mergeability hourly.
The monitor reports only changed state or action needed and never comments,
pushes, requests review or merges. A review, failing check, foreign head, confirmed
conflict, predecessor transition, approval, merge or closure returns ownership to
the steward. If the platform cannot retain a monitor, hand off the exact pending
conditions and the PR number; never describe waiting work as complete.
When a previously active coordination notice disappears because its record was
fulfilled, superseded or cleared, emit that transition explicitly; an empty new
notice is a changed state and returns ownership to the steward.

Every steward also observes exact changed-path overlap, shared interfaces and
semantic dependencies with other open PRs. A material overlap needs one final,
machine-readable recommendation mirrored in every involved PR through
`.agents/pr-coordination.py recommend`. It names every PR, one complete order,
the overlap, why that order minimizes repeated work and when to reconsider it.
Agents resolve uncertainty themselves: prerequisite first, then a current-head
reviewed or more merge-ready PR, then least total rework, then lower PR number as
the deterministic tie-breaker. Never give the human alternatives. For three or
more PRs, publish one complete acyclic sequence. The first completely published
recommendation remains authoritative while the same evidence produces the same
order. Any steward may replace it, regardless of who published it, only when new
observable evidence changes the deterministic order. A different preference or
another reading of the same evidence is not a change. The replacement names the
new fact and affected decision criterion, explicitly supersedes the earlier
record and is mirrored to the union of the new PR set and every superseded
record's PR set. Every PR retains one maintained coordination comment: the
publisher updates the existing comment in place and removes duplicate
coordination comments when groups join. New comments are created only for PRs
that have no entry for the coordinated group. The publisher owns the replacement
through every mirrored write; concurrent agents stand down under the repository
lock and then adopt it.
The marker retains the complete publication target set for
idempotent retries and later fulfillment, including PRs that have since closed.
Any active record sharing even one participant joins the same transitive
coordination group; its replacement must supersede the record and give every open
PR in that connected group one complete order. Closed or merged former
participants remain publication targets but never re-enter the new merge order.
Fulfillment derives the original PRs from its ID and accepts matching fulfilled
copies as recovery metadata, so it can finish old-only targets after every
original PR has closed or already received its fulfilled marker.
Visible coordination prose identifies participants as `PR N`, never with a
hash-number reference, Markdown link or pull-request URL. A merge conflict or
changed-path overlap does not by itself justify GitHub cross-reference events.
The hidden marker retains the numeric identities, and the renderer normalizes
hash-number references in supplied explanations before publication.
Only markers whose GitHub author association is
owner, member or collaborator are authoritative. The helper prints its identifier
before the first comment; if mirroring is interrupted, rerun the same command with
`--id ID` so matching copies are verified and remaining comments are updated in
place. The helper writes
the current open PR set before old-only targets. A retry recovers hidden
superseded IDs and the complete target set from its own already-published marker.
If its first target has since closed, publish a new order for the remaining open
PRs with the partial ID in `--supersedes`; IDs identify the closed PRs whose
comments must be read, so the successor also retires that stranded marker.
Recommendation and fulfillment each hold one atomic repository-label mutex from
before their remote snapshot until every mirrored comment is complete. A
concurrent publisher stands down and retries after release. Inspect and remove a
lock left by a failed process deliberately; never steal it automatically. A
release read failure preserves the publication error and reports the retained
lock for deliberate cleanup.

The order controls merging, not current execution. A later PR may finish its
implementation, review or protected operation but does not merge first or chase
anticipated conflicts. Once its predecessor merges, it integrates that result
once at its next checkpoint, validates and obtains any newly required review.
Other agents must notice and obey a mirrored recommendation; an uncoordinated
overlap or an open predecessor blocks finalization, not ordinary local work.
Any predecessor that closes without merging invalidates the sequence immediately,
even while another predecessor remains open. Mark the record fulfilled after the
sequence has been absorbed. No agent ever
merges, enables auto-merge or queues a merge without an explicit human instruction
naming the pull request. Monitoring, review, repair, coordination and a request to
make a PR ready never imply merge permission.

Worktree cleanup is a separate, conservative lifecycle. SessionEnd retains a
dirty worktree or one waiting on an open pull request, and queues a clean
finished worktree instead of trying to remove its own current directory. A
later SessionStart may remove at most one registered candidate after a 24-hour
grace period, but only when it has no live lease, tracked, untracked or ignored
files, foreign pull-request head, open pull request, closed unmerged pull
request or unknown GitHub state. Inspect and control the queue with:

    python3 .agents/worktrees.py audit
    python3 .agents/worktrees.py retire task-slug
    python3 .agents/worktrees.py sweep

Removing a worktree always retains its local branch. A later sweep may delete
that branch only after a seven-day grace period and proof that it is contained
in canonical `main` or is the exact head of a merged pull request. Remote
branches are never deleted. Every final handoff reports whether cleanup was
completed, queued, or blocked and why.

Claude Code cloud sets `CLAUDE_CODE_REMOTE=true`. Codex cloud may use the
repository-defined `AGENT_EXECUTION=codex-cloud`; GitHub Copilot cloud exposes
its scoped `GITHUB_COPILOT_GIT_TOKEN` and uses the adapter under
`.github/hooks/`. Independently, the hook treats a checkout without `origin` as
an isolated snapshot. Such a snapshot may test and commit, but cannot prove
remote freshness or shell push access. Do not add a personal token or invent a
writable remote. Update the existing pull request through the platform
integration when it offers that operation; otherwise hand the commit and patch
to the integrating agent and say explicitly that nothing was pushed. Never open
a replacement pull request just because a cloud snapshot cannot update the
existing branch.

## Rules that are not preferences

1. **Signing in locally always works.** `authgui.inc` renders the password form
   before the single sign-on block, and nothing here may change that. Every
   failure mode has to end with somebody still being able to get in.
2. **Protocol code remains focused and locally reviewable.** Do not add an OIDC
   framework or implement cryptographic primitives. Signature operations use
   OPNsense's phpseclib runtime; discovery, claim validation and transactions
   live here and are covered by protocol tests.
3. **A refusal says one thing.** Every local-account outcome — no account,
   disabled, expired, root, an address the provider would not vouch for — ends
   in the same sentence and status code. The reason goes to the log alone.
   Splitting them would answer "which accounts exist here" to anyone who can
   sign in at the provider.
4. **A trace carries no tokens, secrets or claim values** beyond what is needed
   to follow the flow. Traces end up in support mail.
5. **Nothing is a setting that the protocol decides.** Algorithms, `exp`,
   `nonce`, `azp`, the subject binding, the redirect allow list: those are what
   OpenID Connect asks for, and an installation does not get to differ. What an
   installation genuinely differs on is a field under *System > Access >
   Servers*.
6. **Privileges stay local unless asked otherwise.** No group claim is consumed
   until one is configured. Anything that would widen this needs a deliberate
   decision, off by default.
7. **The package is named `os-openid-connect`, and ships no file under
   `/usr/local/opnsense/version/`.** The name is the only thing that puts it on
   *System > Firmware > Plugins*, which is where somebody notices their login
   depends on it. A version file is the separate mechanism that would also
   register it in `system.firmware.plugins`, and every plugin sync would then
   try to install it from a repository that does not have it. Name yes, register
   no.
8. **Depending on core means watching core.** Core is somebody else's code and
   moves without warning. Anything newly depended on goes into `TOUCHPOINTS` in
   `packaging/watch/openid-connect-watch`.

## Style

Comments explain **why**, not what — this project's comments are long on
purpose and are not clutter to remove. English throughout, a copyright line in
every file whose format permits one, no host, address or mailbox of whoever
wrote it (`tests/package.py` checks all three, and deliberately names none of
them). A strict-schema machine-import file may omit the line only when an
adjacent human-readable file carries the notice and documents the exception.

Commit messages follow Conventional Commits because the release note is written
out of them; see `CONTRIBUTING.md`. A change that can turn a login that worked
into one that does not is marked `!` with a `BREAKING CHANGE:` footer saying
what to set — not that something changed.

Before an agent creates or writes to a public GitHub issue, pull request, review
or comment, read the complete `github-contribution` skill. Its issue-first rule,
language matching, short-body limits, maintained-detail-comment pattern, tone
and authorship notice apply to every public message written in a contributor's
name.

A pull request remains draft while implementation, validation and automatic
independent review are in progress. The agent marks it ready for review automatically
only when the intended scope is complete, the branch is technically green, the
current-head review cycle has reached its stopping condition, every review thread
has a disposition and the branch is mergeable. That transition is the handoff
to human review, approval and an explicitly authorized merge. New user-requested
scope or a direct user change returns it to draft before the next implementation
change. A confirmed conflict after readiness also returns it to draft while the
steward resolves and validates it. The steward restarts the complete review cycle
when the resolution materially changes reviewed behavior, interfaces or risk;
for a demonstrably mechanical resolution it records that judgment, skips replaying
the prior review history and obtains one current-head reviewer confirmation. Every
new conflict-resolution head remains draft until that review reaches the normal
stopping condition.

Before every external review request or final review handoff, read and follow
the complete `preflight-review` skill against the exact final diff from the
canonical base. A green test gate is evidence, not completion. If the preflight
changes code, rerun the affected validation and repeat its relevant checks on
the new diff before requesting review.

Do not merge a pull request until the execution surface's dedicated local
reviewer, or the GitHub Codex fallback, has reviewed its current head diff from
the recorded canonical base.
P0 and P1 findings block the merge until fixed or technically rebutted in their
thread. A P2 blocks only when it is independently reproducible and affects
security, recoverability, worktree or issue ownership, remote or pull-request
freshness, publication correctness, or cleanup safety; other P2 and all P3
findings are answered and tracked. The integrating agent owns every review
thread through completion. Before requesting another review, it records every
existing thread's disposition and resolves every addressed thread; it never
leaves that cleanup to the reviewer. When the GitHub fallback is used, review requests use
`.agents/review-requests.py request`, never a raw command-only comment. The helper
removes fulfilled or stale request comments authored by the publishing account,
requires a draft pull request, retains at most one request for the current head and leaves Codex reviews,
findings, dispositions and discussion untouched. After a review arrives, run
`.agents/review-requests.py cleanup` to remove its fulfilled trigger. Automatically
run or request another current-head review after each review batch until it has no
findings, or until all remaining non-blocking findings have an explicit
too granular or immaterial disposition. Never use that exception for a P0, P1 or
critical-path P2.

## What this deliberately does not do

Captive Portal and OPNWAF: the first because an integration nobody here can
exercise would be guesswork, the second because it is a Business Edition
product. The Log Out link in the page header: it lives in core's `authgui.inc`,
out of a plugin's reach.

## Skills

`.agents/skills/` holds task-specific procedures. Before changing a setting,
protocol behavior, a dependency on OPNsense core, or release state, read the
complete matching `SKILL.md` and follow it for that task.
