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

    ./tests/run.sh                                    fast host-independent gate; Stop hook and CI
    python3 tests/update-security-report.py --update regenerate the unified security and conformance report
    php tests/run.php                                 the behaviour checks alone
    python3 packaging/build.py --check                does it still build
    python3 packaging/release-notes.py --tag vX.Y.Z   what a release would say
    python3 packaging/commit-lint.py --range main..HEAD
    python3 .agents/hooks/fast_gate.py refresh        refresh remote main before publishing
    python3 .agents/hooks/fast_gate.py reconcile-pr --sha SHA --strategy merge
    python3 packaging/contribution-lint.py --help     what an issue or PR may contain

Installed integration and destructive browser E2E are deliberate manual runs;
they never belong in an automatic agent Stop hook. See `tests/README.md`.

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
path overlap without changing the topic branch. Overlap with new canonical work
blocks another write until the agent integrates it or records a reasoned
deferral with the command reported by the hook. Before any push, pull-request
update, review request or handoff, run the explicit refresh command above. Start
from the reported canonical ref, rebase an unpublished branch, do not routinely
rewrite a published branch, and request a new review after a head change. Never
push an automatic `main` synchronization to a contributor fork.

For a published branch the same event-driven check watches the pull request's
remote head, checks, review decision, merge state and, when GitHub exposes them,
unresolved review threads. It also reports open pull requests whose changed
paths overlap the local work. A remote head not contained locally blocks
further writing or publication until it is reconciled. The refusal reports the
exact SHA; invoke the explicit `reconcile-pr` helper above with that full SHA to
fetch and merge only the freshly verified head. When all local work is
done and only CI, review, approval or merge remains, offer — but never create
without explicit user consent — a read-only ten-minute monitor using
`python3 .agents/hooks/fast_gate.py watch`. Report only state changes or action
needed; the monitor never comments, requests review, pushes or merges.

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
language matching, short-body limits, tone and authorship notice apply to every
public message written in a contributor's name.

Do not merge a pull request until Codex has reviewed its current head commit.
P0 and P1 findings block the merge until fixed or technically rebutted in their
thread. A P2 blocks only when it is independently reproducible and affects
security, recoverability, worktree or issue ownership, remote or pull-request
freshness, publication correctness, or cleanup safety; other P2 and all P3
findings are answered and tracked. The integrating agent owns every review
thread through completion. Before requesting another review, it records every
existing thread's disposition and resolves every addressed thread; it never
leaves that cleanup to the reviewer. Once a current-head review has no blocking
finding, do not request another review merely to obtain zero suggestions.

## What this deliberately does not do

Captive Portal and OPNWAF: the first because an integration nobody here can
exercise would be guesswork, the second because it is a Business Edition
product. The Log Out link in the page header: it lives in core's `authgui.inc`,
out of a plugin's reach.

## Skills

`.agents/skills/` holds task-specific procedures. Before changing a setting,
protocol behavior, a dependency on OPNsense core, or release state, read the
complete matching `SKILL.md` and follow it for that task.
