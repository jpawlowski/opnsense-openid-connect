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
    php tests/run.php                                 the behaviour checks alone
    python3 tests/update-security-report.py --update  regenerate the security and conformance report
    python3 packaging/build.py --check                does it still build
    python3 packaging/release-notes.py --tag vX.Y.Z   what a release would say
    python3 packaging/commit-lint.py --range main..HEAD
    python3 packaging/contribution-lint.py --help     what an issue or PR may contain
    python3 .agents/test-impact.py                    the minimum manual validation for this diff
    python3 .agents/worktrees.py create SLUG --client codex|claude
    python3 .agents/issues.py claim N
    python3 .agents/hooks/fast_gate.py refresh        refresh remote main before publishing

The pull-request helpers — stewardship, review requests, merge order, worktree
retirement — are listed in the `github-contribution` skill beside the rules that
say when to run them, because a command list is where a procedure goes to be
half-remembered.

## Running checks

Redirect a check's output to a log and judge it by that command's own exit code:

    ./tests/run.sh > /tmp/gate.log 2>&1; echo "EXIT=$?"

On a green run that is one line instead of thousands, and the log is there when
it is red. Read the failing part only. Never decide pass or fail from a check
piped into `tail`, `head` or `grep`: the shell then reports the *last* command's
exit code, which is the pager's, and a red run reads as green.

Iterate cheap, gate once. While fixing, rerun only the thing that failed; run
the full gate once at the end, on the complete diff.

Installed integration and destructive browser E2E are deliberate manual runs;
they never belong in an automatic agent Stop hook. See `tests/README.md`.

## Which gate

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

Required manual evidence cannot be silently made optional. An unavailable
environment leaves the technical gate open and the pull request draft; it does
not turn a required run into an optional one.

There is no linter beyond `php -l`; keep to 120 columns and to the style of the
file being edited.

## Parallel agent work

The primary local checkout is an agent read-only control surface. Pure searches
and inspection need neither a branch nor another worktree. Any implementation,
build or test that may write files uses a dedicated worktree. A Codex-managed
worktree may remain detached until its work needs a commit or pull request; a
manual worktree starts with its own topic branch. Cloud sessions already have an
isolated checkout and must not add another.

Parallel subagents are read-only and mark their delegated prompt with
`[read-only]`. Parallel writing happens in separate top-level tasks and
worktrees. One integrating agent owns a pull-request branch; supporting agents
hand over findings, commits or patches instead of pushing that branch.

The shared PreToolUse hook refuses exactly two things, because they are the two
a second agent cannot work around: writing in the control checkout, and writing
in a worktree somebody else holds the lease on. Everything else it observes and
reports — canonical drift, a foreign pull-request head, a missing issue claim.
A report is not a refusal, and an agent that treats every notice as a wall stops
being useful.

Every implementation starts from a visible issue and its claim. The claim
publishes an atomic per-issue label mutex, so a racing agent stands down:

    python3 .agents/issues.py claim 123

**The complete pull-request procedure lives in the `github-contribution` skill,
and only there**: publishing, stewardship, the review cycle and its severities,
thread disposition, Draft and Ready, merge order between overlapping pull
requests, the read-only monitor, worktree retirement and what a cloud checkout
without a remote may claim. Read it before writing anything public on GitHub.

It is one document rather than three on purpose. This file and `CONTRIBUTING.md`
used to restate the same protocol, and the tests checked only that each copy
contained the right keywords — which is not the same as the copies agreeing. On
2026-08-28 a single change to what the write guard enforces had to be corrected
separately in two of them, and would have been wrong in the third. One procedure,
one place; the other two say where it is.

## Working with the human

Ask about one decision at a time. Never present a backlog and never fold several
questions into one; that does not scale for the person answering.

Every question carries a recommendation and its reason, so the answer can be
"yes" or a correction rather than research. A question without a recommendation
moves the work to the other person.

Doubt goes to the human, not into a guess. That is its own outcome, separate
from "done" and from "blocked", and it is the right one for a product decision,
a breaking change, or a security finding whose severity cannot be settled here.

Only demand what you can justify. Every review finding earns its place from a
rule in this file, a skill, a failing test or a real defect. Taste is not a
reason, and "I would have written it differently" is not a finding.

Say what actually happened. A skipped step, an unavailable environment, a check
that was not run: report it as that. "Green" means the gate ran here, on this
diff, and passed.

## What the tools lie about

The things that cost agent hours here are not the rules; they are the moments a
tool reports something that is not what happened.

- **GitHub's *Update branch* button merges textually, not semantically.** On
  2026-08-28 it merged `main` into PR 130 and produced a tree that compiled and
  failed its tests, because the merged branch had made one of that branch's test
  fixtures a special case. Both sides were green alone. After any such merge,
  run the gate locally before believing the PR's own red or green.
- **`gh pr view --json reviewThreads` does not exist.** Review threads and their
  resolved state are GraphQL-only (`repository.pullRequest.reviewThreads`).
  `gh pr view --json reviews` returns submissions, not threads, so an agent that
  checks only the former reports "no open threads" while several are open.
- **The write guard refuses a compound command, a glob and a redirection**, so
  inspection is one simple command or a pipeline of inspection commands. A glob
  stays refused deliberately: expansion can turn a literal into an option after
  the classification has already run, and a file named `--pre=rm` is the case
  that costs.
- **A pull request GitHub reports as conflicting gets no CI run at all**, because
  it cannot build the merge ref. The symptom is silence rather than an error, and
  it reads exactly like broken Actions. Check `mergeStateStatus` before
  suspecting the platform.

Add to this list rather than to the rules whenever a tool wastes an hour.

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
purpose and are not clutter to remove. English throughout, no host, address or
mailbox of whoever wrote it (`tests/package.py` checks all three, and deliberately
names none of them). First-party application code installed by the package follows
the OPNsense convention and carries the complete BSD-2-Clause header. Structural
configuration, generated artifacts, documentation, tests and repository tooling do
not receive a notice merely because their format permits one. Keep the complete
project terms in `LICENSE` and preserve every third-party notice.

Commit messages follow Conventional Commits because the release note is written
out of them; see `CONTRIBUTING.md`. A change that can turn a login that worked
into one that does not is marked `!` with a `BREAKING CHANGE:` footer saying
what to set — not that something changed.

## Before somebody else reads it

Before an agent creates or writes to a public GitHub issue, pull request, review
or comment, read the complete `github-contribution` skill. Its issue-first rule,
language matching, short-body limits, maintained-detail-comment pattern, tone and
authorship notice apply to every public message written in a contributor's name.
The same skill owns the Draft and Ready rule, the review cycle and the merge
threshold for findings.

Before every external review request or final review handoff, read and follow the
complete `preflight-review` skill against the exact final diff from the canonical
base. A green test gate is evidence, not completion. If the preflight changes
code, rerun the affected validation and repeat its relevant checks on the new
diff before requesting review.

No agent merges a pull request, enables auto-merge or queues a merge without an
explicit human instruction naming it. Monitoring, review, repair, coordination
and a request to make a pull request ready never imply merge permission.

## What this deliberately does not do

Captive Portal and OPNWAF: the first because an integration nobody here can
exercise would be guesswork, the second because it is a Business Edition
product. The Log Out link in the page header: it lives in core's `authgui.inc`,
out of a plugin's reach.

## Skills

`.agents/skills/` holds task-specific procedures. Before changing a setting,
protocol behavior, a dependency on OPNsense core, or release state, read the
complete matching `SKILL.md` and follow it for that task. A skill is where a
procedure belongs; this file is for what is true in every session regardless of
what the task is.
