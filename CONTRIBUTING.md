# Working on this

    ./tests/run.sh

Syntax for every language in the tree, the behaviour checks, what a commit
message may be, and checks on the package that gets built. No Composer, no
PHPUnit, no network, no OPNsense. See [`tests/README.md`](tests/README.md).

## Pull requests

GitHub is the source of truth. Work on a branch and open a pull request there;
the Forgejo repository is a read-only code mirror and accepts no contributions.

Pull requests are squash-merged, so their title and description become the one
commit that reaches `main`. Give the title the Conventional Commit shape below.
Use the description for context and, when applicable, the exact `BREAKING
CHANGE:` instruction an installation needs before upgrading. Intermediate
branch commits may be ordinary work in progress; the pipeline judges the future
squash commit shown by the pull request.

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

The subject is a sentence, lower case after the colon, no full stop. Everything
else — how long, how much prose, whether there is a body at all — is yours.

### Local commit setup

    git config commit.template "$(git rev-parse --show-toplevel)/.gitmessage"
    git config core.hooksPath packaging/hooks

Run both once per clone. The template puts the expected shape and the available
types into the commit editor; its guidance consists only of comments and does
not become part of the commit. The hook refuses a message the release note
could not read, before the commit exists rather than after. Neither Git config
nor hooks are part of what Git clones, so the pipeline remains authoritative.

For a pull request, the pipeline checks its title and description instead. On
`main` and tag pushes it checks the commits that arrived, so the protected
branch cannot contain a message the release note cannot read.

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
memory: changing a setting or protocol behavior, depending on something new in
OPNsense core, and cutting a release. Each one is a checklist of the places
that go stale silently, which is most of the work. `.claude/skills` points to
the same directory so Claude and other agents use one canonical copy.

## Protocol changes

The OpenID Connect implementation is intentionally small and lives under
`OPNsense/OpenIDConnect`. Add a behaviour test for every protocol decision and
run the real cryptographic fixtures on OPNsense before release. Cryptographic
primitives remain the responsibility of OPNsense's phpseclib runtime.
