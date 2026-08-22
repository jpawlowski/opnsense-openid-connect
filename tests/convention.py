#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Checks the rule that decides what a commit message may be, and what a
release note makes of one.

Worth checking because two things depend on it that fail in opposite ways: a
rule too strict refuses a message somebody is trying to write, and a rule too
loose lets a change reach a release with nothing said about it in the note. The
second is the one nobody notices.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "tests"))

import commits  # noqa: E402
import harness  # noqa: E402
from harness import check, group  # noqa: E402


def load(name, path):
    """release-notes.py has a hyphen in it, so it cannot simply be imported."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


notes = load("release_notes", ROOT / "packaging" / "release-notes.py")


def refusals(message):
    """@return list[str] what the convention says is wrong with it"""
    return commits.Commit(message).problems()


def main():
    group("A message the convention accepts")
    check("a type and a subject", refusals("fix: something"), [])
    check("a scope as well", refusals("feat(auth): something"), [])
    check("marked as breaking", refusals("fix(auth)!: something"), [])
    check("a scope with a slash in it", refusals("ci(forgejo/build): something"), [])
    check("a body under a blank line", refusals("fix: something\n\nBecause of a reason."), [])
    check("every type this project uses", [t for t in commits.TYPES if refusals(f"{t}: x")], [])

    group("A message it refuses")
    check("no type at all", len(refusals("Something in plain prose")), 1)
    check("a type nobody agreed on", len(refusals("wibble: something")), 1)
    check("nothing after the colon", len(refusals("fix: ")) >= 1, True)
    check("a full stop at the end", len(refusals("fix: something.")), 1)
    check("a body glued to the subject", len(refusals("fix: something\nand more")), 1)
    check(
        "a first line longer than a first line should be",
        len(refusals("fix: " + "x" * commits.HEADER_MAX)),
        1,
    )

    group("What git writes itself is left alone")
    check("a merge", refusals("Merge branch 'main' into a-branch"), [])
    check("a revert git wrote", refusals('Revert "fix: something"'), [])
    check("a fixup", refusals("fixup! fix: something"), [])

    group("Reading a message")
    written = commits.Commit("feat(auth)!: allow the root account\n\nWhy it is off by default.\n\n"
                             "BREAKING CHANGE: root is refused unless the setting is on.\n\n"
                             "Co-Authored-By: Somebody <nobody@example.net>")
    check("the type", written.type, "feat")
    check("the scope", written.scope, "auth")
    check("the subject", written.subject, "allow the root account")
    check("it is breaking", written.breaking, True)
    check(
        "the warning stops before the trailer under it",
        written.breaking_detail,
        "root is refused unless the setting is on.",
    )
    check("and it lands at the top of the note", written.heading(), "Breaking")

    footed = commits.Commit("fix: something\n\nBREAKING CHANGE: and it changes behaviour.")
    check("a footer alone is enough to be breaking", footed.breaking, True)
    check("with no bang needed", footed.heading(), "Breaking")

    group("What a release note makes of them")
    written = [
        commits.Commit("feat(api): an endpoint"),
        commits.Commit("fix: a fault"),
        commits.Commit("docs: a page"),
        commits.Commit("chore: tidying"),
        commits.Commit("fix(auth)!: a refusal\n\nBREAKING CHANGE: fill the field in."),
        commits.Commit("Merge branch 'main'"),
    ]
    note = notes.changes(written)

    check("the breaking one comes first", note.startswith("### Breaking"), True)
    check("its warning travels with it", "fill the field in." in note, True)
    check("and it is not repeated under Fixed", note.count("a refusal"), 1)
    check(
        "the sections are in the order the convention lays down",
        [line for line in note.splitlines() if line.startswith("### ")],
        ["### Breaking", "### New", "### Fixed", "### Documentation", "### Housekeeping"],
    )
    check("a scope is shown where there is one", "**api**: an endpoint" in note, True)
    check("and nothing is invented where there is none", "- a fault" in note, True)
    check("what git wrote itself stays out", "Merge branch" not in note, True)

    check("nothing to say says nothing", notes.changes([]), "")

    group("Every type reaches a section of the note")
    check(
        "none of them fall through to Other",
        [t for t in commits.TYPES if commits.Commit(f"{t}: x").heading() == "Other"],
        [],
    )
    check(
        "and every section a type names is one the note writes",
        sorted({h for h in commits.TYPES.values()} - {name for name, _ in commits.SECTIONS}),
        [],
    )


if __name__ == "__main__":
    harness.run(main)
