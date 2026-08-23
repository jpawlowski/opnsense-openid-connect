#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""What a commit message has to look like, in one place.

Two things read this file: the commit-msg hook next door, which stops a
message before it becomes a commit, and release-notes.py, which turns a range
of them into the note attached to a release. They agree because they are the
same code - a convention only two thirds of the tooling knows is a convention
that quietly stops holding.

The shape is Conventional Commits:

    type(scope)!: what it does

    Why, in whatever length it takes.

    BREAKING CHANGE: what an installation has to do about it.

The scope is optional and free-form; it is decoration for a reader, not a
vocabulary to memorise. The `!` and the footer mean the same thing and either
is enough - it is what puts an entry at the top of a release note, which is
where anything that can lock somebody out of a firewall belongs.
"""
import re
import subprocess

# The type decides where an entry lands in the release note, so the heading
# lives here beside it rather than in a second table somewhere else.
TYPES = {
    "feat": "New",
    "fix": "Fixed",
    "perf": "Faster",
    "refactor": "Changed under the hood",
    "docs": "Documentation",
    "build": "Packaging",
    "ci": "Pipeline",
    "test": "Tests",
    "chore": "Housekeeping",
    "style": "Housekeeping",
    "revert": "Reverted",
}

# Order of the sections in a release note. Anything that can lock somebody out
# comes first; what only a maintainer cares about comes last.
SECTIONS = [
    ("Breaking", None),
    ("New", ["feat"]),
    ("Fixed", ["fix"]),
    ("Faster", ["perf"]),
    ("Changed under the hood", ["refactor"]),
    ("Documentation", ["docs"]),
    ("Packaging", ["build"]),
    ("Pipeline", ["ci"]),
    ("Tests", ["test"]),
    ("Housekeeping", ["chore", "style"]),
    ("Reverted", ["revert"]),
    ("Other", None),
]

HEADER = re.compile(
    r"^(?P<type>[a-z]+)"
    r"(?:\((?P<scope>[^()\r\n]+)\))?"
    r"(?P<breaking>!)?"
    r": (?P<subject>.+)$"
)

# commitlint's own default, and generous enough that nobody has to write worse
# English to fit. A subject is a sentence, not a headline.
HEADER_MAX = 100

# Runs to the next blank line or the next footer, so that a trailer underneath it
# - Co-Authored-By and the like - does not end up read as part of the warning.
BREAKING_FOOTER = re.compile(
    r"^BREAKING[ -]CHANGE: (?P<detail>.+?)(?=\n\s*\n|\n[A-Za-z][A-Za-z-]*: |\Z)",
    re.M | re.S,
)

# Written by a tool, not by a person. Nothing to hold them to.
GENERATED = re.compile(r"^(Merge |Revert \"|fixup! |squash! )")


class Commit:
    """One commit message, and what the convention makes of it."""

    def __init__(self, message, sha=""):
        self.sha = sha
        self.message = message.strip("\n")
        lines = self.message.splitlines() or [""]
        self.header = lines[0]
        self.body = "\n".join(lines[1:]).strip("\n")
        self.blank_line_after_header = len(lines) < 2 or lines[1].strip() == ""

        self.generated = bool(GENERATED.match(self.header))
        match = HEADER.match(self.header)
        self.type = match.group("type") if match else None
        self.scope = match.group("scope") if match else None
        self.subject = match.group("subject") if match else self.header
        footer = BREAKING_FOOTER.search(self.message)
        self.breaking_detail = footer.group("detail").strip() if footer else ""
        self.breaking = bool(match and match.group("breaking")) or bool(footer)

    def problems(self):
        """@return list[str] what is wrong with it, empty when nothing is"""
        if self.generated:
            return []

        if self.type is None:
            return ["it does not start with `type: ` or `type(scope): `"]

        found = []
        if self.type not in TYPES:
            found.append(f"`{self.type}` is not one of: {', '.join(sorted(TYPES))}")
        if len(self.header) > HEADER_MAX:
            found.append(f"the first line is {len(self.header)} characters, at most {HEADER_MAX}")
        if self.subject.endswith("."):
            found.append("the first line ends in a full stop")
        if self.subject[:1].isupper():
            found.append("the subject starts with an upper-case letter")
        if not self.subject.strip():
            found.append("it says nothing after the colon")
        if not self.blank_line_after_header:
            found.append("the second line has to be blank, so the body is a body")

        return found

    def heading(self):
        """@return str the release-note section this belongs under"""
        if self.breaking:
            return "Breaking"

        return TYPES.get(self.type, "Other")


def read(range_or_ref, repo="."):
    """Every commit in a range, newest first.

    @return list[Commit]
    """
    # the two separators ascii keeps for exactly this, written as git's own escapes
    # rather than as bytes - a literal NUL cannot be passed in an argument at all
    out = subprocess.run(
        ["git", "-C", repo, "log", "--no-merges", "--format=%H%x1f%B%x1e", range_or_ref],
        capture_output=True, text=True, check=True,
    ).stdout

    found = []
    for entry in out.split("\x1e"):
        entry = entry.strip("\n")
        if not entry:
            continue
        sha, _, message = entry.partition("\x1f")
        found.append(Commit(message, sha.strip()))

    return found


EXAMPLE = """A message looks like this:

    fix(auth): refuse a login to an account that is disabled

    Core's own connector refuses one before it looks at a password, and
    nothing re-checks it once a session exists.

    BREAKING CHANGE: what an installation has to set for this to keep working.

Types: """ + ", ".join(sorted(TYPES)) + """
The scope in brackets is optional. `!` before the colon, or a BREAKING CHANGE
footer, marks a change that can lock somebody out - it goes to the top of the
release note.
"""
