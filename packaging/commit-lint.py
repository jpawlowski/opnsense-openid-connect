#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Holds commit messages to the convention release-notes.py reads them by.

    python3 packaging/commit-lint.py --message .git/COMMIT_EDITMSG   # one, before it exists
    python3 packaging/commit-lint.py --range origin/main..HEAD       # every one in a range
    python3 packaging/commit-lint.py --pushed                        # whatever a push brought

The shape itself lives in commits.py, next door, so that what is enforced here
and what is read there cannot drift apart.

Merges and the messages git writes itself are left alone. A range that contains
nothing to judge passes: this runs on pushes, and a push that only moves a tag
is not a message.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import commits  # noqa: E402  (it sits next door, and next door has to be on the path first)


def exists(repo, ref):
    return subprocess.run(
        ["git", "-C", repo, "cat-file", "-e", f"{ref}^{{commit}}"],
        capture_output=True,
    ).returncode == 0


def pushed_span(repo):
    """What a push brought, worked out from what the forge left lying around.

    Forgejo and GitHub both write the event to GITHUB_EVENT_PATH and both spell
    it the same way, so one reading serves both. Judging is deliberately
    narrow: a push is answerable for the commits it carries and not for the
    ones that were already there.

    @return str a range git log understands
    """
    head = os.environ.get("GITHUB_SHA") or "HEAD"

    event = {}
    where = os.environ.get("GITHUB_EVENT_PATH", "")
    if where and pathlib.Path(where).is_file():
        try:
            event = json.loads(pathlib.Path(where).read_text())
        except ValueError:
            event = {}

    candidates = [
        ((event.get("pull_request") or {}).get("base") or {}).get("sha") or "",
        event.get("before") or "",
    ]
    for candidate in candidates:
        # a new branch and a force push both leave a zeroed or unknown id behind
        if candidate and set(candidate) != {"0"} and exists(repo, candidate):
            return f"{candidate}..{head}"

    earlier = subprocess.run(
        ["git", "-C", repo, "describe", "--tags", "--abbrev=0", f"{head}^"],
        capture_output=True, text=True,
    )
    if earlier.returncode == 0 and earlier.stdout.strip():
        return f"{earlier.stdout.strip()}..{head}"

    # a tag on an untagged history, or the very first commit there is
    return head


def judge(entries):
    """@return int how many were refused"""
    refused = 0
    for commit in entries:
        problems = commit.problems()
        if not problems:
            continue
        refused += 1
        where = f"{commit.sha[:12]} " if commit.sha else ""
        print(f"\n{where}{commit.header}", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)

    return refused


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--message", help="a file holding one message, as the hook is given")
    source.add_argument("--range", dest="span", help="a commit range, as the pipeline has")
    source.add_argument("--pushed", action="store_true", help="whatever this push brought")
    parser.add_argument("--repo", default=".", help="where the repository is")
    args = parser.parse_args()

    if args.message:
        text = pathlib.Path(args.message).read_text(encoding="utf-8", errors="replace")
        # git keeps the commentary in the file it hands over; it is not the message
        text = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
        entries = [commits.Commit(text)]
    else:
        span = pushed_span(args.repo) if args.pushed else args.span
        print(f"judging {span}")
        try:
            entries = commits.read(span, args.repo)
        except subprocess.CalledProcessError as problem:
            print(f"cannot read {span}: {problem.stderr.strip()}", file=sys.stderr)
            return 1

    refused = judge(entries)
    if refused:
        print(f"\n{refused} message(s) refused.\n\n{commits.EXAMPLE}", file=sys.stderr)
        return 1

    # the hook is in somebody's way at the moment it runs, so it says nothing when
    # there is nothing to say; a pipeline judging a range should report either way
    if not args.message:
        print(f"{len(entries)} message(s), all in shape.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
