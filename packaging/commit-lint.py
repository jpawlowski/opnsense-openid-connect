#!/usr/bin/env python3

"""Holds commit messages to the convention release-notes.py reads them by.

    python3 packaging/commit-lint.py --message .git/COMMIT_EDITMSG   # one, before it exists
    python3 packaging/commit-lint.py --range origin/main..HEAD       # every one in a range
    python3 packaging/commit-lint.py --pushed                        # whatever a push brought
    python3 packaging/commit-lint.py --pull-request                   # the future squash commit

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


def forge_event():
    """Read the GitHub-compatible event payload both for GitHub and Forgejo."""
    where = os.environ.get("GITHUB_EVENT_PATH", "")
    if not where or not pathlib.Path(where).is_file():
        return {}
    try:
        return json.loads(pathlib.Path(where).read_text(encoding="utf-8"))
    except ValueError:
        return {}


def pull_request_message(event):
    """The commit GitHub creates when the configured squash merge is used."""
    request = event.get("pull_request") or {}
    title = request.get("title") or ""
    body = request.get("body") or ""
    if not isinstance(title, str) or not title.strip():
        raise ValueError("the event carries no pull request title")
    if not isinstance(body, str):
        raise ValueError("the pull request description is not text")

    return f"{title.strip()}\n\n{body.strip()}".rstrip()


def pushed_span(repo):
    """What a push brought, worked out from what the forge left lying around.

    Forgejo and GitHub both write the event to GITHUB_EVENT_PATH and both spell
    it the same way, so one reading serves both. Judging is deliberately
    narrow: a push is answerable for the commits it carries and not for the
    ones that were already there.

    @return str a range git log understands
    """
    head = os.environ.get("GITHUB_SHA") or "HEAD"

    event = forge_event()

    # Creating a tag names commits that already exist; it does not introduce a
    # new message. In particular, GitHub reports an all-zero `before` value for
    # the first tag in a repository. Letting that fall through to the history
    # fallback below would make the first release re-lint every old commit.
    ref = event.get("ref") or os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/"):
        return f"{head}..{head}"

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
    source.add_argument(
        "--pull-request",
        action="store_true",
        help="the title and description that will become the squash commit",
    )
    parser.add_argument("--repo", default=".", help="where the repository is")
    args = parser.parse_args()

    if args.message:
        text = pathlib.Path(args.message).read_text(encoding="utf-8", errors="replace")
        # git keeps the commentary in the file it hands over; it is not the message
        text = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
        entries = [commits.Commit(text)]
    elif args.pull_request:
        try:
            entries = [commits.Commit(pull_request_message(forge_event()))]
        except ValueError as problem:
            print(f"cannot read pull request: {problem}", file=sys.stderr)
            return 1
        print("judging the future squash commit")
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
