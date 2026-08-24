#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Claim an implementation issue before an agent writes repository state."""

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / ".agents" / "hooks"))

import fast_gate  # noqa: E402
import issue_claim  # noqa: E402


def claim(arguments):
    with fast_gate.RepositoryLock(ROOT):
        record = issue_claim.claim(ROOT, arguments.issue, language=arguments.language)
    print(f"claimed issue #{record['issue']}: {record['comment_url']}")


def linked(arguments):
    with fast_gate.RepositoryLock(ROOT):
        record = issue_claim.linked(ROOT, arguments.pull_request)
    print(f"pull request #{record['pull_request']} now carries the visible work signal for issue #{record['issue']}")


def adopt(arguments):
    with fast_gate.RepositoryLock(ROOT):
        record = issue_claim.adopt_pull_request(ROOT, arguments.pull_request)
    print(f"adopted pull request #{record['pull_request']} for issue #{record['issue']}")


def release(_arguments):
    with fast_gate.RepositoryLock(ROOT):
        record = issue_claim.release(ROOT)
    print("no issue claim was active" if record is None else f"released issue #{record['issue']}")


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    claiming = commands.add_parser("claim", help="publish an exclusive machine-readable issue claim")
    claiming.add_argument("issue", type=int)
    claiming.add_argument("--language", choices=("en", "de"), default="en")
    claiming.set_defaults(function=claim)
    linking = commands.add_parser("linked", help="replace the issue claim with its linked pull request")
    linking.add_argument("pull_request", type=int)
    linking.set_defaults(function=linked)
    adoption = commands.add_parser("adopt-pr", help="adopt an explicitly requested existing pull request")
    adoption.add_argument("pull_request", type=int)
    adoption.set_defaults(function=adopt)
    releasing = commands.add_parser("release", help="release work that stopped before a pull request")
    releasing.set_defaults(function=release)
    return value


def main():
    arguments = parser().parse_args()
    try:
        arguments.function(arguments)
    except RuntimeError as error:
        print(f"issue claim failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
