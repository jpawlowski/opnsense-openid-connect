#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Create and inspect isolated local agent worktrees from the canonical base."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / ".agents" / "hooks"))

import agent_guard  # noqa: E402
import fast_gate  # noqa: E402
import worktree_cleanup  # noqa: E402


SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,48}[a-z0-9])?$")


def git(repository, *arguments, check=True):
    return subprocess.run(
        ("git", *arguments), cwd=repository, check=check, capture_output=True, text=True,
    )


def worktrees(repository):
    records = []
    current = None
    for line in git(repository, "worktree", "list", "--porcelain").stdout.splitlines():
        if line.startswith("worktree "):
            if current:
                records.append(current)
            current = {"path": line.removeprefix("worktree "), "branch": "detached"}
        elif current is not None and line.startswith("branch refs/heads/"):
            current["branch"] = line.removeprefix("branch refs/heads/")
        elif current is not None and line == "detached":
            current["branch"] = "detached"
    if current:
        records.append(current)
    return records


def control_worktree(repository):
    records = worktrees(repository)
    if not records:
        raise RuntimeError("Git did not report a primary worktree")
    return Path(records[0]["path"])


def create(arguments):
    if not SLUG.fullmatch(arguments.slug):
        raise ValueError("the slug must contain 1-50 lower-case letters, digits or single hyphens")
    synchronization = fast_gate.synchronize_repository(ROOT, 0, required=True)
    if not synchronization["remote_available"]:
        raise RuntimeError("a manual local worktree needs a canonical Git remote")

    control = control_worktree(ROOT)
    branch = f"{arguments.client}/{arguments.slug}"
    target = control.parent / f"{control.name}-{arguments.client}-{arguments.slug}"
    if target.exists():
        raise RuntimeError(f"the worktree path already exists: {target}")
    if git(ROOT, "show-ref", "--verify", f"refs/heads/{branch}", check=False).returncode == 0:
        raise RuntimeError(f"the branch already exists: {branch}")

    git(ROOT, "worktree", "add", "--no-track", "-b", branch, str(target), synchronization["base_name"])
    with fast_gate.RepositoryLock(ROOT):
        worktree_cleanup.register(target, client=arguments.client, slug=arguments.slug, managed_by="repository")
    print(f"created {target}")
    print(f"branch {branch} from {synchronization['base_name']} at {synchronization['base_main'][:12]}")


def show(_arguments):
    lease_by_path = {
        str(value.get("worktree")): str(value.get("session_id", ""))[:12]
        for value in agent_guard.leases(ROOT)
    }
    print("WORKTREE\tBRANCH\tSTATE\tWRITER")
    for record in worktrees(ROOT):
        path = Path(record["path"])
        state = "clean" if agent_guard.clean(path) else "dirty"
        print(f"{path}\t{record['branch']}\t{state}\t{lease_by_path.get(str(path.resolve()), '-')}")


def canonical_state():
    synchronization = fast_gate.synchronize_repository(ROOT, 0, required=True)
    if not synchronization["remote_available"]:
        raise RuntimeError("cleanup audit needs a canonical Git remote")
    return synchronization


def duration(seconds):
    hours = max(1, int((seconds + 3599) // 3600))
    return f"{hours}h"


def audit(_arguments):
    synchronization = canonical_state()
    print("TARGET\tSTATE\tREASON")
    for record in worktree_cleanup.inventory(
        ROOT, synchronization["base_name"], fast_gate.CANONICAL_REPOSITORY, current_path=ROOT,
    ):
        target = record.get("path") or record.get("branch") or record.get("slug")
        reason = str(record.get("reason") or "")
        if record.get("ready_in"):
            reason += f" ({duration(record['ready_in'])} remaining)"
        print(f"{target}\t{record['state']}\t{reason}")


def retire(arguments):
    with fast_gate.RepositoryLock(ROOT):
        record = worktree_cleanup.retire(ROOT, arguments.target)
    target = record.get("path") or record.get("branch")
    print(f"retired {target}; cleanup remains subject to the safety audit")


def sweep(_arguments):
    synchronization = canonical_state()
    with fast_gate.RepositoryLock(ROOT):
        actions = worktree_cleanup.sweep(
            ROOT, synchronization["base_name"], fast_gate.CANONICAL_REPOSITORY, current_path=ROOT,
        )
    if not actions:
        print("no registered worktree or local branch is currently safe to remove")
        return
    for action in actions:
        print(action)


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    creation = commands.add_parser("create", help="create a branch and linked worktree")
    creation.add_argument("slug")
    creation.add_argument("--client", choices=("codex", "claude"), required=True)
    creation.set_defaults(function=create)
    listing = commands.add_parser("list", help="show worktrees, cleanliness and writer leases")
    listing.set_defaults(function=show)
    auditing = commands.add_parser("audit", help="classify worktrees and local branches without deleting them")
    auditing.set_defaults(function=audit)
    retirement = commands.add_parser("retire", help="mark a finished worktree or local branch for cleanup")
    retirement.add_argument("target")
    retirement.set_defaults(function=retire)
    sweeping = commands.add_parser("sweep", help="remove only registered candidates that pass every safety check")
    sweeping.set_defaults(function=sweep)
    return value


def main():
    arguments = parser().parse_args()
    try:
        arguments.function(arguments)
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"worktree request failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
