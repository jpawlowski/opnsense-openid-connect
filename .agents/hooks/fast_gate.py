#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Prepare an agent's clone and run the deterministic test tier when needed."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[2]
RELEVANT_PATHS = (
    ".agents",
    ".claude",
    ".codex",
    ".forgejo/workflows",
    ".github/workflows",
    "LICENSE",
    "packaging",
    "src",
    "tests",
)
START_FETCH_TTL = 5 * 60
ACTIVE_FETCH_TTL = 10 * 60
FETCH_TIMEOUT = 20
LOCK_TIMEOUT = 5


def event_input():
    content = sys.stdin.read()
    return json.loads(content) if content.strip() else {}


def state_paths(event):
    identity = f"{REPOSITORY}\0{event.get('session_id', 'unknown')}".encode()
    key = hashlib.sha256(identity).hexdigest()
    directory = Path(tempfile.gettempdir()) / "opnsense-openid-connect-agent-hooks"
    return directory / f"{key}.json", directory / f"{key}.log"


def git_output(*arguments):
    return subprocess.run(
        ("git", *arguments, "--", *RELEVANT_PATHS),
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def repository_git(repository, *arguments, check=True, timeout=None):
    return subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def git_value(repository, *arguments):
    result = repository_git(repository, *arguments, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def common_git_directory(repository):
    path = Path(git_value(repository, "rev-parse", "--git-common-dir"))
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


class RepositoryLock:
    """Serialize shared config, FETCH_HEAD and ref updates across worktrees."""

    def __init__(self, repository, timeout=LOCK_TIMEOUT):
        self.path = common_git_directory(repository) / "opnsense-agent-sync.lock"
        self.timeout = timeout
        self.acquired = False

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                self.path.mkdir()
                self.acquired = True
                return self
            except FileExistsError:
                # Fetches have their own short timeout. An empty lock older than
                # twice that interval can only be debris from an interrupted hook.
                try:
                    stale = time.time() - self.path.stat().st_mtime > FETCH_TIMEOUT * 2
                except FileNotFoundError:
                    stale = False
                if stale:
                    try:
                        self.path.rmdir()
                    except OSError:
                        pass
                time.sleep(0.05)
        raise TimeoutError("another agent is still synchronizing the shared repository")

    def __exit__(self, exception_type, exception, traceback):
        if self.acquired:
            self.path.rmdir()


def configure_repository(repository):
    """Install worktree-local commit guidance before an agent changes files."""
    # Repository-local configuration is otherwise shared by every linked
    # worktree. Absolute template paths must instead follow the active tree.
    repository_git(repository, "config", "--local", "extensions.worktreeConfig", "true")
    settings = (
        ("commit.template", str(repository / ".gitmessage")),
        ("core.hooksPath", "packaging/hooks"),
    )
    for key, value in settings:
        repository_git(repository, "config", "--worktree", key, value)


def sync_state_path(repository):
    return common_git_directory(repository) / "opnsense-agent-sync.json"


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def checked_out_main(repository):
    path = None
    for line in git_value(repository, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree "):
            path = Path(line.removeprefix("worktree "))
        elif line == "branch refs/heads/main":
            return path
    return None


def fast_forward_main(repository, origin_main):
    local_main = git_value(repository, "rev-parse", "--verify", "refs/heads/main")
    if not origin_main:
        return "origin/main does not exist after the fetch"
    if local_main == origin_main:
        return ""
    if local_main and repository_git(
        repository, "merge-base", "--is-ancestor", local_main, origin_main, check=False,
    ).returncode != 0:
        return "local main has commits outside origin/main and was not changed"

    main_worktree = checked_out_main(repository)
    if main_worktree is not None:
        if git_value(main_worktree, "status", "--porcelain"):
            return f"the main control worktree at {main_worktree} is not clean and was not changed"
        repository_git(main_worktree, "merge", "--ff-only", "refs/remotes/origin/main")
        return ""

    arguments = ["update-ref", "refs/heads/main", origin_main]
    if local_main:
        arguments.append(local_main)
    repository_git(repository, *arguments)
    return ""


def synchronize_repository(repository, max_age, required=False):
    """Refresh origin once for all worktrees and safely mirror it to local main."""
    with RepositoryLock(repository):
        configure_repository(repository)
        path = sync_state_path(repository)
        state = load_json(path)
        now = time.time()
        last_attempt = float(state.get("attempted_at", 0))
        old_origin = git_value(repository, "rev-parse", "--verify", "refs/remotes/origin/main")
        fetched = False
        warning = str(state.get("error", ""))

        if required or now - last_attempt >= max_age:
            state["attempted_at"] = now
            try:
                result = repository_git(
                    repository, "fetch", "--atomic", "--prune", "origin",
                    check=False, timeout=FETCH_TIMEOUT,
                )
                if result.returncode != 0:
                    warning = result.stderr.strip() or "git fetch failed"
                    state["error"] = warning
                else:
                    fetched = True
                    warning = ""
                    state["fetched_at"] = now
                    state.pop("error", None)
            except subprocess.TimeoutExpired:
                warning = f"git fetch exceeded {FETCH_TIMEOUT} seconds"
                state["error"] = warning
            save_json(path, state)

        if warning and required:
            raise RuntimeError(f"origin/main could not be refreshed: {warning}")

        new_origin = git_value(repository, "rev-parse", "--verify", "refs/remotes/origin/main")
        main_warning = fast_forward_main(repository, new_origin)
        warnings = [message for message in (warning, main_warning) if message]
        return {
            "fetched": fetched,
            "old_origin": old_origin,
            "origin_main": new_origin,
            "warning": "; ".join(warnings),
        }


def fingerprint():
    digest = hashlib.sha256()
    digest.update(git_output("status", "--porcelain=v1", "-z", "--untracked-files=all"))
    digest.update(git_output("diff", "--binary", "--no-ext-diff", "HEAD"))

    untracked = git_output("ls-files", "-z", "--others", "--exclude-standard")
    for encoded_path in filter(None, untracked.split(b"\0")):
        path = REPOSITORY / os.fsdecode(encoded_path)
        digest.update(encoded_path)
        digest.update(str(path.lstat().st_mode & 0o111).encode())
        if path.is_symlink():
            digest.update(b"symlink\0" + os.fsencode(os.readlink(path)))
            continue
        digest.update(b"file\0")
        with path.open("rb") as source:
            for block in iter(lambda: source.read(128 * 1024), b""):
                digest.update(block)

    return digest.hexdigest()


def load_state(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path, state):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.replace(path)


def path_output(repository, *arguments):
    output = repository_git(repository, *arguments).stdout
    return {line for line in output.splitlines() if line}


def work_paths(repository, origin_main):
    found = set()
    base = git_value(repository, "merge-base", "HEAD", origin_main) if origin_main else ""
    if base:
        found.update(path_output(repository, "diff", "--name-only", f"{base}..HEAD", "--"))
    found.update(path_output(repository, "diff", "--name-only", "--"))
    found.update(path_output(repository, "diff", "--cached", "--name-only", "--"))
    found.update(path_output(repository, "ls-files", "--others", "--exclude-standard"))
    return found


def main_progress(repository, state, origin_main):
    base = state.get("base_main")
    seen = state.get("seen_main")
    if not base or not origin_main or origin_main in (base, seen):
        return ""

    changed = path_output(repository, "diff", "--name-only", f"{base}..{origin_main}", "--")
    overlap = sorted(changed & work_paths(repository, origin_main))
    count = git_value(repository, "rev-list", "--count", f"{base}..{origin_main}") or "unknown"
    state["seen_main"] = origin_main
    if overlap:
        preview = ", ".join(overlap[:8])
        suffix = ", …" if len(overlap) > 8 else ""
        return (
            f"origin/main advanced by {count} commit(s) since this task began and overlaps this work in: "
            f"{preview}{suffix}. Refresh and integrate deliberately before publishing; no merge or rebase was run."
        )
    return (
        f"origin/main advanced by {count} commit(s) since this task began without a changed-path overlap. "
        "The working branch was left unchanged."
    )


def messages(*values):
    return " ".join(value for value in values if value)


def emit(value):
    json.dump(value, sys.stdout)
    sys.stdout.write("\n")


def initialize(event):
    synchronization = synchronize_repository(REPOSITORY, START_FETCH_TTL)
    state_path, _ = state_paths(event)
    state = load_state(state_path)
    if state is None:
        state = {
            "passed": fingerprint(),
            "failed": None,
            "base_main": synchronization["origin_main"],
            "seen_main": synchronization["origin_main"],
        }
    else:
        state.setdefault("base_main", synchronization["origin_main"])
        state.setdefault("seen_main", synchronization["origin_main"])
    save_state(state_path, state)

    branch = git_value(REPOSITORY, "symbolic-ref", "--short", "HEAD")
    branch_warning = ""
    if branch in ("", "main"):
        branch_warning = "Agent changes need their own topic branch and worktree; do not edit main or a detached HEAD."
    emit({"systemMessage": messages(synchronization["warning"], branch_warning)} if
         synchronization["warning"] or branch_warning else {})


def cleanup(event):
    for path in state_paths(event):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def failed_output(event, log_path, extra=""):
    reason = (
        "The fast host-independent checks failed. Fix the failure and run ./tests/run.sh again. "
        f"The complete output is in {log_path}. Integration and browser E2E tests were not run."
    )
    reason = messages(extra, reason)
    if event.get("stop_hook_active"):
        return {"systemMessage": reason}
    return {"decision": "block", "reason": reason}


def stop(event):
    synchronization = synchronize_repository(REPOSITORY, ACTIVE_FETCH_TTL)
    state_path, log_path = state_paths(event)
    state = load_state(state_path)
    current = fingerprint()

    # A hook added during an existing task has no trustworthy earlier baseline.
    if state is None:
        state = {
            "passed": current,
            "failed": None,
            "base_main": synchronization["origin_main"],
            "seen_main": synchronization["origin_main"],
        }
        save_state(state_path, state)
        emit({"systemMessage": synchronization["warning"]} if synchronization["warning"] else {})
        return

    progress = main_progress(REPOSITORY, state, synchronization["origin_main"])
    notice = messages(synchronization["warning"], progress)
    save_state(state_path, state)

    if current == state["passed"]:
        emit({"systemMessage": notice} if notice else {})
        return

    if current == state.get("failed"):
        emit(failed_output(event, log_path, notice))
        return

    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with log_path.open("wb") as output:
        result = subprocess.run(
            (str(REPOSITORY / "tests" / "run.sh"),),
            cwd=REPOSITORY,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )

    if result.returncode == 0:
        state.update({"passed": current, "failed": None})
        save_state(state_path, state)
        log_path.unlink(missing_ok=True)
        emit({"systemMessage": notice} if notice else {})
        return

    state["failed"] = current
    save_state(state_path, state)
    emit(failed_output(event, log_path, notice))


def refresh(event):
    synchronization = synchronize_repository(REPOSITORY, 0, required=True)
    state_path, _ = state_paths(event)
    state = load_state(state_path) or {
        "passed": fingerprint(), "failed": None,
        "base_main": synchronization["origin_main"],
        "seen_main": synchronization["origin_main"],
    }
    state.setdefault("base_main", synchronization["origin_main"])
    state.setdefault("seen_main", synchronization["origin_main"])
    progress = main_progress(REPOSITORY, state, synchronization["origin_main"])
    save_state(state_path, state)
    origin = synchronization["origin_main"][:12] if synchronization["origin_main"] else "unavailable"
    emit({"systemMessage": messages(f"origin/main is {origin}; local main is a safe fast-forward mirror.", progress)})


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    event = event_input()
    if action == "initialize":
        initialize(event)
    elif action == "stop":
        stop(event)
    elif action == "cleanup":
        cleanup(event)
    elif action == "refresh":
        refresh(event)
    else:
        raise ValueError(f"unknown hook action: {action}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # The agent must get a chance to diagnose a broken gate.
        if len(sys.argv) == 2 and sys.argv[1] == "stop":
            emit({"decision": "block", "reason": f"The fast test hook failed: {error}"})
        else:
            raise
