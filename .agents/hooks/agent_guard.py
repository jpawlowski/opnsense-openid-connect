#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Keep local agent writers in one owned worktree without blocking inspection."""

import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

import worktree_cleanup


LEASE_TTL = 30 * 60
READ_ONLY_PROGRAMS = {
    "cat", "file", "head", "ls", "pwd", "rg", "stat", "tail", "true", "wc", "which",
}
READ_ONLY_GIT = {
    "describe", "diff", "grep", "log", "ls-files", "merge-base", "name-rev", "rev-list", "rev-parse",
    "show", "status",
}
READ_ONLY_GIT_CONFIG = {"--get", "--get-all", "--get-regexp", "--list", "-l"}
READ_ONLY_GIT_BRANCH = {"--contains", "--list", "--points-at", "--show-current"}


def git(repository, *arguments, check=True):
    return subprocess.run(
        ("git", *arguments), cwd=repository, check=check, capture_output=True, text=True,
    )


def git_value(repository, *arguments):
    result = git(repository, *arguments, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def resolve_git_path(repository, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


def common_git_directory(repository):
    return resolve_git_path(repository, git_value(repository, "rev-parse", "--git-common-dir"))


def is_primary_worktree(repository):
    git_directory = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-dir"))
    return git_directory == common_git_directory(repository)


def clean(repository):
    return not git_value(repository, "status", "--porcelain=v1", "--untracked-files=all")


def lease_directory(repository):
    return common_git_directory(repository) / "opnsense-agent-leases"


def lease_path(repository):
    key = hashlib.sha256(str(repository.resolve()).encode()).hexdigest()
    return lease_directory(repository) / f"{key}.json"


def read_lease(repository):
    try:
        return json.loads(lease_path(repository).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_lease(repository, value):
    directory = lease_directory(repository)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = lease_path(repository)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def acquire_lease(repository, session_id, now=None):
    """Return an empty refusal when this session exclusively owns the worktree."""
    if not session_id:
        return "A writing agent needs a session identifier before it may own this worktree."

    now = time.time() if now is None else now
    current = read_lease(repository)
    if current.get("session_id") == session_id:
        current.pop("released_at", None)
        current["heartbeat_at"] = now
        write_lease(repository, current)
        worktree_cleanup.register(repository, session_id=session_id, now=now)
        return ""

    if current:
        heartbeat = float(current.get("heartbeat_at", current.get("acquired_at", 0)))
        released = bool(current.get("released_at"))
        if not clean(repository) or (not released and now - heartbeat <= LEASE_TTL):
            owner = str(current.get("session_id", "unknown"))[:12]
            return (
                f"This worktree is owned by another writing task ({owner}). Resume that task or use a separate "
                "worktree; a dirty worktree is never taken over automatically."
            )

    if not clean(repository):
        return (
            "This worktree already contains unowned changes. Resume the task that created them or hand them over "
            "deliberately before another agent writes here."
        )

    write_lease(repository, {
        "session_id": session_id,
        "worktree": str(repository.resolve()),
        "acquired_at": now,
        "heartbeat_at": now,
    })
    worktree_cleanup.register(repository, session_id=session_id, now=now)
    return ""


def release_lease(repository, session_id):
    current = read_lease(repository)
    if current.get("session_id") != session_id:
        return
    if not clean(repository):
        current["released_at"] = time.time()
        write_lease(repository, current)
        return
    try:
        lease_path(repository).unlink()
    except FileNotFoundError:
        pass


def leases(repository):
    directory = lease_directory(repository)
    if not directory.is_dir():
        return []
    records = []
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return records


def event_command(event):
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return ""
    return str(tool_input.get("command") or tool_input.get("cmd") or "")


def _read_only_git(arguments):
    if not arguments:
        return False
    command, rest = arguments[0], arguments[1:]
    if command in READ_ONLY_GIT:
        return not any(argument == "--output" or argument.startswith("--output=") for argument in rest)
    if command == "branch":
        mutations = {
            "-c", "-C", "-d", "-D", "-m", "-M", "--copy", "--delete", "--edit-description", "--move",
            "-f", "--force", "--set-upstream-to", "--unset-upstream",
        }
        return bool(READ_ONLY_GIT_BRANCH & set(rest)) and not mutations.intersection(rest)
    if command == "config":
        mutations = {
            "--add", "--edit", "-e", "--remove-section", "--rename-section", "--replace-all", "--unset",
            "--unset-all",
        }
        return bool(READ_ONLY_GIT_CONFIG & set(rest)) and not mutations.intersection(rest)
    if command == "remote":
        if rest == ["-v"]:
            return True
        if rest and rest[0] == "get-url":
            return all(value in ("--all", "--push") or not value.startswith("-") for value in rest[1:])
        if rest and rest[0] == "show":
            return all(value == "-n" or not value.startswith("-") for value in rest[1:])
        return False
    if command == "worktree":
        return bool(rest) and rest[0] == "list"
    return False


def _read_only_find(arguments):
    dangerous = {
        "-delete", "-exec", "-execdir", "-fls", "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir",
    }
    return not any(argument.split("=", 1)[0] in dangerous for argument in arguments)


def _read_only_sed(arguments):
    values = list(arguments)
    while values and values[0] in ("-n", "--quiet", "--silent"):
        values.pop(0)
    if len(values) < 2 or any(value.startswith("-") for value in values[1:]):
        return False
    # sed can write through its command language (`w`) or execute a command
    # (`e`) without using --in-place. Only the small line-printing grammar used
    # for inspection is safe enough for the control checkout.
    return bool(re.fullmatch(r"(?:\d+(?:,\d+)?|\$)?[pq]", values[0]))


def _worktree_helper(arguments):
    if len(arguments) < 2:
        return False
    script = arguments[0].replace("\\", "/")
    return script.endswith(".agents/worktrees.py") and arguments[1] in (
        "audit", "create", "list", "retire", "sweep",
    )


def _hook_control(arguments):
    if len(arguments) < 2:
        return False
    script = arguments[0].replace("\\", "/")
    return script.endswith(".agents/hooks/fast_gate.py") and arguments[1] in (
        "acknowledge-main", "refresh", "watch",
    )


def _issue_helper(arguments):
    if len(arguments) < 2:
        return False
    script = arguments[0].replace("\\", "/")
    return script.endswith(".agents/issues.py") and arguments[1] in (
        "adopt-pr", "claim", "linked", "release",
    )


def _read_only_gh(arguments):
    if len(arguments) >= 2 and arguments[0] in ("issue", "pr", "repo", "run"):
        read_actions = {
            "issue": {"list", "status", "view"},
            "pr": {"checks", "diff", "list", "status", "view"},
            "repo": {"list", "view"},
            "run": {"list", "view", "watch"},
        }
        return arguments[1] in read_actions[arguments[0]]
    if arguments and arguments[0] == "search":
        return True
    if arguments and arguments[0] == "api":
        mutations = ("--field", "-f", "--input", "--raw-field", "-F")
        if any(
            value == option or value.startswith(f"{option}=")
            or (option in ("-f", "-F") and value.startswith(option) and value != option)
            for value in arguments[1:] for option in mutations
        ):
            return False
        for index, value in enumerate(arguments[1:]):
            if value in ("--method", "-X"):
                try:
                    return arguments[index + 2].upper() in ("GET", "HEAD")
                except IndexError:
                    return False
            if value.startswith("--method="):
                return value.partition("=")[2].upper() in ("GET", "HEAD")
            if value.startswith("-X") and value != "-X":
                return value[2:].upper() in ("GET", "HEAD")
        return True
    return False


def _shell_invocation(command):
    if not command.strip() or re.search(r"[;&|<>`]", command) or "$(" in command:
        return "", []
    try:
        arguments = shlex.split(command)
    except ValueError:
        return "", []
    while arguments and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", arguments[0]):
        arguments.pop(0)
    if not arguments:
        return "", []

    program = Path(arguments.pop(0)).name
    if program == "env":
        while arguments and (arguments[0].startswith("-") or "=" in arguments[0]):
            arguments.pop(0)
        if not arguments:
            return "", []
        program = Path(arguments.pop(0)).name
    return program, arguments


def is_read_only_shell(command):
    """Accept a deliberately small grammar; ambiguity belongs in an isolated worktree."""
    program, arguments = _shell_invocation(command)
    if not program:
        return False
    if program in READ_ONLY_PROGRAMS:
        return True
    if program == "find":
        return _read_only_find(arguments)
    if program == "sed":
        return _read_only_sed(arguments)
    if program == "git":
        return _read_only_git(arguments)
    if program == "gh":
        return _read_only_gh(arguments)
    if program in ("python", "python3"):
        return _worktree_helper(arguments) or _hook_control(arguments) or _issue_helper(arguments)
    return False


def is_issue_bootstrap(event):
    """Allow the public coordination record to exist before repository writes begin."""
    if str(event.get("tool_name") or "") != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    return bool(program == "gh" and len(arguments) >= 2
                and arguments[0] == "issue" and arguments[1] == "create")


def requires_uncached_remote(event):
    """Identify publication boundaries whose remote view must never come from the active-work cache."""
    tool = str(event.get("tool_name") or "")
    if tool.lower() == "handoff":
        return True
    if tool != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    return bool(
        (program == "git" and arguments and arguments[0] in ("push", "send-pack"))
        or (program == "gh" and not _read_only_gh(arguments))
    )


def requires_topic_branch(event):
    """Keep a managed detached worktree valid until it creates durable Git or GitHub state."""
    if str(event.get("tool_name") or "") != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    return bool(
        (program == "git" and arguments and arguments[0] in ("commit", "push", "send-pack"))
        or (program == "gh" and not _read_only_gh(arguments))
    )


def is_read_only_agent(event):
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return False
    message = str(tool_input.get("message") or tool_input.get("prompt") or "")
    return "[read-only]" in message.lower()


def tool_requires_write(event):
    tool = str(event.get("tool_name") or "")
    if tool == "Bash":
        return not is_read_only_shell(event_command(event))
    return tool in ("apply_patch", "Edit", "Write", "Handoff")


def blocked(reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
