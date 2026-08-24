#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Retire agent worktrees separately from their recoverable local branches."""

import json
from pathlib import Path
import subprocess
import time

import github_watch


REGISTRY_NAME = "opnsense-agent-worktrees.json"
WORKTREE_GRACE = 24 * 60 * 60
BRANCH_GRACE = 7 * 24 * 60 * 60
LEASE_TTL = 30 * 60


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


def registry_path(repository):
    return common_git_directory(repository) / REGISTRY_NAME


def load_registry(repository):
    try:
        value = json.loads(registry_path(repository).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        value = {}
    return {"version": 1, "records": dict(value.get("records") or {})}


def save_registry(repository, registry):
    path = registry_path(repository)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def worktrees(repository):
    records = []
    current = None
    for line in git(repository, "worktree", "list", "--porcelain").stdout.splitlines():
        if line.startswith("worktree "):
            if current:
                records.append(current)
            current = {"path": line.removeprefix("worktree "), "branch": ""}
        elif current is not None and line.startswith("branch refs/heads/"):
            current["branch"] = line.removeprefix("branch refs/heads/")
        elif current is not None and line.startswith("HEAD "):
            current["head"] = line.removeprefix("HEAD ")
    if current:
        records.append(current)
    return records


def primary_worktree(repository):
    values = worktrees(repository)
    if not values:
        raise RuntimeError("Git did not report a primary worktree")
    return Path(values[0]["path"]).resolve()


def record_key(path="", branch=""):
    return f"path:{Path(path).resolve()}" if path else f"branch:{branch}"


def register(repository, client="unknown", slug="", managed_by="observed", session_id="", now=None):
    path = Path(repository).resolve()
    if path == primary_worktree(repository):
        return None
    now = time.time() if now is None else now
    registry = load_registry(repository)
    key = record_key(path=str(path))
    record = dict(registry["records"].get(key) or {})
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    head = git_value(repository, "rev-parse", "HEAD")
    identity_changed = bool(record) and (
        record.get("branch") != branch or record.get("head") != head
    )
    if session_id or identity_changed:
        for field in (
            "branch_deleted_at", "cleanup_error", "retire_reason", "retired_at", "waiting_reason",
            "worktree_removed_at",
        ):
            record.pop(field, None)
    record.update({
        "path": str(path),
        "branch": branch,
        "head": head,
        "client": client if client != "unknown" or not record.get("client") else record["client"],
        "slug": slug or record.get("slug") or (branch.rsplit("/", 1)[-1] if branch else path.name),
        "managed_by": record.get("managed_by") or managed_by,
        "created_at": float(record.get("created_at") or now),
        "last_seen_at": now,
    })
    if session_id:
        record["last_session_id"] = session_id
    registry["records"][key] = record
    save_registry(repository, registry)
    return record


def _find_record(registry, target):
    matches = []
    resolved = str(Path(target).resolve()) if "/" in target else ""
    for key, record in registry["records"].items():
        values = {
            key, str(record.get("path") or ""), Path(str(record.get("path") or ".")).name,
            str(record.get("branch") or ""), str(record.get("slug") or ""),
        }
        if target in values or (resolved and resolved in values):
            matches.append((key, record))
    if len(matches) > 1:
        raise RuntimeError(f"cleanup target is ambiguous: {target}")
    return matches[0] if matches else (None, None)


def retire(repository, target, now=None):
    now = time.time() if now is None else now
    registry = load_registry(repository)
    key, record = _find_record(registry, target)
    if record is None:
        live_matches = []
        resolved = str(Path(target).resolve()) if "/" in target else ""
        for value in worktrees(repository)[1:]:
            path = Path(value["path"])
            branch = str(value.get("branch") or "")
            candidates = {str(path), path.name, branch, branch.rsplit("/", 1)[-1] if branch else ""}
            if target in candidates or (resolved and resolved in candidates):
                live_matches.append(value)
        if len(live_matches) > 1:
            raise RuntimeError(f"cleanup target is ambiguous: {target}")
        if live_matches:
            value = live_matches[0]
            key = record_key(path=value["path"])
            branch = str(value.get("branch") or "")
            record = {
                "path": str(Path(value["path"]).resolve()), "branch": branch, "head": value.get("head") or "",
                "client": branch.split("/", 1)[0] if branch else "unknown",
                "slug": branch.rsplit("/", 1)[-1] if branch else Path(value["path"]).name,
                "managed_by": "imported", "created_at": now,
            }
        else:
            branches = git_value(
                repository, "for-each-ref", "--format=%(refname:short)", "refs/heads",
            ).splitlines()
            matches = [branch for branch in branches if target in (branch, branch.rsplit("/", 1)[-1])]
            if len(matches) > 1:
                raise RuntimeError(f"cleanup target is ambiguous: {target}")
            if not matches:
                raise RuntimeError(f"no registered worktree or local branch matches: {target}")
            branch = matches[0]
            key = record_key(branch=branch)
            record = {
                "path": "", "branch": branch, "head": git_value(repository, "rev-parse", branch),
                "client": branch.split("/", 1)[0], "slug": branch.rsplit("/", 1)[-1],
                "managed_by": "imported", "created_at": now,
            }
    record["retired_at"] = now
    record["retire_reason"] = "explicit retirement"
    record.pop("waiting_reason", None)
    registry["records"][key] = record
    save_registry(repository, registry)
    return record


def finish_session(repository, session_id, pull_number=None, now=None):
    record = register(repository, session_id=session_id, now=now)
    if record is None:
        return "control checkout retained"
    now = time.time() if now is None else now
    registry = load_registry(repository)
    key, record = _find_record(registry, str(Path(repository).resolve()))
    record["session_ended_at"] = now
    if git_value(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        record["waiting_reason"] = "dirty worktree"
        record.pop("retired_at", None)
        status = "retained: dirty worktree"
    elif pull_number:
        record["waiting_reason"] = f"pull request #{pull_number} is still open"
        record.pop("retired_at", None)
        status = f"retained: pull request #{pull_number} is still open"
    else:
        record["retired_at"] = now
        record["retire_reason"] = "agent session ended cleanly"
        record.pop("waiting_reason", None)
        status = "queued for cleanup after the safety grace period"
    registry["records"][key] = record
    save_registry(repository, registry)
    return status


def _lease(repository, path):
    import hashlib

    directory = common_git_directory(repository) / "opnsense-agent-leases"
    key = hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()
    try:
        return json.loads((directory / f"{key}.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _dirty_reason(path):
    path = Path(path)
    if not path.is_dir():
        return ""
    status = git_value(path, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        return "tracked or untracked changes"
    ignored = git_value(path, "status", "--porcelain=v1", "--ignored=matching", "--untracked-files=all")
    if ignored:
        return "ignored files"
    return ""


def _publishing_repository(repository):
    origin = git_value(repository, "remote", "get-url", "origin")
    return github_watch.repository_identity(origin)


def _pull_state(repository, canonical_repository, branch, head, reader=None):
    return github_watch.branch_pull_state(
        canonical_repository, _publishing_repository(repository), branch, head, reader=reader,
    )


def _classify(repository, record, canonical_ref, canonical_repository, current_path, now, reader=None):
    value = dict(record)
    path = str(value.get("path") or "")
    branch = str(value.get("branch") or "")
    head = git_value(repository, "rev-parse", branch) if branch else str(value.get("head") or "")
    value["head"] = head
    value["worktree_status"] = "absent" if not path or not Path(path).is_dir() else "present"
    value["branch_status"] = "present" if branch and git_value(repository, "show-ref", "--verify",
                                                                  f"refs/heads/{branch}") else "absent"

    if path and Path(path).resolve() == primary_worktree(repository):
        value.update({"state": "protected", "reason": "primary control checkout"})
        return value
    if path and Path(path).resolve() == current_path:
        value.update({"state": "active", "reason": "current worktree"})
        return value
    if path and Path(path).is_dir():
        lease = _lease(repository, path)
        heartbeat = float(lease.get("heartbeat_at", lease.get("acquired_at", 0)) or 0)
        if lease and not lease.get("released_at") and now - heartbeat <= LEASE_TTL:
            value.update({"state": "active", "reason": "live writer lease"})
            return value
        dirty = _dirty_reason(path)
        if dirty:
            value.update({"state": "blocked", "reason": dirty})
            return value
    retired_at = float(value.get("retired_at") or 0)
    if not retired_at:
        value.update({"state": "retained", "reason": value.get("waiting_reason") or "not retired"})
        return value

    pull = _pull_state(repository, canonical_repository, branch, head, reader=reader) if branch else {
        "state": "unpublished", "number": None, "warning": "",
    }
    value["pull"] = pull
    if pull["state"] in ("open", "closed", "foreign-head", "unknown"):
        reasons = {
            "open": f"pull request #{pull.get('number')} is open",
            "closed": f"pull request #{pull.get('number')} closed without merge",
            "foreign-head": f"pull request #{pull.get('number')} has another head",
            "unknown": pull.get("warning") or "pull-request state is unknown",
        }
        value.update({"state": "retained" if pull["state"] == "open" else "blocked",
                      "reason": reasons[pull["state"]]})
        return value

    age = now - retired_at
    if path and Path(path).is_dir() and age < WORKTREE_GRACE:
        value.update({"state": "grace", "reason": "worktree safety grace period", "ready_in": WORKTREE_GRACE - age})
        return value
    if path and Path(path).is_dir() and not branch:
        recoverable = git(repository, "merge-base", "--is-ancestor", head, canonical_ref, check=False).returncode == 0
        if not recoverable:
            value.update({"state": "blocked", "reason": "detached head is not recoverable from canonical main"})
            return value
    if path and Path(path).is_dir():
        value.update({"state": "worktree-ready", "reason": "clean retired worktree; branch remains recoverable"})
        return value

    if value["branch_status"] == "present" and branch != "main":
        if age < BRANCH_GRACE:
            value.update({"state": "grace", "reason": "local branch safety grace period",
                          "ready_in": BRANCH_GRACE - age})
            return value
        merged_locally = git(
            repository, "merge-base", "--is-ancestor", head, canonical_ref, check=False,
        ).returncode == 0
        if merged_locally or pull["state"] == "merged":
            value.update({"state": "branch-ready", "reason": "branch is recoverable from merged history"})
            return value
    value.update({"state": "retained", "reason": "local branch is not proven merged"})
    return value


def inventory(repository, canonical_ref, canonical_repository, current_path=None, now=None, reader=None):
    now = time.time() if now is None else now
    current_path = Path.cwd().resolve() if current_path is None else Path(current_path).resolve()
    registry = load_registry(repository)
    records = dict(registry["records"])
    for worktree in worktrees(repository)[1:]:
        key = record_key(path=worktree["path"])
        records.setdefault(key, {
            **worktree, "client": "unknown", "slug": Path(worktree["path"]).name,
            "managed_by": "unregistered", "created_at": now,
        })
    registered_branches = {str(value.get("branch") or "") for value in records.values()}
    for branch in git_value(repository, "for-each-ref", "--format=%(refname:short)", "refs/heads").splitlines():
        if branch == "main" or branch in registered_branches:
            continue
        records[record_key(branch=branch)] = {
            "path": "", "branch": branch, "head": git_value(repository, "rev-parse", branch),
            "client": branch.split("/", 1)[0], "slug": branch.rsplit("/", 1)[-1],
            "managed_by": "unregistered", "created_at": now,
        }
    return [
        _classify(repository, record, canonical_ref, canonical_repository, current_path, now, reader=reader)
        for _key, record in sorted(records.items())
    ]


def sweep(repository, canonical_ref, canonical_repository, current_path=None, now=None, reader=None,
          max_removals=None, max_records=None):
    """Remove only registered candidates; remote branches are deliberately outside this function."""
    now = time.time() if now is None else now
    current_path = Path.cwd().resolve() if current_path is None else Path(current_path).resolve()
    registry = load_registry(repository)
    actions = []
    removals = 0
    checked = 0
    for key, record in list(registry["records"].items()):
        if max_records is not None and checked >= max_records:
            break
        checked += 1
        classified = _classify(
            repository, record, canonical_ref, canonical_repository, current_path, now, reader=reader,
        )
        if classified["state"] == "worktree-ready" and (max_removals is None or removals < max_removals):
            path = classified["path"]
            result = git(primary_worktree(repository), "worktree", "remove", "--", path, check=False)
            if result.returncode != 0:
                record["cleanup_error"] = result.stderr.strip() or "git worktree remove failed"
                continue
            record["worktree_removed_at"] = now
            record.pop("cleanup_error", None)
            actions.append(f"removed worktree {path}; local branch retained")
            removals += 1
        elif classified["state"] == "branch-ready" and (max_removals is None or removals < max_removals):
            branch = classified["branch"]
            head = classified["head"]
            result = git(
                repository, "update-ref", "-d", f"refs/heads/{branch}", head, check=False,
            )
            if result.returncode != 0:
                record["cleanup_error"] = result.stderr.strip() or "local branch deletion failed"
                continue
            record["branch_deleted_at"] = now
            record.pop("cleanup_error", None)
            actions.append(f"deleted merged local branch {branch}; no remote branch was changed")
            removals += 1
        registry["records"][key] = record
    save_registry(repository, registry)
    return actions
