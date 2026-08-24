#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Publish and retain one machine-readable implementation claim per worktree."""

import json
from pathlib import Path
import re
import secrets
import subprocess
import time


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
CLAIM_PREFIX = "wip:"
CLAIM_COLOR = "5319e7"
CLAIM_PATTERN = re.compile(r"<!-- contribution-work-claim:([a-z0-9-]+) -->")
LEGACY_MARKER = "<!-- contribution-work-claim -->"
CLAIM_TEXT = {
    "en": (
        "I am working on this now. This note will be removed when the pull request is linked.",
        "*An AI agent wrote this text on my behalf; I am responsible for its content.*",
    ),
    "de": (
        "Ich arbeite jetzt daran. Dieser Hinweis wird entfernt, sobald der Pull Request verknüpft ist.",
        "*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*",
    ),
}


def git_value(repository, *arguments):
    result = subprocess.run(
        ("git", *arguments), cwd=repository, check=False, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def resolve_git_path(repository, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


def registry_path(repository):
    common = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-common-dir"))
    return common / "opnsense-agent-issue-claims.json"


def load_registry(repository):
    try:
        value = json.loads(registry_path(repository).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        value = {}
    return {"version": 1, "claims": dict(value.get("claims") or {})}


def save_registry(repository, registry):
    path = registry_path(repository)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def worktree_key(repository):
    return str(Path(repository).resolve())


def marker_path(repository):
    git_directory = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-dir"))
    return git_directory / "opnsense-agent-issue-claim"


def write_marker(repository, token):
    path = marker_path(repository)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(str(token), encoding="utf-8")
    temporary.replace(path)


def remove_marker(repository):
    try:
        marker_path(repository).unlink()
    except FileNotFoundError:
        pass


def current_claim(repository):
    record = (load_registry(repository).get("claims") or {}).get(worktree_key(repository))
    if not record or not record.get("worktree_marker"):
        return None
    try:
        token = marker_path(repository).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return record if token == str(record.get("token") or "") else None


def _gh(arguments, json_output=False):
    try:
        result = subprocess.run(
            ("gh", *arguments), check=False, capture_output=True, text=True, timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"GitHub claim operation is unavailable: {error}") from error
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "GitHub claim operation failed")
    return json.loads(result.stdout) if json_output else result.stdout.strip()


def _issue(number):
    return _gh((
        "issue", "view", str(number), "--repo", CANONICAL_REPOSITORY,
        "--json", "number,state,labels,comments,assignees,url",
    ), json_output=True)


def _markers(issue):
    values = []
    for comment in issue.get("comments") or []:
        body = str(comment.get("body") or "")
        match = CLAIM_PATTERN.search(body)
        if match or LEGACY_MARKER in body:
            values.append({
                "token": match.group(1) if match else "legacy",
                "id": comment.get("id"),
                "url": comment.get("url"),
                "created_at": comment.get("createdAt") or "",
            })
    return sorted(values, key=lambda value: (value["created_at"], value["token"]))


def _delete_comment(comment_id):
    if not comment_id:
        return
    _gh((
        "api", "graphql", "-f",
        "query=mutation($id:ID!){deleteIssueComment(input:{id:$id}){clientMutationId}}",
        "-f", f"id={comment_id}",
    ))


def _claim_labels(issue):
    return sorted(
        str(value.get("name") or value)
        for value in issue.get("labels") or []
        if str(value.get("name") or value).startswith(CLAIM_PREFIX)
    )


def _delete_label(label):
    if not label:
        return
    try:
        _gh(("label", "delete", label, "--repo", CANONICAL_REPOSITORY, "--yes"))
    except RuntimeError:
        # A contributor may own the comment but lack permission to manage the
        # repository label. The marker remains sufficient for coordination.
        pass


def _remove_claim_label(number, label):
    if not label:
        return
    try:
        issue = _issue(number)
        if label in _claim_labels(issue):
            try:
                _gh(("issue", "edit", str(number), "--repo", CANONICAL_REPOSITORY,
                     "--remove-label", label))
            except RuntimeError:
                pass
    finally:
        _delete_label(label)


def claim(repository, number, now=None, language="en"):
    """Claim one open issue, resolving a simultaneous race by the unique WIP id."""
    existing = current_claim(repository)
    if existing and int(existing.get("issue", 0)) == int(number) and existing.get("status") == "active":
        return existing
    if existing:
        raise RuntimeError(
            f"this worktree already owns issue #{existing.get('issue')}; link or release that claim first"
        )
    issue = _issue(number)
    if str(issue.get("state") or "").upper() != "OPEN":
        raise RuntimeError(f"issue #{number} is not open")
    markers = _markers(issue)
    labels = _claim_labels(issue)
    if markers:
        raise RuntimeError(f"issue #{number} already has an active agent claim: {markers[0].get('url')}")
    if labels:
        raise RuntimeError(f"issue #{number} already has an agent claim ({labels[0]}); inspect it manually")

    login = _gh(("api", "user", "--jq", ".login"))
    claimed_at = time.time() if now is None else now
    token = f"{int(claimed_at)}-{secrets.token_hex(4)}"
    label = f"{CLAIM_PREFIX}{token}"
    try:
        _gh(("label", "create", label, "--repo", CANONICAL_REPOSITORY,
             "--color", CLAIM_COLOR, "--description", "Temporary exclusive agent work claim", "--force"))
        _gh(("issue", "edit", str(number), "--repo", CANONICAL_REPOSITORY,
             "--add-label", label, "--add-assignee", login))
    except RuntimeError:
        # Fork contributors may lack triage permission; the unique comment is
        # still a visible, machine-readable lock that every agent must honor.
        pass
    work_note, notice = CLAIM_TEXT[language]
    body = (
        f"<!-- contribution-work-claim:{token} -->\n"
        f"{work_note}\n\n"
        f"{notice}"
    )
    try:
        _gh(("issue", "comment", str(number), "--repo", CANONICAL_REPOSITORY, "--body", body))
    except RuntimeError:
        _remove_claim_label(number, label)
        raise
    markers = _markers(_issue(number))
    ours = next((value for value in markers if value["token"] == token), None)
    if ours is None:
        _remove_claim_label(number, label)
        raise RuntimeError("the issue claim comment could not be verified")
    issue = _issue(number)
    contenders = sorted({value["token"] for value in markers} | {
        value.removeprefix(CLAIM_PREFIX) for value in _claim_labels(issue)
    })
    if contenders[0] != token:
        try:
            _delete_comment(ours["id"])
        finally:
            _remove_claim_label(number, label)
        winner = next((value for value in markers if value["token"] == contenders[0]), None)
        raise RuntimeError(f"another agent won the issue claim race: {(winner or {}).get('url') or contenders[0]}")

    registry = load_registry(repository)
    record = {
        "issue": int(number), "token": token, "comment_id": ours["id"], "comment_url": ours["url"],
        "label": label, "login": login, "status": "active", "claimed_at": claimed_at,
        "worktree_marker": True,
    }
    write_marker(repository, token)
    registry["claims"][worktree_key(repository)] = record
    save_registry(repository, registry)
    return record


def _closing_issue(body):
    match = re.search(r"(?im)^\s*Fixes\s+#(\d+)\s*$", str(body or ""))
    return int(match.group(1)) if match else None


def linked(repository, pull_number):
    record = current_claim(repository)
    if not record:
        raise RuntimeError("this worktree has no issue claim")
    pull = _gh((
        "pr", "view", str(pull_number), "--repo", CANONICAL_REPOSITORY,
        "--json", "number,state,body,headRefName,headRefOid,url",
    ), json_output=True)
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    head = git_value(repository, "rev-parse", "HEAD")
    if str(pull.get("state") or "").upper() != "OPEN":
        raise RuntimeError(f"pull request #{pull_number} is not open")
    if pull.get("headRefName") != branch or pull.get("headRefOid") != head:
        raise RuntimeError(f"pull request #{pull_number} does not use this worktree's exact branch head")
    if _closing_issue(pull.get("body")) != int(record["issue"]):
        raise RuntimeError(f"pull request #{pull_number} does not close issue #{record['issue']}")
    try:
        _delete_comment(record.get("comment_id"))
    finally:
        _remove_claim_label(record["issue"], record.get("label"))
    registry = load_registry(repository)
    record.update({"status": "pr-linked", "pull_request": int(pull_number), "comment_id": ""})
    registry["claims"][worktree_key(repository)] = record
    save_registry(repository, registry)
    return record


def adopt_pull_request(repository, pull_number):
    pull = _gh((
        "pr", "view", str(pull_number), "--repo", CANONICAL_REPOSITORY,
        "--json", "number,state,body,headRefName,headRefOid,url",
    ), json_output=True)
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    head = git_value(repository, "rev-parse", "HEAD")
    issue = _closing_issue(pull.get("body"))
    if (str(pull.get("state") or "").upper() != "OPEN" or not issue
            or pull.get("headRefName") != branch or pull.get("headRefOid") != head):
        raise RuntimeError("the open pull request must close one issue and use this worktree's exact branch head")
    registry = load_registry(repository)
    record = {
        "issue": issue, "token": f"pr-{secrets.token_hex(6)}", "status": "pr-linked",
        "pull_request": int(pull_number), "adopted_at": time.time(), "worktree_marker": True,
    }
    write_marker(repository, record["token"])
    registry["claims"][worktree_key(repository)] = record
    save_registry(repository, registry)
    return record


def release(repository, remove_assignee=True):
    record = current_claim(repository)
    if not record:
        return None
    try:
        if record.get("comment_id"):
            _delete_comment(record["comment_id"])
    finally:
        _remove_claim_label(record["issue"], record.get("label"))
    if remove_assignee and record.get("login"):
        try:
            _gh(("issue", "edit", str(record["issue"]), "--repo", CANONICAL_REPOSITORY,
                 "--remove-assignee", record["login"]))
        except RuntimeError:
            pass
    registry = load_registry(repository)
    registry["claims"].pop(worktree_key(repository), None)
    save_registry(repository, registry)
    remove_marker(repository)
    return record


def forget(repository, worktree=None):
    """Drop a completed PR-linked local record after its public claim was already removed."""
    registry = load_registry(repository)
    record = registry["claims"].pop(worktree_key(repository if worktree is None else worktree), None)
    save_registry(repository, registry)
    if worktree is None:
        remove_marker(repository)
    return record
