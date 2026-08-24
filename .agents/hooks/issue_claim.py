#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Publish and retain one machine-readable implementation claim per worktree."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from urllib.parse import urlparse


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
CLAIM_PREFIX = "wip:"
LOCK_PREFIX = "wip-lock:issue-"
CLAIM_COLOR = "5319e7"
CLAIM_PATTERN = re.compile(r"<!-- contribution-work-claim:([a-z0-9-]+) -->")
COMMENT_URL_PATTERN = re.compile(r"#issuecomment-(\d+)$")
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


def github_repository(url):
    """Return owner/name only for an unambiguous GitHub remote URL."""
    value = str(url or "").strip()
    if re.match(r"^[^/@:]+@github\.com:", value):
        path = value.split(":", 1)[1]
    else:
        parsed = urlparse(value)
        if parsed.hostname != "github.com":
            return ""
        path = parsed.path
    repository = path.strip("/").removesuffix(".git")
    return repository if repository.count("/") == 1 else ""


def pull_head_repository(pull):
    value = pull.get("headRepository")
    if isinstance(value, dict):
        name_with_owner = value.get("nameWithOwner")
        if name_with_owner:
            return str(name_with_owner)
        owner = value.get("owner") or {}
        owner_name = owner.get("login") if isinstance(owner, dict) else owner
        if owner_name and value.get("name"):
            return f"{owner_name}/{value['name']}"
        return ""
    return str(value or "")


def resolve_git_path(repository, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


def registry_path(repository):
    common = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-common-dir"))
    return common / "opnsense-agent-issue-claims.json"


@contextmanager
def registry_lock(repository):
    path = registry_path(repository).with_suffix(".lock")
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _load_registry(repository):
    try:
        value = json.loads(registry_path(repository).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        value = {}
    return {"version": 1, "claims": dict(value.get("claims") or {})}


def load_registry(repository):
    with registry_lock(repository):
        return _load_registry(repository)


def _save_registry(repository, registry):
    path = registry_path(repository)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(registry, sort_keys=True))
        temporary.replace(path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def save_registry(repository, registry):
    with registry_lock(repository):
        _save_registry(repository, registry)


def update_registry(repository, update):
    """Apply one claim-registry read-modify-write while all worktrees are serialized."""
    with registry_lock(repository):
        registry = _load_registry(repository)
        result = update(registry)
        _save_registry(repository, registry)
        return result


def worktree_key(repository):
    return str(Path(repository).resolve())


def marker_path(repository):
    git_directory = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-dir"))
    return git_directory / "opnsense-agent-issue-claim"


@contextmanager
def worktree_claim_lock(repository):
    # The shared registry lock protects one local file update, while a claim
    # publishes several remote and local artifacts. Keep that whole transition
    # exclusive for this worktree without serializing claims in other worktrees.
    path = marker_path(repository).with_suffix(".lock")
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
    if token != str(record.get("token") or ""):
        return None
    if record.get("status") == "pr-linked":
        branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
        bound_head = str(record.get("head") or "")
        if branch != record.get("branch") or not bound_head:
            return None
        if subprocess.run(
            ("git", "merge-base", "--is-ancestor", bound_head, "HEAD"), cwd=repository,
            check=False, capture_output=True, text=True,
        ).returncode != 0:
            return None
    return record


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
        "--json", "number,state,labels,comments,assignees,closedByPullRequestsReferences,url",
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
    if str(comment_id).isdigit():
        _gh(("api", "-X", "DELETE", f"repos/{CANONICAL_REPOSITORY}/issues/comments/{comment_id}"))
        return
    try:
        _gh((
            "api", "graphql", "-f",
            "query=mutation($id:ID!){deleteIssueComment(input:{id:$id}){clientMutationId}}",
            "-f", f"id={comment_id}",
        ))
    except RuntimeError as error:
        if "could not resolve to a node" not in str(error).lower():
            raise


def _claim_labels(issue):
    return sorted(
        str(value.get("name") or value)
        for value in issue.get("labels") or []
        if str(value.get("name") or value).startswith(CLAIM_PREFIX)
    )


def _linked_open_pull(issue):
    for reference in issue.get("closedByPullRequestsReferences") or []:
        number = reference.get("number")
        if not number:
            continue
        try:
            pull = _gh((
                "pr", "view", str(number), "--repo", CANONICAL_REPOSITORY,
                "--json", "number,state,url",
            ), json_output=True)
        except RuntimeError:
            return {"number": number, "state": "UNKNOWN"}
        if str(pull.get("state") or "").upper() == "OPEN":
            return pull
    return None


def _lock_label(number):
    return f"{LOCK_PREFIX}{int(number)}"


def _acquire_lock(number, token):
    label = _lock_label(number)
    try:
        _gh((
            "api", f"repos/{CANONICAL_REPOSITORY}/labels",
            "-f", f"name={label}", "-f", f"color={CLAIM_COLOR}",
            "-f", f"description=Exclusive agent claim {token}",
        ), json_output=True)
    except RuntimeError as error:
        raise RuntimeError(
            f"issue #{number} already has an atomic work lock ({label}); inspect it before takeover"
        ) from error
    return label


def _delete_label(label):
    if not label:
        return
    try:
        _gh(("label", "delete", label, "--repo", CANONICAL_REPOSITORY, "--yes"))
    except RuntimeError as error:
        if "not found" not in str(error).lower() and "could not resolve" not in str(error).lower():
            raise


def _remove_claim_labels(label, lock_label):
    errors = []
    for value in (label, lock_label):
        if not value:
            continue
        try:
            _delete_label(value)
        except RuntimeError as error:
            errors.append(str(error))
    if errors:
        raise RuntimeError("claim label cleanup failed: " + "; ".join(errors))


def _available_issue(issue):
    number = issue.get("number")
    if str(issue.get("state") or "").upper() != "OPEN":
        raise RuntimeError(f"issue #{number} is not open")
    markers = _markers(issue)
    labels = _claim_labels(issue)
    pull = _linked_open_pull(issue)
    if markers:
        raise RuntimeError(f"issue #{number} already has an active agent claim: {markers[0].get('url')}")
    if labels:
        raise RuntimeError(f"issue #{number} already has an agent claim ({labels[0]}); inspect it manually")
    if pull:
        raise RuntimeError(
            f"issue #{number} has linked pull request #{pull.get('number')} in state {pull.get('state')}; "
            "inspect it before claiming"
        )


def _claim(repository, number, now=None, language="en"):
    """Claim one open issue through an atomic label-definition lock."""
    existing = current_claim(repository)
    if existing and int(existing.get("issue", 0)) == int(number) and existing.get("status") == "active":
        return existing
    if existing:
        raise RuntimeError(
            f"this worktree already owns issue #{existing.get('issue')}; link or release that claim first"
        )
    _available_issue(_issue(number))

    login = _gh(("api", "user", "--jq", ".login"))
    claimed_at = time.time() if now is None else now
    token = f"{int(claimed_at)}-{secrets.token_hex(4)}"
    label = f"{CLAIM_PREFIX}{token}"
    lock_label = _acquire_lock(number, token)
    label_created = False
    comment_id = ""
    assignee_added = False
    record = None
    try:
        # A contender may have paused before acquiring the atomic label. Check
        # the issue again only after this task owns that cross-clone mutex.
        locked_issue = _issue(number)
        _available_issue(locked_issue)
        already_assigned = any(
            str(value.get("login") or value) == login for value in locked_issue.get("assignees") or []
        )
        _gh(("label", "create", label, "--repo", CANONICAL_REPOSITORY,
             "--color", CLAIM_COLOR, "--description", "Temporary exclusive agent work claim"))
        label_created = True
        _gh(("issue", "edit", str(number), "--repo", CANONICAL_REPOSITORY,
             "--add-label", label, "--add-assignee", login))
        assignee_added = not already_assigned
        work_note, notice = CLAIM_TEXT[language]
        body = (
            f"<!-- contribution-work-claim:{token} -->\n"
            f"{work_note}\n\n"
            f"{notice}"
        )
        comment_output = _gh((
            "issue", "comment", str(number), "--repo", CANONICAL_REPOSITORY, "--body", body,
        ))
        published_comment = COMMENT_URL_PATTERN.search(comment_output)
        comment_id = published_comment.group(1) if published_comment else ""
        markers = _markers(_issue(number))
        ours = next((value for value in markers if value["token"] == token), None)
        if ours is None:
            raise RuntimeError("the issue claim comment could not be verified")
        comment_id = ours["id"]
        issue = _issue(number)
        foreign = [value for value in _markers(issue) if value["token"] != token]
        labels = [value for value in _claim_labels(issue) if value != label]
        if foreign or labels or _linked_open_pull(issue):
            raise RuntimeError("the issue changed while its public claim was being published; inspect it manually")
        record = {
            "issue": int(number), "token": token, "comment_id": ours["id"], "comment_url": ours["url"],
            "label": label, "lock_label": lock_label, "login": login, "assignee_added": assignee_added,
            "status": "active", "claimed_at": claimed_at,
            "worktree_marker": True,
        }
        write_marker(repository, token)

        def store(registry):
            key = worktree_key(repository)
            if registry["claims"].get(key):
                raise RuntimeError("this worktree acquired another claim while the public claim was being published")
            registry["claims"][key] = record

        update_registry(repository, store)
    except RuntimeError:
        remove_marker(repository)
        try:
            if comment_id:
                _delete_comment(comment_id)
        finally:
            try:
                _remove_claim_labels(label if label_created else "", lock_label)
            finally:
                if assignee_added:
                    _gh((
                        "issue", "edit", str(number), "--repo", CANONICAL_REPOSITORY,
                        "--remove-assignee", login,
                    ))
        raise
    return record


def claim(repository, number, now=None, language="en"):
    """Claim one open issue while serializing publication for this worktree."""
    with worktree_claim_lock(repository):
        return _claim(repository, number, now=now, language=language)


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
        _remove_claim_labels(record.get("label"), record.get("lock_label"))
    def store(registry):
        current = registry["claims"].get(worktree_key(repository))
        if not current or current.get("token") != record.get("token"):
            raise RuntimeError("the local issue claim changed while the pull request was being linked")
        current.update({
            "status": "pr-linked", "pull_request": int(pull_number), "comment_id": "",
            "branch": branch, "head": head,
        })
        return current

    record = update_registry(repository, store)
    return record


def adopt_pull_request(repository, pull_number):
    if (load_registry(repository).get("claims") or {}).get(worktree_key(repository)):
        raise RuntimeError(
            "this worktree already owns an issue or pull request; link or release that claim before adoption"
        )
    pull = _gh((
        "pr", "view", str(pull_number), "--repo", CANONICAL_REPOSITORY,
        "--json", "number,state,body,headRefName,headRefOid,headRepository,url",
    ), json_output=True)
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    head = git_value(repository, "rev-parse", "HEAD")
    issue = _closing_issue(pull.get("body"))
    publishing_repository = github_repository(git_value(repository, "remote", "get-url", "origin"))
    head_repository = pull_head_repository(pull)
    if (str(pull.get("state") or "").upper() != "OPEN" or not issue
            or pull.get("headRefName") != branch or pull.get("headRefOid") != head
            or not publishing_repository or head_repository.lower() != publishing_repository.lower()):
        raise RuntimeError(
            "the open pull request must close one issue and use this worktree's exact publishing repository, "
            "branch and head"
        )
    record = {
        "issue": issue, "token": f"pr-{secrets.token_hex(6)}", "status": "pr-linked",
        "pull_request": int(pull_number), "branch": branch, "head": head,
        "adopted_at": time.time(), "worktree_marker": True,
    }
    write_marker(repository, record["token"])
    try:
        def store(registry):
            key = worktree_key(repository)
            if registry["claims"].get(key):
                raise RuntimeError("this worktree acquired another claim while the pull request was being adopted")
            registry["claims"][key] = record

        update_registry(repository, store)
    except RuntimeError:
        remove_marker(repository)
        raise
    return record


def release(repository, remove_assignee=True):
    record = current_claim(repository)
    if not record:
        return None
    try:
        if record.get("comment_id"):
            _delete_comment(record["comment_id"])
    finally:
        _remove_claim_labels(record.get("label"), record.get("lock_label"))
    if remove_assignee and record.get("login") and record.get("assignee_added"):
        try:
            _gh(("issue", "edit", str(record["issue"]), "--repo", CANONICAL_REPOSITORY,
                 "--remove-assignee", record["login"]))
        except RuntimeError:
            pass
    update_registry(repository, lambda registry: registry["claims"].pop(worktree_key(repository), None))
    remove_marker(repository)
    return record


def forget(repository, worktree=None):
    """Drop a completed PR-linked local record after its public claim was already removed."""
    key = worktree_key(repository if worktree is None else worktree)
    record = update_registry(repository, lambda registry: registry["claims"].pop(key, None))
    if worktree is None:
        remove_marker(repository)
    return record
