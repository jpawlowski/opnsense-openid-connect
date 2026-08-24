#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Read pull-request drift without performing any GitHub mutation."""

import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pr_coordination


GITHUB_TIMEOUT = 5
PR_REFRESH_TTL = 10 * 60
USER_AGENT = "opnsense-openid-connect-agent-watch"
CODEX_REVIEWERS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}
REVIEWED_COMMIT = re.compile(r"\*\*Reviewed commit:\*\*\s*`([0-9a-f]{7,40})`", re.I)


def git(repository, *arguments, check=True):
    return subprocess.run(
        ("git", *arguments), cwd=repository, check=check, capture_output=True, text=True,
    )


def git_value(repository, *arguments):
    result = git(repository, *arguments, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def github_token(environment=None):
    environment = os.environ if environment is None else environment
    configured = environment.get("GITHUB_TOKEN") or environment.get("GH_TOKEN")
    if configured:
        return configured
    try:
        result = subprocess.run(
            ("gh", "auth", "token"), check=False, capture_output=True, text=True, timeout=GITHUB_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def github_request(repository, path, token=""):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(f"{api}/repos/{repository}/{path.lstrip('/')}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", USER_AGENT)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
            return json.load(response)
    except HTTPError as error:
        raise ValueError(f"GitHub state could not be read (HTTP {error.code})") from error
    except URLError as error:
        raise ValueError(f"GitHub state could not be read ({error.reason})") from error


def github_graphql(owner, name, number, token):
    if not token:
        return None
    api = os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql")
    query = """
      query($owner: String!, $name: String!, $number: Int!, $after: String) {
        repository(owner: $owner, name: $name) {
          pullRequest(number: $number) {
            reviewThreads(first: 100, after: $after) {
              nodes { isResolved }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }
    """
    unresolved = 0
    after = None
    for _page in range(10):
        body = json.dumps({
            "query": query,
            "variables": {"owner": owner, "name": name, "number": number, "after": after},
        }).encode()
        request = Request(api, data=body, method="POST")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", USER_AGENT)
        try:
            with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
                value = json.load(response)
            threads = value["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = threads["nodes"]
            page = threads["pageInfo"]
        except (HTTPError, URLError, KeyError, TypeError):
            return None
        unresolved += sum(not bool(node.get("isResolved")) for node in nodes)
        if not page.get("hasNextPage"):
            return unresolved
        after = page.get("endCursor")
        if not after:
            return None
    return None


def cache_path(common_directory):
    return common_directory / "opnsense-agent-pr-watch.json"


def load_cache(common_directory):
    try:
        return json.loads(cache_path(common_directory).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_cache(common_directory, value):
    path = cache_path(common_directory)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def _pull_files(repository, number, token, reader):
    files = set()
    for page in range(1, 11):
        path = f"pulls/{number}/files?{urlencode({'per_page': 100, 'page': page})}"
        values = reader(repository, path, token)
        files.update(str(value.get("filename")) for value in values if value.get("filename"))
        if len(values) < 100:
            return sorted(files), False
    return sorted(files), True


def _paged(repository, path, token, reader):
    values = []
    for page in range(1, 11):
        separator = "&" if "?" in path else "?"
        page_path = f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}"
        batch = reader(repository, page_path, token)
        values.extend(batch)
        if len(batch) < 100:
            return values
    raise ValueError(f"GitHub response for {path} exceeded the supported pagination bound")


def _commented_codex_reviews(comments):
    values = []
    for comment in comments:
        login = str((comment.get("user") or {}).get("login") or "").lower()
        match = REVIEWED_COMMIT.search(str(comment.get("body") or ""))
        if login not in CODEX_REVIEWERS or not match:
            continue
        values.append((
            str(comment.get("created_at") or ""),
            int(comment.get("id") or 0),
            match.group(1).lower(),
        ))
    return values


def _review_decision(reviews, head_sha, comments=None, author=""):
    decisions = {}
    submissions = []
    for review in reviews:
        user = str((review.get("user") or {}).get("login") or "")
        state = str(review.get("state") or "").upper()
        if user and user.lower() != author.lower() \
                and state in ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"):
            value = (
                state,
                str(review.get("commit_id") or ""),
                int(review.get("id") or 0),
                str(review.get("submitted_at") or ""),
            )
            submissions.append(value)
            if state != "COMMENTED":
                previous = decisions.get(user)
                if previous is None or (value[3], value[2]) >= (previous[3], previous[2]):
                    decisions[user] = value
    current_decisions = [value for value in decisions.values() if value[1] == head_sha]
    states = {state for state, _commit, _identifier, _submitted in decisions.values()}
    current_states = {state for state, _commit, _identifier, _submitted in current_decisions}
    comment_reviews = _commented_codex_reviews(comments or [])
    current_submission = (
        any(commit == head_sha for _state, commit, _identifier, _submitted in submissions)
        or any(head_sha.startswith(commit) for _submitted, _identifier, commit in comment_reviews)
    )
    marker = max(
        ((submitted, identifier, commit) for _state, commit, identifier, submitted in submissions),
        default=("", 0, ""),
    )
    marker = max(marker, *comment_reviews) if comment_reviews else marker
    if "CHANGES_REQUESTED" in current_states or "CHANGES_REQUESTED" in states:
        decision = "changes requested"
    elif "APPROVED" in current_states:
        decision = "approved"
    elif current_submission:
        decision = "review submitted"
    elif submissions or comment_reviews:
        decision = "stale review"
    else:
        decision = "pending"
    return decision, marker


def _check_state(checks, status):
    runs = checks.get("check_runs") or []
    if any(str(run.get("status")) != "completed" for run in runs):
        return "pending"
    failing = {"action_required", "cancelled", "failure", "stale", "timed_out"}
    if any(str(run.get("conclusion")) in failing for run in runs):
        return "failing"
    combined = str(status.get("state") or "")
    if combined in ("error", "failure"):
        return "failing"
    if combined == "pending" and status.get("statuses"):
        return "pending"
    if runs or combined == "success":
        return "passing"
    return "pending"


def _current_pull(repository, pulls, cached=None):
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    origin = git_value(repository, "remote", "get-url", "origin")
    if not branch or not origin:
        return None

    identity = repository_identity(origin)
    cached_number = int(((cached or {}).get("current") or {}).get("number") or 0)
    if cached_number:
        for pull in pulls:
            head = pull.get("head") or {}
            head_repository = str((head.get("repo") or {}).get("full_name") or "").lower()
            if int(pull.get("number") or 0) == cached_number and head.get("ref") == branch \
                    and head_repository == identity:
                return pull
    for pull in pulls:
        head = pull.get("head") or {}
        head_repository = str((head.get("repo") or {}).get("full_name") or "").lower()
        if head.get("ref") == branch and head_repository == identity:
            return pull
    return None


def _coherent_current(repository, canonical_repository, number, token, reader):
    """Read one open, head-consistent PR snapshot, retrying if the head moves mid-read."""
    owner, name = canonical_repository.split("/", 1)
    for _attempt in range(2):
        before = reader(canonical_repository, f"pulls/{number}", token)
        if str(before.get("state") or "").lower() != "open" or before.get("merged_at"):
            return None
        head_sha = str((before.get("head") or {}).get("sha") or "")
        reviews = _paged(canonical_repository, f"pulls/{number}/reviews", token, reader)
        comments = _paged(canonical_repository, f"issues/{number}/comments", token, reader)
        checks = reader(canonical_repository, f"commits/{head_sha}/check-runs?per_page=100", token)
        status = reader(canonical_repository, f"commits/{head_sha}/status", token)
        unresolved = github_graphql(owner, name, number, token)
        after = reader(canonical_repository, f"pulls/{number}", token)
        if str(after.get("state") or "").lower() != "open" or after.get("merged_at"):
            return None
        after_head = str((after.get("head") or {}).get("sha") or "")
        if head_sha != after_head:
            continue
        author = str((after.get("user") or {}).get("login") or "")
        review_decision, review_marker = _review_decision(reviews, head_sha, comments, author)
        return {
            "number": number,
            "url": after.get("html_url"),
            "head_sha": head_sha,
            "mergeable": after.get("mergeable"),
            "merge_state": after.get("mergeable_state") or "unknown",
            "draft": bool(after.get("draft")),
            "review_decision": review_decision,
            "review_marker": list(review_marker),
            "checks": _check_state(checks, status),
            "unresolved_threads": unresolved,
            "coordination": pr_coordination.records_from_comments(comments),
        }
    raise ValueError(f"pull request #{number} changed head while its state was being observed")


def repository_identity(remote_url):
    """Return owner/name for one GitHub remote without accepting look-alike hosts."""
    from urllib.parse import urlparse

    if remote_url.startswith("git@github.com:"):
        identity = remote_url.removeprefix("git@github.com:")
    else:
        parsed = urlparse(remote_url)
        identity = parsed.path.strip("/") if parsed.hostname == "github.com" else ""
    return identity.removesuffix(".git").lower()


def branch_pull_state(canonical_repository, publishing_repository, branch, head_sha, reader=None):
    """Describe the exact PR state for one published branch without mutating GitHub."""
    if not publishing_repository or not branch:
        return {"state": "unpublished", "number": None, "head_sha": "", "warning": ""}
    reader = github_request if reader is None else reader
    token = github_token()
    owner = publishing_repository.split("/", 1)[0]
    query = urlencode({"state": "all", "base": "main", "head": f"{owner}:{branch}", "per_page": 20})
    try:
        pulls = reader(canonical_repository, f"pulls?{query}", token)
    except (TypeError, ValueError) as error:
        return {"state": "unknown", "number": None, "head_sha": "", "warning": str(error)}
    exact = []
    foreign = []
    for pull in pulls:
        head = pull.get("head") or {}
        head_repository = str((head.get("repo") or {}).get("full_name") or "").lower()
        if head.get("ref") != branch or head_repository != publishing_repository.lower():
            continue
        if str(head.get("sha") or "") == head_sha:
            exact.append(pull)
        else:
            foreign.append(pull)
    open_foreign = [
        pull for pull in foreign
        if str(pull.get("state") or "").lower() == "open" and not pull.get("merged_at")
    ]
    if open_foreign:
        pull = open_foreign[0]
        return {
            "state": "foreign-head",
            "number": pull.get("number"),
            "head_sha": str((pull.get("head") or {}).get("sha") or ""),
            "warning": "",
        }
    if exact:
        pull = exact[0]
        if pull.get("merged_at"):
            state = "merged"
        else:
            state = str(pull.get("state") or "unknown").lower()
        return {
            "state": state,
            "number": pull.get("number"),
            "head_sha": str((pull.get("head") or {}).get("sha") or ""),
            "warning": "",
        }
    if foreign:
        pull = foreign[0]
        return {
            "state": "foreign-head",
            "number": pull.get("number"),
            "head_sha": str((pull.get("head") or {}).get("sha") or ""),
            "warning": "",
        }
    return {"state": "unpublished", "number": None, "head_sha": "", "warning": ""}


def refresh(repository, common_directory, canonical_repository, max_age=PR_REFRESH_TTL, now=None, reader=None):
    """Return a shared read-only PR snapshot and a bounded warning."""
    now = time.time() if now is None else now
    reader = github_request if reader is None else reader
    cache = load_cache(common_directory)
    key = str(repository.resolve())
    cached = (cache.get("worktrees") or {}).get(key, {})
    if cached and now - float(cached.get("refreshed_at", 0)) < max_age:
        return cached, ""

    token = github_token()
    try:
        pulls = reader(canonical_repository, "pulls?state=open&base=main&per_page=100", token)
        previous_pulls = {str(value.get("number")): value for value in cached.get("pulls", [])}
        summaries = []
        for pull in pulls:
            number = int(pull["number"])
            head = pull.get("head") or {}
            head_sha = str(head.get("sha") or "")
            previous = previous_pulls.get(str(number), {})
            if previous.get("head_sha") == head_sha:
                files = list(previous.get("files", []))
                truncated = bool(previous.get("files_truncated"))
            else:
                files, truncated = _pull_files(canonical_repository, number, token, reader)
            summaries.append({
                "number": number,
                "url": pull.get("html_url"),
                "title": pull.get("title"),
                "draft": bool(pull.get("draft")),
                "head_ref": head.get("ref"),
                "head_repo": (head.get("repo") or {}).get("full_name"),
                "head_sha": head_sha,
                "files": files,
                "files_truncated": truncated,
            })

        current_pull = _current_pull(repository, pulls, cached)
        current = None
        if current_pull is not None:
            number = int(current_pull["number"])
            current = _coherent_current(repository, canonical_repository, number, token, reader)
        pull_states = {int(pull["number"]): "open" for pull in pulls}
        for record in (current or {}).get("coordination", []):
            for number in record["order"]:
                if number in pull_states:
                    continue
                detail = reader(canonical_repository, f"pulls/{number}", token)
                pull_states[number] = "merged" if detail.get("merged_at") else str(detail.get("state") or "unknown")
        snapshot = {
            "refreshed_at": now,
            "pulls": summaries,
            "current": current,
            "pull_states": pull_states,
        }
        worktrees = dict(cache.get("worktrees") or {})
        worktrees[key] = snapshot
        save_cache(common_directory, {"worktrees": worktrees})
        return snapshot, ""
    except (KeyError, TypeError, ValueError) as error:
        if cached:
            return cached, str(error)
        return {"refreshed_at": now, "pulls": [], "current": None, "pull_states": {}}, str(error)


def remote_head_refusal(repository, snapshot):
    current = snapshot.get("current") or {}
    remote_head = str(current.get("head_sha") or "")
    local_head = git_value(repository, "rev-parse", "HEAD")
    if not remote_head or not local_head or remote_head == local_head:
        return ""
    if git(repository, "merge-base", "--is-ancestor", remote_head, local_head, check=False).returncode == 0:
        return ""
    return (
        f"Pull request #{current.get('number')} has remote head {remote_head[:12]}, which is not contained in the "
        "local worktree. Fetch and reconcile that head before another change or publication."
    )


def state_notice(previous, current):
    if not current:
        if previous:
            return (
                f"Pull request #{previous.get('number')} is no longer open; it was closed or merged. "
                "The waiting phase must end."
            )
        return ""
    label = (
        current.get("head_sha"), current.get("checks"), current.get("review_decision"),
        current.get("review_marker"), current.get("merge_state"), current.get("unresolved_threads"),
    )
    previous_label = () if not previous else (
        previous.get("head_sha"), previous.get("checks"), previous.get("review_decision"),
        previous.get("review_marker"), previous.get("merge_state"), previous.get("unresolved_threads"),
    )
    if label == previous_label:
        return ""
    threads = current.get("unresolved_threads")
    thread_text = "review threads unavailable" if threads is None else f"{threads} unresolved review thread(s)"
    return (
        f"Pull request #{current.get('number')} is {current.get('checks')}, review is "
        f"{current.get('review_decision')}, merge state is {current.get('merge_state')}, and it has {thread_text}; "
        f"head {str(current.get('head_sha') or '')[:12]}."
    )


def overlap_notice(snapshot, changed_paths):
    changed_paths = set(changed_paths)
    if not changed_paths:
        return ""
    current_number = (snapshot.get("current") or {}).get("number")
    records = (snapshot.get("current") or {}).get("coordination", [])
    coordinated = pr_coordination.coordinated_pairs(records)
    overlaps = []
    truncated = []
    for pull in snapshot.get("pulls", []):
        if pull.get("number") == current_number:
            continue
        if pull.get("files_truncated"):
            truncated.append(f"#{pull.get('number')}")
        shared = sorted(changed_paths & set(pull.get("files", [])))
        if shared and frozenset((current_number, pull.get("number"))) not in coordinated:
            preview = ", ".join(shared[:5])
            suffix = ", …" if len(shared) > 5 else ""
            overlaps.append(f"#{pull.get('number')} ({preview}{suffix})")
    notices = []
    if overlaps:
        notices.append("Open pull requests overlap this work: " + "; ".join(overlaps) + ".")
    if truncated:
        notices.append(
            "Changed-file lists were truncated for " + ", ".join(truncated) + "; additional overlap is unknown."
        )
    if not notices:
        return ""
    return " ".join(notices) + (
        " Publish one final, mirrored merge order with `.agents/pr-coordination.py recommend`; the order guides "
        "humans and agents but never authorizes an agent to merge."
    )


def coordination_notice(snapshot):
    current = snapshot.get("current") or {}
    return pr_coordination.status_notice(
        current.get("coordination", []), current.get("number"), snapshot.get("pull_states", {}),
    )
