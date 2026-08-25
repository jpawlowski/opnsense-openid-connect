#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Request Codex reviews without leaving fulfilled command-only comments behind."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


sys.path.insert(0, str(Path(__file__).resolve().parent / "hooks"))

import github_watch  # noqa: E402


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
GITHUB_TIMEOUT = 10
MARKER = re.compile(r"<!-- agent-codex-review-request:v1 head=([0-9a-f]{40}) -->")
NOTICE = {
    "en": "*An AI agent wrote this text on my behalf; I am responsible for its content.*",
    "de": "*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*",
}


def github_api(path, token, method="GET", body=None, repository=True):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    prefix = f"/repos/{CANONICAL_REPOSITORY}" if repository else ""
    data = None if body is None else json.dumps(body).encode()
    request = Request(f"{api}{prefix}/{path.lstrip('/')}", data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", github_watch.USER_AGENT)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
            return None if response.status == 204 else json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"GitHub review-request operation failed (HTTP {error.code})") from error
    except URLError as error:
        raise RuntimeError(f"GitHub review-request operation failed ({error.reason})") from error


def paged(path, token):
    values = []
    for page in range(1, 11):
        separator = "&" if "?" in path else "?"
        batch = github_api(f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}", token)
        values.extend(batch)
        if len(batch) < 100:
            return values
    raise RuntimeError(f"GitHub response for {path} exceeded the supported pagination bound")


def request_body(head, language="en"):
    if language not in NOTICE or not re.fullmatch(r"[0-9a-f]{40}", str(head or "")):
        raise ValueError("a review request needs a full lowercase head SHA and a supported language")
    return "\n\n".join((
        f"<!-- agent-codex-review-request:v1 head={head} -->",
        "@codex review",
        NOTICE[language],
    ))


def request_head(body):
    body = str(body or "").strip()
    match = MARKER.search(body)
    without_marker = MARKER.sub("", body)
    for notice in NOTICE.values():
        without_marker = without_marker.replace(notice, "")
    if without_marker.strip() != "@codex review":
        return False, ""
    return True, match.group(1) if match else ""


def review_events(reviews, comments):
    events = []
    for review in reviews:
        login = str((review.get("user") or {}).get("login") or "").lower()
        head = str(review.get("commit_id") or "").lower()
        if login in github_watch.CODEX_REVIEWERS and re.fullmatch(r"[0-9a-f]{40}", head):
            events.append((str(review.get("submitted_at") or ""), head))
    for comment in comments:
        login = str((comment.get("user") or {}).get("login") or "").lower()
        match = github_watch.REVIEWED_COMMIT.search(str(comment.get("body") or ""))
        if login in github_watch.CODEX_REVIEWERS and match:
            events.append((str(comment.get("created_at") or ""), match.group(1).lower()))
    return sorted(events)


def head_reviewed(head, events):
    return any(head.startswith(reviewed) or reviewed.startswith(head) for _created, reviewed in events)


def classify_requests(comments, viewer, current_head, head_created, events):
    removable = []
    pending = []
    for comment in comments:
        if str((comment.get("user") or {}).get("login") or "").lower() != viewer.lower():
            continue
        recognized, requested_head = request_head(comment.get("body"))
        if not recognized:
            continue
        created = str(comment.get("created_at") or "")
        if requested_head:
            remove = requested_head != current_head or head_reviewed(requested_head, events)
        else:
            remove = created < head_created or any(reviewed_at >= created for reviewed_at, _head in events)
        (removable if remove else pending).append(comment)
    pending.sort(key=lambda value: (str(value.get("created_at") or ""), int(value.get("id") or 0)))
    removable.extend(pending[1:])
    return removable, pending[:1]


def require_token():
    token = github_watch.github_token()
    if not token:
        raise RuntimeError("GitHub authentication is required to manage Codex review requests")
    return token


def git_value(*arguments):
    result = subprocess.run(("git", *arguments), check=False, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ""


def verify_local_pull(pull):
    head = pull.get("head") or {}
    local_head = git_value("rev-parse", "HEAD")
    local_branch = git_value("symbolic-ref", "--short", "HEAD")
    origin = git_value("remote", "get-url", "origin")
    head_repository = str((head.get("repo") or {}).get("full_name") or "").lower()
    if local_head != str(head.get("sha") or "") or local_branch != str(head.get("ref") or "") \
            or github_watch.repository_identity(origin) != head_repository:
        raise RuntimeError("the requested pull request is not the exact published head of this worktree")
    if str(pull.get("state") or "").lower() != "open" or pull.get("merged_at"):
        raise RuntimeError("Codex review requests require an open pull request")
    return local_head


def review_state(number, token):
    pull = github_api(f"pulls/{number}", token)
    head = verify_local_pull(pull)
    viewer = str(github_api("user", token, repository=False).get("login") or "")
    if not viewer:
        raise RuntimeError("GitHub did not identify the publishing account")
    comments = paged(f"issues/{number}/comments", token)
    reviews = paged(f"pulls/{number}/reviews", token)
    commit = github_api(f"commits/{head}", token)
    commit_value = commit.get("commit") or {}
    head_created = str((commit_value.get("committer") or {}).get("date")
                       or (commit_value.get("author") or {}).get("date") or "")
    events = review_events(reviews, comments)
    removable, pending = classify_requests(comments, viewer, head, head_created, events)
    return head, comments, events, removable, pending


def delete_requests(comments, token):
    for comment in comments:
        github_api(f"issues/comments/{int(comment['id'])}", token, method="DELETE")
        print(f"removed fulfilled or stale review request {comment.get('html_url') or comment['id']}")


def cleanup(arguments):
    token = require_token()
    _head, _comments, _events, removable, _pending = review_state(arguments.pr, token)
    delete_requests(removable, token)
    print(f"review-request cleanup removed {len(removable)} comment(s)")


def request_review(arguments):
    token = require_token()
    head, _comments, events, removable, pending = review_state(arguments.pr, token)
    delete_requests(removable, token)
    if head_reviewed(head, events):
        print(f"Codex already reviewed current head {head[:12]}; no request was added")
        return
    if pending:
        print(f"current-head review request already exists: {pending[0].get('html_url') or pending[0]['id']}")
        return
    result = github_api(
        f"issues/{arguments.pr}/comments", token, method="POST",
        body={"body": request_body(head, language=arguments.language)},
    )
    print(f"requested Codex review for {head[:12]}: {result.get('html_url')}")


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    request_command = commands.add_parser("request", help="clean old triggers and request one current-head review")
    request_command.add_argument("--pr", type=int, required=True)
    request_command.add_argument("--language", choices=("en", "de"), default="en")
    request_command.set_defaults(action=request_review)
    cleanup_command = commands.add_parser("cleanup", help="remove fulfilled or stale own review triggers")
    cleanup_command.add_argument("--pr", type=int, required=True)
    cleanup_command.set_defaults(action=cleanup)
    return value


def main():
    arguments = parser().parse_args()
    try:
        arguments.action(arguments)
    except (RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
