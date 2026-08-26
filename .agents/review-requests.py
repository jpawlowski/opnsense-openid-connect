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
import secrets
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


# The wait subcommand is explicitly permitted in the read-only control checkout.
# Prevent its only local import from turning that observation into an ignored
# filesystem write when Python's bytecode cache is cold.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "hooks"))

import github_watch  # noqa: E402


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
GITHUB_TIMEOUT = 10
MARKER = re.compile(r"<!-- agent-codex-review-request:v1 head=([0-9a-f]{40}) -->")
SUBMITTED_REVIEW_STATES = {"APPROVED", "CHANGES_REQUESTED", "COMMENTED"}
NOTICE = {
    "en": "*An AI agent wrote this text on my behalf; I am responsible for its content.*",
    "de": "*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*",
}
REVIEW_WAIT_MINIMUM = 3 * 60
REVIEW_WAIT_MAXIMUM = 8 * 60
READY_WAIT_SECONDS = 60 * 60


def github_api(path, token, method="GET", body=None, repository=True, missing_ok=False):
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
        if missing_ok and error.code == 404:
            return None
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
        submitted = str(review.get("submitted_at") or "")
        state = str(review.get("state") or "").upper()
        if login in github_watch.CODEX_REVIEWERS and submitted and state in SUBMITTED_REVIEW_STATES \
                and re.fullmatch(r"[0-9a-f]{40}", head):
            events.append((submitted, head))
    for comment in comments:
        login = str((comment.get("user") or {}).get("login") or "").lower()
        match = github_watch.REVIEWED_COMMIT.search(str(comment.get("body") or ""))
        if login in github_watch.CODEX_REVIEWERS and match:
            events.append((str(comment.get("created_at") or ""), match.group(1).lower()))
    return sorted(events)


def head_reviewed(head, events):
    return any(head.startswith(reviewed) or reviewed.startswith(head) for _created, reviewed in events)


def classify_requests(comments, viewer, current_head, events):
    removable = []
    pending = []
    for comment in comments:
        if str((comment.get("user") or {}).get("login") or "").lower() != viewer.lower():
            continue
        recognized, requested_head = request_head(comment.get("body"))
        if not recognized:
            continue
        if requested_head:
            remove = requested_head != current_head or head_reviewed(requested_head, events)
        else:
            # A legacy command has no durable evidence tying it to any head. Keeping it based on timestamps can
            # suppress the exact-head request after a force-push, merge or move to an older commit.
            remove = True
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


def verify_remote_pull(number, expected_head, token, draft_required=False):
    pull = github_api(f"pulls/{number}", token)
    observed_head = str((pull.get("head") or {}).get("sha") or "")
    if observed_head != expected_head or str(pull.get("state") or "").lower() != "open" or pull.get("merged_at"):
        raise RuntimeError("the pull request changed while review requests were being inspected; retry its snapshot")
    if draft_required and not pull.get("draft"):
        raise RuntimeError("automated Codex review requests require a draft pull request")
    return verify_local_pull(pull)


def review_state(number, token, draft_required=False):
    pull = github_api(f"pulls/{number}", token)
    head = verify_local_pull(pull)
    if draft_required and not pull.get("draft"):
        raise RuntimeError("automated Codex review requests require a draft pull request")
    viewer = str(github_api("user", token, repository=False).get("login") or "")
    if not viewer:
        raise RuntimeError("GitHub did not identify the publishing account")
    comments = paged(f"issues/{number}/comments", token)
    reviews = paged(f"pulls/{number}/reviews", token)
    events = review_events(reviews, comments)
    removable, pending = classify_requests(comments, viewer, head, events)
    verify_remote_pull(number, head, token, draft_required=draft_required)
    return head, viewer, comments, events, removable, pending


def delete_requests(comments, number, head, viewer, events, token, draft_required=False):
    removed = 0
    for comment in comments:
        fresh_comments = paged(f"issues/{number}/comments", token)
        verify_remote_pull(number, head, token, draft_required=draft_required)
        fresh_removable, _pending = classify_requests(fresh_comments, viewer, head, events)
        fresh = next((value for value in fresh_removable if int(value.get("id") or 0) == int(comment["id"])), None)
        if fresh is None or str(fresh.get("body") or "") != str(comment.get("body") or ""):
            print(f"kept changed or already removed review request {comment.get('html_url') or comment['id']}")
            continue
        github_api(
            f"issues/comments/{int(comment['id'])}", token, method="DELETE", missing_ok=True,
        )
        print(f"removed fulfilled or stale review request {comment.get('html_url') or comment['id']}")
        removed += 1
    return removed


def cleanup(arguments):
    token = require_token()
    head, viewer, _comments, events, removable, _pending = review_state(arguments.pr, token)
    removed = delete_requests(removable, arguments.pr, head, viewer, events, token)
    print(f"review-request cleanup removed {removed} comment(s)")


def delete_published_request(comment, viewer, expected_body, token):
    identifier = int((comment or {}).get("id") or 0)
    if not identifier:
        return False
    fresh = github_api(f"issues/comments/{identifier}", token, missing_ok=True)
    if fresh is None:
        return True
    author = str((fresh.get("user") or {}).get("login") or "")
    if author.lower() != viewer.lower() or str(fresh.get("body") or "") != expected_body:
        return False
    github_api(f"issues/comments/{identifier}", token, method="DELETE", missing_ok=True)
    return True


def request_review(arguments):
    token = require_token()
    head, viewer, _comments, events, removable, pending = review_state(
        arguments.pr, token, draft_required=True,
    )
    delete_requests(removable, arguments.pr, head, viewer, events, token, draft_required=True)
    if head_reviewed(head, events):
        print(f"Codex already reviewed current head {head[:12]}; no request was added")
        return
    if pending:
        print(f"current-head review request already exists: {pending[0].get('html_url') or pending[0]['id']}")
        return
    verify_remote_pull(arguments.pr, head, token, draft_required=True)
    body = request_body(head, language=arguments.language)
    published = github_api(
        f"issues/{arguments.pr}/comments", token, method="POST",
        body={"body": body},
    )
    try:
        confirmed_head, confirmed_viewer, _comments, confirmed_events, duplicates, confirmed_pending = review_state(
            arguments.pr, token, draft_required=True,
        )
        delete_requests(
            duplicates, arguments.pr, confirmed_head, confirmed_viewer, confirmed_events, token,
            draft_required=True,
        )
        verify_remote_pull(arguments.pr, confirmed_head, token, draft_required=True)
        if head_reviewed(confirmed_head, confirmed_events):
            print(f"Codex already reviewed current head {confirmed_head[:12]}; no request remains")
            return
        if not confirmed_pending:
            raise RuntimeError("the current-head review request could not be confirmed after publication")
    except RuntimeError as error:
        if not delete_published_request(published, viewer, body, token):
            raise RuntimeError(
                f"{error}; the newly published review request could not be removed safely"
            ) from error
        raise
    retained = confirmed_pending[0]
    print(f"requested Codex review for {confirmed_head[:12]}: {retained.get('html_url') or retained['id']}")


def wait_seconds(phase, chooser=secrets.randbelow):
    if phase == "review":
        return REVIEW_WAIT_MINIMUM + chooser(REVIEW_WAIT_MAXIMUM - REVIEW_WAIT_MINIMUM + 1)
    if phase == "ready":
        return READY_WAIT_SECONDS
    raise ValueError(f"unsupported pull-request waiting phase: {phase}")


def print_wait(arguments):
    print(wait_seconds(arguments.phase))


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
    wait_command = commands.add_parser("wait", help="choose the next read-only PR observation delay in seconds")
    wait_command.add_argument("--phase", choices=("review", "ready"), required=True)
    wait_command.set_defaults(action=print_wait)
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
