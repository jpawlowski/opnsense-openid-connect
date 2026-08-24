#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Publish one durable, human-readable merge order across overlapping pull requests."""

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


sys.path.insert(0, str(Path(__file__).resolve().parent / "hooks"))

import github_watch  # noqa: E402
import pr_coordination  # noqa: E402


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
GITHUB_TIMEOUT = 10


def github_write(path, body, token):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(
        f"{api}/repos/{CANONICAL_REPOSITORY}/{path.lstrip('/')}",
        data=json.dumps(body).encode(),
        method="POST",
    )
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", github_watch.USER_AGENT)
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"GitHub coordination comment failed (HTTP {error.code})") from error
    except URLError as error:
        raise RuntimeError(f"GitHub coordination comment failed ({error.reason})") from error


def paged(path, token):
    values = []
    for page in range(1, 11):
        separator = "&" if "?" in path else "?"
        page_path = f"{path}{separator}{urlencode({'per_page': 100, 'page': page})}"
        batch = github_watch.github_request(CANONICAL_REPOSITORY, page_path, token)
        values.extend(batch)
        if len(batch) < 100:
            return values
    raise RuntimeError(f"GitHub response for {path} exceeded the supported pagination bound")


def open_pulls(token):
    return paged("pulls?state=open&base=main", token)


def comments(number, token):
    return paged(f"issues/{number}/comments", token)


def all_records(pulls, token):
    values = []
    for pull in pulls:
        values.extend(comments(int(pull["number"]), token))
    return pr_coordination.records_from_comments(values)


def require_token():
    token = github_watch.github_token()
    if not token:
        raise RuntimeError("GitHub authentication is required to publish coordination comments")
    return token


def recommend(arguments):
    token = require_token()
    prs, order = pr_coordination.validate_order(arguments.prs, arguments.order)
    pulls = open_pulls(token)
    open_numbers = {int(pull["number"]) for pull in pulls}
    missing = sorted(set(prs) - open_numbers)
    if missing:
        raise RuntimeError("coordination targets must be open pull requests: " + ", ".join(map(str, missing)))

    active = all_records(pulls, token)
    replaced = set(arguments.supersedes)
    unknown = replaced - {record["id"] for record in active}
    if unknown:
        raise RuntimeError("superseded coordination is not active: " + ", ".join(sorted(unknown)))
    overlapping = [record for record in active if len(set(record["order"]) & set(prs)) >= 2]
    unaddressed = [record["id"] for record in overlapping if record["id"] not in replaced]
    if unaddressed:
        raise RuntimeError(
            "an active recommendation already covers this pull-request set; supersede it explicitly: "
            + ", ".join(unaddressed)
        )

    identifier = f"{'-'.join(map(str, prs))}-{int(time.time())}-{secrets.token_hex(3)}"
    record = {
        "id": identifier,
        "order": order,
        "state": "final",
        "supersedes": sorted(replaced),
    }
    remaining = [value for value in active if value["id"] not in replaced]
    if pr_coordination.has_cycle([*remaining, record]):
        raise RuntimeError("the recommended order would create a cycle with active coordination records")
    body = pr_coordination.render_final(
        record, arguments.overlap.strip(), arguments.reason.strip(), arguments.reconsider.strip(),
        language=arguments.language,
    )
    urls = []
    for number in prs:
        result = github_write(f"issues/{number}/comments", {"body": body}, token)
        urls.append(str(result.get("html_url") or f"pull request #{number}"))
    print(f"published final coordination {identifier}")
    for url in urls:
        print(url)


def fulfill(arguments):
    token = require_token()
    pulls = open_pulls(token)
    records = all_records(pulls, token)
    record = next((value for value in records if value["id"] == arguments.id), None)
    if record is None:
        raise RuntimeError("the coordination record is not active on an open pull request")
    body = pr_coordination.render_fulfilled(record, language=arguments.language)
    urls = []
    for number in record["order"]:
        result = github_write(f"issues/{number}/comments", {"body": body}, token)
        urls.append(str(result.get("html_url") or f"pull request #{number}"))
    print(f"fulfilled coordination {record['id']}")
    for url in urls:
        print(url)


def status(arguments):
    token = github_watch.github_token()
    values = comments(arguments.pr, token)
    records = pr_coordination.records_from_comments(values)
    if not records:
        print(f"pull request #{arguments.pr} has no active coordination record")
        return
    states = {}
    for record in records:
        for number in record["order"]:
            if number in states:
                continue
            detail = github_watch.github_request(CANONICAL_REPOSITORY, f"pulls/{number}", token)
            states[number] = "merged" if detail.get("merged_at") else str(detail.get("state") or "unknown")
    print(pr_coordination.status_notice(records, arguments.pr, states))


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)

    recommendation = commands.add_parser("recommend", help="publish one final order in every involved PR")
    recommendation.add_argument("--prs", nargs="+", type=int, required=True)
    recommendation.add_argument("--order", nargs="+", type=int, required=True)
    recommendation.add_argument("--overlap", required=True)
    recommendation.add_argument("--reason", required=True)
    recommendation.add_argument("--reconsider", required=True)
    recommendation.add_argument("--supersedes", action="append", default=[])
    recommendation.add_argument("--language", choices=("en", "de"), default="en")
    recommendation.set_defaults(action=recommend)

    completion = commands.add_parser("fulfill", help="mark an active order completed in every involved PR")
    completion.add_argument("--id", required=True)
    completion.add_argument("--language", choices=("en", "de"), default="en")
    completion.set_defaults(action=fulfill)

    inspection = commands.add_parser("status", help="read the active order for one pull request")
    inspection.add_argument("--pr", type=int, required=True)
    inspection.set_defaults(action=status)
    return value


def main():
    arguments = parser().parse_args()
    arguments.action(arguments)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
