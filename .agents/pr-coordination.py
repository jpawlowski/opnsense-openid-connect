#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Publish one durable, human-readable merge order across overlapping pull requests."""

import argparse
import json
import os
from pathlib import Path
import re
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
IDENTIFIER = re.compile(r"[0-9]+(?:-[0-9]+)+-[0-9]+-[0-9a-f]{6}")


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


def comment_sets(pulls, token):
    return {int(pull["number"]): comments(int(pull["number"]), token) for pull in pulls}


def load_target_comments(values_by_pull, numbers, token):
    for number in numbers:
        if number not in values_by_pull:
            values_by_pull[number] = comments(number, token)


def all_records(pulls, token, values_by_pull=None):
    values_by_pull = comment_sets(pulls, token) if values_by_pull is None else values_by_pull
    records = {}
    for values in values_by_pull.values():
        for record in pr_coordination.records_from_comments(values):
            records.setdefault(record["id"], record)
    return sorted(records.values(), key=lambda record: (record["created_at"], record["comment_id"], record["id"]))


def matching_comments(values, identifier):
    matches = []
    for comment in values:
        if not pr_coordination.trusted_comment(comment):
            continue
        record = pr_coordination.parse_marker(comment.get("body"))
        if record is not None and record["id"] == identifier:
            matches.append((comment, record))
    return matches


def publication_identifier(prs, requested):
    if not requested:
        return f"{'-'.join(map(str, prs))}-{int(time.time())}-{secrets.token_hex(3)}"
    if not IDENTIFIER.fullmatch(requested) or not requested.startswith(f"{'-'.join(map(str, prs))}-"):
        raise RuntimeError("coordination id does not belong to this exact pull-request set")
    return requested


def publication_targets(prs, active, replaced):
    targets = set(prs)
    for record in active:
        if record["id"] in replaced:
            targets.update(record.get("targets", record["order"]))
    return sorted(targets)


def coordination_component(records, prs):
    participants = set(prs)
    related = []
    remaining = list(records)
    changed = True
    while changed:
        changed = False
        for record in list(remaining):
            if not participants.intersection(record["order"]):
                continue
            related.append(record)
            remaining.remove(record)
            participants.update(record["order"])
            changed = True
    return related, participants


def publish_mirrored(numbers, body, identifier, token, values_by_pull):
    urls = []
    desired = pr_coordination.parse_marker(body)
    if desired is None or desired["id"] != identifier:
        raise RuntimeError("mirrored publication body has no matching coordination marker")
    print(f"coordination id {identifier}; rerun the same command with --id {identifier} to resume", flush=True)
    try:
        for number in numbers:
            existing = matching_comments(values_by_pull.get(number, []), identifier)
            same_state = [item for item in existing if item[1]["state"] == desired["state"]]
            if same_state:
                if not any(str(comment.get("body") or "") == body for comment, _record in same_state):
                    raise RuntimeError(f"coordination id {identifier} already has different content on #{number}")
                comment = next(comment for comment, _record in same_state if str(comment.get("body") or "") == body)
                urls.append(str(comment.get("html_url") or f"pull request #{number}"))
                continue
            if desired["state"] == "final" and any(record["state"] == "fulfilled" for _comment, record in existing):
                raise RuntimeError(f"coordination id {identifier} is already fulfilled on #{number}")
            result = github_write(f"issues/{number}/comments", {"body": body}, token)
            urls.append(str(result.get("html_url") or f"pull request #{number}"))
    except RuntimeError as error:
        raise RuntimeError(
            f"coordination {identifier} may be partially published; rerun the same command with --id {identifier}"
        ) from error
    return urls


def require_token():
    token = github_watch.github_token()
    if not token:
        raise RuntimeError("GitHub authentication is required to publish coordination comments")
    return token


def recommend(arguments):
    token = require_token()
    prs, order = pr_coordination.validate_order(arguments.prs, arguments.order)
    pulls = open_pulls(token)
    values_by_pull = comment_sets(pulls, token)
    open_numbers = {int(pull["number"]) for pull in pulls}
    missing = sorted(set(prs) - open_numbers)
    if missing:
        raise RuntimeError("coordination targets must be open pull requests: " + ", ".join(map(str, missing)))

    identifier = publication_identifier(prs, arguments.id)
    active = all_records(pulls, token, values_by_pull)
    replaced = set(arguments.supersedes)
    unknown = replaced - {record["id"] for record in active}
    if unknown:
        raise RuntimeError("superseded coordination is not active: " + ", ".join(sorted(unknown)))
    targets = publication_targets(prs, active, replaced)
    overlapping, participants = coordination_component(active, prs)
    unaddressed = [
        record["id"] for record in overlapping
        if record["id"] not in replaced and record["id"] != identifier
    ]
    if unaddressed:
        raise RuntimeError(
            "an active recommendation already covers this pull-request set; supersede it explicitly: "
            + ", ".join(unaddressed)
        )
    missing = sorted(participants - set(prs))
    if missing:
        raise RuntimeError(
            "the replacement must include every transitively coordinated pull request: "
            + ", ".join(map(str, missing))
        )

    record = {
        "id": identifier,
        "order": order,
        "state": "final",
        "supersedes": sorted(replaced),
        "targets": targets,
    }
    remaining = [value for value in active if value["id"] not in replaced and value["id"] != identifier]
    if pr_coordination.has_cycle([*remaining, record]):
        raise RuntimeError("the recommended order would create a cycle with active coordination records")
    body = pr_coordination.render_final(
        record, arguments.overlap.strip(), arguments.reason.strip(), arguments.reconsider.strip(),
        language=arguments.language,
    )
    load_target_comments(values_by_pull, targets, token)
    urls = publish_mirrored(targets, body, identifier, token, values_by_pull)
    print(f"published final coordination {identifier}")
    for url in urls:
        print(url)


def fulfill(arguments):
    token = require_token()
    pulls = open_pulls(token)
    values_by_pull = comment_sets(pulls, token)
    records = [
        record
        for values in values_by_pull.values()
        for _comment, record in matching_comments(values, arguments.id)
        if record["state"] == "final"
    ]
    record = next(iter(records), None)
    if record is None:
        raise RuntimeError("the coordination record is not active on an open pull request")
    body = pr_coordination.render_fulfilled(record, language=arguments.language)
    targets = record.get("targets", record["order"])
    load_target_comments(values_by_pull, targets, token)
    urls = publish_mirrored(targets, body, record["id"], token, values_by_pull)
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
    recommendation.add_argument("--id", help="resume an interrupted mirrored publication with its printed id")
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
