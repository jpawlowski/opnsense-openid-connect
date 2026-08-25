#!/usr/bin/env python3

"""Publish one durable, human-readable merge order across overlapping pull requests."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


sys.path.insert(0, str(Path(__file__).resolve().parent / "hooks"))

import github_watch  # noqa: E402
import pr_coordination  # noqa: E402


CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
GITHUB_TIMEOUT = 10
IDENTIFIER = re.compile(r"[0-9]+(?:-[0-9]+)+-[0-9]+-[0-9a-f]{6}")
LOCK_LABEL = "agent:pr-coordination-publication"
LOCK_COLOR = "ededed"


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


def github_update_comment(comment_id, body, token):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(
        f"{api}/repos/{CANONICAL_REPOSITORY}/issues/comments/{int(comment_id)}",
        data=json.dumps({"body": body}).encode(),
        method="PATCH",
    )
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", github_watch.USER_AGENT)
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
            return json.load(response)
    except HTTPError as error:
        raise RuntimeError(f"GitHub coordination comment update failed (HTTP {error.code})") from error
    except URLError as error:
        raise RuntimeError(f"GitHub coordination comment update failed ({error.reason})") from error


def github_delete(path, token, subject="coordination lock release"):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(
        f"{api}/repos/{CANONICAL_REPOSITORY}/{path.lstrip('/')}",
        method="DELETE",
    )
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("User-Agent", github_watch.USER_AGENT)
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT):
            return
    except HTTPError as error:
        raise RuntimeError(f"GitHub {subject} failed (HTTP {error.code})") from error
    except URLError as error:
        raise RuntimeError(f"GitHub {subject} failed ({error.reason})") from error


def lock_description(owner):
    return f"Temporary PR coordination publication lock owned by {owner}"


def acquire_coordination_lock(token, owner=None):
    owner = owner or f"{int(time.time())}-{secrets.token_hex(8)}"
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(
        f"{api}/repos/{CANONICAL_REPOSITORY}/labels",
        data=json.dumps({
            "name": LOCK_LABEL,
            "color": LOCK_COLOR,
            "description": lock_description(owner),
        }).encode(),
        method="POST",
    )
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", github_watch.USER_AGENT)
    try:
        with urlopen(request, timeout=GITHUB_TIMEOUT) as response:
            json.load(response)
    except HTTPError as error:
        if error.code == 422:
            raise RuntimeError(
                f"another coordination publication owns repository lock {LOCK_LABEL}; retry after it releases"
            ) from error
        raise RuntimeError(f"GitHub coordination lock acquisition failed (HTTP {error.code})") from error
    except URLError as error:
        raise RuntimeError(f"GitHub coordination lock acquisition failed ({error.reason})") from error
    return owner


def release_coordination_lock(token, owner):
    label_path = f"labels/{quote(LOCK_LABEL, safe='')}"
    try:
        label = github_watch.github_request(CANONICAL_REPOSITORY, label_path, token)
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"GitHub coordination lock ownership could not be verified ({error})") from error
    if str(label.get("description") or "") != lock_description(owner):
        raise RuntimeError(
            f"repository lock {LOCK_LABEL} changed ownership; inspect it and do not remove it automatically"
        )
    github_delete(label_path, token)


@contextmanager
def coordination_publication_lock(token):
    owner = acquire_coordination_lock(token)
    active_error = None
    try:
        yield
    except BaseException as error:
        active_error = error
        raise
    finally:
        try:
            release_coordination_lock(token, owner)
        except RuntimeError as error:
            if active_error is None:
                raise
            print(f"coordination publication failed and its lock needs inspection: {error}", file=sys.stderr)


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


def identifier_pull_requests(identifier):
    if not IDENTIFIER.fullmatch(str(identifier or "")):
        return []
    prefix, _timestamp, _nonce = str(identifier).rsplit("-", 2)
    return [int(number) for number in prefix.split("-")]


def publication_targets(prs, active, replaced):
    targets = list(prs)
    for record in active:
        if record["id"] in replaced:
            targets.extend(record.get("targets", record["order"]))
    return list(dict.fromkeys(targets))


def recorded_publication(values_by_pull, identifier):
    matches = [
        (comment, record)
        for values in values_by_pull.values()
        for comment, record in matching_comments(values, identifier)
    ]
    if not matches:
        return None
    expected = matches[0][1]
    fields = ("order", "supersedes", "targets")
    if any(any(record[field] != expected[field] for field in fields) for _comment, record in matches[1:]):
        raise RuntimeError(f"coordination id {identifier} has inconsistent mirrored markers")
    bodies_by_state = {}
    for comment, record in matches:
        body = pr_coordination.without_hash_number_references(comment.get("body"))
        bodies_by_state.setdefault(record["state"], set()).add(body)
    if any(len(bodies) != 1 for bodies in bodies_by_state.values()):
        raise RuntimeError(f"coordination id {identifier} has inconsistent mirrored comment bodies")
    body_state = "final" if "final" in bodies_by_state else next(iter(bodies_by_state))
    return dict(expected, _body=next(iter(bodies_by_state[body_state])))


def resumed_publication(values_by_pull, identifier):
    record = recorded_publication(values_by_pull, identifier)
    if record is None:
        return None
    states = {
        value["state"]
        for values in values_by_pull.values()
        for _comment, value in matching_comments(values, identifier)
    }
    if states != {"final"}:
        raise RuntimeError(f"coordination id {identifier} is already fulfilled")
    return record


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


def missing_order_participants(participants, prs, open_numbers):
    return sorted((participants & open_numbers) - set(prs))


def validate_replacement(overlapping, replaced, order, changed_fact, changed_criterion, resumed=False):
    """Keep the first complete recommendation unless new evidence changes its order."""
    changed_fact = str(changed_fact or "").strip()
    changed_criterion = str(changed_criterion or "").strip()
    if resumed:
        return
    if not replaced:
        if changed_fact or changed_criterion:
            raise RuntimeError("replacement evidence requires at least one --supersedes record")
        return
    if not changed_fact or not changed_criterion:
        raise RuntimeError("a replacement requires both --changed-fact and --changed-criterion")
    if any(record["id"] in replaced and record["order"] == order for record in overlapping):
        raise RuntimeError("the first published recommendation remains active when the merge order is unchanged")


def publish_mirrored(numbers, body, identifier, token, values_by_pull, replace_ids=None, update_existing=False):
    urls = []
    replace_ids = set(replace_ids or [])
    desired = pr_coordination.parse_marker(body)
    if desired is None or desired["id"] != identifier:
        raise RuntimeError("mirrored publication body has no matching coordination marker")
    print(f"coordination id {identifier}; rerun the same command with --id {identifier} to resume", flush=True)
    try:
        for number in numbers:
            existing = matching_comments(values_by_pull.get(number, []), identifier)
            same_state = [item for item in existing if item[1]["state"] == desired["state"]]
            predecessors = [
                item
                for replaced_id in replace_ids
                for item in matching_comments(values_by_pull.get(number, []), replaced_id)
            ]
            if same_state:
                if update_existing and any(
                    pr_coordination.without_hash_number_references(comment.get("body"))
                    != pr_coordination.without_hash_number_references(body)
                    for comment, _record in same_state
                ):
                    raise RuntimeError(
                        f"coordination id {identifier} has inconsistent mirrored content on #{number}"
                    )
                matching = [
                    comment for comment, _record in same_state if str(comment.get("body") or "") == body
                ]
                if matching:
                    comment = min(matching, key=lambda value: int(value.get("id") or 0))
                    result = comment
                elif update_existing:
                    comment, _record = min(same_state, key=lambda item: int(item[0].get("id") or 0))
                    result = github_update_comment(int(comment["id"]), body, token)
                else:
                    raise RuntimeError(f"coordination id {identifier} already has different content on #{number}")
                duplicates = [
                    value for value, _record in (*existing, *predecessors)
                    if int(value.get("id") or 0) != int(comment.get("id") or 0)
                ]
                for duplicate in duplicates:
                    github_delete(
                        f"issues/comments/{int(duplicate['id'])}", token, subject="coordination comment deletion",
                    )
                urls.append(str(result.get("html_url") or f"pull request #{number}"))
                continue
            if desired["state"] == "final" and any(record["state"] == "fulfilled" for _comment, record in existing):
                raise RuntimeError(f"coordination id {identifier} is already fulfilled on #{number}")
            reusable = predecessors
            if desired["state"] == "fulfilled":
                reusable = [item for item in existing if item[1]["state"] == "final"]
            if reusable:
                comment, _record = min(reusable, key=lambda item: int(item[0].get("id") or 0))
                result = github_update_comment(int(comment["id"]), body, token)
                for duplicate, _record in reusable:
                    if int(duplicate.get("id") or 0) == int(comment["id"]):
                        continue
                    github_delete(
                        f"issues/comments/{int(duplicate['id'])}", token, subject="coordination comment deletion",
                    )
            else:
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
    with coordination_publication_lock(token):
        recommend_locked(arguments, token)


def recommend_locked(arguments, token):
    prs, order = pr_coordination.validate_order(arguments.prs, arguments.order)
    pulls = open_pulls(token)
    values_by_pull = comment_sets(pulls, token)
    open_numbers = {int(pull["number"]) for pull in pulls}

    identifier = publication_identifier(prs, arguments.id)
    referenced_numbers = {
        number
        for value in (identifier, *arguments.supersedes)
        for number in identifier_pull_requests(value)
    }
    load_target_comments(values_by_pull, sorted(referenced_numbers), token)
    active = all_records(pulls, token, values_by_pull)
    replaced = set(arguments.supersedes)
    resumed = resumed_publication(values_by_pull, identifier)
    if resumed is not None and (resumed["order"] != order or set(resumed["supersedes"]) != replaced):
        raise RuntimeError(f"coordination id {identifier} belongs to a different recommendation")
    missing = sorted(set(prs) - open_numbers)
    if missing:
        guidance = f"; publish a new open-PR order that supersedes {identifier}" if resumed is not None else ""
        raise RuntimeError(
            "coordination targets must be open pull requests: " + ", ".join(map(str, missing)) + guidance
        )
    known_replaced = set(resumed["supersedes"]) if resumed is not None else set()
    unknown = replaced - {record["id"] for record in active} - known_replaced
    if unknown:
        raise RuntimeError("superseded coordination is not active: " + ", ".join(sorted(unknown)))
    targets = resumed["targets"] if resumed is not None else publication_targets(prs, active, replaced)
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
    missing = missing_order_participants(participants, prs, open_numbers)
    if missing:
        raise RuntimeError(
            "the replacement must include every open transitively coordinated pull request: "
            + ", ".join(map(str, missing))
        )
    validate_replacement(
        overlapping, replaced, order, arguments.changed_fact, arguments.changed_criterion,
        resumed=resumed is not None,
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
    body = (
        pr_coordination.without_hash_number_references(resumed["_body"])
        if resumed is not None else pr_coordination.render_final(
            record, arguments.overlap.strip(), arguments.reason.strip(), arguments.reconsider.strip(),
            changed_fact=arguments.changed_fact.strip(), changed_criterion=arguments.changed_criterion.strip(),
            language=arguments.language,
        )
    )
    load_target_comments(values_by_pull, targets, token)
    urls = publish_mirrored(
        targets, body, identifier, token, values_by_pull, replace_ids=replaced,
        update_existing=resumed is not None,
    )
    print(f"published final coordination {identifier}")
    for url in urls:
        print(url)


def fulfill(arguments):
    token = require_token()
    with coordination_publication_lock(token):
        fulfill_locked(arguments, token)


def fulfill_locked(arguments, token):
    pulls = open_pulls(token)
    values_by_pull = comment_sets(pulls, token)
    load_target_comments(values_by_pull, identifier_pull_requests(arguments.id), token)
    record = recorded_publication(values_by_pull, arguments.id)
    if record is None:
        raise RuntimeError("the coordination record was not found on its original pull requests")
    targets = record.get("targets", record["order"])
    load_target_comments(values_by_pull, targets, token)
    record = recorded_publication(values_by_pull, arguments.id)
    body = pr_coordination.render_fulfilled(record, language=arguments.language)
    urls = publish_mirrored(targets, body, record["id"], token, values_by_pull, update_existing=True)
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
    recommendation.add_argument("--changed-fact", default="")
    recommendation.add_argument("--changed-criterion", default="")
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
