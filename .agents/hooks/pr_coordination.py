#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Render and interpret durable cross-pull-request merge recommendations."""

import json
import re


MARKER = re.compile(r"<!-- agent-pr-coordination:v1 (\{.*?\}) -->")
NOTICE = {
    "en": "*An AI agent wrote this text on my behalf; I am responsible for its content.*",
    "de": "*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*",
}
TRUSTED_ASSOCIATIONS = {"COLLABORATOR", "MEMBER", "OWNER"}
GITHUB_PULL_URL_PATTERN = (
    r"(?:(?:https?://)(?:www[.])?|www[.])github[.]com/"
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(?P<number>[0-9]+)"
    r"(?:[/?#][^\s<>)]*)?"
)
RELATIVE_MARKDOWN_PULL_REFERENCE = re.compile(
    r"!?\[[^]\n]*\]\((?://(?:www[.])?github[.]com)?/"
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(?P<number>[0-9]+)(?:[/?#][^\s<>)]*)?\)",
    re.IGNORECASE,
)
RELATIVE_REFERENCE_PULL_DEFINITION = re.compile(
    r"^[ \t]{0,3}\[(?P<label>[^]\n]+)\]:[ \t]*<?(?://(?:www[.])?github[.]com)?/"
    r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/(?P<number>[0-9]+)(?:[/?#][^\s<>]*)?>?"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^\)\n]*\)))?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
REFERENCE_LINK_USE = re.compile(r"!?\[(?P<text>[^]\n]*)\]\[(?P<label>[^]\n]*)\]")
MARKDOWN_PULL_REFERENCE = re.compile(rf"!?\[[^]\n]*\]\({GITHUB_PULL_URL_PATTERN}\)", re.IGNORECASE)
AUTOLINK_PULL_REFERENCE = re.compile(rf"<{GITHUB_PULL_URL_PATTERN}>", re.IGNORECASE)
PULL_URL_REFERENCE = re.compile(GITHUB_PULL_URL_PATTERN, re.IGNORECASE)
GH_NUMBER_REFERENCE = re.compile(r"(?<![\w-])GH-(?P<number>[0-9]+)\b", re.IGNORECASE)
HASH_NUMBER_REFERENCE = re.compile(
    r"(?<![\w&])(?:(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+))?#(?P<number>[0-9]+)\b"
)


def validate_order(prs, order):
    prs = [int(value) for value in prs]
    order = [int(value) for value in order]
    if len(prs) < 2 or len(prs) != len(set(prs)):
        raise ValueError("coordination needs at least two distinct pull requests")
    if len(order) != len(set(order)) or set(prs) != set(order):
        raise ValueError("the merge order must contain every coordinated pull request exactly once")
    return sorted(prs), order


def marker(record):
    targets = [int(number) for number in record.get("targets", record["order"])]
    value = {
        "id": str(record["id"]),
        "order": [int(number) for number in record["order"]],
        "state": str(record["state"]),
        "supersedes": sorted(str(value) for value in record.get("supersedes", [])),
        "targets": targets,
    }
    return f"<!-- agent-pr-coordination:v1 {json.dumps(value, separators=(',', ':'), sort_keys=True)} -->"


def parse_marker(body):
    match = MARKER.search(str(body or ""))
    if not match:
        return None
    try:
        value = json.loads(match.group(1))
        _prs, order = validate_order(value.get("order", []), value.get("order", []))
        state = str(value.get("state") or "")
        identifier = str(value.get("id") or "")
        supersedes = [str(item) for item in value.get("supersedes", [])]
        targets = [int(number) for number in value.get("targets", order)]
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if state not in ("final", "fulfilled") or not identifier or identifier in supersedes \
            or len(targets) != len(set(targets)) or not set(order).issubset(targets):
        return None
    return {
        "id": identifier, "order": order, "state": state, "supersedes": supersedes, "targets": targets,
    }


def trusted_comment(comment):
    """Accept coordination only from identities GitHub associates with repository stewardship."""
    return str(comment.get("author_association") or "").upper() in TRUSTED_ASSOCIATIONS


def records_from_comments(comments):
    """Return the latest mirrored event for every machine-readable record."""
    latest = {}
    for comment in comments:
        if not trusted_comment(comment):
            continue
        record = parse_marker(comment.get("body"))
        if record is None:
            continue
        record.update({
            "comment_id": int(comment.get("id") or 0),
            "created_at": str(comment.get("created_at") or ""),
            "url": str(comment.get("html_url") or ""),
        })
        previous = latest.get(record["id"])
        key = (record["created_at"], record["comment_id"])
        old_key = (previous.get("created_at", ""), previous.get("comment_id", 0)) if previous else ("", 0)
        if previous is None or key >= old_key:
            latest[record["id"]] = record
    superseded = {
        identifier
        for record in latest.values()
        for identifier in record.get("supersedes", [])
    }
    return sorted(
        (
            record for identifier, record in latest.items()
            if record["state"] == "final" and identifier not in superseded
        ),
        key=lambda record: (record["created_at"], record["comment_id"], record["id"]),
    )


def graph_edges(records):
    return {
        (left, right)
        for record in records
        for left, right in zip(record["order"], record["order"][1:])
    }


def has_cycle(records):
    edges = graph_edges(records)
    successors = {}
    for left, right in edges:
        successors.setdefault(left, set()).add(right)
        successors.setdefault(right, set())
    visiting = set()
    visited = set()

    def visit(node):
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(successor) for successor in successors.get(node, ())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in successors)


def coordinated_pairs(records):
    pairs = set()
    for record in records:
        order = record["order"]
        for index, left in enumerate(order):
            for right in order[index + 1:]:
                pairs.add(frozenset((left, right)))
    return pairs


def pull_reference(number):
    return f"PR {int(number)}"


def without_hash_number_references(value):
    """Keep coordination prose from creating GitHub cross-reference events."""
    def qualified_replacement(match):
        repository = match.group("repository")
        reference = pull_reference(match.group("number"))
        return f"{repository} {reference}" if repository else reference

    reference_definitions = {}

    def remember_reference_definition(match):
        label = " ".join(match.group("label").split()).casefold()
        reference_definitions.setdefault(label, qualified_replacement(match))
        return ""

    def replace_reference_link(match):
        label = match.group("label") or match.group("text")
        return reference_definitions.get(" ".join(label.split()).casefold(), match.group(0))

    value = RELATIVE_REFERENCE_PULL_DEFINITION.sub(remember_reference_definition, str(value or ""))
    value = REFERENCE_LINK_USE.sub(replace_reference_link, value)
    value = RELATIVE_MARKDOWN_PULL_REFERENCE.sub(qualified_replacement, value)
    value = MARKDOWN_PULL_REFERENCE.sub(qualified_replacement, value)
    value = AUTOLINK_PULL_REFERENCE.sub(qualified_replacement, value)
    value = PULL_URL_REFERENCE.sub(qualified_replacement, value)
    value = GH_NUMBER_REFERENCE.sub(lambda match: pull_reference(match.group("number")), value)
    return HASH_NUMBER_REFERENCE.sub(qualified_replacement, value)


def render_final(record, overlap, reason, reconsider, changed_fact="", changed_criterion="", language="en"):
    if language not in NOTICE:
        raise ValueError("coordination language must be en or de")
    _prs, order = validate_order(record["order"], record["order"])
    record = dict(record, order=order, state="final")
    reference_joiner = " und " if language == "de" else " and "
    references = reference_joiner.join(pull_reference(number) for number in order)
    sequence = " → ".join(pull_reference(number) for number in order)
    supersedes = record.get("supersedes", [])
    overlap = without_hash_number_references(overlap)
    reason = without_hash_number_references(reason)
    reconsider = without_hash_number_references(reconsider)
    changed_fact = without_hash_number_references(changed_fact).strip()
    changed_criterion = without_hash_number_references(changed_criterion).strip()
    if supersedes and (not changed_fact or not changed_criterion):
        raise ValueError("a replacement recommendation must name its changed fact and decision criterion")
    if not supersedes and (changed_fact or changed_criterion):
        raise ValueError("changed evidence belongs only to a replacement recommendation")
    if language == "de":
        steps = [f"1. Zuerst {pull_reference(order[0])} mergen."]
        for index, number in enumerate(order[1:], 2):
            steps.append(
                f"{index}. Nach dem Merge aller Vorgänger {pull_reference(number)} darauf aktualisieren und "
                f"validieren; danach {pull_reference(number)} mergen."
            )
        replaced = (
            "Diese Empfehlung ersetzt: " + ", ".join(f"`{value}`" for value in supersedes) + ". "
            f"Neue Tatsache: {changed_fact} Betroffenes Entscheidungskriterium: {changed_criterion}"
            if supersedes else "Diese Empfehlung ist die aktive Reihenfolge für diese Pull Requests."
        )
        sections = [
            marker(record),
            f"Finale Koordination für {references}",
            f"Merge-Reihenfolge: {sequence}",
            "\n".join(steps),
            f"Keine spätere Position darf vor ihren Vorgängern gemergt werden. Überschneidung: {overlap}",
            f"Grund: {reason}",
            f"Neu bewerten, wenn: {reconsider}",
            (
                "Diese Empfehlung bestimmt nur die Reihenfolge. Kein Agent mergt einen Pull Request ohne eine "
                "ausdrückliche menschliche Aufforderung, die den Pull Request nennt."
            ),
            replaced,
            NOTICE[language],
        ]
    else:
        steps = [f"1. Merge {pull_reference(order[0])} first."]
        for index, number in enumerate(order[1:], 2):
            steps.append(
                f"{index}. After every predecessor has merged, update and validate {pull_reference(number)} "
                f"against them; then merge {pull_reference(number)}."
            )
        replaced = (
            "This recommendation supersedes: " + ", ".join(f"`{value}`" for value in supersedes) + ". "
            f"New fact: {changed_fact} Affected decision criterion: {changed_criterion}"
            if supersedes else "This is the active order for these pull requests."
        )
        sections = [
            marker(record),
            f"Final coordination recommendation for {references}",
            f"Merge order: {sequence}",
            "\n".join(steps),
            f"Do not merge a later position before all of its predecessors. Overlap: {overlap}",
            f"Reason: {reason}",
            f"Reconsider when: {reconsider}",
            (
                "This recommendation defines order only. No agent merges a pull request without an explicit human "
                "instruction naming that pull request."
            ),
            replaced,
            NOTICE[language],
        ]
    return "\n\n".join(sections)


def render_fulfilled(record, language="en"):
    if language not in NOTICE:
        raise ValueError("coordination language must be en or de")
    record = dict(record, state="fulfilled")
    sequence = " → ".join(pull_reference(number) for number in record["order"])
    text = (
        f"Koordination `{record['id']}` für {sequence} ist erfüllt."
        if language == "de" else f"Coordination `{record['id']}` for {sequence} is fulfilled."
    )
    return "\n\n".join((marker(record), text, NOTICE[language]))


def status_notice(records, current_number, pull_states):
    notices = []
    for record in records:
        order = record["order"]
        if current_number not in order:
            continue
        position = order.index(current_number)
        predecessors = order[:position]
        open_predecessors = [number for number in predecessors if pull_states.get(number) == "open"]
        merged_predecessors = [number for number in predecessors if pull_states.get(number) == "merged"]
        closed_predecessors = [number for number in predecessors if pull_states.get(number) == "closed"]
        sequence = " -> ".join(f"#{number}" for number in order)
        if closed_predecessors:
            notices.append(
                f"Final coordination {sequence} needs replacement because "
                f"{', '.join(f'#{number}' for number in closed_predecessors)} closed without merging."
            )
        elif open_predecessors:
            notices.append(
                f"Final coordination {sequence} is active: current pull request #{current_number} must not merge "
                f"before {', '.join(f'#{number}' for number in open_predecessors)}, but may continue to its next "
                "safe synchronization checkpoint."
            )
        elif merged_predecessors:
            notices.append(
                f"Final coordination {sequence} is now actionable: integrate the merged predecessor(s) "
                f"{', '.join(f'#{number}' for number in merged_predecessors)} once at the next checkpoint."
            )
        elif position == 0:
            notices.append(
                f"Final coordination {sequence} gives current pull request #{current_number} precedence; do not "
                "integrate later pull requests merely to chase anticipated conflicts."
            )
    return " ".join(notices)
