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


def validate_order(prs, order):
    prs = [int(value) for value in prs]
    order = [int(value) for value in order]
    if len(prs) < 2 or len(prs) != len(set(prs)):
        raise ValueError("coordination needs at least two distinct pull requests")
    if len(order) != len(set(order)) or set(prs) != set(order):
        raise ValueError("the merge order must contain every coordinated pull request exactly once")
    return sorted(prs), order


def marker(record):
    value = {
        "id": str(record["id"]),
        "order": [int(number) for number in record["order"]],
        "state": str(record["state"]),
        "supersedes": sorted(str(value) for value in record.get("supersedes", [])),
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
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if state not in ("final", "fulfilled") or not identifier or identifier in supersedes:
        return None
    return {"id": identifier, "order": order, "state": state, "supersedes": supersedes}


def records_from_comments(comments):
    """Return the latest mirrored event for every machine-readable record."""
    latest = {}
    for comment in comments:
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


def render_final(record, overlap, reason, reconsider, language="en"):
    if language not in NOTICE:
        raise ValueError("coordination language must be en or de")
    _prs, order = validate_order(record["order"], record["order"])
    record = dict(record, order=order, state="final")
    references = " and ".join(f"#{number}" for number in order)
    sequence = " → ".join(f"#{number}" for number in order)
    supersedes = record.get("supersedes", [])
    if language == "de":
        steps = [f"1. Zuerst #{order[0]} mergen."]
        for index, number in enumerate(order[1:], 2):
            steps.append(
                f"{index}. Nach dem Merge aller Vorgänger #{number} darauf aktualisieren und validieren; "
                f"danach #{number} mergen."
            )
        replaced = (
            "Diese Empfehlung ersetzt: " + ", ".join(f"`{value}`" for value in supersedes) + "."
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
        steps = [f"1. Merge #{order[0]} first."]
        for index, number in enumerate(order[1:], 2):
            steps.append(
                f"{index}. After every predecessor has merged, update and validate #{number} against them; "
                f"then merge #{number}."
            )
        replaced = (
            "This recommendation supersedes: " + ", ".join(f"`{value}`" for value in supersedes) + "."
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
    sequence = " → ".join(f"#{number}" for number in record["order"])
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
        if open_predecessors:
            notices.append(
                f"Final coordination {sequence} is active: current pull request #{current_number} must not merge "
                f"before {', '.join(f'#{number}' for number in open_predecessors)}, but may continue to its next "
                "safe synchronization checkpoint."
            )
        elif closed_predecessors:
            notices.append(
                f"Final coordination {sequence} needs replacement because "
                f"{', '.join(f'#{number}' for number in closed_predecessors)} closed without merging."
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
