#!/usr/bin/env python3

"""Keep issues and pull requests short, complete and useful to a reviewer.

    python3 packaging/contribution-lint.py --title "fix(auth): ..." --body-file /tmp/pr.md
    python3 packaging/contribution-lint.py --pull-request-event
    python3 packaging/contribution-lint.py --issue-event --result-file /tmp/result.json

The commit header remains defined by commits.py. This file owns only the
forge-facing structure and the deliberately forgiving prose count.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))

import commits  # noqa: E402


ISSUE_LIMIT = 175
PULL_REQUEST_LIMIT = 125
ISSUE_HEADINGS = ("TL;DR", "Where", "Now", "Want", "To decide")
PULL_REQUEST_HEADINGS = ("Issue", "Area", "Change", "Resolution", "Validation", "Upgrade impact")
AI_NOTICES = (
    "*An AI agent wrote this text on my behalf; I am responsible for its content.*",
    "*Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.*",
)
KNOWN_HEADINGS = set(ISSUE_HEADINGS + PULL_REQUEST_HEADINGS + ("Suggested area",))
AREA_LABELS = {
    "area: oidc", "area: opnsense", "area: ui", "area: packaging", "area: contribution",
}
CHANGE_BY_COMMIT = {
    "feat": "change: feature",
    "fix": "change: fix",
    "perf": "change: performance",
    "docs": "change: docs",
    "refactor": "change: maintenance",
    "build": "change: maintenance",
    "ci": "change: maintenance",
    "test": "change: maintenance",
    "chore": "change: maintenance",
    "style": "change: maintenance",
    "revert": "change: maintenance",
}
CHANGE_LABELS = set(CHANGE_BY_COMMIT.values())
ISSUE_TYPE_LABELS = {"type: bug", "type: change", "type: docs", "type: question"}
BREAKING_LABEL = "impact: breaking"
LABEL_PROBLEM_PREFIXES = (
    "pull request labels must contain",
    "pull request `area:*` labels must match",
    "issue `type:*` labels do not belong",
    f"`{BREAKING_LABEL}` must match",
)
PULL_REQUEST_POLL_ATTEMPTS = 6
PULL_REQUEST_POLL_DELAY = 2

HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
FENCED_CODE = re.compile(r"^\s*(```|~~~).*?^\s*\1\s*$", re.M | re.S)
INLINE_CODE = re.compile(r"`+[^`\n]*`+")
IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
RAW_URL = re.compile(r"(?:https?|ftp)://[^\s<>)]+|<https?://[^>]+>", re.I)
CLOSING_REFERENCE = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#\d+\b", re.I)
HEADING = re.compile(r"^(#{2,6})\s+(.+?)\s*$", re.M)
CHECKBOX = re.compile(r"^\s*[-*+]\s+\[([ xX])\]\s*(.*)$", re.M)
WORD = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)*|\d+", re.UNICODE)
TECHNICAL_TOKEN = re.compile(
    r"(?<!\w)(?:--?[A-Za-z][\w-]*|#\d+)(?!\w)"
    r"|(?<!\w)[\w.-]+(?:[/\\][\w.@+~-]+)+(?!\w)"
    r"|\b(?:[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+|[a-z]+[A-Z][A-Za-z0-9]*)\b"
    r"|\b[A-Z][A-Z0-9_]{1,}\b"
    r"|\b[A-Za-z0-9_-]+\.(?:php|py|js|mjs|json|ya?ml|md|sh|xml|inc|conf|pkg)\b"
    r"|\b(?:type|area):\s*[a-z][a-z-]*\b",
)
PLACEHOLDER = re.compile(r"^(?:todo|tbd|n/?a|no response|replace this.*)$", re.I)
ISSUE_REFERENCE = re.compile(r"^Fixes\s+#(?P<number>[1-9]\d*)$", re.I)


def event_payload():
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path or not Path(path).is_file():
        raise ValueError("GITHUB_EVENT_PATH does not name an event payload")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def without_authored_markup(text):
    """Remove material that is formatting or machine-readable rather than prose."""
    text = HTML_COMMENT.sub(" ", text)
    text = FENCED_CODE.sub(" ", text)
    text = INLINE_CODE.sub(" ", text)
    text = IMAGE.sub(" ", text)
    text = LINK.sub(r"\1", text)
    text = RAW_URL.sub(" ", text)
    text = CLOSING_REFERENCE.sub(" ", text)
    for notice in AI_NOTICES:
        text = text.replace(notice, " ")

    kept = []
    for line in text.splitlines():
        heading = HEADING.fullmatch(line)
        if heading and heading.group(2).strip() in KNOWN_HEADINGS:
            continue
        if PLACEHOLDER.fullmatch(re.sub(r"[*_~]", "", line.strip())):
            continue
        if line.strip() == "None":
            continue
        if line.strip() == "Same as issue":
            continue
        line = re.sub(r"^\s*BREAKING[ -]CHANGE:\s*", "", line)
        line = re.sub(r"^\s*[-*+]\s+\[[ xX]\]\s*", "", line)
        kept.append(line)

    text = "\n".join(kept)
    text = TECHNICAL_TOKEN.sub(" ", text)
    text = re.sub(r"[*_~>|{}()[\]#]", " ", text)
    return text


def prose_words(text):
    return WORD.findall(without_authored_markup(text))


def count_prose(text):
    return len(prose_words(text))


def sections(text):
    """Return headings in order and their content; duplicates remain visible."""
    cleaned = HTML_COMMENT.sub("", text)
    matches = list(HEADING.finditer(cleaned))
    found = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(cleaned)
        found.append((match.group(2).strip(), cleaned[match.end():end].strip()))
    return found


def structure_problems(body, expected):
    found = sections(body)
    names = [name for name, _ in found]
    problems = []
    positions = []
    for heading in expected:
        occurrences = [index for index, name in enumerate(names) if name == heading]
        if not occurrences:
            problems.append(f"missing `{heading}` section")
            continue
        if len(occurrences) > 1:
            problems.append(f"duplicate `{heading}` section")
        positions.append(occurrences[0])
        content = found[occurrences[0]][1].strip()
        if not content or PLACEHOLDER.fullmatch(content):
            problems.append(f"`{heading}` is empty or still a placeholder")
    if len(positions) == len(expected) and positions != sorted(positions):
        problems.append("required sections are not in the template order")
    return problems


def validate_issue(body):
    count = count_prose(body)
    problems = structure_problems(body, ISSUE_HEADINGS)
    if count > ISSUE_LIMIT:
        problems.append(f"issue prose has {count} words; at most {ISSUE_LIMIT} are allowed")
    return {"valid": not problems, "word_count": count, "limit": ISSUE_LIMIT, "problems": problems}


def visible_text(body):
    return HTML_COMMENT.sub("", FENCED_CODE.sub("", body)).strip()


def notice_problems(body):
    visible = visible_text(body)
    exact = [(notice, visible.count(notice)) for notice in AI_NOTICES]
    count = sum(amount for _, amount in exact)
    mentions_notice = "AI agent wrote this text" in visible or "KI-Agent hat diesen Text" in visible
    if not count and not mentions_notice:
        return [], False

    problems = []
    if count != 1:
        problems.append("an agent contribution must contain exactly one supported AI notice")
        return problems, True

    notice = next(notice for notice, amount in exact if amount)
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", visible) if part.strip()]
    if not paragraphs or paragraphs[-1] != notice:
        problems.append("the exact AI notice must be its own final paragraph")
    if mentions_notice and not visible.endswith(notice):
        problems.append("the AI notice text must not be changed")
    return list(dict.fromkeys(problems)), True


def repository_from_remote():
    configured = os.environ.get("GITHUB_REPOSITORY", "")
    if configured:
        return configured
    remote = subprocess.run(
        ("git", "config", "--get", "remote.origin.url"),
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    match = re.search(r"github\.com[/:](?P<repo>[^/]+/[^/]+?)(?:\.git)?$", remote)
    return match.group("repo") if match else ""


def github_resource(repository, path, description):
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    request = Request(f"{api}/repos/{repository}/{path.lstrip('/')}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "opnsense-openid-connect-contribution-lint")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=15) as response:
            return json.load(response)
    except HTTPError as error:
        raise ValueError(f"{description} could not be read (HTTP {error.code})") from error
    except URLError as error:
        raise ValueError(f"{description} could not be read ({error.reason})") from error


def github_issue(repository, number):
    return github_resource(repository, f"issues/{number}", f"issue #{number}")


def github_pull_request(repository, number):
    # Pull requests share GitHub's issue endpoint, including current title,
    # body and labels. Using it keeps the workflow's permission metadata-only.
    return github_resource(repository, f"issues/{number}", f"pull request #{number}")


def instant(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def validate_issue_reference(number, repository, pull_request_created, issue_reader):
    if not repository:
        return ["the repository is needed to verify the referenced issue"]
    try:
        issue = issue_reader(repository, number)
    except ValueError as error:
        return [str(error)]
    if issue.get("pull_request") is not None:
        return [f"#{number} is a pull request, not an issue"]
    issue_created = instant(issue.get("created_at"))
    request_created = instant(pull_request_created)
    if request_created and (not issue_created or issue_created >= request_created):
        return [f"issue #{number} was not created before this pull request"]
    return []


def label_names(labels):
    return [label if isinstance(label, str) else label.get("name", "") for label in (labels or [])]


def requested_areas(area_text, issue_match, repository, issue_reader):
    if area_text == "Same as issue":
        if not issue_match:
            return [], ["`Area` can use `Same as issue` only with `Fixes #N`"]
        if not repository:
            return [], ["the repository is needed to inherit the issue area"]
        number = int(issue_match.group("number"))
        try:
            issue = issue_reader(repository, number)
        except ValueError as error:
            return [], [str(error)]
        if issue.get("pull_request") is not None:
            return [], [f"#{number} is a pull request, not an issue"]
        areas = [name for name in label_names(issue.get("labels")) if name in AREA_LABELS]
        if not 1 <= len(areas) <= 2:
            return [], [f"issue #{number} needs one or two `area:*` labels before the pull request can inherit them"]
        return areas, []

    areas = [line.strip() for line in area_text.splitlines() if line.strip()]
    if not 1 <= len(areas) <= 2 or len(set(areas)) != len(areas) or any(area not in AREA_LABELS for area in areas):
        return [], ["`Area` must contain `Same as issue`, or one or two supported `area:*` labels"]
    return areas, []


def validate_pull_request(title, body, repository="", created_at="", issue_reader=github_issue, labels=None):
    problems = []
    future = commits.Commit(f"{title.strip()}\n\n{body.strip()}")
    if future.generated:
        problems.append("the pull request title must use the Conventional Commit form")
    else:
        problems.extend(future.problems())

    found = sections(body)
    by_name = {name: content for name, content in found}
    problems.extend(structure_problems(body, PULL_REQUEST_HEADINGS))
    count = count_prose(body)
    if count > PULL_REQUEST_LIMIT:
        problems.append(f"pull request prose has {count} words; at most {PULL_REQUEST_LIMIT} are allowed")

    issue_text = by_name.get("Issue", "").strip()
    issue_match = ISSUE_REFERENCE.fullmatch(issue_text)
    if issue_text != "None" and not issue_match:
        problems.append("`Issue` must contain exactly `Fixes #N`, or `None` for a human-authored direct contribution")

    areas, area_errors = requested_areas(by_name.get("Area", "").strip(), issue_match, repository, issue_reader)
    problems.extend(area_errors)

    for heading in ("Change", "Resolution"):
        if heading in by_name and not prose_words(by_name[heading]):
            problems.append(f"`{heading}` must contain authored prose")

    validation = by_name.get("Validation", "")
    checked = any(mark.lower() == "x" for mark, _ in CHECKBOX.findall(validation))
    not_run = re.search(r"(?m)^\s*Not run:\s*\S.+$", validation)
    if validation and not checked and not not_run:
        problems.append("`Validation` needs a checked test or `Not run: <reason>`")

    upgrade = by_name.get("Upgrade impact", "").strip()
    title_match = commits.HEADER.match(title.strip())
    title_breaking = bool(title_match and title_match.group("breaking"))
    footer = commits.BREAKING_FOOTER.search(upgrade)
    if title_breaking and not footer:
        problems.append("a `!` title needs a concrete `BREAKING CHANGE:` operator instruction")
    if footer and not title_breaking:
        problems.append("a `BREAKING CHANGE:` instruction also needs `!` in the pull request title")

    if labels is not None:
        assigned = set(label_names(labels))
        future_change = CHANGE_BY_COMMIT.get(future.type)
        assigned_changes = assigned & CHANGE_LABELS
        if not future_change or assigned_changes != {future_change}:
            expected = future_change or "a supported change:* label"
            problems.append(f"pull request labels must contain exactly `{expected}`")
        assigned_areas = assigned & AREA_LABELS
        if areas and assigned_areas != set(areas):
            problems.append("pull request `area:*` labels must match its `Area` section")
        if assigned & ISSUE_TYPE_LABELS:
            problems.append("issue `type:*` labels do not belong on pull requests")
        if title_breaking != (BREAKING_LABEL in assigned):
            problems.append(f"`{BREAKING_LABEL}` must match the `!` in the pull request title")

    notice_errors, agent_authored = notice_problems(body)
    problems.extend(notice_errors)
    if agent_authored:
        if not issue_match:
            problems.append("an agent-authored pull request must close exactly one earlier issue with `Fixes #N`")
        else:
            problems.extend(validate_issue_reference(
                int(issue_match.group("number")), repository, created_at, issue_reader
            ))

    return {
        "valid": not problems,
        "word_count": count,
        "limit": PULL_REQUEST_LIMIT,
        "agent_authored": agent_authored,
        "problems": list(dict.fromkeys(problems)),
    }


def validate_pull_request_event(event, request_reader=github_pull_request, issue_reader=github_issue,
                                pause=time.sleep):
    """Validate live PR metadata, waiting briefly for the separate label workflow."""
    payload = event.get("pull_request") or {}
    repository = (event.get("repository") or {}).get("full_name") or ""
    number = event.get("number") or payload.get("number")
    if not repository or not number:
        raise ValueError("the pull request event needs a repository and number")

    result = None
    for attempt in range(PULL_REQUEST_POLL_ATTEMPTS):
        request = request_reader(repository, int(number))
        result = validate_pull_request(
            request.get("title") or "",
            request.get("body") or "",
            repository,
            request.get("created_at") or payload.get("created_at") or "",
            issue_reader=issue_reader,
            labels=request.get("labels") or [],
        )
        waiting_for_labels = any(
            problem.startswith(LABEL_PROBLEM_PREFIXES) for problem in result["problems"]
        )
        if not waiting_for_labels or attempt + 1 == PULL_REQUEST_POLL_ATTEMPTS:
            return result
        pause(PULL_REQUEST_POLL_DELAY)
    return result


def print_result(result):
    if result["valid"]:
        print(f"{result['word_count']} counted prose words (limit {result['limit']}); contribution is in shape.")
        return 0
    print(f"{result['word_count']} counted prose words (limit {result['limit']}).", file=sys.stderr)
    for problem in result["problems"]:
        print(f"  - {problem}", file=sys.stderr)
    return 1


def arguments():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pull-request-event", action="store_true", help="read the current pull request event")
    source.add_argument("--issue-event", action="store_true", help="read the current issue event")
    source.add_argument("--title", help="locally validate this pull request title")
    parser.add_argument("--body-file", help="pull request body used with --title")
    parser.add_argument("--repository", help="owner/name used to verify an agent's issue")
    parser.add_argument("--result-file", help="write the machine-readable result here")
    return parser.parse_args()


def main():
    args = arguments()
    try:
        if args.issue_event:
            event = event_payload()
            result = validate_issue((event.get("issue") or {}).get("body") or "")
        elif args.pull_request_event:
            event = event_payload()
            result = validate_pull_request_event(event)
        else:
            if not args.body_file:
                raise ValueError("--title also requires --body-file")
            result = validate_pull_request(
                args.title,
                Path(args.body_file).read_text(encoding="utf-8"),
                args.repository or repository_from_remote(),
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"cannot validate contribution: {error}", file=sys.stderr)
        return 1

    if args.result_file:
        Path(args.result_file).write_text(json.dumps(result), encoding="utf-8")
        return 0
    return print_result(result)


if __name__ == "__main__":
    sys.exit(main())
