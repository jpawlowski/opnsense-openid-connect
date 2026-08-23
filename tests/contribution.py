#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Checks the small, scan-friendly issue and pull-request contract."""

import importlib.util
import json
import pathlib
import os
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "tests"))

from harness import check, group  # noqa: E402
import harness  # noqa: E402


def load():
    spec = importlib.util.spec_from_file_location(
        "contribution_lint", ROOT / "packaging" / "contribution-lint.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint = load()


def issue_body(tldr="Short summary.", where="The login flow.", now="It fails.",
               want="It works.", decide="Choose the safe direction."):
    return (
        f"### TL;DR\n{tldr}\n\n### Where\n{where}\n\n### Now\n{now}\n\n"
        f"### Want\n{want}\n\n### To decide\n{decide}"
    )


def pull_request_body(issue="None", change="Added a focused check.",
                      resolution="It prevents empty submissions.",
                      validation="- [x] `./tests/run.sh`", upgrade="None", notice=""):
    body = (
        f"## Issue\n\n{issue}\n\n## Change\n\n{change}\n\n## Resolution\n\n{resolution}\n\n"
        f"## Validation\n\n{validation}\n\n## Upgrade impact\n\n{upgrade}"
    )
    return f"{body}\n\n{notice}" if notice else body


def main():
    group("Only authored prose counts")
    sample = (
        "Three visible words [and two](https://example.net/path) `inline code`\n"
        "```php\nfunction hidden_code() {}\n```\n"
        "Fixes #123\n./tests/run.sh --flag src/file.php\nNone\n"
        f"{lint.AI_NOTICES[0]}"
    )
    check("formatting, code, references and exact defaults are free",
          lint.prose_words(sample), ["Three", "visible", "words", "and", "two"])
    check("a custom link label remains prose", lint.count_prose("[read this](https://example.net)"), 2)
    check("an unknown heading is authored prose", lint.count_prose("## Additional context\nUseful detail"), 4)
    check("the breaking prefix is free but its instruction counts",
          lint.prose_words("BREAKING CHANGE: set the provider again"),
          ["set", "the", "provider", "again"])

    group("Issue structure and limit")
    check("the five concise fields pass", lint.validate_issue(issue_body())["valid"], True)
    missing = lint.validate_issue(issue_body().replace("### Want", "### Other"))
    check("a renamed required field fails", any("missing `Want`" in item for item in missing["problems"]))
    blank = lint.validate_issue(issue_body(where="No response"))
    check("an untouched empty form answer fails", any("`Where` is empty" in item for item in blank["problems"]))
    at_limit = issue_body(tldr="word " * 164)
    check("175 counted issue words pass", lint.validate_issue(at_limit)["word_count"], 175)
    check("the exact issue limit passes", lint.validate_issue(at_limit)["valid"], True)
    over_limit = issue_body(tldr="word " * 165)
    check("176 counted issue words fail", lint.validate_issue(over_limit)["valid"], False)

    group("Pull-request structure and title")
    valid = pull_request_body()
    check("a human may make a direct contribution", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", valid
    )["valid"], True)
    check("a capitalized release-note subject fails", lint.validate_pull_request(
        "fix(ci): Reject empty pull request bodies", valid
    )["valid"], False)
    unchecked = pull_request_body(validation="- [ ] `./tests/run.sh`")
    check("an untouched validation checkbox fails", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", unchecked
    )["valid"], False)
    check("an explicit reason instead of a test passes", lint.validate_pull_request(
        "docs: explain contribution checks", pull_request_body(validation="Not run: documentation only")
    )["valid"], True)
    commented = pull_request_body().replace(
        "## Change\n", "## Change\n\n<!-- retained template guidance -->\n"
    )
    check("retained hidden template guidance does not disturb sections", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", commented
    )["valid"], True)
    untouched = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    template_commit = lint.commits.Commit("fix: ordinary change\n\n" + untouched)
    check("the template's example footer cannot mark every squash commit as breaking",
          template_commit.breaking, False)
    old_title = lint.validate_pull_request("Add CODEOWNERS file for repository ownership", untouched)
    new_title = lint.validate_pull_request("chore: add CODEOWNERS file for repository ownership", untouched)
    check("the original title from PR 7 fails", old_title["valid"], False)
    check("the corrected PR 7 title still cannot excuse an untouched body", new_title["valid"], False)

    at_pr_limit = pull_request_body(change="word " * 123, resolution="One two.")
    check("125 counted pull-request words pass",
          lint.validate_pull_request("fix: keep a concise change", at_pr_limit)["word_count"], 125)
    check("the exact pull-request limit passes",
          lint.validate_pull_request("fix: keep a concise change", at_pr_limit)["valid"], True)
    over_pr_limit = pull_request_body(change="word " * 124, resolution="One two.")
    check("126 counted pull-request words fail",
          lint.validate_pull_request("fix: keep a concise change", over_pr_limit)["valid"], False)

    group("Breaking changes and agent attribution")
    breaking = pull_request_body(upgrade="BREAKING CHANGE: set the provider before upgrading.")
    check("a marked title and operator instruction pass", lint.validate_pull_request(
        "fix(auth)!: require a provider setting", breaking
    )["valid"], True)
    check("a bang without an instruction fails", lint.validate_pull_request(
        "fix(auth)!: require a provider setting", valid
    )["valid"], False)
    check("an instruction without a bang fails", lint.validate_pull_request(
        "fix(auth): require a provider setting", breaking
    )["valid"], False)

    notice = lint.AI_NOTICES[0]
    agent_body = pull_request_body(issue="Fixes #42", notice=notice)
    older_issue = lambda repository, number: {"number": number, "created_at": "2026-01-01T00:00:00Z"}
    agent = lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", agent_body, "owner/repo",
        "2026-01-02T00:00:00Z", older_issue,
    )
    check("an attributed agent links one earlier issue", agent["valid"], True)
    check("the exact agent notice is excluded from prose",
          lint.count_prose(agent_body), lint.count_prose(agent_body.replace(notice, "")))
    check("an agent cannot use the human None escape", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", pull_request_body(notice=notice),
        "owner/repo", "2026-01-02T00:00:00Z", older_issue,
    )["valid"], False)
    later_issue = lambda repository, number: {"number": number, "created_at": "2026-01-03T00:00:00Z"}
    check("the linked issue must predate the pull request", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", agent_body, "owner/repo",
        "2026-01-02T00:00:00Z", later_issue,
    )["valid"], False)
    not_an_issue = lambda repository, number: {
        "number": number, "created_at": "2026-01-01T00:00:00Z", "pull_request": {}
    }
    check("a pull request number is not accepted as the issue", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", agent_body, "owner/repo",
        "2026-01-02T00:00:00Z", not_an_issue,
    )["valid"], False)
    check("the notice must be the final paragraph", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies", f"{agent_body}\n\nAfterthought.",
        "owner/repo", "2026-01-02T00:00:00Z", older_issue,
    )["valid"], False)

    group("The workflows keep edits and automation safe")
    build = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    issue_workflow = (ROOT / ".github" / "workflows" / "issue-hygiene.yml").read_text(encoding="utf-8")
    pull_request_template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    contribution_skill = (
        ROOT / ".agents" / "skills" / "github-contribution" / "SKILL.md"
    ).read_text(encoding="utf-8")
    check("editing a title or body triggers a fresh pull-request check",
          "types: [opened, edited, synchronize, reopened]" in build)
    check("only the latest pull-request run matters",
          "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in build)
    check("the contribution linter replaces the narrower pull-request check",
          "contribution-lint.py --pull-request-event" in build)
    check("issue hygiene reacts to edits", "types: [opened, edited, reopened]" in issue_workflow)
    check("the issue mutator is pinned to an immutable action commit",
          "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3" in issue_workflow)
    check("untrusted issue text is passed through an event file, not shell interpolation",
          "github.event.issue.body" not in issue_workflow)
    check("the skill exposes every release-note type",
          [kind for kind in lint.commits.TYPES if f"`{kind}`" not in contribution_skill], [])
    check("the pull-request template exposes every release-note type",
          [kind for kind in lint.commits.TYPES
           if not re.search(rf"\b{re.escape(kind)}\b", pull_request_template)], [])
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    check("agent and contributor rules wait for a review of the current head",
          all("current head" in text.lower() for text in (contribution_skill, agents, contributing)), True)
    check("high and medium Codex findings are explicitly merge-blocking",
          all("P0, P1 and P2" in text for text in (contribution_skill, agents, contributing)), True)
    rules_readme = (ROOT / ".github" / "rulesets" / "README.md").read_text(encoding="utf-8")
    json.loads((ROOT / ".github" / "rulesets" / "main.json").read_text(encoding="utf-8"))
    check("the strict ruleset import has a documented adjacent copyright exception",
          "Copyright (C) 2026 Julian Pawlowski" in rules_readme
          and "strict import schema" in rules_readme, True)

    forms = [
        (ROOT / ".github" / "ISSUE_TEMPLATE" / name).read_text(encoding="utf-8")
        for name in ("bug.yml", "change.yml")
    ]
    field_ids = [re.findall(r"^\s+id:\s+(\S+)$", form, re.M) for form in forms]
    check("both issue forms use the same five fields in the same order",
          field_ids, [["tldr", "where", "now", "want", "to_decide"]] * 2)
    config = (ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
    check("blank issues are disabled and security reports stay private",
          "blank_issues_enabled: false" in config and "/security/advisories/new" in config)

    group("Issue-event output remains a soft hygiene result")
    with tempfile.TemporaryDirectory() as temporary:
        temporary = pathlib.Path(temporary)
        event = temporary / "event.json"
        result = temporary / "result.json"
        event.write_text(json.dumps({"issue": {"body": ""}}), encoding="utf-8")
        environment = os.environ.copy()
        environment["GITHUB_EVENT_PATH"] = str(event)
        process = subprocess.run(
            [sys.executable, str(ROOT / "packaging" / "contribution-lint.py"),
             "--issue-event", "--result-file", str(result)],
            env=environment, capture_output=True, text=True, check=False,
        )
        check("the soft issue command succeeds so the workflow can reconcile state", process.returncode, 0)
        check("an invalid issue produces machine-readable state without closing it",
              json.loads(result.read_text(encoding="utf-8"))["valid"], False)


if __name__ == "__main__":
    harness.run(main)
