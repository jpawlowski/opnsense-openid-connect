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


def pull_request_body(issue="None", area="area: contribution", change="Added a focused check.",
                      resolution="It prevents empty submissions.",
                      validation="- [x] `./tests/run.sh`", upgrade="None", notice=""):
    body = (
        f"## Issue\n\n{issue}\n\n## Area\n\n{area}\n\n## Change\n\n{change}\n\n## Resolution\n\n{resolution}\n\n"
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
    area_suggestion = "### Suggested area\n\narea: contribution\n\n" + issue_body()
    check("the form's allow-listed area suggestion is boilerplate",
          lint.count_prose(area_suggestion), lint.count_prose(issue_body()))
    check("the optional area precedes the five required fields", lint.validate_issue(area_suggestion)["valid"], True)
    no_area = "### Suggested area\n\n_No response_\n\n" + issue_body()
    check("an unanswered optional area is boilerplate", lint.count_prose(no_area), lint.count_prose(issue_body()))
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
    detail_link = "Details: [maintained comment](https://example.net/issues/42#issuecomment-7)"
    check("an issue may link its maintained detail comment from a required field",
          lint.validate_issue(issue_body(now=f"It fails.\n\n{detail_link}"))["valid"], True)

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
    check("a pull request may link its maintained detail comment from a required section",
          lint.validate_pull_request(
              "docs: explain maintained contribution details",
              pull_request_body(change=f"Added the documented pattern.\n\n{detail_link}"),
          )["valid"], True)
    same_issue = lambda repository, number: {
        "number": number, "created_at": "2026-01-01T00:00:00Z",
        "labels": [{"name": "type: bug"}, {"name": "area: oidc"}],
    }
    inherited = lint.validate_pull_request(
        "fix(auth): keep the callback bounded",
        pull_request_body(issue="Fixes #42", area="Same as issue"),
        "owner/repo", "2026-01-02T00:00:00Z", same_issue,
        labels=[{"name": "change: fix"}, {"name": "area: oidc"}],
    )
    check("a pull request deliberately inherits only the issue area", inherited["valid"], True)
    wrong_labels = lint.validate_pull_request(
        "fix(auth): keep the callback bounded",
        pull_request_body(issue="Fixes #42", area="Same as issue"),
        "owner/repo", "2026-01-02T00:00:00Z", same_issue,
        labels=[{"name": "type: bug"}, {"name": "change: feature"}, {"name": "area: ui"}],
    )
    check("issue type and mismatched change or area labels fail the pull request", wrong_labels["valid"], False)
    check("a direct human contribution cannot inherit from a missing issue", lint.validate_pull_request(
        "docs: explain a direct contribution", pull_request_body(area="Same as issue"),
    )["valid"], False)

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
    legacy_notice = "AI notice: An AI agent wrote this text on my behalf; I am responsible for its content."
    check("a non-italic legacy notice is refused", lint.validate_pull_request(
        "fix(ci): reject empty pull request bodies",
        pull_request_body(issue="Fixes #42", notice=legacy_notice),
        "owner/repo", "2026-01-02T00:00:00Z", older_issue,
    )["valid"], False)

    group("Pull-request events follow current GitHub metadata")
    current = {
        "number": 18,
        "title": "fix(contribution): validate current labels",
        "body": pull_request_body(),
        "created_at": "2026-01-02T00:00:00Z",
    }
    responses = [
        {**current, "labels": [{"name": "change: feature"}, {"name": "area: contribution"}]},
        {**current, "labels": [{"name": "change: fix"}, {"name": "area: contribution"}]},
    ]
    reads = []
    pauses = []

    def current_request(repository, number):
        reads.append((repository, number))
        return responses[min(len(reads) - 1, len(responses) - 1)]

    live = lint.validate_pull_request_event({
        "number": 18,
        "repository": {"full_name": "owner/repo"},
        "pull_request": {"number": 18, "title": "stale invalid title", "body": ""},
    }, request_reader=current_request, issue_reader=older_issue, pause=pauses.append)
    check("the immutable event body is replaced by current pull-request metadata", live["valid"], True)
    check("the linter waits for the separate classifier to reconcile labels", reads,
          [("owner/repo", 18), ("owner/repo", 18)])
    check("label polling is short and bounded", pauses, [lint.PULL_REQUEST_POLL_DELAY])

    group("The workflows keep edits and automation safe")
    build = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    issue_workflow = (ROOT / ".github" / "workflows" / "issue-hygiene.yml").read_text(encoding="utf-8")
    label_workflow = (ROOT / ".github" / "workflows" / "pull-request-labels.yml").read_text(encoding="utf-8")
    pull_request_template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    contribution_skill = (
        ROOT / ".agents" / "skills" / "github-contribution" / "SKILL.md"
    ).read_text(encoding="utf-8")
    check("editing a title or body triggers a fresh pull-request check",
          "types: [opened, edited, synchronize, reopened, ready_for_review, labeled, unlabeled]" in build)
    check("only the latest pull-request run matters",
          "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in build)
    check("the contribution linter replaces the narrower pull-request check",
          "contribution-lint.py --pull-request-event" in build)
    check("issue hygiene reacts to edits", "types: [opened, edited, reopened]" in issue_workflow)
    check("the issue mutator is pinned to an immutable action commit",
          "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3" in issue_workflow)
    check("untrusted issue text is passed through an event file, not shell interpolation",
          "github.event.issue.body" not in issue_workflow)
    check("fork pull requests receive labels from trusted base code only",
          "pull_request_target:" in label_workflow
          and "github.event.pull_request.base.sha" in label_workflow
          and "github.event.pull_request.head.sha" not in label_workflow, True)
    check("the label workflow has only metadata write permission",
          "contents: read" in label_workflow
          and "issues: read" in label_workflow
          and "pull-requests: write" in label_workflow, True)
    check("the label workflow uses immutable action revisions",
          "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803" in label_workflow
          and "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3" in label_workflow, True)
    check("the skill exposes every release-note type",
          [kind for kind in lint.commits.TYPES if f"`{kind}`" not in contribution_skill], [])
    check("every release-note type has one pull-request change class",
          set(lint.CHANGE_BY_COMMIT), set(lint.commits.TYPES))
    check("the pull-request template exposes every release-note type",
          [kind for kind in lint.commits.TYPES
           if not re.search(rf"\b{re.escape(kind)}\b", pull_request_template)], [])
    check("the pull-request template makes its area decision visible",
          "## Area" in pull_request_template and "Same as issue" in pull_request_template, True)
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    preflight = (
        ROOT / ".agents" / "skills" / "preflight-review" / "SKILL.md"
    ).read_text(encoding="utf-8")
    check("implementing agents inspect the exact final diff before external review",
          "Before every external review request" in agents
          and "exact final diff" in agents
          and "Inventory the complete diff" in preflight
          and "never replaces the independent current-head review" in preflight, True)
    check("Claude simplifies the completed change before the shared preflight",
          "/simplify" in claude
          and claude.index("/simplify") < claude.index("preflight-review")
          and "behavior-preserving" in claude
          and "Rerun the affected validation" in claude, True)
    check("agent and contributor rules wait for a review of the current head",
          all("current head" in text.lower() for text in (contribution_skill, agents, contributing)), True)
    readiness = [re.sub(r"\s+", " ", text.lower()) for text in (contribution_skill, agents, contributing)]
    check("review readiness requires explicit human intent as well as a technically green branch",
          all("human intent gate" in text and "technically green" in text and "explicit human" in text
              and "draft" in text and "automatically" in text for text in readiness), True)
    check("Codex findings use one consistent risk-based merge threshold",
          all("P0 and P1" in text and "P2" in text and "recoverability" in text
              for text in (contribution_skill, agents, contributing)), True)
    check("a clean current-head risk review is the explicit stopping point",
          all("merely to obtain zero suggestions" in text
              for text in (contribution_skill, agents, contributing)), True)
    check("one integrating agent owns review threads through completion",
          all(re.search(r"owns\s+every\s+review\s+thread\s+through\s+completion", text)
              for text in (contribution_skill, agents, contributing)), True)
    check("the agent closes old review threads before requesting another review",
          "Only after all existing threads have a disposition" in contribution_skill
          and "request exactly one new review" in contribution_skill
          and "does not update or close an earlier review's threads" in contribution_skill, True)
    review_hygiene = [re.sub(r"\s+", " ", text.lower()) for text in (contribution_skill, agents, contributing)]
    check("agents retain one temporary review trigger without deleting review evidence",
          all("at most one" in text and "fulfilled" in text and "stale" in text
              and "review" in text and "finding" in text and "disposition" in text
              for text in review_hygiene), True)
    check("human and agent guidance distinguishes upstream branches from forks",
          all("without write access" in text.lower() and "opnsense-openid-connect:main" in text
              for text in (contribution_skill, contributing)), True)
    check("the agent resolves permission before choosing its push target",
          "viewerPermission" in contribution_skill and "<fork-owner>:<branch>" in contribution_skill, True)
    check("parallel agents refresh one shared remote view without automatic integration",
          all("origin/main" in text and "worktree" in text.lower()
              and ("never" in text.lower() or "without changing" in text.lower())
              for text in (contribution_skill, agents, contributing)), True)
    check("the primary checkout is read-only while managed detached worktrees remain valid",
          all("read-only" in text.lower() and "detached" in text.lower()
              for text in (contribution_skill, agents, contributing)), True)
    check("parallel subagents stay read-only and writing moves to top-level tasks",
          all("subagent" in text.lower() and "top-level" in text.lower()
              for text in (contribution_skill, agents, contributing)), True)
    check("agents observe canonical and pull-request drift without automatic integration",
          all("remote head" in text.lower() and "overlap" in text.lower()
              and "never" in text.lower() and "merge" in text.lower()
              for text in (contribution_skill, agents, contributing)), True)
    check("waiting monitors retain the PR identity and remain read-only",
          all("read-only" in text.lower() and "monitor" in text.lower() and "never" in text.lower()
              and re.search(r"(?:pr|pull-request) number", text, re.I)
              for text in (contribution_skill, agents, contributing)), True)
    workflow_rules = [re.sub(r"\s+", " ", text.lower()) for text in (contribution_skill, agents, contributing)]
    check("costly work may batch any amount of canonical drift until a safe checkpoint",
          all("safe checkpoint" in text and "any number" in text for text in workflow_rules), True)
    check("overlapping pull requests give humans one order without agent merge authority",
          all("merge" in text and "order" in text and "explicit human" in text and "alternatives" in text
              for text in workflow_rules), True)
    check("any steward may replace an order only when new evidence changes it",
          all("any steward" in text and "new observable evidence" in text
              and "same evidence" in text and "same order" in text
              for text in workflow_rules), True)
    check("replacement records update one maintained entry and serialize competing publishers",
          all("maintained" in text and "existing" in text and "comment" in text
              and "stand down" in text and "adopt" in text for text in workflow_rules), True)
    check("finished agent work has a conservative event-driven cleanup lifecycle",
          all("24-hour" in text and "seven-day" in text
              and "ignored" in text and "remote branch" in text
              and "never" in text and "audit" in text
              for text in (re.sub(r"\s+", " ", value.lower())
                           for value in (contribution_skill, agents, contributing))), True)
    check("every final handoff reports its cleanup disposition",
          all("cleanup" in text.lower() and ("handoff" in text.lower() or "audit" in text.lower())
              for text in (contribution_skill, agents, contributing)), True)
    check("cloud agents keep one existing pull request and never invent credentials",
          all("existing pull request" in text.lower()
              and "personal" in text.lower() and "token" in text.lower()
              and "patch" in text.lower() for text in (contribution_skill, agents, contributing)), True)
    check("Codex, Claude and Copilot cloud contexts have explicit recognition paths",
          all("AGENT_EXECUTION=codex-cloud" in text
              and "CLAUDE_CODE_REMOTE" in text
              and "GITHUB_COPILOT_GIT_TOKEN" in text
              for text in (contribution_skill, agents, contributing)), True)
    check("both paths use the permission-neutral Development link",
          all("Development link" in text and "Fixes #N" in text
              for text in (contribution_skill, contributing)), True)
    reuse_rules = [re.sub(r"\s+", " ", text) for text in (contribution_skill, contributing)]
    check("agents reuse a coherent issue and pull request before creating more",
          all("placeholder" in text and "issue-first rule" in text
              and "continuous" in text and "independently" in text for text in reuse_rules), True)
    check("an ambiguous split returns to the user",
          all(re.search(r"ask(?:s)? the user (?:before|once)", text, re.I) for text in reuse_rules), True)
    check("agents ask once before broad work is split into a new session",
          "ask the user once" in contribution_skill
          and "new session" in contribution_skill
          and "Do not ask repeatedly" in contribution_skill, True)
    check("agents prefer meaningful native sub-issues without manufacturing hierarchy",
          "native sub-issue relationship" in contribution_skill
          and "placeholder parent" in contribution_skill
          and "not the first choice" in contribution_skill, True)
    check("the sub-issue workflow is not imposed on human contributors",
          "native sub-issue relationship" not in contributing
          and "new session" not in contributing, True)
    check("agents without triage suggest rather than fabricate a sub-issue relation",
          "requires repository triage permission" in contribution_skill
          and "Sub-issue of #N" in contribution_skill
          and "suggestion for a maintainer" in contribution_skill, True)
    work_claim_rules = [re.sub(r"\s+", " ", text) for text in (contribution_skill, contributing)]
    check("active work is assigned when permission allows",
          all("assign" in text and "permit" in text
              for text in work_claim_rules), True)
    check("an unlinked start leaves a temporary work signal",
          all("temporary" in text and "wip:<epoch>-<random>" in text
              for text in work_claim_rules), True)
    check("only the author's own obsolete claim is deleted",
          all("delete" in text and "own" in text and "another" in text
              for text in work_claim_rules), True)
    check("the agent work claim combines a timestamped signal with an atomic mutex",
          "<!-- contribution-work-claim:<epoch>-<random> -->" in contribution_skill
          and "fixed per-issue label definition" in contribution_skill
          and "atomic" in contribution_skill, True)
    check("the issue claim is cleaned completely rather than copied to the pull request",
          all("label definition" in text and "pull request" in text and "do not" in text
              for text in work_claim_rules), True)
    check("new implementation sessions must search and claim before writing",
          "Before the first implementation write in every new task" in contribution_skill
          and "python3 .agents/issues.py claim N" in contribution_skill, True)
    rules_readme = (ROOT / ".github" / "rulesets" / "README.md").read_text(encoding="utf-8")
    json.loads((ROOT / ".github" / "rulesets" / "main.json").read_text(encoding="utf-8"))
    check("the strict ruleset import has a documented adjacent copyright exception",
          "Copyright (C) 2026 Julian Pawlowski" in rules_readme
          and "strict import schema" in rules_readme, True)

    forms = [
        (ROOT / ".github" / "ISSUE_TEMPLATE" / name).read_text(encoding="utf-8")
        for name in ("bug.yml", "change.yml")
    ]
    detail_guidance = (contribution_skill, contributing, pull_request_template, *forms)
    check("human and agent guidance shares one maintained detail-comment pattern",
          all("`## Details`" in text
              and "[maintained comment](permalink)" in text
              and "no separate word limit" in text
              and "existing detail comment" in text
              for text in detail_guidance), True)
    check("the agent entry point names the maintained-detail-comment pattern",
          "maintained-detail-comment pattern" in agents, True)
    field_ids = [re.findall(r"^\s+id:\s+(\S+)$", form, re.M) for form in forms]
    check("both issue forms offer an area before the same five required fields",
          field_ids, [["area", "tldr", "where", "now", "want", "to_decide"]] * 2)
    check("the forms apply the canonical type labels",
          ['labels: ["type: bug"]' in forms[0], 'labels: ["type: change"]' in forms[1]], [True, True])
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
