<!--
Keep the complete pull request body to at most 125 counted prose words. Code,
commands, paths, URLs, `Fixes #N`, `None`, template text and the AI notice do
not count.

The title becomes the squash commit and release-note entry. Before opening the
pull request, validate it with packaging/contribution-lint.py. The title is at
most 100 characters and has this form:

    type(scope)!: lower-case description without a full stop

Allowed types: feat, fix, perf, refactor, docs, build, ci, test, chore, style,
revert. A breaking change requires both `!` and a concrete `BREAKING CHANGE:`
operator instruction below.

Describe the problem in the issue. Here, describe only the change and how it
resolves the issue. English and German are accepted; prefer English when in
doubt.
-->

## Issue

<!-- Use exactly `Fixes #N`. A human-authored direct contribution may use exactly `None`. -->

## Change

<!-- What changed? Do not repeat the problem statement from the issue. -->

## Resolution

<!-- How does this change resolve the linked issue? -->

## Validation

- [ ] `./tests/run.sh`

<!-- Check at least one test, or add `Not run: <reason>`. -->

## Upgrade impact

<!--
Keep `None` when no operator action is needed. Otherwise give the exact action.
A breaking pull request must use: `BREAKING CHANGE: <operator instruction>`.
-->
None

<!--
Agent-authored text must add exactly one of these as its own final paragraph:

AI notice: An AI agent wrote this text on my behalf; I am responsible for its content.
KI-Hinweis: Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.
-->
