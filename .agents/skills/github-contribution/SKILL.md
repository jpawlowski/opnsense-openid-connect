---
name: github-contribution
description: >-
  Prepare or publish an issue, pull request, review, or comment for opnsense-openid-connect. Use before an agent
  writes publicly on GitHub in a contributor's name; do not use for read-only inspection.
---

# Contributing on GitHub

Keep the public conversation easy to scan. Be concise, friendly, factual and
focused on the work. Do not insult, threaten, use sarcasm at another person's
expense, or speculate about anybody's competence or motives.

Write in the language of the issue or pull request. Prefer English when opening
a contribution or when the existing conversation is mixed.

## Issues before pull requests

An agent-authored pull request must close one same-repository issue that already
exists before the pull request is opened. Create the issue first when there is
no suitable one. Use the Bug or Change form and retain these headings in order:
`TL;DR`, `Where`, `Now`, `Want`, `To decide`. Keep implementation detail out;
`To decide` names one decision and recommends a direction at a high level.

Keep counted issue prose to 175 words. The issue workflow helps with structure
and length but does not close an issue or grant permission to start work.

## Pull requests

The title is the squash commit and a release-note entry. Choose it before
opening the pull request:

    type(scope)!: lower-case description without a full stop

It is at most 100 characters. The scope and `!` are optional; the allowed types
are `feat`, `fix`, `perf`, `refactor`, `docs`, `build`, `ci`, `test`, `chore`,
`style`, and `revert`. A breaking change uses both `!` and a concrete
`BREAKING CHANGE:` instruction saying what an operator must do.

Put exactly `Fixes #N` under `Issue`. Do not repeat the issue's problem. Describe
the change under `Change`, how it resolves the issue under `Resolution`, actual
checks under `Validation`, and any operator action under `Upgrade impact`. Keep
counted pull-request prose to 125 words.

Before publishing, save the proposed body and validate the exact title and body:

    python3 packaging/contribution-lint.py \
        --title "type(scope): lower-case description" \
        --body-file /path/to/pr-body.md \
        --repository jpawlowski/opnsense-openid-connect

Do not open the pull request until this passes. A title or body edit triggers
the required check again after publication.

## Agent notice

Every issue, pull request, review, or comment written by an agent in a person's
name ends with exactly one matching notice as its own final paragraph:

    AI notice: An AI agent wrote this text on my behalf; I am responsible for its content.

    KI-Hinweis: Ein KI-Agent hat diesen Text in meinem Namen verfasst; ich verantworte seinen Inhalt.

Use only the notice matching the contribution's language. The notice discloses
authorship; the person publishing remains responsible for the content.
