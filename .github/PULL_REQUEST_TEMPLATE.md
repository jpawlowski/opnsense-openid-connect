<!--
The pull request title becomes the squash commit and a release-note entry. Use:

    type(scope)!: concise description of the observable change

For example: fix(auth): keep local login available when discovery fails
See CONTRIBUTING.md for the allowed types and the breaking-change convention.
-->

## Why

<!-- Describe the problem, risk or opportunity this pull request addresses. -->

## What changes

<!-- Describe the resulting behaviour and the important implementation choices. -->

## Validation

- [ ] `./tests/run.sh`

<!--
List additional relevant checks below. Container, live-provider and browser
tests are deliberately explicit and are only expected when the change needs
them.
-->

## Upgrade impact

<!--
Leave "None" when existing installations need no action. Otherwise replace it
with the exact operator action. A breaking change must use this final line:

BREAKING CHANGE: what an installation has to do before upgrading.
-->
None
