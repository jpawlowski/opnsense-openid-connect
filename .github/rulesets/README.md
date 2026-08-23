<!-- Copyright (C) 2026 Julian Pawlowski -->

# GitHub rulesets

`main.json` is the importable repository ruleset for the default branch. In
GitHub, open **Settings > Rules > Rulesets**, choose **New ruleset > Import a
ruleset**, and select the file.

Review the imported ruleset before creating it. Keep the existing classic
branch protection active until the imported ruleset is active and its effective
rules have been verified. The classic protection can then be removed so the
same policy is not maintained twice.

The ruleset deliberately requires no approving review. This keeps pull requests
usable for a repository with one maintainer while still requiring the current
branch and the GitHub Actions `check` job to pass before a squash merge.

`main.json` follows GitHub's strict import schema, which has no comment or
metadata field for a copyright notice. This adjacent README therefore carries
the notice for that machine-import file as the documented format exception.
