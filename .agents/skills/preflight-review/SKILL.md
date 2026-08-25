---
name: preflight-review
description: >-
  Review the completed implementation diff adversarially before an external
  code review or final handoff. Use after the intended scope is complete and
  initially green; do not use as a replacement for the independent review.
---

<!-- Copyright (C) 2026 Julian Pawlowski -->

# Preflight review

Find defects while the implementing agent still owns the branch. Treat green
tests as evidence about exercised paths, not proof that the change is complete.
This pass never replaces the independent current-head review.

## Freeze the review target

Compare the exact final branch diff with the current canonical base. Read the
issue and acceptance decision, the changed files, affected callers and tests.
Keep unrelated user changes outside the scope. Inventory the complete diff
before editing so the first plausible defect does not end the review early.

Concentrate effort where the change creates a real boundary or state transition:

- Follow new state through creation, use, consumption, retry, expiry, removal
  and package cleanup. Check older configurations where a new field is absent,
  and active sessions or saved state after related settings change.
- For concurrent or remote mutation, identify every read/check/write window.
  Reload after acquiring the authoritative lock, revalidate at the point of
  mutation, avoid holding local locks across external calls, and make partial
  publication, retry and resume behavior safe and idempotent.
- Exercise meaningful missing, empty, `null`, zero, numeric, maximum-size,
  timeout, abort and partial-response cases. Reconcile state symmetrically when
  inputs may be added, removed or edited.
- Recheck the repository's access, recovery, uniform-refusal, privilege and
  secret-handling invariants at each new outcome, including failure paths.
- Identify every new dependency on OPNsense core behavior, including copied or
  inherited rules, and cover its supplying files in `TOUCHPOINTS`.
- Compare documentation and UI assurances with the code's actual side effects.
  Verify that claimed test or conformance evidence reaches the production
  boundary instead of replacing the decisive operation with a stub or override.

Use these as risk prompts, not a demand to invent implausible cases. Trace the
actual changed behavior and report only actionable gaps.

## Close the pass

Record all actionable findings before fixing them. Apply one coherent,
in-scope batch and add regression evidence for each accepted defect where a
repeatable check is possible. Rerun the affected focused checks and the required
repository gates. Review the new diff again wherever the fixes changed control
flow, state, failure handling or an external boundary.

The pass is complete when the intended outcome is present, the validation is
green, and no known actionable correctness, security, compatibility, lifecycle,
concurrency, core-dependency, documentation or test-evidence gap remains. It
does not grant permission to publish, request review, mark a pull request ready
or merge.
