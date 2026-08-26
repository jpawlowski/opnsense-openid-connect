@AGENTS.md

## Local review

Use Claude Code's built-in, read-only `/review` as the normal automatic reviewer
described in `AGENTS.md`. Continue the same PR-linked session for a focused
follow-up or rerun `/review` after a changed head; no separate named follow-up
command is required. Repository rules, not the built-in command, decide review
scope, severity, dispositions and Draft/Ready state.

## Final simplification

When the intended implementation scope is complete and initially green, invoke
Claude Code's built-in `/simplify` skill against the complete final diff before
following the repository's `preflight-review` skill. Apply only useful,
in-scope, behavior-preserving simplifications; retain security and recovery
invariants and comments that explain why. Rerun the affected validation after
any change. If `/simplify` is unavailable in the current execution surface,
perform the equivalent reuse, clarity and efficiency review directly rather
than skipping the pass.
