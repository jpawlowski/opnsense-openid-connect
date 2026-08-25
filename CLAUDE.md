@AGENTS.md

## Final simplification

When the intended implementation scope is complete and initially green, invoke
Claude Code's built-in `/simplify` skill against the complete final diff before
following the repository's `preflight-review` skill. Apply only useful,
in-scope, behavior-preserving simplifications; retain security and recovery
invariants and comments that explain why. Rerun the affected validation after
any change. If `/simplify` is unavailable in the current execution surface,
perform the equivalent reuse, clarity and efficiency review directly rather
than skipping the pass.
