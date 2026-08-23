# Copilot hook adapter

Copyright (C) 2026 Julian Pawlowski

`agent-hygiene.json` adapts GitHub Copilot's version-1 hook schema to the same
implementation used by Codex and Claude under `.agents/hooks/fast_gate.py`.
The adapter contains no duplicated behavior.

The adjacent JSON file omits the copyright line because GitHub's strict hook
schema has no comment or metadata field for it.
