# Copilot hook adapter

`agent-hygiene.json` adapts GitHub Copilot's version-1 hook schema to the same
implementation used by Codex and Claude under `.agents/hooks/fast_gate.py`.
The adapter contains no duplicated behavior. It stays within GitHub's strict hook schema.
