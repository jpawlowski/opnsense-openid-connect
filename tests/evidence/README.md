# Retained audit evidence

Place sanitized evidence produced by an installed OPNsense integration run or
the disposable browser/ZAP run in this directory when its validated statements
should appear in `docs/reference/security-and-conformance.md`.

Only `*.json` files are read. The report generator accepts a passing result only
when it uses the current evidence schema, names a known tier, is bound to a
clean Git revision available in this repository, and the relevant implementation
and validation files are unchanged since that revision. Generated evidence is
designed not to contain hosts, users, claims, tokens, cookies or secrets; review
it before committing it nevertheless.

Do not hand-edit a result to make it pass. Regenerate it with the documented
installed-integration or browser-E2E command.

Provider interoperability cells have an additional contract in
`tests/providers/capabilities.json`: a `live` or `adapter` cell must name a test
date, the provider version or hosted-service revision, and a retained artifact
in this directory. An adapter result must also name the provider deviation. A
result remains a dated historical fact until newer contradictory evidence
explicitly replaces it; it does not silently certify later provider revisions.
