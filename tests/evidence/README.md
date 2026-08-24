# Retained audit evidence

Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

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
in this directory. Revisions use `version:`, `release:`, `service:` or `commit:`
to identify what was tested. The JSON artifact uses schema version 1 and
evidence type `provider_interoperability`; it repeats the provider, revision and
date, retains a sanitized non-empty `configuration` object, and has one result
containing the feature and its `live` or `adapter` status. An adapter result
must also repeat the exact named provider deviation. The catalog validator
rejects blank or malformed record fields, artifacts outside this directory,
mismatched identities and unproven capabilities. A result remains a dated
historical fact until newer contradictory evidence explicitly replaces it; it
does not silently certify later provider revisions.
