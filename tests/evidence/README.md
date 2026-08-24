# Retained audit evidence

Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

Place sanitized evidence produced by an installed OPNsense integration run or
the disposable browser/ZAP run in this directory when its validated statements
should appear in `docs/reference/security-and-conformance.md`.

Only top-level `*.json` files are read as audit evidence. The report generator
accepts a passing result only when it uses the current evidence schema, names a
known tier, is bound to a clean Git revision available in this repository, and the relevant implementation
and validation files are unchanged since that revision. Generated evidence is
designed not to contain hosts, users, claims, tokens, cookies or secrets; review
it before committing it nevertheless.

Do not hand-edit a result to make it pass. Regenerate it with the documented
installed-integration or browser-E2E command.

Provider interoperability artifacts are kept separately under the `providers/`
subdirectory and are never read as audit evidence. Their cells have an
additional contract in `tests/providers/capabilities.json`: a `live` or `adapter`
cell must name retained evidence; an `unavailable` or `incompatible` cell may
likewise use it instead of a feature-specific source. Each record names a test
date and provider version or hosted-service revision, plus an artifact
in that subdirectory. Revisions use a bounded `version:`, `release:` or `commit:`
identifier, or `service:YYYY-MM-DD` for a hosted service without a published
version. The JSON artifact uses schema version 1 and
evidence type `provider_interoperability`; it repeats the provider, revision and
date and has one result containing the feature and its exact evidence status.
Its `configuration` object has exactly five publishable fields:
`provider_profile`, the repository-relative `guide`, `client_type` set to
`confidential`, `flow` set to `authorization_code`, and `feature_mode` set to
`enabled`, `automatic` or `required`. The artifact and each result reject all
other fields. No endpoint, tenant, user, client ID, secret or token belongs in
retained evidence. An adapter result must also repeat
the exact named provider deviation. The catalog validator rejects blank or
malformed record fields, extra catalog fields, artifacts outside that
subdirectory, extra configuration fields, mismatched identities and unproven capabilities. Evidence-backed
statuses are forbidden as catalog defaults, so every green cell has an explicit
provider record. A result remains a dated historical fact until newer
contradictory evidence explicitly replaces it; it does not silently certify
later provider revisions.

These generated strict-schema JSON artifacts omit an embedded copyright field;
the adjacent notice in this file covers them without opening the schema to
arbitrary metadata.
