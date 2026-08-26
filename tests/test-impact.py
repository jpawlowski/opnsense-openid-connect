#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Fixtures for every test-impact decision class."""

import importlib.util
import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("test_impact", ROOT / ".agents" / "test-impact.py")
impact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(impact)
rules = json.loads((ROOT / ".agents" / "test-impact-rules.json").read_text(encoding="utf-8"))


def tiers(paths, patch=""):
    return impact.analyze(paths, patch.lower(), rules)


def require(label, paths, tier, provider=None, cluster=None, patch=""):
    records = tiers(paths, patch)
    if not any(
        record["tier"] == tier
        and (provider is None or record.get("provider") == provider)
        and (cluster is None or record.get("cluster") == cluster)
        and record.get("reason")
        for record in records
    ):
        raise SystemExit(f"{label}: missing explained {tier} recommendation")


require("documentation", ["docs/README.md"], "fast-gate")
require("package", ["packaging/build.py"], "build-check")
require("installed session", ["src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SessionRegistry.php"],
        "installed-integration", patch="session")
require("browser callback", ["src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/AuthController.php"],
        "provider-e2e", "keycloak", "direct", patch="callback")
require("canonical driver", ["tests/e2e/oidc.spec.mjs"], "provider-e2e", "keycloak", "direct")
require("approval", ["src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/ApprovalController.php"],
        "provider-e2e", "keycloak", "direct", patch="approval")
require("authentik", ["docs/providers/authentik.md"], "provider-e2e", "authentik", "direct", patch="Blueprint")
require("authentik profile", ["src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php"],
        "provider-e2e", "authentik", "direct", patch="authentik logout")
require("SaaS adapter", ["tests/e2e/provider.spec.mjs"], "provider-e2e", "okta", "direct", patch="Okta")
require("SaaS-only behavior", ["docs/providers/entra-id.md"], "live-provider", "entra", "direct",
        patch="Conditional Access")
require("public ingress", ["tests/e2e/public-inbound.py"], "provider-e2e", "keycloak", "public-inbound",
        patch="cloudflared")
require("public receiver without keywords",
        ["src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/SsfController.php"],
        "provider-e2e", "keycloak", "public-inbound", patch="remove an authentication guard")
require("hosted Shared Signals", ["docs/providers/okta.md"], "live-provider", "okta", "public-inbound",
        patch="Shared Signals")

original_git = impact.git
original_has_ref = impact.has_ref
try:
    impact.has_ref = lambda _reference: False
    impact.git = lambda *arguments: (
        "" if arguments == ("remote",) else "1" * 40 + "\n"
        if arguments == ("hash-object", "-t", "tree", "/dev/null") else ""
    )
    if impact.canonical_base() != "1" * 40:
        raise SystemExit("isolated checkout did not select its reproducible root fallback")
finally:
    impact.git = original_git
    impact.has_ref = original_has_ref

print("Agent test-impact fixtures explain every validation class")
