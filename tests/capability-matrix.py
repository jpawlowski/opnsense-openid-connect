#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Prove that incomplete standards and provider evidence cannot turn green."""

import copy
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import harness  # noqa: E402
from harness import check, group  # noqa: E402


def load_matrix():
    spec = importlib.util.spec_from_file_location("capability_matrix", ROOT / "tests" / "update-capability-matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load_matrix()


def refused(call):
    try:
        call()
        return False
    except matrix.CatalogError:
        return True


def main():
    standards = matrix.read_json(matrix.STANDARDS)
    providers = matrix.read_json(matrix.PROVIDERS)

    group("A standards claim cannot outrun its normative evidence")
    uncovered = copy.deepcopy(standards)
    uncovered["coverage"].pop("boundary")
    check("an unbounded standards list is rejected", refused(lambda: matrix.validate_standards(uncovered)), True)

    empty = copy.deepcopy(standards)
    empty["standards"][0]["claim"] = "verified"
    empty["standards"][0]["audit_complete"] = True
    check("an empty normative inventory cannot be green", refused(lambda: matrix.validate_standards(empty)), True)

    one_sided = copy.deepcopy(standards)
    one_sided["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-MUST-001",
        "section": "3.1.2.1",
        "strength": "must",
        "applicable": True,
        "evidence": {"positive": [{"path": "tests/capability-matrix.py", "contains": "OIDC-CORE-CODE-MUST-001"}]},
    }]
    check("a MUST without refusal evidence is rejected", refused(lambda: matrix.validate_standards(one_sided)), True)

    reviewed = copy.deepcopy(standards)
    reviewed["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-SHOULD-001",
        "section": "3.1.2.1",
        "strength": "should",
        "applicable": True,
        "evidence": {},
        "deviation": "Reviewed profile decision with no conformance claim.",
    }]
    check("an explicit SHOULD deviation remains auditable", refused(lambda: matrix.validate_standards(reviewed)), False)

    complete = copy.deepcopy(standards)
    complete["standards"][0]["claim"] = "verified"
    complete["standards"][0]["audit_complete"] = True
    complete["standards"][0]["source_review"] = {
        "specification_revision": "test fixture",
        "reviewed_on": "2026-08-24",
        "profile": "test-only RP profile",
        "sections": ["test fixture"],
    }
    marker = {"path": "tests/capability-matrix.py", "contains": "OIDC-CORE-CODE-MUST-VERIFIED"}
    complete["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-MUST-VERIFIED",
        "section": "test fixture",
        "strength": "must",
        "applicable": True,
        "evidence": {"positive": [marker], "negative": [marker]},
    }]
    check("a pinned complete inventory with two-sided evidence may become green", refused(
        lambda: matrix.validate_standards(complete)
    ), False)

    group("A provider claim cannot outrun retained interoperability evidence")
    incomplete = copy.deepcopy(providers)
    incomplete["capability_defaults"].pop("login")
    standard_ids = matrix.validate_standards(standards)
    check(
        "every provider capability has an explicit catalog default",
        refused(lambda: matrix.validate_providers(incomplete, standard_ids)),
        True,
    )

    unsupported = copy.deepcopy(providers)
    unsupported["providers"][0]["capabilities"]["login"] = "live"
    check(
        "a live green cell requires a retained dated artifact",
        refused(lambda: matrix.validate_providers(unsupported, standard_ids)),
        True,
    )

    adapted = copy.deepcopy(providers)
    adapted["providers"][0]["capabilities"]["login"] = "adapter"
    check(
        "an adapter cell cannot hide an unnamed provider deviation",
        refused(lambda: matrix.validate_providers(adapted, standard_ids)),
        True,
    )

    group("Security comparison preserves trade-offs")
    ranked_standards = copy.deepcopy(standards)
    for standard in ranked_standards["standards"]:
        if standard["id"] in {"pkce", "par"}:
            standard["claim"] = "verified"
    ranked_providers = copy.deepcopy(providers)
    ranked_providers["providers"][0]["capabilities"].update({"login": "live", "pkce": "live", "par": "live"})
    ranked_providers["providers"][1]["capabilities"].update({"login": "live", "pkce": "live", "par": "unknown"})
    dimensions, frontier = matrix.security_frontier(ranked_standards, ranked_providers)
    check("only verified dimensions enter the comparison", [item["id"] for item in dimensions], ["pkce", "par"])
    check("a strictly weaker provider is dominated without a numeric score", frontier, ["general"])

if __name__ == "__main__":
    harness.run(main)
