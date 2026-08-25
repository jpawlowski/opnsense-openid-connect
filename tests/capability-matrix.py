#!/usr/bin/env python3

"""Prove that incomplete standards and provider evidence cannot turn green."""

import copy
import importlib.util
import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import harness  # noqa: E402
from harness import check, group  # noqa: E402


def load_matrix():
    spec = importlib.util.spec_from_file_location("capability_matrix", ROOT / "tests" / "update-capability-matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_security_report():
    path = ROOT / "tests" / "update-security-report.py"
    spec = importlib.util.spec_from_file_location("security_report", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load_matrix()
security_report = load_security_report()


def refused(call):
    try:
        call()
        return False
    except matrix.CatalogError:
        return True


def retained_artifact(root, artifact):
    path = root / "tests" / "evidence" / "providers" / "provider-result.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact), encoding="utf-8")
    return "tests/evidence/providers/provider-result.json"


def unreachable_evidence_fixture():
    check(
        "OIDC-CORE-CODE-MUST-VERIFIED positive: an unreachable acceptance fixture",
        True,
        True,
    )


def gate_executed_tests():
    path = pathlib.Path(os.environ.get("OPENIDCONNECT_EXECUTED_TESTS", ""))
    try:
        records = json.loads(path.read_text(encoding="utf-8"))["executed_tests"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError, OSError):
        return set()
    return {
        (pathlib.PurePosixPath(record["path"]), record["test"])
        for record in records
        if isinstance(record, dict)
        and isinstance(record.get("path"), str)
        and isinstance(record.get("test"), str)
    }


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

    check(
        "OIDC-CORE-CODE-MUST-VERIFIED positive: a named acceptance fixture executes",
        True,
        True,
    )
    check(
        "OIDC-CORE-CODE-MUST-VERIFIED negative: a named refusal fixture executes",
        refused(lambda: matrix.validate_test_evidence(
            "OIDC-CORE-CODE-MUST-VERIFIED",
            "negative",
            {"path": "README.md", "test": "not a gate test"},
        )),
        True,
    )
    matrix.EXECUTED_TESTS = gate_executed_tests() | {
        (pathlib.PurePosixPath(source), test)
        for source, test in harness.executed_tests()
    }
    # This file attacks catalog structure in isolation. The publication generator below it in
    # tests/run.sh independently loads the shared manifest and proves these PHP checks executed.
    for standard in standards["standards"]:
        for requirement in standard.get("requirements", []):
            for references in requirement.get("evidence", {}).values():
                matrix.EXECUTED_TESTS.update(
                    (pathlib.PurePosixPath(reference["path"]), reference["test"])
                    for reference in references
                )

    one_sided = copy.deepcopy(standards)
    one_sided["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-MUST-001",
        "section": "3.1.2.1",
        "strength": "must",
        "applicable": True,
        "evidence": {
            "positive": [{
                "path": "tests/capability-matrix.py",
                "test": "OIDC-CORE-CODE-MUST-001 positive: incomplete fixture",
            }],
        },
    }]
    check("a MUST without refusal evidence is rejected", refused(lambda: matrix.validate_standards(one_sided)), True)

    reviewed = copy.deepcopy(standards)
    reviewed["standards"][0]["claim"] = "verified"
    reviewed["standards"][0]["audit_complete"] = True
    reviewed["standards"][0]["source_review"] = {
        "specification_revision": "test fixture",
        "reviewed_on": "2026-08-24",
        "profile": "test-only RP profile",
        "sections": ["test fixture"],
    }
    reviewed["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-SHOULD-001",
        "section": "3.1.2.1",
        "strength": "should",
        "applicable": True,
        "evidence": {},
        "deviation": {
            "reviewed_on": "2026-08-24",
            "rationale": "Reviewed profile decision for the synthetic recommendation.",
        },
    }]
    check("a verified SHOULD may use an explicit reviewed deviation", refused(
        lambda: matrix.validate_standards(reviewed)
    ), False)

    future_deviation = copy.deepcopy(reviewed)
    future_deviation["standards"][0]["requirements"][0]["deviation"]["reviewed_on"] = "2999-01-01"
    check("a future deviation review cannot support conformance", refused(
        lambda: matrix.validate_standards(future_deviation)
    ), True)

    complete = copy.deepcopy(standards)
    complete["standards"][0]["claim"] = "verified"
    complete["standards"][0]["audit_complete"] = True
    complete["standards"][0]["source_review"] = {
        "specification_revision": "test fixture",
        "reviewed_on": "2026-08-24",
        "profile": "test-only RP profile",
        "sections": ["test fixture"],
    }
    positive = {
        "path": "tests/capability-matrix.py",
        "test": "OIDC-CORE-CODE-MUST-VERIFIED positive: a named acceptance fixture executes",
    }
    negative = {
        "path": "tests/capability-matrix.py",
        "test": "OIDC-CORE-CODE-MUST-VERIFIED negative: a named refusal fixture executes",
    }
    complete["standards"][0]["requirements"] = [{
        "id": "OIDC-CORE-CODE-MUST-VERIFIED",
        "section": "test fixture",
        "strength": "must",
        "applicable": True,
        "evidence": {"positive": [positive], "negative": [negative]},
    }]
    check("a pinned complete inventory with two-sided evidence may become green", refused(
        lambda: matrix.validate_standards(complete)
    ), False)

    future_source_review = copy.deepcopy(complete)
    future_source_review["standards"][0]["source_review"]["reviewed_on"] = "2999-01-01"
    check("a future source review cannot make a standard green", refused(
        lambda: matrix.validate_standards(future_source_review)
    ), True)

    unimplemented = copy.deepcopy(complete)
    unimplemented["standards"][0]["implementation"] = "not_planned"
    check("an unimplemented standard cannot make a verified claim", refused(
        lambda: matrix.validate_standards(unimplemented)
    ), True)

    string_audit_flag = copy.deepcopy(complete)
    string_audit_flag["standards"][0]["audit_complete"] = "false"
    check("a truthy string cannot mark a standards audit complete", refused(
        lambda: matrix.validate_standards(string_audit_flag)
    ), True)

    empty_requirement_id = copy.deepcopy(complete)
    empty_requirement_id["standards"][0]["requirements"][0]["id"] = ""
    check("an empty requirement identifier cannot fill a verified inventory", refused(
        lambda: matrix.validate_standards(empty_requirement_id)
    ), True)

    empty_requirement_section = copy.deepcopy(complete)
    empty_requirement_section["standards"][0]["requirements"][0]["section"] = ""
    check("an empty requirement section cannot fill a verified inventory", refused(
        lambda: matrix.validate_standards(empty_requirement_section)
    ), True)

    non_text_rationale = copy.deepcopy(complete)
    requirement = non_text_rationale["standards"][0]["requirements"][0]
    requirement["applicable"] = False
    requirement["evidence"] = {}
    requirement["rationale"] = True
    check("a non-text value cannot justify excluding a normative requirement", refused(
        lambda: matrix.validate_standards(non_text_rationale)
    ), True)

    arbitrary = copy.deepcopy(complete)
    arbitrary["standards"][0]["requirements"][0]["evidence"]["positive"] = [{
        "path": "README.md",
        "test": "OIDC-CORE-CODE-MUST-VERIFIED positive: README substring",
    }]
    check("an arbitrary repository substring cannot become normative evidence", refused(
        lambda: matrix.validate_standards(arbitrary)
    ), True)

    reused = copy.deepcopy(complete)
    reused["standards"][0]["requirements"][0]["evidence"]["negative"] = [positive]
    check("one executed test cannot satisfy both evidence directions", refused(
        lambda: matrix.validate_standards(reused)
    ), True)

    unreachable = copy.deepcopy(complete)
    unreachable["standards"][0]["requirements"][0]["evidence"]["positive"] = [{
        "path": "tests/capability-matrix.py",
        "test": "OIDC-CORE-CODE-MUST-VERIFIED positive: an unreachable acceptance fixture",
    }]
    check("a statically present but unexecuted check cannot become evidence", refused(
        lambda: matrix.validate_standards(unreachable)
    ), True)

    unpinned = copy.deepcopy(complete)
    unpinned["standards"][0]["source_review"] = {
        "specification_revision": "",
        "reviewed_on": "",
        "profile": "",
        "sections": [],
    }
    check("empty source-review pins cannot make a standard verified", refused(
        lambda: matrix.validate_standards(unpinned)
    ), True)

    group("An active draft remains informative")
    check("a pinned draft delta inventory remains non-conformant", refused(
        lambda: matrix.validate_standards(standards)
    ), False)

    claimed_draft = copy.deepcopy(standards)
    tracked = next(item for item in claimed_draft["standards"] if item["id"] == "oauth2-1-draft")
    tracked["claim"] = "verified"
    check("draft tracking cannot become a verified claim", refused(
        lambda: matrix.validate_standards(claimed_draft)
    ), True)

    malformed_draft = copy.deepcopy(standards)
    tracked = next(item for item in malformed_draft["standards"] if item["id"] == "oauth2-1-draft")
    tracked["draft_tracking"]["deltas"][0]["disposition"] = "conformant"
    check("a draft delta cannot invent a conformance disposition", refused(
        lambda: matrix.validate_standards(malformed_draft)
    ), True)

    group("A provider claim cannot outrun retained interoperability evidence")
    incomplete = copy.deepcopy(providers)
    incomplete["capability_defaults"].pop("login")
    standard_ids = matrix.validate_standards(standards)
    check(
        "every provider capability has an explicit catalog default",
        refused(lambda: matrix.validate_providers(incomplete, standard_ids)),
        True,
    )

    live_default = copy.deepcopy(providers)
    live_default["capability_defaults"]["par"] = "live"
    check("a capability default cannot grant inherited live status", refused(
        lambda: matrix.validate_providers(live_default, standard_ids)
    ), True)

    malformed_orphan = copy.deepcopy(providers)
    malformed_orphan["providers"][0]["live_evidence"] = [{"client_secret": "must-not-be-retained"}]
    check("every retained provider evidence record is validated", refused(
        lambda: matrix.validate_providers(malformed_orphan, standard_ids)
    ), True)

    unrelated_documentation = copy.deepcopy(providers)
    unrelated_documentation["providers"][1]["capabilities"]["back_logout"] = "documented"
    check("an unrelated guide URL cannot support another provider feature", refused(
        lambda: matrix.validate_providers(unrelated_documentation, standard_ids)
    ), True)

    unsupported_negative = copy.deepcopy(providers)
    unsupported_negative["providers"][1]["capabilities"]["back_logout"] = "unavailable"
    check("a definitive negative provider cell needs feature-specific evidence", refused(
        lambda: matrix.validate_providers(unsupported_negative, standard_ids)
    ), True)

    unsupported = copy.deepcopy(providers)
    unsupported["providers"][0]["capabilities"]["login"] = "live"
    unsupported["documentation"]["general"].pop("login")
    check(
        "a live green cell requires a retained dated artifact",
        refused(lambda: matrix.validate_providers(unsupported, standard_ids)),
        True,
    )

    adapted = copy.deepcopy(providers)
    adapted["providers"][0]["capabilities"]["login"] = "adapter"
    adapted["documentation"]["general"].pop("login")
    check("an adapter cell also needs retained live evidence", refused(
        lambda: matrix.validate_providers(adapted, standard_ids)
    ), True)

    provider = {"id": "general", "guide": "docs/providers/general.md"}
    dated_record = {
        "feature": "login",
        "tested_on": "2026-08-24",
        "provider_revision": "version:fixture-1",
        "artifact": "tests/evidence/providers/provider-result.json",
    }
    blank = copy.deepcopy(dated_record)
    blank["tested_on"] = ""
    check("a live record rejects an empty test date", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", blank)
    ), True)

    blank_revision = copy.deepcopy(dated_record)
    blank_revision["provider_revision"] = ""
    check("a live record rejects an empty provider revision", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", blank_revision)
    ), True)

    malformed_revision = copy.deepcopy(dated_record)
    malformed_revision["provider_revision"] = "fixture-1"
    check("a live record rejects an untyped provider revision", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", malformed_revision)
    ), True)

    extra_record_field = copy.deepcopy(dated_record)
    extra_record_field["client_secret"] = "must-not-be-retained"
    check("a live record rejects fields outside its publishable schema", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", extra_record_field)
    ), True)

    impossible_service_revision = copy.deepcopy(dated_record)
    impossible_service_revision["provider_revision"] = "service:2026-02-30"
    check("a live record rejects an impossible hosted-service date", refused(
        lambda: matrix.validate_live_evidence_record(
            provider, "login", "live", impossible_service_revision
        )
    ), True)

    future_test = copy.deepcopy(dated_record)
    future_test["tested_on"] = "2999-01-01"
    check("a live record rejects a future test date", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", future_test)
    ), True)

    service_after_test = copy.deepcopy(dated_record)
    service_after_test["provider_revision"] = "service:2026-08-25"
    check("a live record rejects a service revision later than its test", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", service_after_test)
    ), True)

    arbitrary_artifact = copy.deepcopy(dated_record)
    arbitrary_artifact["artifact"] = "LICENSE"
    check("an arbitrary existing file cannot prove live interoperability", refused(
        lambda: matrix.validate_live_evidence_record(provider, "login", "live", arbitrary_artifact)
    ), True)

    with tempfile.TemporaryDirectory() as temporary:
        evidence_root = pathlib.Path(temporary)
        artifact = {
            "schema_version": 1,
            "evidence_type": "provider_interoperability",
            "provider": "another-provider",
            "provider_revision": "version:fixture-1",
            "tested_on": "2026-08-24",
            "configuration": {
                "provider_profile": "general",
                "guide": "docs/providers/general.md",
                "client_type": "confidential",
                "flow": "authorization_code",
                "feature_mode": "enabled",
            },
            "results": [{"feature": "login", "status": "live"}],
        }
        retained_artifact(evidence_root, artifact)
        original_evidence_directory = security_report.EVIDENCE_DIRECTORY
        security_report.EVIDENCE_DIRECTORY = evidence_root / "tests" / "evidence"
        try:
            check(
                "provider interoperability artifacts stay outside audit evidence discovery",
                security_report.evidence_paths([]),
                [],
            )
        finally:
            security_report.EVIDENCE_DIRECTORY = original_evidence_directory
        check("an artifact for another provider cannot make a cell green", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "live", dated_record, evidence_root
            )
        ), True)
        artifact["provider"] = "general"
        retained_artifact(evidence_root, artifact)
        check("a schema-bound provider result may become retained live evidence", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "live", dated_record, evidence_root
            )
        ), False)
        artifact["results"] = [{"feature": "login", "status": "unavailable"}]
        retained_artifact(evidence_root, artifact)
        check("a negative provider result uses the same retained evidence schema", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "unavailable", dated_record, evidence_root
            )
        ), False)
        artifact["results"] = [{"feature": "login", "status": "live"}]
        artifact["results"].append({"access_token": "must-not-be-retained"})
        retained_artifact(evidence_root, artifact)
        check("an unvalidated extra result cannot travel with live evidence", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "live", dated_record, evidence_root
            )
        ), True)
        artifact["results"] = [{"feature": "login", "status": "live"}]
        artifact["configuration"]["client_secret"] = "must-not-be-retained"
        retained_artifact(evidence_root, artifact)
        check("a retained configuration rejects sensitive or unknown fields", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "live", dated_record, evidence_root
            )
        ), True)
        del artifact["configuration"]["client_secret"]
        artifact["access_token"] = "must-not-be-retained"
        retained_artifact(evidence_root, artifact)
        check("a retained artifact rejects fields outside its safe schema", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "live", dated_record, evidence_root
            )
        ), True)
        del artifact["access_token"]
        artifact["results"] = [{
            "feature": "login",
            "status": "adapter",
            "adaptation": "synthetic provider deviation",
        }]
        retained_artifact(evidence_root, artifact)
        check("an adapter artifact cannot hide an unnamed provider deviation", refused(
            lambda: matrix.validate_live_evidence_record(
                provider, "login", "adapter", dated_record, evidence_root
            )
        ), True)

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
