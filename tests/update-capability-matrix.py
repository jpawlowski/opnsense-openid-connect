#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Validate the evidence gates and render the public capability matrices."""

import argparse
import datetime
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STANDARDS = ROOT / "tests" / "standards" / "catalog.json"
PROVIDERS = ROOT / "tests" / "providers" / "capabilities.json"
OUTPUT = ROOT / "tests" / "generated" / "provider-capabilities.md"
CONNECTOR = ROOT / "src" / "opnsense" / "mvc" / "app" / "library" / "OPNsense" / "Auth" / "OpenIDConnect.php"

IMPLEMENTATION = {"implemented", "partial", "candidate", "deferred", "not_planned", "not_applicable"}
CLAIMS = {"verified", "unverified", "not_claimed", "not_applicable"}
EVIDENCE = {"live", "adapter", "documented", "conditional", "unavailable", "incompatible", "unknown"}
SOURCE_EVIDENCE = {"documented", "conditional", "unavailable", "incompatible"}
ARTIFACT_EVIDENCE = {"live", "adapter", "unavailable", "incompatible"}
REQUIREMENT_STRENGTH = {"must", "must_not", "should", "should_not", "may"}
DRAFT_DELTA_DISPOSITIONS = {"aligned", "differs", "not_applicable"}
GATE_EVIDENCE_TEST = pathlib.PurePosixPath("tests/capability-matrix.py")
PROVIDER_EVIDENCE_DIRECTORY = pathlib.PurePosixPath("tests/evidence/providers")
PROVIDER_REVISION = re.compile(
    r"^(?:(?:version|release|commit):[A-Za-z0-9][A-Za-z0-9._+-]{0,111}|service:\d{4}-\d{2}-\d{2})$"
)
SAFE_CONFIGURATION_FIELDS = {"provider_profile", "guide", "client_type", "flow", "feature_mode"}
LIVE_EVIDENCE_FIELDS = {"feature", "tested_on", "provider_revision", "artifact", "source", "cluster"}
EMULATOR_EVIDENCE_FIELDS = {
    "feature", "tested_on", "emulator_revision", "artifact", "adaptation", "source", "cluster",
}
APPLE_EMULATOR_ADAPTATION = (
    "Generic profile plus reviewed PKCE and Form Post discovery metadata missing from emulate 0.10.0"
)
FEATURE_MODES = {"enabled", "automatic", "required"}
EXECUTED_TESTS = set()
REQUIREMENT_FIELDS = {"id", "section", "strength", "applicable", "evidence", "claimed", "rationale", "deviation"}

STATUS_LABEL = {
    "implemented": "Implemented",
    "partial": "Partial",
    "candidate": "Candidate",
    "deferred": "Deferred",
    "not_planned": "Not planned",
    "not_applicable": "N/A",
}
CLAIM_LABEL = {
    "verified": "✅ verified",
    "unverified": "🟡 unverified",
    "not_claimed": "— not claimed",
    "not_applicable": "N/A",
}
DRAFT_DISPOSITION_LABEL = {
    "aligned": "Aligned",
    "differs": "Differs",
    "not_applicable": "N/A",
}
EVIDENCE_SYMBOL = {
    "live": "✅",
    "adapter": "🟦",
    "documented": "📘",
    "conditional": "◇",
    "unavailable": "❌",
    "incompatible": "⚠️",
    "unknown": "?",
}


class CatalogError(ValueError):
    pass


def provider_result_capabilities():
    path = ROOT / "tests" / "e2e" / "provider-result.py"
    spec = importlib.util.spec_from_file_location("matrix_provider_result", path)
    if spec is None or spec.loader is None:
        raise CatalogError("provider result capability policy cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CAPABILITIES


PROVIDER_RESULT_CAPABILITIES = provider_result_capabilities()


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def unique(items, label):
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise CatalogError(f"{label} inventory contains a non-object entry")
        value = item["id"]
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
            raise CatalogError(f"{label} id must be a stable, non-empty identifier")
        if value in seen:
            raise CatalogError(f"duplicate {label} id: {value}")
        seen.add(value)
    return seen


def historical_date(value, label):
    try:
        parsed = datetime.date.fromisoformat(value) if isinstance(value, str) else None
        if parsed is None or parsed.isoformat() != value:
            raise ValueError
    except ValueError as error:
        raise CatalogError(f"{label} must use YYYY-MM-DD") from error
    if parsed > datetime.date.today():
        raise CatalogError(f"{label} cannot be in the future")
    return parsed


def repository_file(value, label, root=ROOT):
    if not isinstance(value, str) or not value or "\\" in value:
        raise CatalogError(f"{label}: path must be a repository-relative POSIX path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != value:
        raise CatalogError(f"{label}: path must be a normalized repository-relative POSIX path")
    return relative, root.joinpath(*relative.parts)


def gate_evidence_path(relative):
    return relative == GATE_EVIDENCE_TEST or (
        relative.parent == pathlib.PurePosixPath("tests/unit") and relative.suffix == ".php"
    )


def is_gate_evidence_test(relative, path):
    if not gate_evidence_path(relative):
        raise CatalogError(f"{relative}: normative evidence must name a test suite executed by ./tests/run.sh")
    if not path.is_file():
        raise CatalogError(f"{relative}: evidence test suite does not exist")


def load_executed_tests(path):
    try:
        data = read_json(path)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise CatalogError("executed-test manifest is missing or invalid JSON") from error
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise CatalogError("executed-test manifest has an unsupported schema")
    records = data.get("executed_tests")
    if not isinstance(records, list):
        raise CatalogError("executed-test manifest has no test inventory")
    executed = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "test"}:
            raise CatalogError("executed-test manifest contains an invalid record")
        relative, test_path = repository_file(record["path"], "executed-test manifest")
        if not gate_evidence_path(relative):
            continue
        is_gate_evidence_test(relative, test_path)
        if not isinstance(record["test"], str) or not record["test"]:
            raise CatalogError("executed-test manifest contains an empty test name")
        executed.add((relative, record["test"]))
    return executed


def validate_test_evidence(requirement_id, direction, reference):
    if not isinstance(reference, dict) or set(reference) != {"path", "test"}:
        raise CatalogError(f"{requirement_id}: evidence must name one gate test path and exact test name")
    relative, path = repository_file(reference["path"], requirement_id)
    test = reference["test"]
    prefix = f"{requirement_id} {direction}: "
    if not isinstance(test, str) or not test.startswith(prefix):
        raise CatalogError(f"{requirement_id}: {direction} evidence test must begin with '{prefix}'")
    is_gate_evidence_test(relative, path)
    if (relative, test) not in EXECUTED_TESTS:
        raise CatalogError(f"{requirement_id}: exact {direction} test did not execute in the current gate")
    return relative, test


def reviewed_deviation(requirement):
    deviation = requirement.get("deviation")
    if deviation is None:
        return False
    if requirement["strength"] not in {"should", "should_not"}:
        raise CatalogError(f"{requirement['id']}: only recommendations may record a deviation")
    if not isinstance(deviation, dict) or not {"reviewed_on", "rationale"} <= deviation.keys():
        raise CatalogError(f"{requirement['id']}: deviation needs a review date and rationale")
    historical_date(deviation["reviewed_on"], f"{requirement['id']}: deviation review date")
    rationale = deviation["rationale"]
    if not isinstance(rationale, str) or rationale.strip() != rationale or not 1 <= len(rationale) <= 1000:
        raise CatalogError(f"{requirement['id']}: deviation needs a non-empty reviewed rationale")
    return True


def validate_source_review(standard, review):
    label = standard["id"]
    fields = {"specification_revision", "reviewed_on", "profile", "sections"}
    if not isinstance(review, dict) or set(review) != fields:
        raise CatalogError(f"{label}: verified requires a pinned source and applicability review")
    for field in ("specification_revision", "profile"):
        value = review[field]
        if not isinstance(value, str) or value.strip() != value or not 1 <= len(value) <= 500:
            raise CatalogError(f"{label}: source review {field} must be a non-empty, trimmed value")
    historical_date(review["reviewed_on"], f"{label}: source review date")
    sections = review["sections"]
    if (
        not isinstance(sections, list)
        or not sections
        or any(
            not isinstance(section, str)
            or section.strip() != section
            or not section
            or len(section) > 200
            for section in sections
        )
        or len(set(sections)) != len(sections)
    ):
        raise CatalogError(f"{label}: source review needs distinct, non-empty specification sections")


def validate_draft_tracking(standard, tracking):
    label = standard["id"]
    fields = {"specification_revision", "reviewed_on", "status", "deltas"}
    if not isinstance(tracking, dict) or set(tracking) != fields:
        raise CatalogError(f"{label}: draft tracking must use the informative tracking schema")
    if standard["claim"] != "not_claimed" or standard["audit_complete"]:
        raise CatalogError(f"{label}: an active draft may be tracked only without a conformance claim")
    revision = tracking["specification_revision"]
    if not isinstance(revision, str) or not re.fullmatch(r"draft-[a-z0-9-]+-\d{2}", revision):
        raise CatalogError(f"{label}: draft tracking must pin an exact numbered revision")
    historical_date(tracking["reviewed_on"], f"{label}: draft tracking review date")
    if tracking["status"] != "informative":
        raise CatalogError(f"{label}: draft tracking cannot become a conformance status")
    deltas = tracking["deltas"]
    if not isinstance(deltas, list) or not deltas:
        raise CatalogError(f"{label}: draft tracking needs a non-empty delta inventory")
    unique(deltas, f"draft delta in {label}")
    delta_fields = {"id", "section", "summary", "disposition", "note"}
    for delta in deltas:
        if set(delta) != delta_fields or delta["disposition"] not in DRAFT_DELTA_DISPOSITIONS:
            raise CatalogError(f"{label}: draft delta has an invalid shape or disposition")
        for field in ("section", "summary", "note"):
            value = delta[field]
            if (
                not isinstance(value, str)
                or value.strip() != value
                or not 1 <= len(value) <= 1000
                or not all(character.isprintable() for character in value)
            ):
                raise CatalogError(f"{label}: draft delta {field} must be non-empty reviewable text")


def validate_requirement(standard, requirement):
    if not isinstance(requirement, dict) or not set(requirement) <= REQUIREMENT_FIELDS:
        raise CatalogError(f"{standard['id']}: requirement contains fields outside the publishable schema")
    missing = {"id", "section", "strength", "applicable", "evidence"} - requirement.keys()
    if missing:
        raise CatalogError(f"{standard['id']}: requirement misses {', '.join(sorted(missing))}")
    section = requirement["section"]
    if (
        not isinstance(section, str)
        or section.strip() != section
        or not 1 <= len(section) <= 200
        or not all(character.isprintable() for character in section)
    ):
        raise CatalogError(f"{requirement['id']}: section must be a stable, non-empty reference")
    if not isinstance(requirement["applicable"], bool):
        raise CatalogError(f"{requirement['id']}: applicable must be a boolean")
    if "claimed" in requirement and not isinstance(requirement["claimed"], bool):
        raise CatalogError(f"{requirement['id']}: claimed must be a boolean")
    if requirement["strength"] not in REQUIREMENT_STRENGTH:
        raise CatalogError(f"{requirement['id']}: invalid normative strength")
    evidence = requirement["evidence"]
    if not isinstance(evidence, dict):
        raise CatalogError(f"{requirement['id']}: evidence must be an object")
    has_reviewed_deviation = reviewed_deviation(requirement)
    if not requirement["applicable"]:
        rationale = requirement.get("rationale")
        if (
            not isinstance(rationale, str)
            or rationale.strip() != rationale
            or not 1 <= len(rationale) <= 1000
            or not all(character.isprintable() for character in rationale)
        ):
            raise CatalogError(f"{requirement['id']}: non-applicability needs a reviewable rationale")
        return
    if requirement["applicable"]:
        if requirement["strength"] in {"must", "must_not"} and not {"positive", "negative"} <= evidence.keys():
            raise CatalogError(f"{requirement['id']}: mandatory requirement needs positive and negative evidence")
        if requirement["strength"] in {"should", "should_not"} and not (
            {"positive", "negative"} <= evidence.keys() or has_reviewed_deviation
        ):
            raise CatalogError(f"{requirement['id']}: recommendation needs evidence or an explicit deviation")
        if (
            requirement["strength"] == "may"
            and requirement.get("claimed")
            and not {"positive", "negative"} <= evidence.keys()
        ):
            raise CatalogError(f"{requirement['id']}: claimed optional behaviour needs positive and negative evidence")
    evidence_tests = {}
    for direction, references in evidence.items():
        if direction not in {"positive", "negative"} or not isinstance(references, list) or not references:
            raise CatalogError(f"{requirement['id']}: invalid {direction} evidence")
        evidence_tests[direction] = set()
        for reference in references:
            evidence_tests[direction].add(validate_test_evidence(requirement["id"], direction, reference))
    if evidence_tests.get("positive", set()) & evidence_tests.get("negative", set()):
        raise CatalogError(f"{requirement['id']}: positive and negative evidence must name distinct tests")


def validate_standards(data):
    coverage = data.get("coverage", {})
    if not {"reviewed_on", "sources", "boundary", "excluded_families"} <= coverage.keys():
        raise CatalogError("standards catalog must pin its coverage review and boundary")
    if not isinstance(coverage["sources"], list) or len(coverage["sources"]) < 2:
        raise CatalogError("standards catalog needs the OpenID and OAuth source indexes")
    historical_date(coverage["reviewed_on"], "standards coverage review date")
    ids = unique(data["standards"], "standard")
    requirement_ids = set()
    for standard in data["standards"]:
        if standard["implementation"] not in IMPLEMENTATION:
            raise CatalogError(f"{standard['id']}: invalid implementation status")
        if standard["claim"] not in CLAIMS:
            raise CatalogError(f"{standard['id']}: invalid claim status")
        if not isinstance(standard.get("audit_complete"), bool):
            raise CatalogError(f"{standard['id']}: audit_complete must be a boolean")
        if standard["claim"] == "verified" and standard["implementation"] != "implemented":
            raise CatalogError(f"{standard['id']}: verified requires an implemented standard scope")
        requirements = standard.get("requirements", [])
        unique(requirements, f"requirement in {standard['id']}")
        for requirement in requirements:
            if requirement["id"] in requirement_ids:
                raise CatalogError(f"duplicate global requirement id: {requirement['id']}")
            requirement_ids.add(requirement["id"])
            validate_requirement(standard, requirement)
        if standard["claim"] == "verified":
            if not standard["audit_complete"] or not requirements:
                raise CatalogError(f"{standard['id']}: verified requires a complete, non-empty normative inventory")
            validate_source_review(standard, standard.get("source_review"))
        if standard["audit_complete"] and not requirements:
            raise CatalogError(f"{standard['id']}: an empty inventory cannot be complete")
        if "draft_tracking" in standard:
            validate_draft_tracking(standard, standard["draft_tracking"])
    return ids


def configured_profiles():
    source = CONNECTOR.read_text(encoding="utf-8")
    match = re.search(r"public const PROVIDER_PROFILES = \[(.*?)\n\s*\];", source, re.DOTALL)
    if not match:
        raise CatalogError("cannot locate PROVIDER_PROFILES in connector")
    return set(re.findall(r"'([^']+)'", match.group(1)))


def validate_record_text(record, field, label):
    value = record.get(field)
    if not isinstance(value, str) or value.strip() != value or not 1 <= len(value) <= 128:
        raise CatalogError(f"{label}: {field} must be a non-empty, trimmed value of at most 128 characters")
    if not all(character.isprintable() for character in value):
        raise CatalogError(f"{label}: {field} contains non-printable characters")
    return value


def validate_safe_configuration(provider, feature_id, configuration):
    label = f"{provider['id']}/{feature_id}"
    if not isinstance(configuration, dict) or set(configuration) != SAFE_CONFIGURATION_FIELDS:
        raise CatalogError(f"{label}: artifact configuration must use only the publishable safe schema")
    expected = {
        "provider_profile": provider["id"],
        "guide": provider.get("guide"),
        "client_type": "confidential",
        "flow": "authorization_code",
    }
    if any(configuration.get(key) != value for key, value in expected.items()):
        raise CatalogError(f"{label}: artifact configuration is not bound to the public provider profile")
    if configuration["feature_mode"] not in FEATURE_MODES:
        raise CatalogError(f"{label}: artifact configuration has an invalid feature mode")


def validate_live_evidence_record(provider, feature_id, status, record, root=ROOT):
    label = f"{provider['id']}/{feature_id}"
    if not isinstance(record, dict) or set(record) != LIVE_EVIDENCE_FIELDS:
        raise CatalogError(f"{label}: live evidence record must use only the publishable schema")
    if record["feature"] != feature_id:
        raise CatalogError(f"{label}: live evidence record names another feature")
    if record["source"] not in {"local", "live"} or record["cluster"] not in {"direct", "public-inbound"}:
        raise CatalogError(f"{label}: live evidence record has no valid source and cluster")
    exercised = PROVIDER_RESULT_CAPABILITIES.get(
        (provider["id"], record["source"], record["cluster"]),
        set(),
    )
    if feature_id not in exercised:
        raise CatalogError(f"{label}: live evidence selection does not exercise this capability")
    tested_on = validate_record_text(record, "tested_on", label)
    tested_date = historical_date(tested_on, f"{label}: tested_on")
    provider_revision = validate_record_text(record, "provider_revision", label)
    if not PROVIDER_REVISION.fullmatch(provider_revision):
        raise CatalogError(
            f"{label}: provider_revision must be a safe version, release, service date or commit identifier"
        )
    if provider_revision.startswith("service:"):
        service_date = provider_revision.removeprefix("service:")
        try:
            service_revision_date = datetime.date.fromisoformat(service_date)
            if service_revision_date.isoformat() != service_date:
                raise ValueError
        except ValueError as error:
            raise CatalogError(f"{label}: service revision must contain a real YYYY-MM-DD date") from error
        if service_revision_date > tested_date:
            raise CatalogError(f"{label}: service revision cannot be later than tested_on")
    relative, artifact_path = repository_file(record.get("artifact"), label, root)
    if relative.parent != PROVIDER_EVIDENCE_DIRECTORY or relative.suffix != ".json":
        raise CatalogError(f"{label}: live evidence artifact must be a JSON file in tests/evidence/providers")
    try:
        artifact = read_json(artifact_path)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise CatalogError(f"{label}: live evidence artifact is missing or invalid JSON") from error
    expected = {
        "schema_version": 1,
        "evidence_type": "provider_interoperability",
        "provider": provider["id"],
        "source": record["source"],
        "cluster": record["cluster"],
        "provider_revision": provider_revision,
        "tested_on": tested_on,
    }
    artifact_fields = set(expected) | {"configuration", "results"}
    if (
        not isinstance(artifact, dict)
        or set(artifact) != artifact_fields
        or any(artifact.get(key) != value for key, value in expected.items())
    ):
        raise CatalogError(f"{label}: artifact is not bound to the provider, revision and test date")
    validate_safe_configuration(provider, feature_id, artifact.get("configuration"))
    results = artifact.get("results")
    if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
        raise CatalogError(f"{label}: artifact must contain exactly one provider capability result")
    result = results[0]
    if result.get("feature") != feature_id or result.get("status") != status:
        raise CatalogError(f"{label}: artifact does not prove this capability status")
    result_fields = {"feature", "status", "adaptation"} if status == "adapter" else {"feature", "status"}
    if set(result) != result_fields:
        raise CatalogError(f"{label}: capability result contains fields outside the publishable schema")
    if status == "adapter":
        adaptation = provider.get("adaptations", {}).get(feature_id)
        if not isinstance(adaptation, str) or not adaptation.strip():
            raise CatalogError(f"{label}: adapter status must name the deviation")
        if result.get("adaptation") != adaptation:
            raise CatalogError(f"{label}: artifact is not bound to the named provider adaptation")


def validate_emulator_evidence_record(provider, feature_id, record, root=ROOT):
    label = f"{provider['id']}/{feature_id}"
    if provider["id"] not in {"entra", "okta", "apple"}:
        raise CatalogError(f"{label}: this provider has no reviewed emulator")
    if not isinstance(record, dict) or set(record) != EMULATOR_EVIDENCE_FIELDS:
        raise CatalogError(f"{label}: emulator evidence record must use only the publishable schema")
    if record["feature"] != feature_id:
        raise CatalogError(f"{label}: emulator evidence record names another feature")
    if record["source"] != "emulated" or record["cluster"] != "direct":
        raise CatalogError(f"{label}: emulator evidence record has no valid source and cluster")
    historical_date(validate_record_text(record, "tested_on", label), f"{label}: tested_on")
    revision = validate_record_text(record, "emulator_revision", label)
    if not PROVIDER_REVISION.fullmatch(revision):
        raise CatalogError(f"{label}: emulator revision is not pinned")
    relative, artifact_path = repository_file(record.get("artifact"), label, root)
    if relative.parent != PROVIDER_EVIDENCE_DIRECTORY or relative.suffix != ".json":
        raise CatalogError(f"{label}: emulator evidence must be retained in tests/evidence/providers")
    try:
        artifact = read_json(artifact_path)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise CatalogError(f"{label}: emulator evidence artifact is missing or invalid JSON") from error
    fields = {
        "schema_version", "evidence_type", "repository_revision", "repository_dirty", "harness_digest",
        "provider", "source", "subject", "cluster", "tested_on", "configuration_profile", "results",
        "provider_adaptation",
    }
    if (
        not isinstance(artifact, dict) or set(artifact) != fields
        or artifact.get("schema_version") != 1 or artifact.get("evidence_type") != "provider_test_run"
        or artifact.get("provider") != provider["id"] or artifact.get("source") != "emulated"
        or artifact.get("cluster") != "direct" or artifact.get("repository_dirty") is not False
        or artifact.get("configuration_profile") != ("general" if provider["id"] == "apple" else provider["id"])
        or artifact.get("tested_on") != record["tested_on"]
        or not re.fullmatch(r"[a-f0-9]{40,64}", artifact.get("repository_revision", ""))
        or not re.fullmatch(r"[a-f0-9]{64}", artifact.get("harness_digest", ""))
    ):
        raise CatalogError(f"{label}: emulator artifact is not bound to its sanitized test run")
    subject = artifact.get("subject")
    expected_subject = "entra-local" if provider["id"] == "entra" else "vercel-labs-emulate"
    if (
        not isinstance(subject, dict) or set(subject) != {"name", "revision"}
        or subject.get("name") != expected_subject or subject.get("revision") != revision
    ):
        raise CatalogError(f"{label}: emulator artifact has an invalid test subject")
    adaptation = record.get("adaptation")
    if adaptation != artifact.get("provider_adaptation") or (
        adaptation is not None
        and (not isinstance(adaptation, str) or adaptation.strip() != adaptation or not 1 <= len(adaptation) <= 256)
    ):
        raise CatalogError(f"{label}: emulator artifact adaptation is not safe and exact")
    expected_adaptation = APPLE_EMULATOR_ADAPTATION if provider["id"] == "apple" else None
    if adaptation != expected_adaptation:
        raise CatalogError(f"{label}: emulator evidence differs from its reviewed adaptation")
    results = artifact.get("results")
    if (
        not isinstance(results, list)
        or any(not isinstance(item, dict) or set(item) != {"feature", "outcome"} for item in results)
    ):
        raise CatalogError(f"{label}: emulator artifact does not prove the named emulated capability")
    if any(not isinstance(item["feature"], str) or not isinstance(item["outcome"], str) for item in results):
        raise CatalogError(f"{label}: emulator artifact capability results must be text")
    result_features = [item["feature"] for item in results]
    exercised = PROVIDER_RESULT_CAPABILITIES.get((provider["id"], "emulated", "direct"), set())
    if (
        len(set(result_features)) != len(result_features)
        or not set(result_features) <= exercised
        or any(item["outcome"] not in {"pass", "unavailable", "incompatible"} for item in results)
        or {"feature": feature_id, "outcome": "pass"} not in results
    ):
        raise CatalogError(f"{label}: emulator artifact contains an unexercised or duplicate capability")


def validate_providers(data, standard_ids):
    feature_ids = unique(data["features"], "feature")
    if set(data["capability_defaults"]) != feature_ids:
        raise CatalogError("capability defaults must name every feature exactly once")
    if any(status not in EVIDENCE for status in data["capability_defaults"].values()):
        raise CatalogError("capability defaults contain an invalid evidence status")
    if any(status != "unknown" for status in data["capability_defaults"].values()):
        raise CatalogError("capability defaults must remain unknown so every provider claim is explicit")
    for feature in data["features"]:
        if feature["standard"] is not None and feature["standard"] not in standard_ids:
            raise CatalogError(f"{feature['id']}: unknown standard {feature['standard']}")
    provider_ids = unique(data["providers"], "provider")
    if provider_ids != configured_profiles():
        missing = configured_profiles() - provider_ids
        extra = provider_ids - configured_profiles()
        raise CatalogError(f"provider catalog differs from code; missing={sorted(missing)}, extra={sorted(extra)}")
    documentation = data.get("documentation")
    if not isinstance(documentation, dict) or set(documentation) != provider_ids:
        raise CatalogError("provider documentation must name every provider exactly once")
    for provider in data["providers"]:
        guide_path = ROOT / provider["guide"]
        if not guide_path.is_file():
            raise CatalogError(f"{provider['id']}: guide does not exist")
        guide_text = guide_path.read_text(encoding="utf-8")
        unknown = set(provider["capabilities"]) - feature_ids
        if unknown:
            raise CatalogError(f"{provider['id']}: unknown capabilities {sorted(unknown)}")
        source_eligible_features = {
            feature_id for feature_id, status in provider["capabilities"].items()
            if status in SOURCE_EVIDENCE
        }
        source_required_features = {
            feature_id for feature_id, status in provider["capabilities"].items()
            if status in {"documented", "conditional"}
        }
        sources = documentation[provider["id"]]
        if (
            not isinstance(sources, dict)
            or not source_required_features <= set(sources)
            or not set(sources) <= source_eligible_features
        ):
            raise CatalogError(f"{provider['id']}: documentation differs from its source-backed feature claims")
        for feature_id, source in sources.items():
            if (
                not isinstance(source, str)
                or not re.fullmatch(r"https://[^\s<>\"]{1,2040}", source)
                or f"]({source})" not in guide_text
            ):
                raise CatalogError(f"{provider['id']}/{feature_id}: documentation source is not cited in its guide")
        all_records = provider.get("live_evidence", [])
        if not isinstance(all_records, list):
            raise CatalogError(f"{provider['id']}: live_evidence must be a list")
        evidenced_features = set()
        for record in all_records:
            if not isinstance(record, dict):
                raise CatalogError(f"{provider['id']}: live_evidence contains a non-object record")
            feature_id = record.get("feature")
            if not isinstance(feature_id, str) or feature_id not in feature_ids:
                raise CatalogError(f"{provider['id']}: live_evidence names an unknown feature")
            status = provider["capabilities"].get(feature_id)
            if status not in ARTIFACT_EVIDENCE:
                raise CatalogError(f"{provider['id']}/{feature_id}: interoperability evidence has no matching claim")
            validate_live_evidence_record(provider, feature_id, status, record)
            evidenced_features.add(feature_id)
        emulator_records = provider.get("emulator_evidence", [])
        if not isinstance(emulator_records, list):
            raise CatalogError(f"{provider['id']}: emulator_evidence must be a list")
        emulator_features = set()
        for record in emulator_records:
            feature_id = record.get("feature") if isinstance(record, dict) else None
            if feature_id not in feature_ids or feature_id in emulator_features:
                raise CatalogError(f"{provider['id']}: emulator_evidence has an invalid or duplicate feature")
            validate_emulator_evidence_record(provider, feature_id, record)
            emulator_features.add(feature_id)
        for feature_id, status in provider["capabilities"].items():
            if status not in EVIDENCE:
                raise CatalogError(f"{provider['id']}/{feature_id}: invalid evidence status {status}")
            if status in {"live", "adapter"} and feature_id not in evidenced_features:
                raise CatalogError(f"{provider['id']}/{feature_id}: live status needs a retained evidence record")
            if (
                status in {"unavailable", "incompatible"}
                and feature_id not in sources
                and feature_id not in evidenced_features
            ):
                raise CatalogError(
                    f"{provider['id']}/{feature_id}: negative status needs a source or retained evidence"
                )


def cell(defaults, documentation, provider, feature_id):
    status = provider["capabilities"].get(feature_id, defaults[feature_id])
    symbol = EVIDENCE_SYMBOL[status]
    source = documentation[provider["id"]].get(feature_id)
    rendered = f"[{symbol}]({source})" if source else symbol
    emulator = next((record for record in provider.get("emulator_evidence", []) if record["feature"] == feature_id), None)
    if emulator:
        artifact = pathlib.PurePosixPath(emulator["artifact"])
        rendered += f" [🧪](../../tests/evidence/providers/{artifact.name})"
    return rendered


def resolved_status(providers, provider, feature_id):
    return provider["capabilities"].get(feature_id, providers["capability_defaults"][feature_id])


def security_frontier(standards, providers):
    claims = {standard["id"]: standard["claim"] for standard in standards["standards"]}
    dimensions = [
        feature for feature in providers["features"]
        if feature["security"] and feature["standard"] and claims[feature["standard"]] == "verified"
    ]
    if not dimensions:
        return dimensions, []
    supported = {
        provider["id"]: {
            feature["id"] for feature in dimensions
            if resolved_status(providers, provider, feature["id"]) == "live"
        }
        for provider in providers["providers"]
        if resolved_status(providers, provider, "login") == "live"
    }
    supported = {provider_id: values for provider_id, values in supported.items() if values}
    frontier = []
    for provider_id, values in supported.items():
        dominated = any(values < other for other_id, other in supported.items() if other_id != provider_id)
        if not dominated:
            frontier.append(provider_id)
    return dimensions, frontier


def render(standards, providers):
    lines = [
        "## Standards and provider capabilities",
        "",
        "<!-- Generated by tests/update-capability-matrix.py; edit the JSON catalogs, not this file. -->",
        "",
        "Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.",
        "",
        "This report deliberately starts conservative. A feature is green only after the exact relying-party profile has a",
        "complete inventory of all applicable normative requirements and the required positive and negative evidence. Existing",
        "implementation tests do not become standards claims merely because they pass.",
        "",
        f"Catalog boundary (reviewed {standards['coverage']['reviewed_on']}): {standards['coverage']['boundary']}",
        f"Excluded families: {standards['coverage']['excluded_families']}",
        "Source indexes: " + ", ".join(f"[{source}]({source})" for source in standards["coverage"]["sources"]) + ".",
        "",
        "Provider interoperability is a separate claim. A dated live result remains a historical result for the tested service",
        "revision; it does not expire automatically and does not silently prove later revisions.",
        "",
        "### Standards catalog",
        "",
        "| Standard or profile | RP scope | Implementation | Conformance | Reason or next condition |",
        "|---|---|---:|---:|---|",
    ]
    for standard in standards["standards"]:
        reason = standard["note"]
        if standard.get("reconsider_when"):
            reason += " Reconsider: " + standard["reconsider_when"]
        lines.append(
            f"| [{standard['title']}]({standard['reference']}) | {standard['scope']} | "
            f"{STATUS_LABEL[standard['implementation']]} | {CLAIM_LABEL[standard['claim']]} | {reason} |"
        )

    for standard in standards["standards"]:
        tracking = standard.get("draft_tracking")
        if tracking is None:
            continue
        lines += [
            "",
            f"### {standard['title']} tracking",
            "",
            f"Informative only: `{tracking['specification_revision']}` was reviewed "
            f"{tracking['reviewed_on']}; no draft conformance is claimed.",
            "",
            "| Draft difference | RP status | Current disposition |",
            "|---|---:|---|",
        ]
        for delta in tracking["deltas"]:
            lines.append(
                f"| {delta['summary']} ({delta['section']}) | "
                f"{DRAFT_DISPOSITION_LABEL[delta['disposition']]} | {delta['note']} |"
            )

    features = providers["features"]
    lines += [
        "",
        "### Provider interoperability matrix",
        "",
        "The cells describe provider evidence, not plugin standards conformance: ✅ retained real-provider test; 🟦 retained",
        "real-provider test with a named adapter; 🧪 retained emulator test; 📘 vendor documentation only; ◇ conditional;",
        "❌ unavailable; ⚠️ incompatible; ? unknown. Emulator evidence is additional and never makes a cell green.",
        "",
        "| Provider | " + " | ".join(feature["title"] for feature in features) + " |",
        "|---|" + "---:|" * len(features),
    ]
    for provider in providers["providers"]:
        guide = "../" + str(pathlib.PurePosixPath(provider["guide"]).relative_to("docs"))
        lines.append(
            f"| [{provider['title']}]({guide}) | "
            + " | ".join(
                cell(providers["capability_defaults"], providers["documentation"], provider, feature["id"])
                for feature in features
            )
            + " |"
        )

    security_features = [feature for feature in features if feature["security"]]
    verified_dimensions, frontier = security_frontier(standards, providers)
    lines += [
        "",
        "### Verified security comparison",
        "",
        "The comparison uses only security features for which the plugin has a verified standards claim and the provider has",
        "retained live evidence. Vendor adaptations do not become standard-conformant green cells. The result is a Pareto",
        "frontier instead of a numeric score that hides trade-offs.",
        "",
        "Security dimensions reserved for that comparison: "
        + ", ".join(feature["title"] for feature in security_features)
        + ".",
        "",
    ]
    if not verified_dimensions:
        lines.append("Current result: no provider is ranked because no security dimension has passed the normative gate.")
    elif not frontier:
        lines.append("Current result: no provider has retained live login and security evidence on the verified dimensions.")
    else:
        provider_titles = {provider["id"]: provider["title"] for provider in providers["providers"]}
        lines.append("Current Pareto frontier: " + ", ".join(provider_titles[item] for item in frontier) + ".")
    lines += [
        "",
        "### How a cell becomes green",
        "",
        "1. Fix the exact specification version, RP role, feature profile and applicability boundary.",
        "2. Inventory every normative MUST, MUST NOT, SHOULD, SHOULD NOT and claimed MAY with a stable requirement ID.",
        "3. Give every applicable MUST and MUST NOT positive and negative evidence. Test a SHOULD likewise or record a reviewed deviation.",
        "4. Let the catalog validator reject incomplete inventories and broken evidence references.",
        "5. For a provider cell, retain the provider revision, test date, configuration and result. Record vendor adaptations separately.",
        "",
        "The OIDF conformance suite may add useful independent evidence, but an internal result is not represented as OpenID",
        "certification. Contradictory newer evidence supersedes a claim explicitly; the passage of time alone does not.",
        "",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--update", action="store_true")
    parser.add_argument("--executed-tests", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, help="alternate output path for a transactional render")
    args = parser.parse_args()
    output = args.output.resolve() if args.output else OUTPUT
    if args.output and not args.update:
        parser.error("--output requires --update")

    try:
        global EXECUTED_TESTS
        EXECUTED_TESTS = load_executed_tests(args.executed_tests) if args.executed_tests else set()
        standards = read_json(STANDARDS)
        providers = read_json(PROVIDERS)
        standard_ids = validate_standards(standards)
        validate_providers(providers, standard_ids)
        rendered = render(standards, providers)
    except (CatalogError, KeyError, json.JSONDecodeError) as error:
        print(f"capability catalog: {error}", file=sys.stderr)
        return 1

    if args.update:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        label = output.relative_to(ROOT) if output.is_relative_to(ROOT) else output
        print(f"rendered {label}")
        return 0

    current = output.read_text(encoding="utf-8") if output.exists() else ""
    if current != rendered:
        print("capability matrix is stale; run tests/update-capability-matrix.py --update", file=sys.stderr)
        return 1
    print("capability catalog and generated matrix agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
