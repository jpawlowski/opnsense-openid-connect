#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Validate the evidence gates and render the public capability matrices."""

import argparse
import datetime
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
REQUIREMENT_STRENGTH = {"must", "must_not", "should", "should_not", "may"}
GATE_EVIDENCE_TEST = pathlib.PurePosixPath("tests/capability-matrix.py")
PROVIDER_EVIDENCE_DIRECTORY = pathlib.PurePosixPath("tests/evidence")
PROVIDER_REVISION = re.compile(r"^(?:version|release|service|commit):[A-Za-z0-9][A-Za-z0-9._+:/@ -]{0,111}$")

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


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def unique(items, label):
    seen = set()
    for item in items:
        value = item["id"]
        if value in seen:
            raise CatalogError(f"duplicate {label} id: {value}")
        seen.add(value)
    return seen


def repository_file(value, label, root=ROOT):
    if not isinstance(value, str) or not value or "\\" in value:
        raise CatalogError(f"{label}: path must be a repository-relative POSIX path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != value:
        raise CatalogError(f"{label}: path must be a normalized repository-relative POSIX path")
    return relative, root.joinpath(*relative.parts)


def gate_test_names(relative, path):
    is_unit = relative.parent == pathlib.PurePosixPath("tests/unit") and relative.suffix == ".php"
    if relative != GATE_EVIDENCE_TEST and not is_unit:
        raise CatalogError(f"{relative}: normative evidence must name a test suite executed by ./tests/run.sh")
    if not path.is_file():
        raise CatalogError(f"{relative}: evidence test suite does not exist")
    source = path.read_text(encoding="utf-8")
    if relative.suffix == ".php":
        pattern = r"Checks::(?:that|throws)\(\s*(['\"])(.*?)\1"
    else:
        pattern = r"\bcheck\(\s*(['\"])(.*?)\1"
    return {match[1] for match in re.findall(pattern, source, re.DOTALL)}


def validate_test_evidence(requirement_id, direction, reference):
    if not isinstance(reference, dict) or set(reference) != {"path", "test"}:
        raise CatalogError(f"{requirement_id}: evidence must name one gate test path and exact test name")
    relative, path = repository_file(reference["path"], requirement_id)
    test = reference["test"]
    prefix = f"{requirement_id} {direction}: "
    if not isinstance(test, str) or not test.startswith(prefix):
        raise CatalogError(f"{requirement_id}: {direction} evidence test must begin with '{prefix}'")
    if test not in gate_test_names(relative, path):
        raise CatalogError(f"{requirement_id}: exact {direction} test is not present in {relative}")
    return relative, test


def reviewed_deviation(requirement):
    deviation = requirement.get("deviation")
    if deviation is None:
        return False
    if requirement["strength"] not in {"should", "should_not"}:
        raise CatalogError(f"{requirement['id']}: only recommendations may record a deviation")
    if not isinstance(deviation, dict) or not {"reviewed_on", "rationale"} <= deviation.keys():
        raise CatalogError(f"{requirement['id']}: deviation needs a review date and rationale")
    reviewed_on = deviation["reviewed_on"]
    try:
        if not isinstance(reviewed_on, str) or datetime.date.fromisoformat(reviewed_on).isoformat() != reviewed_on:
            raise ValueError
    except ValueError as error:
        raise CatalogError(f"{requirement['id']}: deviation review date must use YYYY-MM-DD") from error
    rationale = deviation["rationale"]
    if not isinstance(rationale, str) or rationale.strip() != rationale or not 1 <= len(rationale) <= 1000:
        raise CatalogError(f"{requirement['id']}: deviation needs a non-empty reviewed rationale")
    return True


def validate_requirement(standard, requirement):
    missing = {"id", "section", "strength", "applicable", "evidence"} - requirement.keys()
    if missing:
        raise CatalogError(f"{standard['id']}: requirement misses {', '.join(sorted(missing))}")
    if requirement["strength"] not in REQUIREMENT_STRENGTH:
        raise CatalogError(f"{requirement['id']}: invalid normative strength")
    evidence = requirement["evidence"]
    has_reviewed_deviation = reviewed_deviation(requirement)
    if not requirement["applicable"]:
        if not requirement.get("rationale"):
            raise CatalogError(f"{requirement['id']}: non-applicability needs a rationale")
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
    ids = unique(data["standards"], "standard")
    requirement_ids = set()
    for standard in data["standards"]:
        if standard["implementation"] not in IMPLEMENTATION:
            raise CatalogError(f"{standard['id']}: invalid implementation status")
        if standard["claim"] not in CLAIMS:
            raise CatalogError(f"{standard['id']}: invalid claim status")
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
            review = standard.get("source_review", {})
            if not {"specification_revision", "reviewed_on", "profile", "sections"} <= review.keys():
                raise CatalogError(f"{standard['id']}: verified requires a pinned source and applicability review")
        if standard["audit_complete"] and not requirements:
            raise CatalogError(f"{standard['id']}: an empty inventory cannot be complete")
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


def validate_live_evidence_record(provider, feature_id, status, record, root=ROOT):
    label = f"{provider['id']}/{feature_id}"
    if not isinstance(record, dict) or not {"feature", "tested_on", "provider_revision", "artifact"} <= record.keys():
        raise CatalogError(f"{label}: incomplete live evidence record")
    if record["feature"] != feature_id:
        raise CatalogError(f"{label}: live evidence record names another feature")
    tested_on = validate_record_text(record, "tested_on", label)
    try:
        if datetime.date.fromisoformat(tested_on).isoformat() != tested_on:
            raise ValueError
    except ValueError as error:
        raise CatalogError(f"{label}: tested_on must use YYYY-MM-DD") from error
    provider_revision = validate_record_text(record, "provider_revision", label)
    if not PROVIDER_REVISION.fullmatch(provider_revision):
        raise CatalogError(
            f"{label}: provider_revision must start with version:, release:, service: or commit:"
        )
    relative, artifact_path = repository_file(record.get("artifact"), label, root)
    if relative.parent != PROVIDER_EVIDENCE_DIRECTORY or relative.suffix != ".json":
        raise CatalogError(f"{label}: live evidence artifact must be a JSON file in tests/evidence")
    try:
        artifact = read_json(artifact_path)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise CatalogError(f"{label}: live evidence artifact is missing or invalid JSON") from error
    expected = {
        "schema_version": 1,
        "evidence_type": "provider_interoperability",
        "provider": provider["id"],
        "provider_revision": provider_revision,
        "tested_on": tested_on,
    }
    if not isinstance(artifact, dict) or any(artifact.get(key) != value for key, value in expected.items()):
        raise CatalogError(f"{label}: artifact is not bound to the provider, revision and test date")
    configuration = artifact.get("configuration")
    if not isinstance(configuration, dict) or not configuration:
        raise CatalogError(f"{label}: artifact must retain a sanitized non-empty provider configuration")
    results = artifact.get("results")
    if not isinstance(results, list):
        raise CatalogError(f"{label}: artifact must contain provider capability results")
    matches = [result for result in results if isinstance(result, dict) and result.get("feature") == feature_id]
    if len(matches) != 1 or matches[0].get("status") != status:
        raise CatalogError(f"{label}: artifact does not prove this capability status")
    if status == "adapter":
        adaptation = provider.get("adaptations", {}).get(feature_id)
        if not isinstance(adaptation, str) or not adaptation.strip():
            raise CatalogError(f"{label}: adapter status must name the deviation")
        if matches[0].get("adaptation") != adaptation:
            raise CatalogError(f"{label}: artifact is not bound to the named provider adaptation")


def validate_providers(data, standard_ids):
    feature_ids = unique(data["features"], "feature")
    if set(data["capability_defaults"]) != feature_ids:
        raise CatalogError("capability defaults must name every feature exactly once")
    if any(status not in EVIDENCE for status in data["capability_defaults"].values()):
        raise CatalogError("capability defaults contain an invalid evidence status")
    for feature in data["features"]:
        if feature["standard"] is not None and feature["standard"] not in standard_ids:
            raise CatalogError(f"{feature['id']}: unknown standard {feature['standard']}")
    provider_ids = unique(data["providers"], "provider")
    if provider_ids != configured_profiles():
        missing = configured_profiles() - provider_ids
        extra = provider_ids - configured_profiles()
        raise CatalogError(f"provider catalog differs from code; missing={sorted(missing)}, extra={sorted(extra)}")
    for provider in data["providers"]:
        guide_path = ROOT / provider["guide"]
        if not guide_path.is_file():
            raise CatalogError(f"{provider['id']}: guide does not exist")
        unknown = set(provider["capabilities"]) - feature_ids
        if unknown:
            raise CatalogError(f"{provider['id']}: unknown capabilities {sorted(unknown)}")
        for feature_id, status in provider["capabilities"].items():
            if status not in EVIDENCE:
                raise CatalogError(f"{provider['id']}/{feature_id}: invalid evidence status {status}")
            if status in {"documented", "conditional"} and "http" not in guide_path.read_text(encoding="utf-8"):
                raise CatalogError(
                    f"{provider['id']}/{feature_id}: documented status needs an external source in its guide"
                )
            if status in {"live", "adapter"}:
                all_records = provider.get("live_evidence", [])
                if not isinstance(all_records, list):
                    raise CatalogError(f"{provider['id']}: live_evidence must be a list")
                records = [
                    record for record in all_records
                    if isinstance(record, dict) and record.get("feature") == feature_id
                ]
                if not records:
                    raise CatalogError(f"{provider['id']}/{feature_id}: live status needs a retained evidence record")
                for record in records:
                    validate_live_evidence_record(provider, feature_id, status, record)


def cell(defaults, provider, feature_id):
    return EVIDENCE_SYMBOL[provider["capabilities"].get(feature_id, defaults[feature_id])]


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

    features = providers["features"]
    lines += [
        "",
        "### Provider interoperability matrix",
        "",
        "The cells describe provider evidence, not plugin standards conformance: ✅ retained live test; 🟦 retained live test",
        "with a named adapter; 📘 vendor documentation only; ◇ conditional; ❌ unavailable; ⚠️ incompatible; ? unknown.",
        "A provider guide alone is never rendered green.",
        "",
        "| Provider | " + " | ".join(feature["title"] for feature in features) + " |",
        "|---|" + "---:|" * len(features),
    ]
    for provider in providers["providers"]:
        guide = "../" + str(pathlib.PurePosixPath(provider["guide"]).relative_to("docs"))
        lines.append(
            f"| [{provider['title']}]({guide}) | "
            + " | ".join(cell(providers["capability_defaults"], provider, feature["id"]) for feature in features)
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
    args = parser.parse_args()

    try:
        standards = read_json(STANDARDS)
        providers = read_json(PROVIDERS)
        standard_ids = validate_standards(standards)
        validate_providers(providers, standard_ids)
        rendered = render(standards, providers)
    except (CatalogError, KeyError, json.JSONDecodeError) as error:
        print(f"capability catalog: {error}", file=sys.stderr)
        return 1

    if args.update:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered, encoding="utf-8")
        print(f"updated {OUTPUT.relative_to(ROOT)}")
        return 0

    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
    if current != rendered:
        print("capability matrix is stale; run tests/update-capability-matrix.py --update", file=sys.stderr)
        return 1
    print("capability catalog and generated matrix agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
