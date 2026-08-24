#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Validate the evidence gates and render the public capability matrices."""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STANDARDS = ROOT / "tests" / "standards" / "catalog.json"
PROVIDERS = ROOT / "tests" / "providers" / "capabilities.json"
OUTPUT = ROOT / "docs" / "reference" / "provider-capabilities.md"
CONNECTOR = ROOT / "src" / "opnsense" / "mvc" / "app" / "library" / "OPNsense" / "Auth" / "OpenIDConnect.php"

IMPLEMENTATION = {"implemented", "partial", "candidate", "deferred", "not_planned", "not_applicable"}
CLAIMS = {"verified", "unverified", "not_claimed", "not_applicable"}
EVIDENCE = {"live", "adapter", "documented", "conditional", "unavailable", "incompatible", "unknown"}
REQUIREMENT_STRENGTH = {"must", "must_not", "should", "should_not", "may"}

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


def validate_requirement(standard, requirement):
    missing = {"id", "section", "strength", "applicable", "evidence"} - requirement.keys()
    if missing:
        raise CatalogError(f"{standard['id']}: requirement misses {', '.join(sorted(missing))}")
    if requirement["strength"] not in REQUIREMENT_STRENGTH:
        raise CatalogError(f"{requirement['id']}: invalid normative strength")
    evidence = requirement["evidence"]
    if requirement["applicable"]:
        if requirement["strength"] in {"must", "must_not"} and not {"positive", "negative"} <= evidence.keys():
            raise CatalogError(f"{requirement['id']}: mandatory requirement needs positive and negative evidence")
        if requirement["strength"] in {"should", "should_not"} and not (
            {"positive", "negative"} <= evidence.keys() or requirement.get("deviation")
        ):
            raise CatalogError(f"{requirement['id']}: recommendation needs evidence or an explicit deviation")
        if requirement["strength"] == "may" and requirement.get("claimed") and not evidence:
            raise CatalogError(f"{requirement['id']}: claimed optional behaviour needs evidence")


def validate_standards(data):
    ids = unique(data["standards"], "standard")
    for standard in data["standards"]:
        if standard["implementation"] not in IMPLEMENTATION:
            raise CatalogError(f"{standard['id']}: invalid implementation status")
        if standard["claim"] not in CLAIMS:
            raise CatalogError(f"{standard['id']}: invalid claim status")
        requirements = standard.get("requirements", [])
        unique(requirements, f"requirement in {standard['id']}")
        for requirement in requirements:
            validate_requirement(standard, requirement)
        if standard["claim"] == "verified":
            if not standard["audit_complete"] or not requirements:
                raise CatalogError(f"{standard['id']}: verified requires a complete, non-empty normative inventory")
            if any(requirement["applicable"] and not requirement["evidence"] for requirement in requirements):
                raise CatalogError(f"{standard['id']}: verified has an applicable requirement without evidence")
        if standard["audit_complete"] and not requirements:
            raise CatalogError(f"{standard['id']}: an empty inventory cannot be complete")
    return ids


def configured_profiles():
    source = CONNECTOR.read_text(encoding="utf-8")
    match = re.search(r"public const PROVIDER_PROFILES = \[(.*?)\n\s*\];", source, re.DOTALL)
    if not match:
        raise CatalogError("cannot locate PROVIDER_PROFILES in connector")
    return set(re.findall(r"'([^']+)'", match.group(1)))


def validate_providers(data, standard_ids):
    feature_ids = unique(data["features"], "feature")
    for feature in data["features"]:
        if feature["standard"] is not None and feature["standard"] not in standard_ids:
            raise CatalogError(f"{feature['id']}: unknown standard {feature['standard']}")
    provider_ids = unique(data["providers"], "provider")
    if provider_ids != configured_profiles():
        missing = configured_profiles() - provider_ids
        extra = provider_ids - configured_profiles()
        raise CatalogError(f"provider catalog differs from code; missing={sorted(missing)}, extra={sorted(extra)}")
    for provider in data["providers"]:
        if not (ROOT / provider["guide"]).is_file():
            raise CatalogError(f"{provider['id']}: guide does not exist")
        unknown = set(provider["capabilities"]) - feature_ids
        if unknown:
            raise CatalogError(f"{provider['id']}: unknown capabilities {sorted(unknown)}")
        for feature_id, status in provider["capabilities"].items():
            if status not in EVIDENCE:
                raise CatalogError(f"{provider['id']}/{feature_id}: invalid evidence status {status}")


def cell(provider, feature_id):
    return EVIDENCE_SYMBOL[provider["capabilities"].get(feature_id, "unknown")]


def render(standards, providers):
    lines = [
        "# OpenID Connect standards and provider capabilities",
        "",
        "<!-- Generated by tests/update-capability-matrix.py; edit the JSON catalogs, not this file. -->",
        "",
        "Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.",
        "",
        "This report deliberately starts conservative. A feature is green only after the exact relying-party profile has a",
        "complete inventory of all applicable normative requirements and the required positive and negative evidence. Existing",
        "implementation tests do not become standards claims merely because they pass.",
        "",
        "Provider interoperability is a separate claim. A dated live result remains a historical result for the tested service",
        "revision; it does not expire automatically and does not silently prove later revisions.",
        "",
        "## Standards catalog",
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
        "## Provider interoperability matrix",
        "",
        "The cells describe provider evidence, not plugin standards conformance: ✅ retained live test; 🟦 retained live test",
        "with a named adapter; 📘 vendor documentation only; ◇ conditional; ❌ unavailable; ⚠️ incompatible; ? unknown.",
        "A provider guide alone is never rendered green.",
        "",
        "| Provider | " + " | ".join(feature["title"] for feature in features) + " |",
        "|---|" + "---:|" * len(features),
    ]
    for provider in providers["providers"]:
        guide = "../../" + provider["guide"]
        lines.append(
            f"| [{provider['title']}]({guide}) | "
            + " | ".join(cell(provider, feature["id"]) for feature in features)
            + " |"
        )

    security_features = [feature for feature in features if feature["security"]]
    lines += [
        "",
        "## Verified security comparison",
        "",
        "No provider is currently placed on a security frontier. The comparison will use only security features for which both",
        "the plugin has a verified standards claim and the provider has retained live evidence. It will show the Pareto frontier",
        "instead of inventing a numeric score that hides trade-offs.",
        "",
        "Security dimensions reserved for that comparison: "
        + ", ".join(feature["title"] for feature in security_features)
        + ".",
        "",
        "## How a cell becomes green",
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
