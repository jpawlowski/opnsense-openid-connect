#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Deliberately import selected sanitized provider-run results into the public matrix."""

import argparse
import datetime
import importlib.util
import json
import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "tests" / "providers" / "capabilities.json"
EVIDENCE = ROOT / "tests" / "evidence" / "providers"
RAW_FIELDS = {
    "schema_version", "evidence_type", "repository_revision", "repository_dirty", "harness_digest",
    "provider", "source", "subject", "cluster", "tested_on", "configuration_profile", "results",
    "provider_adaptation",
}
SUBJECTS = {
    "entra-local": ("entra", "emulated"),
    "vercel-labs-emulate": ({"okta", "apple"}, "emulated"),
    "keycloak": ("keycloak", "local"),
    "authentik": ("authentik", "local"),
    "authelia": ("authelia", "local"),
    "pocketid": ("pocketid", "local"),
    "entra": ("entra", "live"),
    "okta": ("okta", "live"),
    "apple": ("apple", "live"),
}
REVISION = re.compile(
    r"^(?:(?:version|release|commit):[A-Za-z0-9][A-Za-z0-9._+-]{0,111}|service:\d{4}-\d{2}-\d{2})$"
)
APPLE_ADAPTATION = "Generic profile plus reviewed PKCE and Form Post discovery metadata missing from emulate 0.10.0"


def load_result(path):
    try:
        result = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError("provider result is missing or invalid JSON") from error
    if not isinstance(result, dict) or set(result) != RAW_FIELDS:
        raise ValueError("provider result contains unknown or missing fields")
    if result.get("schema_version") != 1 or result.get("evidence_type") != "provider_test_run":
        raise ValueError("provider result uses an unsupported schema")
    if result.get("repository_dirty") is not False:
        raise ValueError("provider result from a dirty worktree cannot be retained")
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    if result.get("repository_revision") != head:
        raise ValueError("provider result does not belong to the current repository revision")
    if not re.fullmatch(r"[a-f0-9]{64}", result.get("harness_digest", "")):
        raise ValueError("provider result has no valid harness digest")
    spec = importlib.util.spec_from_file_location("provider_result", ROOT / "tests" / "e2e" / "provider-result.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    if result["harness_digest"] != generator.harness_digest():
        raise ValueError("provider result does not match the current test harness")
    provider = result.get("provider")
    source = result.get("source")
    expected_profile = "general" if provider == "apple" and source == "emulated" else provider
    if (
        result.get("configuration_profile") != expected_profile
        or result.get("cluster") not in {"direct", "public-inbound"}
    ):
        raise ValueError("provider result is not bound to its public profile and cluster")
    adaptation = result.get("provider_adaptation")
    if adaptation is not None and (
        not isinstance(adaptation, str) or adaptation.strip() != adaptation or not 1 <= len(adaptation) <= 256
        or not all(character.isprintable() for character in adaptation)
    ):
        raise ValueError("provider result has an unsafe provider adaptation")
    expected_adaptation = APPLE_ADAPTATION if provider == "apple" and source == "emulated" else None
    if adaptation != expected_adaptation:
        raise ValueError("provider result differs from the reviewed provider adaptation")
    subject = result.get("subject")
    if not isinstance(subject, dict) or set(subject) != {"name", "revision"} or subject.get("name") not in SUBJECTS:
        raise ValueError("provider result names an unknown test subject")
    expected_provider, expected_source = SUBJECTS[subject["name"]]
    if (provider not in expected_provider if isinstance(expected_provider, set) else provider != expected_provider):
        raise ValueError("provider result test subject belongs to another provider")
    if source != expected_source or not REVISION.fullmatch(subject.get("revision", "")):
        raise ValueError("provider result test subject is not pinned to the selected source")
    try:
        tested_on = datetime.date.fromisoformat(result.get("tested_on", ""))
        if tested_on.isoformat() != result["tested_on"] or tested_on > datetime.date.today():
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError("provider result test date is invalid or in the future") from error
    if source == "live":
        if not subject["revision"].startswith("service:"):
            raise ValueError("hosted provider evidence must use a service-date revision")
        service_date = datetime.date.fromisoformat(subject["revision"].removeprefix("service:"))
        if service_date > tested_on:
            raise ValueError("hosted service revision cannot be later than the test")
    if (
        subject["name"] in generator.FIXED_REVISIONS
        and subject["revision"] != generator.FIXED_REVISIONS[subject["name"]]
    ):
        raise ValueError("provider result emulator revision differs from the reviewed dependency")
    if source == "local":
        images = json.loads((ROOT / "tests" / "e2e" / "providers" / "images.json").read_text(encoding="utf-8"))
        expected_revision = "version:" + images["providers"][provider]["tag"]
        if subject["revision"] != expected_revision:
            raise ValueError("provider result image revision differs from the reviewed manifest")
    results = result.get("results")
    if (
        not isinstance(results, list) or not results
        or any(not isinstance(item, dict) or set(item) != {"feature", "outcome"} for item in results)
        or any(item["outcome"] not in {"pass", "unavailable", "incompatible"} for item in results)
        or any(not isinstance(item["feature"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item["feature"])
               for item in results)
        or len({item["feature"] for item in results}) != len(results)
    ):
        raise ValueError("provider result has invalid capability outcomes")
    allowed = generator.CAPABILITIES.get((provider, source, result["cluster"]), set())
    if not {item["feature"] for item in results} <= allowed:
        raise ValueError("provider result contains a capability this selection did not exercise")
    return result


def safe_name(*parts):
    return "-".join(re.sub(r"[^a-z0-9]+", "-", part.lower()).strip("-") for part in parts)


def import_result(result, features):
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    feature_ids = {feature["id"] for feature in catalog["features"]}
    selected = [item for item in result["results"] if item["feature"] in features]
    if not selected or {item["feature"] for item in selected} != set(features) or not set(features) <= feature_ids:
        raise ValueError("every selected feature must be a known result in the artifact")
    provider = next((item for item in catalog["providers"] if item["id"] == result["provider"]), None)
    if provider is None:
        raise ValueError("provider result names no catalog provider")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if result["source"] == "emulated":
        if any(item["outcome"] != "pass" for item in selected):
            raise ValueError("emulator negatives cannot become provider capability evidence")
        name = safe_name(result["provider"], "emulated", result["tested_on"], result["harness_digest"][:12]) + ".json"
        artifact = EVIDENCE / name
        artifact.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        records = provider.setdefault("emulator_evidence", [])
        for item in selected:
            record = {
                "feature": item["feature"], "tested_on": result["tested_on"],
                "emulator_revision": result["subject"]["revision"],
                "artifact": str(artifact.relative_to(ROOT)),
                "adaptation": result["provider_adaptation"], "source": result["source"],
                "cluster": result["cluster"],
            }
            records[:] = [
                old for old in records
                if (
                    old.get("feature"), old.get("source"), old.get("cluster")
                ) != (item["feature"], result["source"], result["cluster"])
            ]
            records.append(record)
    else:
        for item in selected:
            status = "live" if item["outcome"] == "pass" else item["outcome"]
            name = safe_name(
                result["provider"], item["feature"], result["source"], result["cluster"], result["tested_on"],
            ) + ".json"
            artifact = EVIDENCE / name
            retained = {
                "schema_version": 1,
                "evidence_type": "provider_interoperability",
                "provider": result["provider"],
                "source": result["source"],
                "cluster": result["cluster"],
                "provider_revision": result["subject"]["revision"],
                "tested_on": result["tested_on"],
                "configuration": {
                    "provider_profile": result["provider"], "guide": provider["guide"],
                    "client_type": "confidential", "flow": "authorization_code", "feature_mode": "enabled",
                },
                "results": [{"feature": item["feature"], "status": status}],
            }
            artifact.write_text(json.dumps(retained, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            provider["capabilities"][item["feature"]] = status
            catalog["documentation"][result["provider"]].pop(item["feature"], None)
            records = provider.setdefault("live_evidence", [])
            records[:] = [
                old for old in records
                if (
                    old.get("feature"), old.get("source"), old.get("cluster")
                ) != (item["feature"], result["source"], result["cluster"])
            ]
            records.append({
                "feature": item["feature"], "tested_on": result["tested_on"],
                "provider_revision": result["subject"]["revision"], "artifact": str(artifact.relative_to(ROOT)),
                "source": result["source"], "cluster": result["cluster"],
            })
    CATALOG.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("result")
    parser.add_argument("--feature", action="append", required=True)
    arguments = parser.parse_args()
    try:
        import_result(load_result(arguments.result), arguments.feature)
    except ValueError as error:
        parser.error(str(error))
    print("Imported selected provider evidence; regenerate the capability matrix before committing.")


if __name__ == "__main__":
    main()
