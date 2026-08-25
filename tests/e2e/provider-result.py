#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Write a sanitized, caller-owned result for one manual provider run."""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROVIDERS = {"keycloak", "authentik", "authelia", "pocketid", "entra", "okta", "apple"}
SOURCES = {"local", "emulated", "live"}
CLUSTERS = {"direct", "public-inbound"}
OUTCOMES = {"pass", "unavailable", "incompatible"}
APPLE_ADAPTATION = "Generic profile plus reviewed PKCE and Form Post discovery metadata missing from emulate 0.10.0"
EXPECTED = {
    ("keycloak", "local"): ("keycloak", "keycloak"),
    ("authentik", "local"): ("authentik", "authentik"),
    ("authelia", "local"): ("authelia", "authelia"),
    ("pocketid", "local"): ("pocketid", "pocketid"),
    ("entra", "emulated"): ("entra-local", "entra"),
    ("okta", "emulated"): ("vercel-labs-emulate", "okta"),
    ("apple", "emulated"): ("vercel-labs-emulate", "general"),
    ("entra", "live"): ("entra", "entra"),
    ("okta", "live"): ("okta", "okta"),
    ("apple", "live"): ("apple", "apple"),
}
FEATURE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
REVISION = re.compile(
    r"^(?:(?:version|release|commit):[A-Za-z0-9][A-Za-z0-9._+-]{0,111}|service:\d{4}-\d{2}-\d{2})$"
)
HARNESS_FILES = (
    "audit-evidence.mjs", "audit-reporter.mjs", "live-config.py", "local.sh", "oidc.spec.mjs",
    "package-lock.json", "package.json", "playwright.config.mjs", "provider-result.py", "provider.config.mjs",
    "provider.spec.mjs", "public-inbound-canary.py", "public-inbound-target.py", "public-inbound.py",
    "remote-cleanup-live.php", "remote-cleanup.php", "run-keycloak.sh", "run-live.sh", "run-provider.sh", "run.sh",
    "selection.py", "ssf-transmitter.mjs", "ssh.sh", "vm.py", "zap-report.mjs", "providers/emulate-adapter.mjs",
    "providers/image.py", "providers/images.json", "providers/stack.py", "vm/bootstrap.exp", "vm/trust.json",
)


def command(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout.strip()


def harness_digest():
    digest = hashlib.sha256()
    for relative in HARNESS_FILES:
        path = HERE / relative
        if not path.is_file():
            continue
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def source_state():
    revision = command("git", "-C", str(ROOT), "rev-parse", "HEAD")
    dirty = bool(command("git", "-C", str(ROOT), "status", "--porcelain"))
    return revision, dirty


def result(provider, source, cluster, subject_name, subject_revision, profile, capabilities, adaptation=None):
    if provider not in PROVIDERS or source not in SOURCES or cluster not in CLUSTERS:
        raise ValueError("unknown provider result selection")
    if (provider, source) not in EXPECTED or EXPECTED[(provider, source)] != (subject_name, profile):
        raise ValueError("test subject or profile differs from the selected provider source")
    if not REVISION.fullmatch(subject_revision):
        raise ValueError("test subject revision is not pinned")
    if not isinstance(subject_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,79}", subject_name):
        raise ValueError("test subject name is not publishable")
    parsed = []
    for capability in capabilities:
        feature, separator, outcome = capability.partition("=")
        if not separator or not FEATURE.fullmatch(feature) or outcome not in OUTCOMES:
            raise ValueError(f"invalid capability result: {capability}")
        parsed.append({"feature": feature, "outcome": outcome})
    if not parsed or len({item["feature"] for item in parsed}) != len(parsed):
        raise ValueError("provider result needs distinct capability outcomes")
    expected_adaptation = APPLE_ADAPTATION if (provider, source) == ("apple", "emulated") else None
    if adaptation != expected_adaptation:
        raise ValueError("provider adaptation differs from the reviewed provider driver")
    revision, dirty = source_state()
    return {
        "schema_version": 1,
        "evidence_type": "provider_test_run",
        "repository_revision": revision,
        "repository_dirty": dirty,
        "harness_digest": harness_digest(),
        "provider": provider,
        "source": source,
        "subject": {"name": subject_name, "revision": subject_revision},
        "cluster": cluster,
        "tested_on": datetime.date.today().isoformat(),
        "configuration_profile": profile,
        "provider_adaptation": adaptation,
        "results": parsed,
    }


def write_output(path, payload):
    output = pathlib.Path(path)
    if not output.is_absolute() or not output.parent.is_dir():
        raise ValueError("E2E_PROVIDER_RESULT must be an absolute path in an existing directory")
    temporary = output.parent / f".{output.name}.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(output)
    output.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--subject-name", required=True)
    parser.add_argument("--subject-revision", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--capability", action="append", required=True)
    parser.add_argument("--adaptation")
    parser.add_argument("--output", default=os.environ.get("E2E_PROVIDER_RESULT", ""))
    arguments = parser.parse_args()
    if not arguments.output:
        return
    try:
        payload = result(
            arguments.provider, arguments.source, arguments.cluster, arguments.subject_name,
            arguments.subject_revision, arguments.profile, arguments.capability, arguments.adaptation or None,
        )
        write_output(arguments.output, payload)
    except ValueError as error:
        parser.error(str(error))
    print("Wrote sanitized provider result.")


if __name__ == "__main__":
    main()
