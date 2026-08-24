#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Generate the unified security and conformance report."""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT = ROOT / "docs" / "reference" / "security-and-conformance.md"
CATALOG = ROOT / "tests" / "audit-controls.json"
CAPABILITY_REPORT = ROOT / "tests" / "generated" / "provider-capabilities.md"
SECURITY_MODEL = ROOT / "tests" / "security-model.md"
EVIDENCE_DIRECTORY = ROOT / "tests" / "evidence"
EVIDENCE_SCHEMA = "opnsense-openid-connect.audit-evidence/v1"
E2E_SUITE_FILES = (
    "tests/e2e/audit-evidence.mjs",
    "tests/e2e/audit-reporter.mjs",
    "tests/e2e/oidc.spec.mjs",
    "tests/e2e/playwright.config.mjs",
    "tests/e2e/run-keycloak.sh",
    "tests/e2e/zap-report.mjs",
)
STAGES = (
    ("syntax", "== syntax =="),
    ("behaviour", "== behaviour =="),
    ("convention", "== what a commit message may be =="),
    ("package", "== the package that gets built =="),
)

# A capability deliberately follows test intent rather than a method name. A
# renamed group therefore makes its security claim disappear until the mapping
# is reviewed, instead of silently treating unrelated checks as evidence.
HOST_CAPABILITIES = {
    "discovery-exact-issuer": (
        "Strict provider discovery",
        "Keeping the exact configured issuer",
    ),
    "authorization-code-pkce": (
        "Login transactions, PKCE and mix-up protection",
        "Choosing the address the provider returns to",
    ),
    "jar-request-object": ("JWT-secured authorization requests",),
    "mix-up-replay-protection": (
        "Login transactions, PKCE and mix-up protection",
    ),
    "jarm-response-policy": ("JWT-secured authorization responses",),
    "jwt-claim-policy": (
        "Asymmetric JWA verification profile",
        "ID token claim validation",
        "Whom a token was issued for",
    ),
    "provider-http-policy": ("Bounded HTTPS transport",),
    "private-key-jwt-client-auth": (
        "Private-key JWT client assertions",
        "Endpoint client authentication",
    ),
    "userinfo-subject-binding": (
        "Separating identity claims from protocol claims",
        "Strict endpoint responses and logout binding",
    ),
    "issuer-bound-logout-grants": ("Strict endpoint responses and logout binding",),
    "stable-subject-binding": ("Stable issuer and subject bindings",),
    "account-admission-policy": (
        "An account that may not be used",
        "Administrator approval admission policy",
    ),
    "group-scope-policy": (
        "Group membership is left alone unless asked for",
        "What the provider offers",
        "Default groups belong to the login that creates the account",
    ),
    "webgui-access-policy": ("local WebGUI authorization",),
    "form-post-transaction": ("Login transactions, PKCE and mix-up protection",),
    "logout-token-policy": (
        "Back-channel logout token claims",
        "Strict endpoint responses and logout binding",
    ),
    "shared-signals-policy": (
        "Shared Signals settings",
        "Shared Signals discovery",
        "Shared Signals event profile",
        "Shared Signals replay and session cutoff",
    ),
    "login-content-safety": (
        "Where the login button gets its icon",
        "What the login page is handed",
        "Stage: Package/archive/supply chain",
    ),
    "package-archive-integrity": ("Stage: Package/archive/supply chain",),
    "release-provenance-policy": (
        "What a release note makes of them",
        "A release is attested and published only once",
        "The nightly run, and what is left behind when it goes",
    ),
    "provider-onboarding-invariants": (
        "Provider setup files from an unfinished form",
        "Defaults when a field is left empty",
    ),
}


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, text=True, check=False, **kwargs)


def section(output, heading):
    start = output.find(heading)
    if start < 0:
        return None
    following = [output.find(other, start + len(heading)) for _, other in STAGES]
    following = [position for position in following if position >= 0]
    return output[start:min(following) if following else len(output)]


def passed_groups(output):
    groups = {}
    for stage, heading in STAGES:
        body = section(output, heading)
        if body is None:
            continue
        current = None
        for line in body.splitlines()[1:]:
            if re.match(r"^\d+ checks passed", line):
                current = None
            elif line.startswith("  ok    ") and current:
                groups.setdefault(current, {"passed": 0, "failed": 0})["passed"] += 1
            elif line.startswith("  FAIL  ") and current:
                groups.setdefault(current, {"passed": 0, "failed": 0})["failed"] += 1
            elif line and not line.startswith(" ") and not line.startswith("=="):
                current = line.strip()
        summary = re.search(r"(?m)^(\d+) checks passed(?:, none failed\.|, (\d+) FAILED:)", body)
        if stage != "syntax" and summary and int(summary.group(2) or 0) == 0:
            groups[f"Stage: {stage_label(stage)}"] = {"passed": int(summary.group(1)), "failed": 0}
    return {name for name, counts in groups.items() if counts["failed"] == 0 and counts["passed"] > 0}


def stage_label(stage):
    return {
        "behaviour": "Behaviour",
        "convention": "Commit/release convention",
        "package": "Package/archive/supply chain",
    }.get(stage, stage.capitalize())


def host_evidence(output):
    groups = passed_groups(output)
    capabilities = {
        capability
        for capability, requirements in HOST_CAPABILITIES.items()
        if all(requirement in groups for requirement in requirements)
    }
    return {
        "tier": "host-independent",
        "capabilities": capabilities,
        "label": "current host-independent regression suite",
        "path": None,
        "revision": None,
        "payload": None,
    }


def load_catalog():
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("sections"), list):
        raise ValueError("tests/audit-controls.json has an unsupported schema")
    tiers = catalog.get("evidence_tiers")
    if not isinstance(tiers, dict) or "host-independent" not in tiers:
        raise ValueError("audit control catalog has no host-independent evidence tier")
    producer_capabilities = {
        "host-independent": set(HOST_CAPABILITIES),
        "installed-integration": set(re.findall(
            r"\$validated\('([^']+)'\)",
            (ROOT / "tests/integration/opnsense.php").read_text(encoding="utf-8"),
        )),
        "browser-e2e": set(re.findall(
            r"^\s*\['([^']+)'",
            (ROOT / "tests/e2e/audit-evidence.mjs").read_text(encoding="utf-8"),
            re.MULTILINE,
        )),
    }
    declared_capabilities = {}
    for tier, definition in tiers.items():
        capabilities = definition.get("capabilities") if isinstance(definition, dict) else None
        if not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
            raise ValueError(f"audit evidence tier {tier} has no capability inventory")
        declared_capabilities[tier] = set(capabilities)
        if tier in producer_capabilities and declared_capabilities[tier] != producer_capabilities[tier]:
            raise ValueError(f"audit evidence tier {tier} differs from its evidence producer")

    used_capabilities = {tier: set() for tier in tiers}
    section_slugs = set()
    slugs = set()
    for section_item in catalog["sections"]:
        section_slug = section_item.get("slug")
        if not isinstance(section_slug, str) or section_slug in section_slugs:
            raise ValueError("audit control section slugs must be unique strings")
        section_slugs.add(section_slug)
        if not isinstance(section_item.get("controls"), list):
            raise ValueError("audit control catalog section has no control list")
        for control in section_item["controls"]:
            slug = control.get("slug")
            if not isinstance(slug, str) or slug in slugs:
                raise ValueError("audit control slugs must be unique strings")
            slugs.add(slug)
            paths = control.get("implementation")
            requirements = control.get("evidence", {}).get("all_of")
            if not isinstance(paths, list) or not paths or not isinstance(requirements, list) or not requirements:
                raise ValueError(f"audit control {slug} has incomplete implementation or evidence")
            for path in paths:
                if not (ROOT / path).is_file():
                    raise ValueError(f"audit control {slug} references missing implementation {path}")
            for requirement in requirements:
                tier = requirement.get("tier")
                capabilities = requirement.get("capabilities")
                validation = requirement.get("validation")
                if tier not in tiers or not isinstance(capabilities, list) or not capabilities:
                    raise ValueError(f"audit control {slug} has invalid evidence requirements")
                if not set(capabilities).issubset(declared_capabilities[tier]):
                    raise ValueError(f"audit control {slug} references an unknown {tier} capability")
                used_capabilities[tier].update(capabilities)
                if not isinstance(validation, list) or not validation:
                    raise ValueError(f"audit control {slug} has no validation references")
                for path in validation:
                    if not (ROOT / path).is_file():
                        raise ValueError(f"audit control {slug} references missing validation {path}")
    for tier, declared in declared_capabilities.items():
        unused = declared - used_capabilities[tier]
        if unused:
            raise ValueError(f"audit evidence tier {tier} has capabilities without controls: {sorted(unused)}")
    return catalog


def evidence_paths(arguments):
    paths = sorted(EVIDENCE_DIRECTORY.glob("*.json")) if EVIDENCE_DIRECTORY.is_dir() else []
    paths.extend(pathlib.Path(value).expanduser().resolve() for value in arguments)
    return list(dict.fromkeys(paths))


def revision_file(revision, path):
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        raise ValueError(f"source revision {revision[:12]} has no {path}")
    return result.stdout


def e2e_suite_digest(revision):
    digest = hashlib.sha256()
    prefix = "tests/e2e/"
    for path in E2E_SUITE_FILES:
        name = path.removeprefix(prefix)
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(revision_file(revision, path))
        digest.update(b"\0")
    return digest.hexdigest()


def evidence_subject(payload, path, revision):
    subject = payload.get("subject")
    if not isinstance(subject, dict):
        raise ValueError(f"{path} has no evidence subject")
    package = subject.get("package")
    opnsense = subject.get("opnsense")
    if not isinstance(package, dict) or package.get("name") != "os-openid-connect":
        raise ValueError(f"{path} does not identify the installed package")
    version_pattern = r"[0-9A-Za-z][0-9A-Za-z._,+-]{0,127}"
    if not isinstance(package.get("version"), str) or not re.fullmatch(version_pattern, package["version"]):
        raise ValueError(f"{path} has no valid installed package version")
    if (
        not isinstance(opnsense, dict)
        or not isinstance(opnsense.get("version"), str)
        or not re.fullmatch(version_pattern, opnsense["version"])
    ):
        raise ValueError(f"{path} has no valid OPNsense version")

    if payload["tier"] == "browser-e2e":
        source = subject["source"]
        if source.get("dirty") is not False:
            raise ValueError(f"{path} was not produced from an explicitly clean source tree")
        package_sha = package.get("sha256")
        tested_sha = source.get("tested_package_sha256")
        if (
            not isinstance(package_sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", package_sha)
            or tested_sha != package_sha
        ):
            raise ValueError(f"{path} does not bind the installed package bytes")
        suite_sha = source.get("test_suite_sha256")
        if suite_sha != e2e_suite_digest(revision):
            raise ValueError(f"{path} does not match its revision's browser audit harness")


def load_external_evidence(paths, catalog):
    known_tiers = set(catalog["evidence_tiers"]) - {"host-independent"}
    evidence = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != EVIDENCE_SCHEMA:
            raise ValueError(f"{path} has an unsupported audit evidence schema")
        tier = payload.get("tier")
        if tier not in known_tiers:
            raise ValueError(f"{path} uses unknown audit evidence tier {tier!r}")
        execution = payload.get("execution")
        if not isinstance(execution, dict) or execution.get("status") != "passed":
            raise ValueError(f"{path} does not contain a completed passing execution")
        capabilities = payload.get("capabilities")
        if not isinstance(capabilities, list):
            raise ValueError(f"{path} has no capability list")
        passed = {
            item.get("id") for item in capabilities
            if isinstance(item, dict) and item.get("status") == "passed" and isinstance(item.get("id"), str)
        }
        unknown = passed - set(catalog["evidence_tiers"][tier]["capabilities"])
        if unknown:
            raise ValueError(f"{path} reports unknown {tier} capabilities: {sorted(unknown)}")
        subject = payload.get("subject")
        source = subject.get("source") if isinstance(subject, dict) else None
        if not isinstance(source, dict):
            raise ValueError(f"{path} has no source identity")
        revision = source.get("revision")
        dirty = source.get("dirty", False) or (isinstance(revision, str) and revision.endswith(".dirty"))
        if dirty or not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", revision):
            raise ValueError(f"{path} is not bound to a clean source revision")
        if run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            raise ValueError(f"{path} references a source revision absent from this repository")
        if run(
            ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            raise ValueError(f"{path} does not describe an ancestor of the current source")
        evidence_subject(payload, path, revision)
        evidence.append({
            "tier": tier,
            "capabilities": passed,
            "label": external_label(payload),
            "path": path,
            "revision": revision,
            "payload": payload,
        })
    return evidence


def external_label(payload):
    subject = payload.get("subject", {})
    tier = payload.get("tier")
    revision = subject.get("source", {}).get("revision", "")[:12]
    parts = ["installed OPNsense integration" if tier == "installed-integration" else "browser E2E"]
    opnsense = subject.get("opnsense", {}).get("version")
    package = subject.get("package", {}).get("version")
    if opnsense:
        parts.append(f"OPNsense {opnsense}")
    if package:
        parts.append(f"package {package}")
    if revision:
        parts.append(f"source {revision}")
    return ", ".join(parts)


def artifact_applies(evidence, control, requirement):
    if evidence["tier"] != requirement["tier"]:
        return False
    if not set(requirement["capabilities"]).issubset(evidence["capabilities"]):
        return False
    if evidence["tier"] == "host-independent":
        return True
    relevant = list(dict.fromkeys(control["implementation"] + requirement["validation"]))
    for path in relevant:
        if run(
            ["git", "cat-file", "-e", f"{evidence['revision']}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            return False
    changed = run(
        ["git", "diff", "--quiet", evidence["revision"], "--", *relevant],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode
    return changed == 0


def validated_controls(catalog, evidence):
    result = []
    for section_item in catalog["sections"]:
        controls = []
        for control in section_item["controls"]:
            matched = []
            for requirement in control["evidence"]["all_of"]:
                candidate = next(
                    (item for item in evidence if artifact_applies(item, control, requirement)),
                    None,
                )
                if candidate is None:
                    break
                matched.append((requirement, candidate))
            else:
                controls.append((control, matched))
        if controls:
            result.append((section_item, controls))
    return result


def link(path):
    return f"[{path}](../../{path})"


def source_fragment(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    fragment = "\n".join(
        line for line in lines
        if not line.startswith("<!-- Source fragment")
        and not line.startswith("<!-- Generated by tests/update-capability")
        and not line.startswith("Copyright (C)")
    ).strip()
    return re.sub(r"\n{3,}", "\n\n", fragment)


def report(catalog, controls, evidence, capability_report=CAPABILITY_REPORT):
    lines = [
        "<!-- Generated by tests/update-security-report.py; do not edit this file manually. -->",
        "# Security and conformance",
        "",
        "Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see LICENSE at the repository root.",
        "",
        "This is the single publication point for supported standards, provider interoperability,",
        "security comparison, threat controls and validation evidence. Standards conformance and",
        "provider compatibility remain separate claims; neither documentation nor an ordinary",
        "regression test becomes a green conformance statement by implication.",
        "",
        source_fragment(capability_report),
        "",
        source_fragment(SECURITY_MODEL),
        "",
        "## Evidence-backed implementation controls",
        "",
        "A property appears below only when every evidence tier required by",
        "`tests/audit-controls.json` succeeds. This is a positive validation statement, not a",
        "backlog, certification, independent penetration test or substitute for the stricter",
        "requirement-level conformance gate above.",
        "",
        "### Evidence model",
        "",
        "```mermaid",
        "flowchart LR",
        "    Source[\"Implementation\"] --> Host[\"Current regression suite\"]",
        "    Runtime[\"Revision-bound OPNsense evidence\"] --> Gate{\"All required evidence present?\"}",
        "    Browser[\"Revision-bound browser and ZAP evidence\"] --> Gate",
        "    Host --> Gate",
        "    Gate -->|Yes| Report[\"Published validation statement\"]",
        "    Gate -->|No| Omit[\"Statement omitted\"]",
        "    classDef verified fill:#E8F7EE,stroke:#197343,color:#103D26;",
        "    classDef boundary fill:#FFF4D6,stroke:#A66A00,color:#4A3200;",
        "    class Report verified;",
        "    class Gate,Omit boundary;",
        "```",
        "",
        "The host-independent suite is executed for every regeneration. External evidence",
        "is accepted only when it reports a complete passing execution from a clean source",
        "revision and none of the control's implementation or validation files changed",
        "after that revision.",
        "",
        "Evidence contributing to this report:",
        "",
        "- current host-independent regression suite",
    ]
    external = [item for item in evidence if item["tier"] != "host-independent"]
    for item in external:
        lines.append(f"- {item['label']} (`{item['path'].name}`)")

    for section_item, section_controls in controls:
        lines.extend([
            "",
            f"### {section_item['title']}",
            "",
            "| Validated security property | Implementation | Validation evidence |",
            "|---|---|---|",
        ])
        for control, matched in section_controls:
            implementation = "<br/>".join(link(path) for path in control["implementation"])
            validations = []
            for requirement, item in matched:
                references = ", ".join(link(path) for path in requirement["validation"])
                validations.append(f"{item['label']}: {references}")
            lines.append(
                f"| {control['claim']} | {implementation} | {'<br/>'.join(validations)} |"
            )

    lines.extend([
        "",
        "## Interpretation boundary",
        "",
        "The absence of a statement is not represented as a finding. It means only that",
        "the complete evidence required for that statement was not supplied to this",
        "generation. Trust boundaries and component ownership remain documented separately",
        "in [architecture.md](architecture.md).",
        "",
        "## Reproduction",
        "",
        "    python3 tests/update-security-report.py --check",
        "    python3 tests/update-security-report.py --update",
        "",
        "Retained sanitized evidence may be placed under `tests/evidence/*.json` or supplied",
        "with repeated `--evidence /absolute/path.json` options. CI uses `--check`, so a",
        "changed implementation, validation rule or evidence set cannot leave this report",
        "silently stale.",
        "",
    ])
    return "\n".join(lines)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--update", action="store_true", help="replace the generated report")
    mode.add_argument("--check", action="store_true", help="fail when the generated report is stale")
    parser.add_argument("--evidence", action="append", default=[], help="additional evidence JSON")
    parser.add_argument("--quiet", action="store_true", help="do not repeat the host test output")
    return parser.parse_args()


def main():
    args = arguments()
    suite_command = [str(ROOT / "tests" / "run.sh")]
    temporary = None
    capability_report = CAPABILITY_REPORT
    if args.update:
        temporary = tempfile.TemporaryDirectory(prefix="openid-connect-report-")
        capability_report = pathlib.Path(temporary.name) / "provider-capabilities.md"
        suite_command.extend(["--render-capability-matrix", str(capability_report)])
    suite = run(
        suite_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if not args.quiet:
        sys.stdout.write(suite.stdout)
    if suite.returncode != 0:
        if temporary:
            temporary.cleanup()
        print("host-independent suite failed; generated reports were not changed", file=sys.stderr)
        return suite.returncode

    try:
        catalog = load_catalog()
        evidence = [host_evidence(suite.stdout)]
        evidence.extend(load_external_evidence(evidence_paths(args.evidence), catalog))
        generated = report(catalog, validated_controls(catalog, evidence), evidence, capability_report)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        if temporary:
            temporary.cleanup()
        print(f"report generation failed; generated reports were not changed: {error}", file=sys.stderr)
        return 1

    current = REPORT.read_text(encoding="utf-8") if REPORT.exists() else ""
    stale = current != generated
    if args.update:
        capability_rendered = capability_report.read_text(encoding="utf-8")
        capability_current = CAPABILITY_REPORT.read_text(encoding="utf-8") if CAPABILITY_REPORT.exists() else ""
        if capability_current != capability_rendered:
            CAPABILITY_REPORT.write_text(capability_rendered, encoding="utf-8")
            print(f"updated {CAPABILITY_REPORT.relative_to(ROOT)}")
        else:
            print(f"already current: {CAPABILITY_REPORT.relative_to(ROOT)}")
        if stale:
            REPORT.write_text(generated, encoding="utf-8")
            print(f"updated {REPORT.relative_to(ROOT)}")
        else:
            print(f"already current: {REPORT.relative_to(ROOT)}")
    elif stale:
        print(
            "security and conformance report is stale; run python3 tests/update-security-report.py --update",
            file=sys.stderr,
        )
    if temporary:
        temporary.cleanup()
    return 1 if args.check and stale else 0


if __name__ == "__main__":
    sys.exit(main())
