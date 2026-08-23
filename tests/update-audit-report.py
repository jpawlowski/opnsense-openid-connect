#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Generate the implementation audit report from the canonical test suite."""

import argparse
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT = ROOT / "docs" / "reference" / "audit-report.md"
STAGES = (
    ("syntax", "Syntax", "== syntax =="),
    ("behaviour", "Behaviour", "== behaviour =="),
    ("convention", "Commit/release convention", "== what a commit message may be =="),
    ("package", "Package/archive/supply chain", "== the package that gets built =="),
)

# This is the audit policy, not generated prose. Renaming or removing a test
# group makes the corresponding control visibly unverified until this mapping
# is reviewed alongside the changed test.
CONTROLS = (
    ("A-01", "high", "Stable issuer/subject identity binding", (
        "Stable issuer and subject bindings",
    ), ""),
    ("A-02", "high", "Local account admission and refusal policy", (
        "An account that may not be used",
        "Administrator approval admission policy",
    ), ""),
    ("A-03", "high", "Mix-up, callback-origin and local redirect protection", (
        "Login transactions, PKCE and mix-up protection",
        "Choosing the address the provider returns to",
        "local WebGUI authorization",
    ), ""),
    ("A-04", "high", "JWT issuer, signature, audience and claim policy", (
        "ID token claim validation",
        "Whom a token was issued for",
    ), "real phpseclib execution requires the installed integration tier"),
    ("A-05", "high", "Provider group claims cannot silently widen privilege", (
        "Group membership is left alone unless asked for",
        "What the provider offers",
        "Default groups belong to the login that creates the account",
    ), "real core group synchronization requires the installed integration tier"),
    ("A-06", "high", "Session elevation rotates and removes the old session ID", (),
     "requires the disposable browser E2E tier"),
    ("A-07", "high", "Stored logout grants remain bound to the exact issuer", (
        "Strict endpoint responses and logout binding",
    ), ""),
    ("A-08", "high", "Provider HTTP is HTTPS-only, bounded and credential-safe", (
        "Bounded HTTPS transport",
    ), ""),
    ("A-09", "medium", "Form POST state is bounded and single-use", (
        "Login transactions, PKCE and mix-up protection",
    ), "file mode, expiry and browser SameSite behavior require installed and E2E tiers"),
    ("A-10", "medium", "Federated logout is authenticated and replay-resistant", (
        "Back-channel logout token claims",
        "Strict endpoint responses and logout binding",
    ), "actual front/back-channel session invalidation requires the E2E tier"),
    ("A-11", "medium", "Login icons and provider presentation remain safe and correct", (
        "Where the login button gets its icon",
        "What the login page is handed",
    ), "real core login-page rendering requires the E2E tier"),
    ("A-12", "medium", "Discovery, provider presets and no-secret onboarding are complete", (
        "Strict provider discovery",
        "Provider setup files from an unfinished form",
        "Defaults when a field is left empty",
        "What the settings form refuses",
    ), "real provider imports and login compatibility remain provider-specific evidence"),
    ("A-13", "medium", "Package provenance, archive integrity and release convention", (
        "Stage: Commit/release convention",
        "Stage: Package/archive/supply chain",
    ), "actual Sigstore and immutable-release issuance requires a tagged GitHub release"),
    ("A-14", "low", "Public failures are generic and sensitive detail stays in logs", (),
     "requires installed controller and browser E2E evidence"),
    ("A-15", "medium", "Direct plugin responses carry endpoint-specific browser headers", (),
     "requires the disposable browser E2E and passive ZAP tiers"),
)


def section(output, heading):
    start = output.find(heading)
    if start < 0:
        return None
    following = [output.find(other, start + len(heading)) for _, _, other in STAGES]
    following = [position for position in following if position >= 0]
    return output[start:min(following) if following else len(output)]


def stage_results(output):
    parsed = {}
    for key, label, heading in STAGES:
        body = section(output, heading)
        if body is None:
            parsed[key] = {"label": label, "status": "not run", "passed": None, "failed": None}
            continue
        if key == "syntax":
            status = "passed" if "all files parse" in body else "failed"
            parsed[key] = {"label": label, "status": status, "passed": None, "failed": None}
            continue
        summary = re.search(r"(?m)^(\d+) checks passed(?:, none failed\.|, (\d+) FAILED:)", body)
        if summary is None:
            parsed[key] = {"label": label, "status": "failed", "passed": None, "failed": None}
            continue
        passed = int(summary.group(1))
        failed = int(summary.group(2) or 0)
        parsed[key] = {
            "label": label,
            "status": "failed" if failed else "passed",
            "passed": passed,
            "failed": failed,
        }
    return parsed


def check_results(output):
    groups = {}
    failures = []
    for _, stage_label, heading in STAGES:
        body = section(output, heading)
        if body is None:
            continue
        current = None
        for line in body.splitlines()[1:]:
            if re.match(r"^\d+ checks passed", line):
                current = None
            elif line.startswith("  ok    "):
                if current:
                    groups.setdefault(current, {"passed": 0, "failed": 0})["passed"] += 1
            elif line.startswith("  FAIL  "):
                name = line.removeprefix("  FAIL  ").strip()
                if current:
                    groups.setdefault(current, {"passed": 0, "failed": 0})["failed"] += 1
                    failures.append(f"{stage_label} / {current} / {name}")
                else:
                    failures.append(f"{stage_label} / {name}")
            elif line and not line.startswith(" ") and not line.startswith("=="):
                current = line.strip()
    return groups, failures


def status_evidence(stage, groups):
    evidence = {
        name: "failed" if counts["failed"] else "passed"
        for name, counts in groups.items()
    }
    evidence.update({f"Stage: {item['label']}": item["status"] for item in stage.values()})
    return evidence


def control_result(requirements, boundary, evidence):
    if not requirements:
        return "not exercised"
    states = [evidence.get(requirement, "not run") for requirement in requirements]
    if "failed" in states:
        return "failed"
    if any(state != "passed" for state in states):
        return "not run"
    return "partial" if boundary else "passed"


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def report(stage, groups, failures, returncode):
    complete = returncode == 0 and all(item["status"] == "passed" for item in stage.values())
    overall = "PASSED" if complete else "FAILED"
    evidence = status_evidence(stage, groups)
    lines = [
        "<!-- Generated by tests/update-audit-report.py; do not edit this file manually. -->",
        "# Automated implementation audit",
        "",
        "This report is regenerated from the current working tree by",
        "`python3 tests/update-audit-report.py --update`. Its assertions are limited",
        "to evidence produced by the repository test tiers; it is not OpenID",
        "certification, an independent code audit or a penetration test.",
        "",
        "## Result",
        "",
        f"Overall host-independent result: **{overall}**.",
        "",
        "```mermaid",
        "flowchart LR",
        "    Source[\"Current source tree\"] --> Host[\"Host-independent suite<br/>" + overall + "\"]",
        "    Host --> Report[\"Generated audit report\"]",
        "    Installed[\"Installed OPNsense integration<br/>not run\"] -.-> Report",
        "    Browser[\"Browser E2E and passive ZAP<br/>not run\"] -.-> Report",
        "    classDef passed fill:#E8F7EE,stroke:#197343,color:#103D26;",
        "    classDef failed fill:#FBEAEA,stroke:#9C2F2F,color:#4A1717;",
        "    classDef pending fill:#FFF4D6,stroke:#A66A00,color:#4A3200;",
        "    class Host " + ("passed" if complete else "failed") + ";",
        "    class Installed,Browser pending;",
        "```",
        "",
        "## Test-stage evidence",
        "",
        "| Stage | Result | Evidence |",
        "|---|---:|---|",
    ]
    for item in stage.values():
        if item["passed"] is None:
            detail = "all files parse" if item["status"] == "passed" else "no completed summary"
        elif item["failed"]:
            detail = f"{item['passed']} passed; {item['failed']} failed"
        else:
            detail = f"{item['passed']} checks passed"
        lines.append(f"| {item['label']} | **{item['status']}** | {detail} |")

    lines.extend(["", "## Current findings", ""])
    if failures:
        lines.append("The current suite reports these unsatisfied checks:")
        lines.append("")
        lines.extend(f"- `{cell(failure)}`" for failure in failures)
    else:
        lines.append("No host-independent check currently fails.")

    lines.extend([
        "",
        "## Security and implementation control matrix",
        "",
        "| Result | Meaning |",
        "|---|---|",
        "| passed | every mapped host-independent check passed |",
        "| failed | at least one mapped check failed |",
        "| partial | mapped host checks passed, but a named runtime boundary was not exercised |",
        "| not run | fail-fast stopped before mapped evidence was produced |",
        "| not exercised | the control belongs entirely to an explicit external test tier |",
        "",
        "| ID | Severity | Control objective | Result | Evidence boundary |",
        "|---|---:|---|---:|---|",
    ])
    for identifier, severity, objective, requirements, boundary in CONTROLS:
        result = control_result(requirements, boundary, evidence)
        source = "; ".join(requirements)
        if boundary:
            source = f"{source}; {boundary}" if source else boundary
        lines.append(
            f"| {identifier} | {severity} | {cell(objective)} | **{result}** | {cell(source)} |"
        )

    lines.extend([
        "",
        "## Executed check groups",
        "",
        "| Test group | Passed | Failed |",
        "|---|---:|---:|",
    ])
    if groups:
        for name, counts in groups.items():
            lines.append(f"| {cell(name)} | {counts['passed']} | {counts['failed']} |")
    else:
        lines.append("| No behavior group completed | 0 | 0 |")

    lines.extend([
        "",
        "## Evidence not collected by this run",
        "",
        "The following remain explicit evidence gaps, not implied passes:",
        "",
        "- installed OPNsense integration (`php tests/integration/opnsense.php`),",
        "  including the real phpseclib, session storage, dispatcher and core ACL behavior;",
        "- destructive Keycloak/browser E2E and its local passive ZAP header scan",
        "  (`tests/e2e/run.sh`);",
        "- a complete authentik authorization-code login and logout run;",
        "- installation and login-page smoke testing on every declared OPNsense target line;",
        "- narrow-viewport visual review;",
        "- an external OIDC conformance suite and independent security assessment.",
        "",
        "Historical manual runs are deliberately not copied into this generated report:",
        "without a machine-readable artifact tied to the current source tree they cannot",
        "establish current evidence.",
        "",
        "## Scope and residual-risk references",
        "",
        "The implemented protocol profile, unsupported optional features, threat model,",
        "browser-header ownership and accepted residual risks are maintained in",
        "[security.md](security.md). Component ownership, state, trust boundaries and",
        "browser outcomes are maintained in [architecture.md](architecture.md). The",
        "declared product scope and supported OPNsense target lines remain in the",
        "[project README](../../README.md).",
        "",
        "## Reproduction",
        "",
        "    python3 tests/update-audit-report.py --check",
        "    python3 tests/update-audit-report.py --update",
        "",
        "`--check` runs the canonical suite and fails if this file differs from the",
        "result it would generate. `--update` replaces the complete report, including",
        "a failed result, and returns the suite's non-zero status when checks fail.",
        "",
    ])
    return "\n".join(lines)


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--update", action="store_true", help="replace the complete audit report")
    mode.add_argument("--check", action="store_true", help="fail when the generated report is stale")
    parser.add_argument("--quiet", action="store_true", help="do not repeat the underlying test output")
    return parser.parse_args()


def main():
    args = arguments()
    run = subprocess.run(
        [str(ROOT / "tests" / "run.sh")], cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, check=False,
    )
    if not args.quiet:
        sys.stdout.write(run.stdout)
    stage = stage_results(run.stdout)
    groups, failures = check_results(run.stdout)
    generated = report(stage, groups, failures, run.returncode)
    current = REPORT.read_text(encoding="utf-8") if REPORT.exists() else ""
    stale = current != generated

    if args.update:
        if stale:
            REPORT.write_text(generated, encoding="utf-8")
            print(f"updated {REPORT.relative_to(ROOT)}")
        else:
            print(f"already current: {REPORT.relative_to(ROOT)}")
    elif stale:
        print(
            "audit report is stale; run python3 tests/update-audit-report.py --update",
            file=sys.stderr,
        )

    if run.returncode != 0:
        print("host-independent suite failed; the generated report records that result", file=sys.stderr)
    return 1 if run.returncode != 0 or (args.check and stale) else 0


if __name__ == "__main__":
    sys.exit(main())
