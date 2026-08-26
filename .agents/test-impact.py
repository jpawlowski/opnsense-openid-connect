#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Explain the minimum manual validation implied by a Git change without running it."""

import argparse
import json
import os
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = pathlib.Path(__file__).with_name("test-impact-rules.json")
ORDER = {"fast-gate": 0, "build-check": 1, "installed-integration": 2, "provider-e2e": 3, "live-provider": 4}
SAAS_PROVIDERS = {
    "entra": ("entra", "entra-id"),
    "okta": ("okta",),
    "apple": ("apple",),
}


def git(*arguments):
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments], check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout


def has_ref(reference):
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet", reference],
        capture_output=True, text=True, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )
    return result.returncode == 0


def canonical_base():
    remotes = set(git("remote").split())
    candidates = []
    if "upstream" in remotes:
        candidates.append("upstream/main")
    if "origin" in remotes:
        candidates.append("origin/main")
    candidates.append("main")
    for candidate in candidates:
        if has_ref(candidate):
            return candidate
    # An isolated snapshot may deliberately have neither a remote nor a local
    # main branch. Comparing with Git's empty tree deliberately over-selects
    # validation, including for a one-commit snapshot, rather than hiding the
    # root commit behind an invented or unavailable base.
    empty_tree = git("hash-object", "-t", "tree", "/dev/null").strip()
    if not empty_tree:
        raise RuntimeError("cannot determine a Git base for this isolated checkout")
    print("No canonical main ref is available; comparing the isolated snapshot with Git's empty tree.", file=sys.stderr)
    return empty_tree


def changed(base):
    paths = [line for line in git("diff", "--name-only", base).splitlines() if line]
    untracked = [line for line in git("ls-files", "--others", "--exclude-standard").splitlines() if line]
    paths = list(dict.fromkeys(paths + untracked))
    patch = git("diff", "--unified=0", base, "--", *paths) if paths else ""
    for relative in untracked:
        try:
            patch += "\n" + (ROOT / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            pass
    return paths, patch.lower()


def matches(rule, paths, patch):
    path_match = any(any(path == prefix or path.startswith(prefix) for prefix in rule["paths"]) for path in paths)
    content_match = not rule["content"] or any(token.lower() in patch for token in rule["content"])
    return path_match and content_match


def analyze(paths, patch, rules):
    recommendations = [{
        "rule": "baseline", "tier": "fast-gate",
        "reason": "Every change must pass the host-independent gate.",
    }]
    for rule in rules["rules"]:
        if matches(rule, paths, patch):
            validation = rule["validation"]
            providers = [validation.get("provider")]
            if providers == ["affected"]:
                providers = [
                    provider for provider, tokens in SAAS_PROVIDERS.items()
                    if any(any(token in path.lower() for token in tokens) for path in paths)
                    or any(token in patch for token in tokens)
                ]
                providers = providers or sorted(SAAS_PROVIDERS)
            for provider in providers:
                recommendation = {"rule": rule["id"], **validation, "reason": rule["reason"]}
                if provider is None:
                    recommendation.pop("provider", None)
                else:
                    recommendation["provider"] = provider
                recommendations.append(recommendation)
    unique = []
    seen = set()
    for item in recommendations:
        identity = tuple((key, item.get(key)) for key in ("tier", "provider", "source", "cluster"))
        if identity not in seen:
            unique.append(item)
            seen.add(identity)
    unique.sort(key=lambda item: ORDER[item["tier"]])
    return unique


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    arguments = parser.parse_args()
    base = arguments.base or canonical_base()
    paths, patch = changed(base)
    rules = json.loads(RULES.read_text(encoding="utf-8"))
    recommendations = analyze(paths, patch, rules)
    payload = {"schema_version": 1, "base": base, "changed_paths": paths, "recommendations": recommendations}
    if arguments.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"Validation impact against {base}:")
    for item in recommendations:
        selection = "/".join(item[key] for key in ("provider", "source", "cluster") if key in item)
        print(f"- {item['tier']}{f' ({selection})' if selection else ''}: {item['reason']}")


if __name__ == "__main__":
    main()
