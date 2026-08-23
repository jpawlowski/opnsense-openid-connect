#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Resolve reviewed provider images, or a non-mutating latest-release canary."""

import argparse
import json
import pathlib
import re
import subprocess
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent
MANIFEST = ROOT / "images.json"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9]+$")


def manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def latest_tag(provider):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{provider['release_repository']}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "opnsense-oidc-e2e"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        tag = json.load(response).get("tag_name", "")
    if provider["release_tag"] == "strip-v":
        tag = tag.removeprefix("v")
    if not re.fullmatch(r"v?[0-9]+(?:\.[0-9]+){1,3}(?:[-.][a-z0-9.]+)?", tag, re.I):
        raise SystemExit(f"latest release returned an unsafe tag: {tag!r}")
    return tag


def digest_for(reference):
    result = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", reference, "--format", "{{json .Manifest.Digest}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    digest = json.loads(result.stdout)
    if not DIGEST.fullmatch(digest):
        raise SystemExit(f"Docker returned an unsafe digest: {digest!r}")
    return digest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("--canary", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    arguments = parser.parse_args()
    if not NAME.fullmatch(arguments.name):
        parser.error("provider names contain lower-case letters and digits only")

    data = manifest()
    provider = data["providers"].get(arguments.name) or data["support"].get(arguments.name)
    if provider is None:
        parser.error(f"unknown image {arguments.name!r}")
    if arguments.canary and "release_repository" in provider:
        tag = latest_tag(provider)
        digest = digest_for(f"{provider['image']}:{tag}")
    else:
        tag = provider["tag"]
        digest = provider["digest"]
        if not DIGEST.fullmatch(digest):
            raise SystemExit(f"reviewed manifest contains an unsafe digest for {arguments.name}")

    resolved = {**provider, "tag": tag, "digest": digest, "reference": f"{provider['image']}@{digest}"}
    print(json.dumps(resolved, sort_keys=True) if arguments.metadata else resolved["reference"])


if __name__ == "__main__":
    main()
