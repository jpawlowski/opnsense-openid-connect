#!/usr/bin/env python3

"""Host-independent consistency checks for the manual E2E harness."""

import hashlib
import json
import pathlib
import re
import subprocess


HERE = pathlib.Path(__file__).resolve().parent
EXPECTED_PROVIDERS = {"keycloak", "authentik", "authelia", "pocketid"}
EXPECTED_SUPPORT = {"nginx", "postgres"}
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def check(condition, message):
    if not condition:
        raise SystemExit(message)


images = json.loads((HERE / "providers" / "images.json").read_text(encoding="utf-8"))
check(images.get("schema") == 1, "provider image manifest schema changed")
check(set(images.get("providers", {})) == EXPECTED_PROVIDERS, "provider matrix and manifest differ")
check(set(images.get("support", {})) == EXPECTED_SUPPORT, "support image manifest changed unexpectedly")
for category in ("providers", "support"):
    for name, metadata in images[category].items():
        check(DIGEST.fullmatch(metadata.get("digest", "")), f"{name} does not have a reviewed image digest")
        check(metadata.get("tag") and metadata.get("tag") != "latest", f"{name} uses an unstable image tag")
        reference = subprocess.run(
            [str(HERE / "providers" / "image.py"), name], check=True, capture_output=True, text=True,
        ).stdout.strip()
        check(reference == f"{metadata['image']}@{metadata['digest']}", f"bad image reference for {name}")

trust = json.loads((HERE / "vm" / "trust.json").read_text(encoding="utf-8"))
check(trust.get("schema") == 1, "VM trust manifest schema changed")
check(re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", trust.get("release", "")), "invalid OPNsense release")
check(re.fullmatch(r"[a-f0-9]{64}", trust.get("compressed_sha256", "")), "invalid image checksum anchor")
pem = trust.get("public_key_pem", "").encode()
check(hashlib.sha256(pem).hexdigest() == trust.get("public_key_sha256"), "embedded public key hash differs")

matrix = (HERE / "run.sh").read_text(encoding="utf-8")
for provider in EXPECTED_PROVIDERS:
    check(provider in matrix, f"{provider} is absent from the E2E runner")
for path in [
    HERE / "run.sh", HERE / "run-keycloak.sh", HERE / "run-provider.sh", HERE / "local.sh",
    HERE / "vm.py", HERE / "vm" / "bootstrap.exp", HERE / "providers" / "image.py",
    HERE / "providers" / "stack.py",
]:
    check(path.stat().st_mode & 0o111, f"{path.relative_to(HERE)} is not executable")

print("E2E manifests and entry points agree")
