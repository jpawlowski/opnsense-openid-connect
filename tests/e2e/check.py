#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Host-independent consistency checks for the manual E2E harness."""

import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
EXPECTED_PROVIDERS = {"keycloak", "authentik", "authelia", "pocketid", "entra"}
EXPECTED_SUPPORT = {"nginx", "postgres", "node", "cloudflared"}
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

matrix = (HERE / "run.sh").read_text(encoding="utf-8") + (HERE / "selection.py").read_text(encoding="utf-8")
for provider in EXPECTED_PROVIDERS | {"okta", "apple"}:
    check(provider in matrix, f"{provider} is absent from the E2E runner")
for path in [
    HERE / "run.sh", HERE / "run-keycloak.sh", HERE / "run-provider.sh", HERE / "local.sh",
    HERE / "run-live.sh", HERE / "selection.py", HERE / "public-inbound.py", HERE / "provider-result.py",
    HERE / "public-inbound-canary.py", HERE / "public-inbound-target.py", HERE / "live-config.py",
    HERE / "vm.py", HERE / "vm" / "bootstrap.exp", HERE / "providers" / "image.py",
    HERE / "providers" / "stack.py",
]:
    check(path.stat().st_mode & 0o111, f"{path.relative_to(HERE)} is not executable")


def module(name, relative):
    specification = importlib.util.spec_from_file_location(name, HERE / relative)
    loaded = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(loaded)
    return loaded


selection = module("e2e_selection", "selection.py")
for suite in selection.SUITES:
    for provider in [None, *sorted(selection.PROVIDERS)]:
        for source in sorted(selection.SOURCES):
            for cluster in sorted(selection.CLUSTERS):
                explicit_source = selection.AUTO_SOURCE.get(provider) if source == "auto" and provider else source
                if provider is None:
                    has_direct = source != "live" and any(
                        (selection.AUTO_SOURCE[item] if source == "auto" else source)
                        in selection.PROVIDERS[item]["sources"]
                        for item in selection.SUITES[suite]
                    )
                    has_public = source != "live" and any(
                        (selection.AUTO_SOURCE[item] if source == "auto" else source)
                        in selection.PROVIDERS[item]["public_inbound"]
                        for item in selection.SUITES[suite]
                    )
                    expected_valid = source != "live" and (
                        has_direct if cluster == "direct" else has_public if cluster == "public-inbound"
                        else has_direct or has_public
                    )
                else:
                    source_valid = explicit_source in selection.PROVIDERS[provider]["sources"]
                    public_valid = explicit_source in selection.PROVIDERS[provider]["public_inbound"]
                    expected_valid = source_valid and (cluster == "direct" or public_valid)
                try:
                    candidate = selection.resolve(suite, provider, source, cluster)
                except selection.SelectionError:
                    check(not expected_valid, f"valid selection was refused: {suite}/{provider}/{source}/{cluster}")
                else:
                    check(expected_valid and candidate["records"],
                          f"invalid selection was accepted: {suite}/{provider}/{source}/{cluster}")
resolved = selection.resolve("full", cluster="all")
check(resolved["records"][0] == {"provider": "keycloak", "source": "local", "cluster": "direct"},
      "all does not begin with the direct cluster")
first_public = next(index for index, item in enumerate(resolved["records"]) if item["cluster"] == "public-inbound")
check(all(item["cluster"] == "direct" for item in resolved["records"][:first_public]),
      "all opens public ingress before every direct provider completes")
check(resolved["records"][first_public:] == [
    {"provider": "keycloak", "source": "local", "cluster": "public-inbound"},
], "the automatic suite starts more than its one applicable tunnel")
for provider, expected in selection.AUTO_SOURCE.items():
    record = selection.resolve(provider=provider)["records"]
    check(record == [{"provider": provider, "source": expected, "cluster": "direct"}],
          f"{provider} auto source differs from policy")
for arguments in [
    {"provider": "keycloak", "source": "emulated"},
    {"provider": "entra", "source": "local"},
    {"provider": "apple", "source": "live", "cluster": "public-inbound"},
    {"source": "live"},
    {"provider": "unknown"},
    {"provider": "okta", "source": "live", "canary": True},
    {"provider": "okta", "source": "emulated", "canary": True},
    {"provider": "apple", "source": "emulated", "canary": True},
]:
    try:
        selection.resolve(**arguments)
    except selection.SelectionError:
        pass
    else:
        raise SystemExit(f"invalid selection was accepted: {arguments}")

public_inbound = module("public_inbound", "public-inbound.py")
proxy = public_inbound.proxy_config("https://opnsense.test:443", "opnsense.test", "e2e-deadbeef")
check(proxy.count("limit_except POST") == 2, "public proxy does not constrain both receiver routes to POST")
check("access_log off" in proxy and "client_max_body_size 128k" in proxy,
      "public proxy logging or body bounds changed")
check("location / { return 404; }" in proxy and proxy.count("location = ") == 2,
      "public proxy is not deny-by-default with two exact routes")
check("proxy_set_header Authorization \"\"" in proxy,
      "back-channel proxy forwards an unnecessary caller Authorization header")
check(public_inbound.SAFE_APPLICATION.fullmatch("stable-lab-code"),
      "public ingress rejects a bounded stable live application code")
check(not public_inbound.SAFE_APPLICATION.fullmatch("unsafe/application"),
      "public ingress accepts an application code that escapes its path segment")

canary_suite = selection.resolve("full", canary=True)
check(not any(item["provider"] in {"okta", "apple"} for item in canary_suite["records"]),
      "the full canary suite still runs npm-emulated providers")
check(len([message for message in canary_suite["skipped"] if "npm emulator" in message]) == 2,
      "the full canary suite does not explain both npm-emulator skips")

live = module("live_config", "live-config.py")
with tempfile.TemporaryDirectory() as temporary:
    config = pathlib.Path(temporary) / "live.json"
    profile = {
        "schema": live.SCHEMA,
        "profiles": {
            "okta": {
                "issuer": "https://example.okta.test/oauth2/default",
                "client_id": "fixture-client",
                "client_secret": "fixture-secret",
                "provider_revision": "service:2026-08-25",
                "application_code": "e2e-fixture",
                "webgui_port": 48443,
            },
        },
    }
    config.write_text(json.dumps(profile), encoding="utf-8")
    config.chmod(0o600)
    loaded = live.load_config(config, "okta")
    check(loaded["interaction"] == "manual", "live profiles do not default to manual takeover")
    driver = pathlib.Path(temporary) / "driver"
    driver.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    driver.chmod(0o700)
    profile["profiles"]["okta"]["public_inbound"] = {
        "capabilities": ["shared_signals"], "driver": str(driver),
        "ssf_issuer": "https://example.okta.test/ssf/default",
        "ssf_audience": "fixture-audience", "ssf_push_secret": "fixture-push-secret",
    }
    config.write_text(json.dumps(profile), encoding="utf-8")
    loaded = live.load_config(config, "okta")
    check(loaded["public_inbound"]["driver"] == str(driver), "owner-only public driver was refused")
    driver.chmod(0o755)
    try:
        live.load_config(config, "okta")
    except ValueError:
        pass
    else:
        raise SystemExit("live config accepted a group/world-accessible provider driver")
    driver.chmod(0o700)
    config.chmod(0o644)
    try:
        live.load_config(config, "okta")
    except ValueError:
        pass
    else:
        raise SystemExit("live config accepted group/world-readable secrets")
    config.chmod(0o600)
    profile["profiles"]["okta"]["issuer"] = ["https://not-a-string.example"]
    config.write_text(json.dumps(profile), encoding="utf-8")
    try:
        live.load_config(config, "okta")
    except ValueError:
        pass
    else:
        raise SystemExit("live config accepted a non-string issuer")
    profile["profiles"]["okta"]["issuer"] = "https://example.okta.test/oauth2/default"
    profile["profiles"]["okta"]["access_token"] = "must-not-be-accepted"
    config.write_text(json.dumps(profile), encoding="utf-8")
    try:
        live.load_config(config, "okta")
    except ValueError:
        pass
    else:
        raise SystemExit("live config accepted an unknown sensitive field")

lock = json.loads((HERE / "package-lock.json").read_text(encoding="utf-8"))
check(lock["packages"][""]["devDependencies"].get("emulate") == "0.10.0", "emulate is not exactly pinned")
check(lock["packages"].get("node_modules/emulate", {}).get("version") == "0.10.0", "emulate lock differs")

generator = module("provider_result", "provider-result.py")
import_spec = importlib.util.spec_from_file_location("provider_import", HERE.parent / "import-provider-result.py")
provider_import = importlib.util.module_from_spec(import_spec)
import_spec.loader.exec_module(provider_import)
revision = subprocess.run(
    ["git", "-C", str(HERE.parent.parent), "rev-parse", "HEAD"],
    check=True, capture_output=True, text=True,
).stdout.strip()
raw = {
    "schema_version": 1,
    "evidence_type": "provider_test_run",
    "repository_revision": revision,
    "repository_dirty": False,
    "harness_digest": generator.harness_digest(),
    "provider": "okta",
    "source": "emulated",
    "subject": {"name": "vercel-labs-emulate", "revision": "version:0.10.0"},
    "cluster": "direct",
    "tested_on": "2026-08-25",
    "configuration_profile": "okta",
    "provider_adaptation": None,
    "results": [{"feature": "login", "outcome": "pass"}],
}
with tempfile.TemporaryDirectory() as temporary:
    artifact = pathlib.Path(temporary) / "provider.json"
    artifact.write_text(json.dumps(raw), encoding="utf-8")
    check(provider_import.load_result(artifact)["provider"] == "okta", "valid sanitized provider result was refused")
    raw["client_secret"] = "must-not-be-retained"
    artifact.write_text(json.dumps(raw), encoding="utf-8")
    try:
        provider_import.load_result(artifact)
    except ValueError:
        pass
    else:
        raise SystemExit("provider evidence importer accepted a sensitive unknown field")
    del raw["client_secret"]
    raw["subject"]["revision"] = "version:unpinned"
    artifact.write_text(json.dumps(raw), encoding="utf-8")
    try:
        provider_import.load_result(artifact)
    except ValueError:
        pass
    else:
        raise SystemExit("provider evidence importer accepted an unreviewed emulator revision")
    raw["subject"]["revision"] = "version:0.10.0"
    raw["configuration_profile"] = "tenant-secret"
    artifact.write_text(json.dumps(raw), encoding="utf-8")
    try:
        provider_import.load_result(artifact)
    except ValueError:
        pass
    else:
        raise SystemExit("provider evidence importer accepted an unreviewed configuration profile")
    raw["configuration_profile"] = "okta"
    raw["results"] = [{"feature": "shared_signals", "outcome": "pass"}]
    artifact.write_text(json.dumps(raw), encoding="utf-8")
    try:
        provider_import.load_result(artifact)
    except ValueError:
        pass
    else:
        raise SystemExit("provider evidence importer accepted an unexercised direct capability")

with tempfile.TemporaryDirectory() as temporary:
    retained_root = pathlib.Path(temporary)
    retained_catalog = retained_root / "tests" / "providers" / "capabilities.json"
    retained_catalog.parent.mkdir(parents=True)
    retained_catalog.write_text(provider_import.CATALOG.read_text(encoding="utf-8"), encoding="utf-8")
    original_root, original_catalog, original_evidence = (
        provider_import.ROOT, provider_import.CATALOG, provider_import.EVIDENCE,
    )
    provider_import.ROOT = retained_root
    provider_import.CATALOG = retained_catalog
    provider_import.EVIDENCE = retained_root / "tests" / "evidence" / "providers"
    retained = {
        **raw,
        "provider": "keycloak", "source": "local", "cluster": "direct",
        "subject": {"name": "keycloak", "revision": "version:26.3.3"},
        "configuration_profile": "keycloak", "results": [{"feature": "login", "outcome": "pass"}],
    }
    try:
        provider_import.import_result(retained, ["login"])
        retained_provider = next(
            item for item in json.loads(retained_catalog.read_text(encoding="utf-8"))["providers"]
            if item["id"] == "keycloak"
        )
        retained_record = next(item for item in retained_provider["live_evidence"] if item["feature"] == "login")
        retained_artifact = json.loads((retained_root / retained_record["artifact"]).read_text(encoding="utf-8"))
        check(retained_record["source"] == "local" and retained_record["cluster"] == "direct",
              "retained provider evidence drops its source or cluster")
        check(retained_artifact["source"] == "local" and retained_artifact["cluster"] == "direct",
              "retained provider artifact drops its source or cluster")
    finally:
        provider_import.ROOT, provider_import.CATALOG, provider_import.EVIDENCE = (
            original_root, original_catalog, original_evidence,
        )

try:
    generator.result(
        "apple", "emulated", "direct", "vercel-labs-emulate", "version:0.10.0", "general",
        ["login=pass"], None,
    )
except ValueError:
    pass
else:
    raise SystemExit("provider result omitted Apple's required named adaptation")

live_runner = (HERE / "run-live.sh").read_text(encoding="utf-8")
for action in ("prepare", "register", "trigger"):
    check(f"invoke_driver {action}" in live_runner, f"live public driver omits its {action} lifecycle action")
check(live_runner.index('"$public_driver" cleanup') < live_runner.index('public-inbound.py" stop'),
      "live cleanup removes the tunnel before provider registration cleanup")
check(live_runner.index('E2E_PUBLIC_PHASE=prepare') < live_runner.index('invoke_driver trigger'),
      "live public inbound triggers before establishing a matching session")
check(live_runner.index('invoke_driver trigger') < live_runner.index('E2E_PUBLIC_PHASE=assert'),
      "live public inbound records no post-trigger session assertion")
check('if [ "$provider" != apple ]; then' in live_runner
      and 'direct_capabilities="--capability login=pass $direct_capabilities"' in live_runner,
      "the reusable Apple live run still claims a WebGUI login without administrator approval")

provider_spec = (HERE / "provider.spec.mjs").read_text(encoding="utf-8")
live_direct = provider_spec[provider_spec.rindex("if (state.source === 'live') {"):]
check(live_direct.index('await testProviderSignIn(adminPage)')
      < live_direct.index('await establishLiveSession(await liveSession.newPage())'),
      "live direct evidence does not establish a provider-backed WebGUI session")
check("if (state.provider !== 'apple')" in live_direct,
      "the live session assertion ignores Apple's explicit administrator-approval boundary")
check("await providerLogin(await emulatedSession.newPage())" in provider_spec,
      "emulated login evidence does not establish a provider-backed WebGUI session")
check("await queueAppleApproval" in provider_spec and "await approveAppleIdentity" in provider_spec,
      "the Apple emulator bypasses its administrator-approval admission boundary")
check("configured.or(page.getByRole('link', { name: 'Microsoft' }))" in provider_spec,
      "the Entra session flow cannot select its fixed Microsoft login label")

provider_config = (HERE / "provider.config.mjs").read_text(encoding="utf-8")
check("liveHandoffTimeout * liveHandoffs" in provider_config
      and "process.env.E2E_CLUSTER === 'direct' ? 2 : 1" in provider_config,
      "the live direct timeout does not budget both manual provider handoffs")

keycloak_runner = (HERE / "run-keycloak.sh").read_text(encoding="utf-8")
ssf_transmitter = (HERE / "ssf-transmitter.mjs").read_text(encoding="utf-8")
check(keycloak_runner.index('= public-inbound ]; then') < keycloak_runner.index('ssf-transmitter.mjs'),
      "the signed SSF transmitter is not confined to public-inbound")
check('shared_signals=pass' in keycloak_runner and "delivered.status === 202" in ssf_transmitter,
      "public Keycloak evidence is not bound to receiver acceptance")
check("process.env.E2E_SSF_SUBJECT" in ssf_transmitter and "id: $subject" in keycloak_runner,
      "the signed Shared Signal is not bound to the imported Keycloak subject")
check(keycloak_runner.index('E2E_SSF_SUBJECT=') < keycloak_runner.index('ssf-transmitter.mjs'),
      "the Shared Signals subject is not prepared before its transmitter starts")
check("signal: AbortSignal.timeout(20_000)" in ssf_transmitter,
      "the local SSF transmitter has no bounded public delivery")

print("E2E manifests, selections, secret boundaries and entry points agree")
