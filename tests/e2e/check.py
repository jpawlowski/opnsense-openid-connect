#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Host-independent consistency checks for the manual E2E harness."""

import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
import types


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
    HERE / "providers" / "stack.py", HERE / "publish-screenshots.py",
]:
    check(path.stat().st_mode & 0o111, f"{path.relative_to(HERE)} is not executable")

local_runner = (HERE / "local.sh").read_text(encoding="utf-8")
keycloak_runner = (HERE / "run-keycloak.sh").read_text(encoding="utf-8")
check("free_loopback_port" not in local_runner, "local E2E closes supposedly reserved ports before Docker binds")
for name in ("E2E_KEYCLOAK_PORT", "E2E_BACKCHANNEL_PORT", "E2E_SSF_PORT"):
    check(f"{name}=${{{name}:-0}}" in local_runner, f"local E2E does not request Docker allocation for {name}")
check(keycloak_runner.count(".NetworkSettings.Ports") == 3,
      "the Keycloak runner does not inspect all three Docker-allocated host ports")
check("/e2e/keycloak-origin" in keycloak_runner and "/e2e-state/ssf-issuer" in keycloak_runner,
      "a dynamic service can start before its Docker-allocated external URL is known")
check("trap '' HUP INT TERM" in keycloak_runner and "documentation_publication_status" in keycloak_runner,
      "the wrapper can report failure after the screenshot publisher has committed successfully")

with tempfile.TemporaryDirectory() as temporary:
    screenshot_directory = pathlib.Path(temporary) / "screenshots"
    screenshot_directory.mkdir()
    audit_evidence = pathlib.Path(temporary) / "audit.json"
    audit_evidence.write_text("keep existing evidence\n", encoding="utf-8")
    provider_evidence = pathlib.Path(temporary) / "provider.json"
    provider_evidence.write_text("keep existing provider evidence\n", encoding="utf-8")
    clean_environment = dict(os.environ)
    for name in (
        "E2E_AUDIT_EVIDENCE", "E2E_DOCUMENTATION_SCREENSHOTS", "E2E_PROVIDER_RESULT", "E2E_CLUSTER",
        "E2E_PROVIDER_HOST", "E2E_KEYCLOAK_URL", "E2E_PROVIDER_BROWSER_IP", "E2E_OPNSENSE_BROWSER_IP",
        "E2E_KEYCLOAK_PORT", "E2E_BACKCHANNEL_PORT", "E2E_SSF_PORT",
    ):
        clean_environment.pop(name, None)
    conflicting = subprocess.run(
        [str(HERE / "run-keycloak.sh")],
        env={
            **clean_environment,
            "E2E_AUDIT_EVIDENCE": str(audit_evidence),
            "E2E_DOCUMENTATION_SCREENSHOTS": str(screenshot_directory),
        },
        capture_output=True,
        text=True,
    )
    check(conflicting.returncode == 2 and "cannot be used together" in conflicting.stderr,
          "the Keycloak runner does not reject audit and screenshot output before setup")
    check(audit_evidence.read_text(encoding="utf-8") == "keep existing evidence\n",
          "a rejected screenshot run removes existing audit evidence")

    provider_conflict = subprocess.run(
        [str(HERE / "run-keycloak.sh")],
        env={
            **clean_environment,
            "E2E_DOCUMENTATION_SCREENSHOTS": str(screenshot_directory),
            "E2E_PROVIDER_RESULT": str(provider_evidence),
        },
        capture_output=True,
        text=True,
    )
    check(provider_conflict.returncode == 2 and "cannot be used together" in provider_conflict.stderr,
          "the Keycloak runner accepts provider evidence in focused screenshot mode")
    check(provider_evidence.read_text(encoding="utf-8") == "keep existing provider evidence\n",
          "a rejected screenshot run removes existing provider evidence")

    wrong_cluster = subprocess.run(
        [str(HERE / "run-keycloak.sh")],
        env={
            **clean_environment,
            "E2E_CLUSTER": "public-inbound",
            "E2E_DOCUMENTATION_SCREENSHOTS": str(screenshot_directory),
        },
        capture_output=True,
        text=True,
    )
    check(wrong_cluster.returncode == 2 and "requires the direct cluster" in wrong_cluster.stderr,
          "the Keycloak runner accepts screenshot mode outside the direct cluster")

    inherited = subprocess.run(
        [str(HERE / "local.sh"), "--suite", "core"],
        env={**clean_environment, "E2E_DOCUMENTATION_SCREENSHOTS": str(screenshot_directory)},
        capture_output=True,
        text=True,
    )
    check(inherited.returncode == 2 and "use --screenshots instead" in inherited.stderr,
          "an inherited screenshot environment silently shortens a normal local suite")

    inherited_network = subprocess.run(
        [str(HERE / "local.sh"), "--provider", "keycloak", "--screenshots", str(screenshot_directory)],
        env={
            **clean_environment,
            "E2E_PROVIDER_HOST": "login.corporate.example",
            "E2E_KEYCLOAK_URL": "https://login.corporate.example:9443",
            "E2E_PROVIDER_BROWSER_IP": "192.0.2.10",
            "E2E_KEYCLOAK_PORT": "9443",
        },
        capture_output=True,
        text=True,
    )
    check(inherited_network.returncode == 2 and "cannot inherit" in inherited_network.stderr,
          "a documentation run can capture inherited provider hostnames or fixed lab ports")

    local_conflict = subprocess.run(
        [str(HERE / "local.sh"), "--provider", "keycloak", "--screenshots", str(screenshot_directory)],
        env={**clean_environment, "E2E_AUDIT_EVIDENCE": str(audit_evidence)},
        capture_output=True,
        text=True,
    )
    check(local_conflict.returncode == 2 and "cannot be combined" in local_conflict.stderr,
          "the local wrapper starts a VM before rejecting audit screenshot mode")
    check(audit_evidence.read_text(encoding="utf-8") == "keep existing evidence\n",
          "the local screenshot refusal removes existing audit evidence")

    local_provider_conflict = subprocess.run(
        [str(HERE / "local.sh"), "--provider", "keycloak", "--screenshots", str(screenshot_directory)],
        env={**clean_environment, "E2E_PROVIDER_RESULT": str(provider_evidence)},
        capture_output=True,
        text=True,
    )
    check(local_provider_conflict.returncode == 2 and "cannot be combined" in local_provider_conflict.stderr,
          "the local wrapper starts a VM before rejecting provider evidence in screenshot mode")
    check(provider_evidence.read_text(encoding="utf-8") == "keep existing provider evidence\n",
          "the local screenshot refusal removes existing provider evidence")


def module(name, relative):
    specification = importlib.util.spec_from_file_location(name, HERE / relative)
    loaded = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(loaded)
    return loaded


screenshot_publisher = module("e2e_screenshot_publisher", "publish-screenshots.py")
with tempfile.TemporaryDirectory() as temporary:
    publication_root = pathlib.Path(temporary)
    output = publication_root / "output"
    output.mkdir()
    sources = []
    for generation in ("first", "second"):
        source = publication_root / generation
        source.mkdir()
        for name in screenshot_publisher.SCREENSHOTS:
            (source / name).write_text(f"{generation}:{name}\n", encoding="utf-8")
        sources.append(source)

    lock_descriptor = os.open(screenshot_publisher.lock_path(output), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
    publishers = [
        subprocess.Popen(
            [
                str(HERE / "publish-screenshots.py"), "--source", str(source), "--output", str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for source in sources
    ]
    time.sleep(0.1)
    check(all(process.poll() is None for process in publishers),
          "a screenshot publisher does not wait for the output-directory lock")
    fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
    os.close(lock_descriptor)
    for process in publishers:
        stdout, stderr = process.communicate(timeout=10)
        check(process.returncode == 0, f"a serialized screenshot publisher failed: {stdout}{stderr}")
    generations = {
        (output / name).read_text(encoding="utf-8").split(":", 1)[0]
        for name in screenshot_publisher.SCREENSHOTS
    }
    check(len(generations) == 1, "concurrent screenshot publishers leave a mixed generation")
    check(
        {path.name for path in output.iterdir()} == set(screenshot_publisher.SCREENSHOTS),
        "serialized screenshot publication leaves temporary or backup files behind",
    )

    for simulated_failure in (
        OSError("simulated publication failure"),
        InterruptedError("simulated publication signal"),
    ):
        for name in screenshot_publisher.SCREENSHOTS:
            (output / name).write_text(f"maintained:{name}\n", encoding="utf-8")
        replacement_calls = [0]

        def failing_replace(source, target):
            replacement_calls[0] += 1
            if replacement_calls[0] == len(screenshot_publisher.SCREENSHOTS) + 2:
                raise simulated_failure
            os.replace(source, target)

        try:
            screenshot_publisher.publish_screenshots(sources[0], output, replace=failing_replace)
        except type(simulated_failure):
            pass
        else:
            check(False, "the screenshot rollback regression did not reach its simulated failure")
        check(all(
            (output / name).read_text(encoding="utf-8") == f"maintained:{name}\n"
            for name in screenshot_publisher.SCREENSHOTS
        ), "a failed or interrupted screenshot publication does not restore the maintained generation")
        check(
            {path.name for path in output.iterdir()} == set(screenshot_publisher.SCREENSHOTS),
            "failed screenshot publication leaves temporary or backup files behind",
        )

    def signal_during_backup_cleanup(path):
        should_signal = path.suffix == ".backup" and not signal_during_backup_cleanup.sent
        if should_signal:
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            check(
                {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}.issubset(blocked),
                "handled signals are not masked while committed screenshot backups are removed",
            )
            os.kill(os.getpid(), signal.SIGTERM)
            signal_during_backup_cleanup.sent = True
        path.unlink(missing_ok=True)

    signal_during_backup_cleanup.sent = False
    screenshot_publisher.publish_screenshots(
        sources[1], output, remove_path=signal_during_backup_cleanup
    )
    check(signal_during_backup_cleanup.sent, "the committed-cleanup signal regression did not reach a backup")
    check(all(
        (output / name).read_text(encoding="utf-8") == f"second:{name}\n"
        for name in screenshot_publisher.SCREENSHOTS
    ), "a signal during committed backup cleanup changes the published screenshot generation")


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
check(public_inbound.proxy_host_arguments("opnsense.test", "") == [],
      "prepared public-inbound labs no longer retain their DNS route")
check(public_inbound.proxy_host_arguments("opnsense.test", "host-gateway")
      == ["--add-host", "opnsense.test:host-gateway"],
      "the local VM cannot route its public-inbound proxy through Docker's host gateway")
check(public_inbound.proxy_host_arguments("opnsense.test", "192.0.2.10")
      == ["--add-host", "opnsense.test:192.0.2.10"],
      "a prepared lab cannot explicitly pin its Docker proxy route")
try:
    public_inbound.proxy_host_arguments("opnsense.test", "other.example")
except ValueError:
    pass
else:
    raise SystemExit("public ingress accepts an unsafe Docker target-address override")

with tempfile.TemporaryDirectory() as temporary:
    commands = []
    original_run = public_inbound.run
    original_image = public_inbound.image
    original_resolver = public_inbound.socket.getaddrinfo
    original_monotonic = public_inbound.time.monotonic
    original_sleep = public_inbound.time.sleep
    clock = [0.0]
    resolver_calls = []

    def fake_inbound_run(*arguments, **options):
        commands.append(arguments)
        if arguments[1] == "logs":
            output = "https://prepared-route.trycloudflare.com\n"
        elif arguments[1] == "inspect":
            output = "true\n"
        else:
            output = ""
        return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")

    try:
        public_inbound.run = fake_inbound_run
        public_inbound.image = lambda name: f"fixture/{name}"
        public_inbound.time.monotonic = lambda: clock[0]
        public_inbound.time.sleep = lambda seconds: clock.__setitem__(0, clock[0] + seconds)

        def resolve_after_warmup(*arguments):
            resolver_calls.append(clock[0])
            return [(None, None, None, None, None)]

        public_inbound.socket.getaddrinfo = resolve_after_warmup
        inbound_state = pathlib.Path(temporary) / "state.json"
        with contextlib.redirect_stdout(io.StringIO()):
            public_inbound.start(types.SimpleNamespace(
                run_id="deadbeef", application_code="fixture-code",
                opnsense_url="https://prepared.example/", target_address="",
                work_dir=temporary, state=str(inbound_state),
            ))
    finally:
        public_inbound.run = original_run
        public_inbound.image = original_image
        public_inbound.socket.getaddrinfo = original_resolver
        public_inbound.time.monotonic = original_monotonic
        public_inbound.time.sleep = original_sleep
    proxy_command = next(command for command in commands if "opnsense-oidc-inbound-deadbeef-proxy" in command)
    check("--add-host" not in proxy_command,
          "prepared public-inbound startup still replaces its configured DNS route")
    proxy_configuration = (pathlib.Path(temporary) / "public-inbound-nginx.conf").read_text(encoding="utf-8")
    check("proxy_pass https://prepared.example;" in proxy_configuration,
          "a trailing slash makes Nginx replace the public receiver path")
    check(resolver_calls and resolver_calls[0] >= public_inbound.DNS_WARMUP_SECONDS,
          "public ingress still poisons the system resolver with an immediate Quick Tunnel lookup")

canary_suite = selection.resolve("full", canary=True)
check(not any(item["provider"] in {"okta", "apple"} for item in canary_suite["records"]),
      "the full canary suite still runs npm-emulated providers")
check(len([message for message in canary_suite["skipped"] if "npm emulator" in message]) == 2,
      "the full canary suite does not explain both npm-emulator skips")
with tempfile.TemporaryDirectory() as temporary:
    for runner, arguments in (
        ("run.sh", ["--provider", "authentik", "--canary"]),
        ("run-provider.sh", ["--provider", "authentik", "--canary"]),
    ):
        canary_result = pathlib.Path(temporary) / f"{runner}.json"
        canary_result.write_text("keep existing evidence\n", encoding="utf-8")
        refused_canary_result = subprocess.run(
            [str(HERE / runner), *arguments],
            env={**os.environ, "E2E_PROVIDER_RESULT": str(canary_result)}, capture_output=True, text=True,
        )
        check(refused_canary_result.returncode == 2
              and "cannot retain an unreviewed canary image" in refused_canary_result.stderr,
              f"{runner} accepts retained evidence for an unreviewed canary image")
        check(canary_result.read_text(encoding="utf-8") == "keep existing evidence\n",
              f"the refused {runner} canary run removes the caller's existing provider evidence")

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
        "ssf_issuer": "https://example.okta.test/ssf/default", "ssf_audience": "fixture-audience",
        "ssf_push_secret": "a" * 43,
    }
    config.write_text(json.dumps(profile), encoding="utf-8")
    loaded = live.load_config(config, "okta")
    check(loaded["public_inbound"]["driver"] == str(driver), "owner-only public driver was refused")
    profile["profiles"]["okta"]["public_inbound"]["ssf_push_secret"] = "fixture-push-secret"
    config.write_text(json.dumps(profile), encoding="utf-8")
    try:
        live.load_config(config, "okta")
    except ValueError:
        pass
    else:
        raise SystemExit("live config accepted a push secret that OPNsense refuses")
    profile["profiles"]["okta"]["public_inbound"]["ssf_push_secret"] = "a" * 43
    config.write_text(json.dumps(profile), encoding="utf-8")
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
    apple_live = {
        **raw,
        "provider": "apple", "source": "live",
        "subject": {"name": "apple", "revision": "service:2026-08-25"},
        "configuration_profile": "apple", "results": [{"feature": "login", "outcome": "pass"}],
    }
    artifact.write_text(json.dumps(apple_live), encoding="utf-8")
    try:
        provider_import.load_result(artifact)
    except ValueError:
        pass
    else:
        raise SystemExit("provider evidence importer accepted an unexercised Apple live login")

try:
    generator.result(
        "okta", "emulated", "direct", "vercel-labs-emulate", "version:99.0.0", "okta",
        ["login=pass"], None,
    )
except ValueError:
    pass
else:
    raise SystemExit("provider result generator accepted an unreviewed emulator revision")

try:
    generator.result(
        "apple", "live", "direct", "apple", "service:2026-08-25", "apple", ["login=pass"], None,
    )
except ValueError:
    pass
else:
    raise SystemExit("provider result generator accepted an unexercised Apple live login")

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
        retained["cluster"] = "public-inbound"
        retained["results"] = [{"feature": "back_logout", "outcome": "pass"}]
        provider_import.import_result(retained, ["back_logout"])
        retained["cluster"] = "direct"
        provider_import.import_result(retained, ["back_logout"])
        retained_provider = next(
            item for item in json.loads(retained_catalog.read_text(encoding="utf-8"))["providers"]
            if item["id"] == "keycloak"
        )
        boundaries = {
            (item["source"], item["cluster"])
            for item in retained_provider["live_evidence"] if item["feature"] == "back_logout"
        }
        check(boundaries == {("local", "direct"), ("local", "public-inbound")},
              "a later import removes evidence for another network boundary")
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
driver_cleanup = live_runner[live_runner.index('if [ "$driver_prepared" = 1 ]'):live_runner.index(
    'python3 "$script_dir/public-inbound.py" stop'
)]
check("cleanup_failed=1" in driver_cleanup and "|| true" not in driver_cleanup,
      "live provider cleanup failure cannot fail the run or request manual cleanup")
remote_cleanup = live_runner[
    live_runner.index("php '$remote_cleanup' cleanup"):live_runner.index("rm -f '$remote_cleanup'")
]
check("remote firewall cleanup failed" in remote_cleanup and "manually" in remote_cleanup
      and "cleanup_failed=1" in remote_cleanup,
      "live firewall cleanup failure is silent or omits its manual recovery warning")
check(live_runner.index('E2E_PUBLIC_PHASE=prepare') < live_runner.index('invoke_driver trigger'),
      "live public inbound triggers before establishing a matching session")
check(live_runner.index('invoke_driver trigger') < live_runner.index('E2E_PUBLIC_PHASE=assert'),
      "live public inbound records no post-trigger session assertion")
check('if [ "$provider" != apple ]; then' in live_runner
      and 'direct_capabilities="--capability login=pass $direct_capabilities"' in live_runner,
      "the reusable Apple live run still claims a WebGUI login without administrator approval")
check(" snapshot '$server_name' '$application_code'" in live_runner
      and " cleanup '$server_name' '$application_code'" in live_runner,
      "live provider cleanup does not bracket the run with an account baseline")

live_cleanup = (HERE / "remote-cleanup-live.php").read_text(encoding="utf-8")
check("openidconnect_subject_bindings" in live_cleanup and "existing_uids" in live_cleanup,
      "live cleanup does not constrain created-account removal to new bound UIDs")
check("is_int($uid)" in live_cleanup and "$existingUids[(string)$uid]" in live_cleanup,
      "live cleanup rejects numeric UIDs after its JSON baseline round trip")
check("unset($root->system->user[$index])" in live_cleanup and "auth sync user" in live_cleanup,
      "live cleanup leaves provider-created accounts or their system state behind")

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
keycloak_spec = (HERE / "oidc.spec.mjs").read_text(encoding="utf-8")
check("...await request.allHeaders()" in keycloak_spec,
      "the observed browser proxy drops session-bearing request headers")
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
