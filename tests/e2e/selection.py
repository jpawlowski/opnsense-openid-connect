#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Resolve the deliberately manual provider/source/network E2E matrix."""

import argparse
import json
import sys


PROVIDERS = {
    "keycloak": {"sources": {"local"}, "public_inbound": {"local"}},
    "authentik": {"sources": {"local"}, "public_inbound": set()},
    "authelia": {"sources": {"local"}, "public_inbound": set()},
    "pocketid": {"sources": {"local"}, "public_inbound": set()},
    "entra": {"sources": {"emulated", "live"}, "public_inbound": {"live"}},
    "okta": {"sources": {"emulated", "live"}, "public_inbound": {"live"}},
    "apple": {"sources": {"emulated", "live"}, "public_inbound": set()},
}
SUITES = {
    "core": ["keycloak", "authentik"],
    "full": ["keycloak", "authentik", "authelia", "pocketid", "entra", "okta", "apple"],
}
AUTO_SOURCE = {
    "keycloak": "local",
    "authentik": "local",
    "authelia": "local",
    "pocketid": "local",
    "entra": "emulated",
    "okta": "emulated",
    "apple": "emulated",
}
SOURCES = {"auto", "local", "emulated", "live"}
CLUSTERS = {"direct", "public-inbound", "all"}
NPM_EMULATED_PROVIDERS = {"okta", "apple"}


class SelectionError(ValueError):
    pass


def resolve(suite="core", provider=None, source="auto", cluster="direct", canary=False):
    if suite not in SUITES:
        raise SelectionError(f"unknown suite: {suite}")
    if provider is not None and provider not in PROVIDERS:
        raise SelectionError(f"unknown provider: {provider}")
    if source not in SOURCES:
        raise SelectionError(f"unknown source: {source}")
    if cluster not in CLUSTERS:
        raise SelectionError(f"unknown cluster: {cluster}")
    if source == "live" and provider is None:
        raise SelectionError("live tests require one explicit provider")
    if canary and source == "live":
        raise SelectionError("a live service cannot use the container release canary")

    selected = [provider] if provider is not None else SUITES[suite]
    requested_clusters = ["direct", "public-inbound"] if cluster == "all" else [cluster]
    records = []
    skipped = []
    # Cluster-major order is intentional: `all` completes every direct run before
    # the first public listener exists.
    for selected_cluster in requested_clusters:
        for selected_provider in selected:
            selected_source = AUTO_SOURCE[selected_provider] if source == "auto" else source
            if canary and selected_source == "emulated" and selected_provider in NPM_EMULATED_PROVIDERS:
                message = f"{selected_provider}/{selected_source}: npm emulator has no container release canary"
                if provider is not None:
                    raise SelectionError(message)
                if message not in skipped:
                    skipped.append(message)
                continue
            if selected_source not in PROVIDERS[selected_provider]["sources"]:
                message = f"{selected_provider}/{selected_source}: source is not supported"
                if provider is not None:
                    raise SelectionError(message)
                if message not in skipped:
                    skipped.append(message)
                continue
            if (
                selected_cluster == "public-inbound"
                and selected_source not in PROVIDERS[selected_provider]["public_inbound"]
            ):
                message = f"{selected_provider}/{selected_source}/public-inbound: not applicable"
                if provider is not None:
                    raise SelectionError(message)
                if message not in skipped:
                    skipped.append(message)
                continue
            records.append({
                "provider": selected_provider,
                "source": selected_source,
                "cluster": selected_cluster,
            })
    if not records:
        raise SelectionError("the selection contains no runnable provider/source/cluster combination")
    return {"records": records, "skipped": skipped}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", default="core")
    parser.add_argument("--provider")
    parser.add_argument("--source", default="auto")
    parser.add_argument("--cluster", default="direct")
    parser.add_argument("--canary", action="store_true")
    parser.add_argument("--format", choices=("json", "words"), default="json")
    arguments = parser.parse_args()
    try:
        selection = resolve(
            arguments.suite,
            arguments.provider,
            arguments.source,
            arguments.cluster,
            arguments.canary,
        )
    except SelectionError as error:
        parser.error(str(error))
    for message in selection["skipped"]:
        print(f"OIDC E2E: {message}", file=sys.stderr)
    if arguments.format == "json":
        print(json.dumps(selection, indent=2, sort_keys=True))
    else:
        print(" ".join(
            f"{record['provider']}:{record['source']}:{record['cluster']}"
            for record in selection["records"]
        ))


if __name__ == "__main__":
    main()
