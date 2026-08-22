#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Checks whether the bundled third-party file still matches its origin.

A bundled copy receives no security updates - not through Composer, not
through the system's package manager. If something is found over there,
nobody here learns of it by itself. This script is the countermeasure.

It runs on the BUILD HOST, not on the firewall. A watchdog that reaches out
to the internet from a firewall would be the wrong trade - and at build time
somebody is sitting in front of it who can act on what it says.

    python3 packaging/vendor-check.py           # check
    python3 packaging/vendor-check.py --update  # pull in and record

When pulling in, the file is taken UNCHANGED. Everything we want differently
lives as an override in RelyingParty.php, so the comparison stays a copy and
never becomes a merge.
"""
import hashlib
import json
import pathlib
import sys
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
INDEX = HERE / "vendor.json"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
API = "https://api.github.com/repos/{repo}/commits/{branch}"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vendor-check"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def main():
    update = "--update" in sys.argv
    index = json.loads(INDEX.read_text())
    drift = False

    for name, meta in index.items():
        local = REPO / meta["path"]
        have = hashlib.sha256(local.read_bytes()).hexdigest()
        if have != meta["sha256"]:
            print(f"{name}: DIFFERS from the record - the bundled file has been "
                  f"altered.\n  recorded {meta['sha256'][:16]}...\n  found    {have[:16]}...")
            drift = True

        head = json.loads(fetch(API.format(repo=meta["repo"], branch=meta["branch"])))
        ref, date = head["sha"], head["commit"]["author"]["date"][:10]
        if ref == meta["ref"]:
            print(f"{name}: current ({meta['repo']}@{ref[:12]}, {date})")
            continue

        newest = fetch(RAW.format(repo=meta["repo"], ref=ref, path=meta["upstream_path"]))
        if hashlib.sha256(newest).hexdigest() == have:
            print(f"{name}: current in content, upstream has merely moved on "
                  f"({ref[:12]}, {date}) - record it with --update")
            if update:
                meta["ref"], meta["ref_date"] = ref, date
            continue

        drift = True
        print(f"{name}: UPSTREAM HAS CHANGED ({ref[:12]}, {date})")
        print(f"  {RAW.format(repo=meta['repo'], ref=ref, path=meta['upstream_path'])}")
        if update:
            local.write_bytes(newest)
            meta["ref"], meta["ref_date"] = ref, date
            meta["sha256"] = hashlib.sha256(newest).hexdigest()
            print("  pulled in - look at the differences (git diff) and check the "
                  "overrides in RelyingParty.php against them")

    if update:
        INDEX.write_text(json.dumps(index, indent=2) + "\n")

    return 1 if drift and not update else 0


if __name__ == "__main__":
    sys.exit(main())
