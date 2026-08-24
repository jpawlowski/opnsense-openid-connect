#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""The same very small harness harness.php is, for the checks written in Python.

Not unittest, for the reason given over there: a name per check, a readable
failure and a non-zero exit code are the three things that matter, and a
failure should read the same whichever language it came from.
"""
import json
import os
import pathlib
import sys

_passed = 0
_failures = []
_executed = set()
_root = pathlib.Path(__file__).resolve().parent.parent


def group(name):
    print(f"\n{name}")


def check(what, actual, expected=True, detail=""):
    """Compares and reports. Passing only `actual` asserts that it is true."""
    global _passed
    caller = pathlib.Path(sys._getframe(1).f_code.co_filename).resolve()
    try:
        source = caller.relative_to(_root).as_posix()
    except ValueError:
        source = caller.as_posix()
    _executed.add((source, what))
    if actual == expected:
        _passed += 1
        print(f"  ok    {what}")
        return

    _failures.append(what)
    print(f"  FAIL  {what}")
    print(f"        expected {expected!r}")
    print(f"        got      {actual!r}")
    if detail:
        print(f"        {detail}")


def report():
    """@return int what to exit with"""
    publish_executed_tests()
    print(f"\n{_passed} checks passed", end="")
    if not _failures:
        print(", none failed.")
        return 0

    print(f", {len(_failures)} FAILED:")
    for failure in _failures:
        print(f"  {failure}")

    return 1


def executed_tests():
    """Return the exact checks reached by this process."""
    return set(_executed)


def publish_executed_tests():
    """Merge reached checks into the private manifest requested by the gate."""
    destination = os.environ.get("OPENIDCONNECT_EXECUTED_TESTS", "")
    if not destination:
        return
    path = pathlib.Path(destination)
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.stat().st_size else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        current = {}
    records = {
        (item.get("path"), item.get("test"))
        for item in current.get("executed_tests", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("test"), str)
    }
    records.update(_executed)
    payload = {
        "schema_version": 1,
        "executed_tests": [
            {"path": source, "test": test}
            for source, test in sorted(records)
        ],
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def run(main):
    """Run a file of checks and exit with what they say."""
    main()
    sys.exit(report())
