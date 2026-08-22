#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""The same very small harness harness.php is, for the checks written in Python.

Not unittest, for the reason given over there: a name per check, a readable
failure and a non-zero exit code are the three things that matter, and a
failure should read the same whichever language it came from.
"""
import sys

_passed = 0
_failures = []


def group(name):
    print(f"\n{name}")


def check(what, actual, expected=True, detail=""):
    """Compares and reports. Passing only `actual` asserts that it is true."""
    global _passed
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
    print(f"\n{_passed} checks passed", end="")
    if not _failures:
        print(", none failed.")
        return 0

    print(f", {len(_failures)} FAILED:")
    for failure in _failures:
        print(f"  {failure}")

    return 1


def run(main):
    """Run a file of checks and exit with what they say."""
    main()
    sys.exit(report())
