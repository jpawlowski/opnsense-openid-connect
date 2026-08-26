#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Prove that a Quick Tunnel exposes only the bounded receiver allow list."""

import argparse
import http.client
import time
import urllib.error
import urllib.request


def status(url, method="GET", body=None, timeout=15):
    request = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def expect(url, expected, method="GET", body=None):
    actual = status(url, method, body)
    if actual != expected:
        raise RuntimeError(f"public-inbound canary expected HTTP {expected}, received {actual}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--application-code", required=True)
    parser.add_argument("--expect-forwarded", action="store_true")
    arguments = parser.parse_args()
    origin = arguments.origin.rstrip("/")
    backchannel = f"{origin}/api/openidconnect/auth/backchannel/{arguments.application_code}"
    for attempt in range(30):
        try:
            expect(f"{origin}/not-a-receiver", 404)
            break
        except (OSError, RuntimeError, http.client.HTTPException):
            if attempt == 29:
                raise
            time.sleep(1)
    expect(backchannel, 403)
    expect(f"{origin}/api/openidconnect/auth/backchannel/wrong-application", 404, "POST", b"logout_token=x")
    expect(backchannel, 413, "POST", b"x" * (129 * 1024))
    if arguments.expect_forwarded:
        expect(backchannel, 204, "POST", b"logout_token=opaque-canary")
    print("Public-inbound proxy canary refused foreign paths, GET, wrong application codes and oversized bodies.")


if __name__ == "__main__":
    main()
