#!/bin/sh
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
#
# Validate repository automation and contributor policy without exercising the
# firewall product, package assembly or protocol conformance suite.
set -eu

cd "$(dirname "$0")/.."

echo '== control-plane syntax =='
find .agents .codex packaging tests -name '*.py' -print0 |
    xargs -0 -n1 python3 -m py_compile
python3 -m json.tool .codex/hooks.json >/dev/null
for file in .agents/*.sh packaging/hooks/*; do
    [ -f "$file" ] && sh -n "$file"
done
echo 'control-plane files parse'

echo
echo '== contribution policy =='
python3 tests/convention.py
python3 tests/contribution.py
node tests/issue-hygiene.mjs
node tests/pull-request-labels.mjs

echo
echo '== agent behavior =='
python3 tests/agent-hooks.py
