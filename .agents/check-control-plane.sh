#!/bin/sh
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
#
# Validate repository automation and contributor policy without exercising the
# firewall product, package assembly or protocol conformance suite.
set -eu
export PYTHONDONTWRITEBYTECODE=1

cd "$(dirname "$0")/.."

echo '== control-plane syntax =='
python3 - <<'PY'
from pathlib import Path

for root in (Path(".agents"), Path(".codex"), Path("packaging"), Path("tests")):
    for path in root.rglob("*.py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
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
