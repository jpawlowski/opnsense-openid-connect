#!/bin/sh
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
#
# Runs every host-independent check. Same command by hand, from an agent Stop
# hook and in the pipeline, so a failure looks the same in all three places.
# Tests that need OPNsense, containers or a browser stay explicit and manual.
set -eu

cd "$(dirname "$0")/.."

echo '== syntax =='
find src packaging tests -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null
# An earlier E2E run may have left Playwright dependencies here. They are not
# this repository's source, while the E2E modules themselves are.
find src tests -type f \( -name '*.js' -o -name '*.mjs' \) \
    -not -path '*/node_modules/*' -print0 | xargs -0 -r -n1 node --check
find .agents .codex packaging tests -name '*.py' -print0 | xargs -0 -n1 python3 -m py_compile
python3 -m json.tool .codex/hooks.json >/dev/null
for f in packaging/watch/openid-connect-watch packaging/hooks/* tests/run.sh tests/e2e/*.sh; do sh -n "$f"; done
python3 tests/e2e/check.py
python3 tests/update-capability-matrix.py --check
echo 'all files parse'

echo
echo '== behaviour =='
php tests/run.php

echo
echo '== what a commit message may be =='
python3 tests/convention.py

echo
echo '== what an issue or pull request may say =='
python3 tests/contribution.py
node tests/issue-hygiene.mjs
node tests/pull-request-labels.mjs

echo
echo '== what an agent task prepares =='
python3 tests/agent-hooks.py

echo
echo '== the package that gets built =='
python3 tests/package.py
