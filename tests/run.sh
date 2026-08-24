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

capability_action=--check
capability_output=
capability_temporary=
case "${1:-}" in
    --update-capability-matrix)
        capability_action=--update
        capability_temporary=$(mktemp "tests/generated/provider-capabilities.md.tmp.XXXXXX")
        capability_output=$capability_temporary
        shift
        ;;
    --render-capability-matrix)
        if [ "$#" -lt 2 ]; then
            echo 'usage: ./tests/run.sh --render-capability-matrix OUTPUT' >&2
            exit 2
        fi
        capability_action=--update
        capability_output=$2
        shift 2
        ;;
esac
if [ "$#" -ne 0 ]; then
    echo 'usage: ./tests/run.sh [--update-capability-matrix | --render-capability-matrix OUTPUT]' >&2
    exit 2
fi
executed_tests=$(mktemp "${TMPDIR:-/tmp}/openid-connect-executed-tests.XXXXXX")
cleanup() {
    rm -f "$executed_tests"
    if [ -n "$capability_temporary" ]; then
        rm -f "$capability_temporary"
    fi
}
trap cleanup EXIT HUP INT TERM
export OPENIDCONNECT_EXECUTED_TESTS="$executed_tests"

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
echo 'all files parse'

echo
echo '== behaviour =='
php tests/run.php

echo
echo '== normative conformance evidence =='
python3 tests/capability-matrix.py
if [ -n "$capability_output" ]; then
    python3 tests/update-capability-matrix.py "$capability_action" \
        --executed-tests "$executed_tests" --output "$capability_output"
else
    python3 tests/update-capability-matrix.py "$capability_action" --executed-tests "$executed_tests"
fi

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

if [ -n "$capability_temporary" ]; then
    mv "$capability_temporary" tests/generated/provider-capabilities.md
    capability_temporary=
    echo 'updated tests/generated/provider-capabilities.md'
fi
