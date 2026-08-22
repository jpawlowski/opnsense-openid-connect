#!/bin/sh
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
#
# Runs everything. Same command by hand as in the pipeline, so a failure looks
# the same in both places.
set -eu

cd "$(dirname "$0")/.."

echo '== syntax =='
find src packaging tests -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null
find src tests -name '*.js' -print0 | xargs -0 -r -n1 node --check
find packaging tests -name '*.py' -print0 | xargs -0 -n1 python3 -m py_compile
for f in packaging/watch/openid-connect-watch packaging/hooks/* tests/run.sh; do sh -n "$f"; done
echo 'all files parse'

echo
echo '== behaviour =='
php tests/run.php

echo
echo '== what a commit message may be =='
python3 tests/convention.py

echo
echo '== the package that gets built =='
python3 tests/package.py
