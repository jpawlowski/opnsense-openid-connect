#!/bin/sh
#
# Validate repository automation and contributor policy without exercising the
# firewall product, package assembly or protocol conformance suite.
set -eu
export PYTHONDONTWRITEBYTECODE=1

cd "$(dirname "$0")/.."

echo '== control-plane syntax =='
python3 - <<'PY'
from pathlib import Path

for root in (
    Path(".agents"), Path(".claude"), Path(".codex"),
    Path(".github/hooks"), Path(".github/scripts"), Path("packaging"), Path("tests"),
):
    for path in root.rglob("*.py"):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
find -L .agents .claude .codex .github/hooks .github/scripts -type f -name '*.json' -print0 |
    xargs -0 -n1 python3 -m json.tool >/dev/null
find -L .agents .claude .codex .github/hooks .github/scripts -type f \
    \( -name '*.js' -o -name '*.mjs' \) -print0 | xargs -0 -r -n1 node --check
find -L .agents .claude .codex .github/hooks .github/scripts -type f -name '*.sh' -print0 |
    xargs -0 -r -n1 sh -n
for file in packaging/hooks/*; do
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
python3 tests/test-impact.py
