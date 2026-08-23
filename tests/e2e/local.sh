#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
backend=auto
refresh=0
keep=0
runner_arguments=

usage() {
  printf '%s\n' \
    'usage: tests/e2e/local.sh [--backend auto|qemu|utm] [--refresh-opnsense]' \
    '                          [--suite core|full] [--provider NAME] [--canary] [--keep]' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --backend)
      [ "$#" -ge 2 ] || usage
      backend=$2
      shift 2
      ;;
    --refresh-opnsense) refresh=1; shift ;;
    --suite|--provider)
      [ "$#" -ge 2 ] || usage
      runner_arguments="$runner_arguments $1 $2"
      shift 2
      ;;
    --canary) runner_arguments="$runner_arguments --canary"; shift ;;
    --keep) keep=1; runner_arguments="$runner_arguments --keep"; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

case "$backend" in auto|qemu|utm) ;; *) usage ;; esac
command -v python3 >/dev/null
command -v node >/dev/null

refresh_argument=
[ "$refresh" = 0 ] || refresh_argument=--refresh
vm=$(python3 "$script_dir/vm.py" start --backend "$backend" $refresh_argument)
vm_field() {
  printf '%s' "$vm" | node -e \
    'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d)[process.argv[1]]))' "$1"
}
state=$(vm_field state)

cleanup() {
  status=$?
  if [ "$keep" = 1 ]; then
    printf 'Local OPNsense VM retained; stop it with:\n  %s/vm.py stop --state %s\n' "$script_dir" "$state" >&2
  else
    python3 "$script_dir/vm.py" stop --state "$state" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

E2E_OPNSENSE_URL=$(vm_field url)
E2E_OPNSENSE_SSH=$(vm_field ssh)
E2E_OPNSENSE_SSH_CONFIG=$(vm_field ssh_config)
E2E_OPNSENSE_USERNAME=${E2E_OPNSENSE_USERNAME:-root}
E2E_OPNSENSE_PASSWORD=${E2E_OPNSENSE_PASSWORD:-opnsense}
E2E_PROVIDER_HOST=${E2E_PROVIDER_HOST:-provider.opnsense.test}
E2E_PROVIDER_BROWSER_IP=${E2E_PROVIDER_BROWSER_IP:-127.0.0.1}
E2E_OPNSENSE_BROWSER_IP=${E2E_OPNSENSE_BROWSER_IP:-127.0.0.1}
export E2E_OPNSENSE_URL E2E_OPNSENSE_SSH E2E_OPNSENSE_SSH_CONFIG
export E2E_OPNSENSE_USERNAME E2E_OPNSENSE_PASSWORD E2E_PROVIDER_HOST E2E_PROVIDER_BROWSER_IP
export E2E_OPNSENSE_BROWSER_IP

# Arguments originate in the strict case statement above and contain no shell
# metacharacters; word splitting preserves the underlying runner's POSIX CLI.
# shellcheck disable=SC2086
"$script_dir/run.sh" $runner_arguments
