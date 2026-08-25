#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

# Runs provider stacks against an explicitly supplied disposable firewall. The
# local VM wrapper supplies the same three OPNsense variables as a prepared lab.
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
suite=core
provider=
source=auto
cluster=direct
canary=0
E2E_KEEP=${E2E_KEEP:-0}

usage() {
  printf '%s\n' \
    'usage: tests/e2e/run.sh [--suite core|full] [--provider NAME]' \
    '                        [--source auto|local|emulated|live]' \
    '                        [--cluster direct|public-inbound|all] [--canary] [--keep]' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --suite)
      [ "$#" -ge 2 ] || usage
      suite=$2
      shift 2
      ;;
    --provider)
      [ "$#" -ge 2 ] || usage
      provider=$2
      shift 2
      ;;
    --source)
      [ "$#" -ge 2 ] || usage
      source=$2
      shift 2
      ;;
    --cluster)
      [ "$#" -ge 2 ] || usage
      cluster=$2
      shift 2
      ;;
    --canary) canary=1; shift ;;
    --keep) E2E_KEEP=1; shift ;;
    -h|--help)
      sed -n '6,8p' "$0"
      exit 0
      ;;
    *) usage ;;
  esac
done

: "${E2E_PROVIDER_RESULT:=}"
if [ -n "$E2E_PROVIDER_RESULT" ]; then
  [ -n "$provider" ] || { printf 'E2E_PROVIDER_RESULT requires one explicit provider.\n' >&2; exit 2; }
  [ "$cluster" != all ] || { printf 'E2E_PROVIDER_RESULT requires one explicit cluster.\n' >&2; exit 2; }
  case "$E2E_PROVIDER_RESULT" in /*) ;; *) printf 'E2E_PROVIDER_RESULT must be absolute.\n' >&2; exit 2 ;; esac
  [ -d "$(dirname -- "$E2E_PROVIDER_RESULT")" ] || {
    printf 'The E2E provider result directory does not exist.\n' >&2
    exit 2
  }
  rm -f -- "$E2E_PROVIDER_RESULT"
fi

: "${E2E_OPNSENSE_URL:?Set the HTTPS origin of the disposable OPNsense instance}"
: "${E2E_OPNSENSE_SSH:?Set the certificate-authenticated SSH target}"
: "${E2E_OPNSENSE_PASSWORD:?Set the local WebGUI password}"

selection_arguments="--suite $suite --source $source --cluster $cluster"
[ -z "$provider" ] || selection_arguments="$selection_arguments --provider $provider"
[ "$canary" = 0 ] || selection_arguments="$selection_arguments --canary"
# Every value above is accepted only by selection.py's closed enumerations.
# shellcheck disable=SC2086
selections=$(python3 "$script_dir/selection.py" $selection_arguments --format words) || exit $?

if [ -z "${E2E_PROVIDER_HOST:-}" ]; then
  if [ -n "${E2E_KEYCLOAK_URL:-}" ]; then
    E2E_PROVIDER_HOST=$(node -e 'console.log(new URL(process.argv[1]).hostname)' "$E2E_KEYCLOAK_URL")
  else
    E2E_PROVIDER_HOST=provider.opnsense.test
  fi
fi
export E2E_KEEP E2E_PROVIDER_HOST E2E_PROVIDER_RESULT

failures=
for selection in $selections; do
  previous_ifs=$IFS
  IFS=:
  set -- $selection
  IFS=$previous_ifs
  current=$1
  current_source=$2
  current_cluster=$3
  printf '\n== OIDC E2E: %s / %s / %s%s ==\n' \
    "$current" "$current_source" "$current_cluster" "$( [ "$canary" = 1 ] && printf ' canary' )"
  canary_argument=
  [ "$canary" = 0 ] || canary_argument=--canary
  E2E_SOURCE=$current_source
  E2E_CLUSTER=$current_cluster
  export E2E_SOURCE E2E_CLUSTER
  if [ "$current_source" = live ]; then
    "$script_dir/run-live.sh" --provider "$current" || status=$?
  elif [ "$current" = keycloak ]; then
    E2E_KEYCLOAK_URL=${E2E_KEYCLOAK_URL:-"https://${E2E_PROVIDER_HOST}:${E2E_KEYCLOAK_PORT:-18443}"}
    E2E_KEYCLOAK_IMAGE=$(python3 "$script_dir/providers/image.py" keycloak $canary_argument)
    export E2E_KEYCLOAK_URL E2E_KEYCLOAK_IMAGE
    "$script_dir/run-keycloak.sh" || status=$?
  else
    "$script_dir/run-provider.sh" --provider "$current" $canary_argument || status=$?
  fi
  status=${status:-0}
  if [ "$status" -ne 0 ]; then
    failures="${failures}${failures:+ }${current}/${current_source}/${current_cluster}:${status}"
    [ "$E2E_KEEP" = 0 ] || break
  fi
  unset status
done

if [ -n "$failures" ]; then
  printf '\nProvider failures: %s\n' "$failures" >&2
  exit 1
fi
