#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

# Runs provider stacks against an explicitly supplied disposable firewall. The
# local VM wrapper supplies the same three OPNsense variables as a prepared lab.
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
suite=core
provider=
canary=0
E2E_KEEP=${E2E_KEEP:-0}

usage() {
  printf '%s\n' \
    'usage: tests/e2e/run.sh [--suite core|full] [--provider NAME] [--canary] [--keep]' >&2
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
    --canary) canary=1; shift ;;
    --keep) E2E_KEEP=1; shift ;;
    -h|--help)
      sed -n '6,8p' "$0"
      exit 0
      ;;
    *) usage ;;
  esac
done

case "$suite" in core|full) ;; *) usage ;; esac
case "$provider" in ''|keycloak|authentik|authelia|dex|pocketid) ;; *) usage ;; esac
: "${E2E_OPNSENSE_URL:?Set the HTTPS origin of the disposable OPNsense instance}"
: "${E2E_OPNSENSE_SSH:?Set the certificate-authenticated SSH target}"
: "${E2E_OPNSENSE_PASSWORD:?Set the local WebGUI password}"

if [ -n "$provider" ]; then
  providers=$provider
elif [ "$suite" = core ]; then
  providers='keycloak authentik'
else
  providers='keycloak authentik authelia dex pocketid'
fi

if [ -z "${E2E_PROVIDER_HOST:-}" ]; then
  if [ -n "${E2E_KEYCLOAK_URL:-}" ]; then
    E2E_PROVIDER_HOST=$(node -e 'console.log(new URL(process.argv[1]).hostname)' "$E2E_KEYCLOAK_URL")
  else
    E2E_PROVIDER_HOST=provider.localhost
  fi
fi
export E2E_KEEP E2E_PROVIDER_HOST

failures=
for current in $providers; do
  printf '\n== OIDC E2E: %s%s ==\n' "$current" "$( [ "$canary" = 1 ] && printf ' canary' )"
  canary_argument=
  [ "$canary" = 0 ] || canary_argument=--canary
  if [ "$current" = keycloak ]; then
    E2E_KEYCLOAK_URL=${E2E_KEYCLOAK_URL:-"https://${E2E_PROVIDER_HOST}:${E2E_KEYCLOAK_PORT:-18443}"}
    E2E_KEYCLOAK_IMAGE=$(python3 "$script_dir/providers/image.py" keycloak $canary_argument)
    export E2E_KEYCLOAK_URL E2E_KEYCLOAK_IMAGE
    "$script_dir/run-keycloak.sh" || status=$?
  else
    "$script_dir/run-provider.sh" --provider "$current" $canary_argument || status=$?
  fi
  status=${status:-0}
  if [ "$status" -ne 0 ]; then
    failures="${failures}${failures:+ }${current}:${status}"
    [ "$E2E_KEEP" = 0 ] || break
  fi
  unset status
done

if [ -n "$failures" ]; then
  printf '\nProvider failures: %s\n' "$failures" >&2
  exit 1
fi
