#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
backend=auto
refresh=0
keep=0
runner_arguments=
screenshots=
selected_provider=
selected_source=auto
selected_cluster=direct
selected_canary=0
inherited_screenshots=${E2E_DOCUMENTATION_SCREENSHOTS:-}
inherited_provider_host=${E2E_PROVIDER_HOST:-}
inherited_keycloak_url=${E2E_KEYCLOAK_URL:-}
inherited_provider_browser_ip=${E2E_PROVIDER_BROWSER_IP:-}
inherited_opnsense_browser_ip=${E2E_OPNSENSE_BROWSER_IP:-}
inherited_keycloak_port=${E2E_KEYCLOAK_PORT:-}
inherited_backchannel_port=${E2E_BACKCHANNEL_PORT:-}
inherited_ssf_port=${E2E_SSF_PORT:-}
unset E2E_DOCUMENTATION_SCREENSHOTS

usage() {
  printf '%s\n' \
    'usage: tests/e2e/local.sh [--backend auto|qemu|utm] [--refresh-opnsense]' \
    '                          [--suite core|full] [--provider NAME]' \
    '                          [--source auto|local|emulated|live]' \
    '                          [--cluster direct|public-inbound|all] [--canary] [--keep]' \
    '                          [--screenshots ABSOLUTE_DIRECTORY]' >&2
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
    --suite|--provider|--source|--cluster)
      [ "$#" -ge 2 ] || usage
      [ "$1" != --provider ] || selected_provider=$2
      [ "$1" != --source ] || selected_source=$2
      [ "$1" != --cluster ] || selected_cluster=$2
      runner_arguments="$runner_arguments $1 $2"
      shift 2
      ;;
    --canary) selected_canary=1; runner_arguments="$runner_arguments --canary"; shift ;;
    --keep) keep=1; runner_arguments="$runner_arguments --keep"; shift ;;
    --screenshots)
      [ "$#" -ge 2 ] || usage
      screenshots=$2
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

case "$backend" in auto|qemu|utm) ;; *) usage ;; esac
command -v python3 >/dev/null
command -v node >/dev/null

if [ -n "$inherited_screenshots" ]; then
  printf '%s\n' 'E2E_DOCUMENTATION_SCREENSHOTS is internal; use --screenshots instead.' >&2
  exit 2
fi

# Zero asks Docker to allocate and retain each host port atomically when its
# container starts. Explicit caller-supplied ports remain available for a
# deliberately fixed external lab.
E2E_KEYCLOAK_PORT=${E2E_KEYCLOAK_PORT:-0}
E2E_BACKCHANNEL_PORT=${E2E_BACKCHANNEL_PORT:-0}
E2E_SSF_PORT=${E2E_SSF_PORT:-0}
export E2E_KEYCLOAK_PORT E2E_BACKCHANNEL_PORT E2E_SSF_PORT

if [ -n "$screenshots" ]; then
  if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
    printf '%s\n' 'Documentation screenshots cannot be combined with E2E_AUDIT_EVIDENCE.' >&2
    exit 2
  fi
  if [ -n "${E2E_PROVIDER_RESULT:-}" ]; then
    printf '%s\n' 'Documentation screenshots cannot be combined with E2E_PROVIDER_RESULT.' >&2
    exit 2
  fi
  if [ -n "$inherited_provider_host$inherited_keycloak_url$inherited_provider_browser_ip" ] || \
      [ -n "$inherited_opnsense_browser_ip$inherited_keycloak_port$inherited_backchannel_port$inherited_ssf_port" ]; then
    printf '%s\n' \
      'Documentation screenshots cannot inherit provider hosts, browser targets or service ports.' >&2
    exit 2
  fi
  if [ "$selected_provider" != keycloak ]; then
    printf '%s\n' 'Documentation screenshots require --provider keycloak.' >&2
    exit 2
  fi
  case "$selected_source" in auto|local) ;; *)
    printf '%s\n' 'Documentation screenshots require --source local (or the default auto source).' >&2
    exit 2
  esac
  if [ "$selected_cluster" != direct ] || [ "$selected_canary" = 1 ]; then
    printf '%s\n' 'Documentation screenshots require the direct cluster and the pinned provider image.' >&2
    exit 2
  fi
  case "$screenshots" in
    /*) ;;
    *) printf 'The screenshot directory must be an absolute path.\n' >&2; exit 2 ;;
  esac
  mkdir -p -- "$screenshots"
  E2E_DOCUMENTATION_SCREENSHOTS=$screenshots
  export E2E_DOCUMENTATION_SCREENSHOTS
fi

refresh_argument=
[ "$refresh" = 0 ] || refresh_argument=--refresh
web_port_argument=
if [ "$selected_source" = live ]; then
  : "${E2E_LIVE_CONFIG:?Set E2E_LIVE_CONFIG to an owner-only live profile file}"
  [ -n "$selected_provider" ] || { printf 'Local live tests require one explicit provider.\n' >&2; exit 2; }
  live_web_port=$(python3 "$script_dir/live-config.py" --config "$E2E_LIVE_CONFIG" \
    --provider "$selected_provider" --print-web-port)
  web_port_argument="--web-port $live_web_port"
fi
# Values are either closed CLI enums or the validated numeric live WebGUI port.
# shellcheck disable=SC2086
vm=$(python3 "$script_dir/vm.py" start --backend "$backend" $refresh_argument $web_port_argument)
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
# Only the local VM reaches its forwarded WebGUI port through Docker's host gateway.
E2E_OPNSENSE_PROXY_ADDRESS=host-gateway
export E2E_OPNSENSE_URL E2E_OPNSENSE_SSH E2E_OPNSENSE_SSH_CONFIG
export E2E_OPNSENSE_USERNAME E2E_OPNSENSE_PASSWORD E2E_PROVIDER_HOST E2E_PROVIDER_BROWSER_IP
export E2E_OPNSENSE_BROWSER_IP E2E_OPNSENSE_PROXY_ADDRESS

# Arguments originate in the strict case statement above and contain no shell
# metacharacters; word splitting preserves the underlying runner's POSIX CLI.
# shellcheck disable=SC2086
"$script_dir/run.sh" $runner_arguments
