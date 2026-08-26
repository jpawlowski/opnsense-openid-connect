#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_dir/../.." && pwd)
. "$script_dir/ssh.sh"
provider=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --provider) provider=${2:-}; shift 2 ;;
    *) printf 'unknown live-run argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "$provider" in entra|okta|apple) ;; *) exit 2 ;; esac

: "${E2E_LIVE_CONFIG:?Set E2E_LIVE_CONFIG to an owner-only live profile file}"
: "${E2E_OPNSENSE_URL:?Set the HTTPS origin of the disposable OPNsense instance}"
: "${E2E_OPNSENSE_SSH:?Set the certificate-authenticated SSH target}"
: "${E2E_OPNSENSE_PASSWORD:?Set the local WebGUI password}"

for command in jq npm openssl python3 scp ssh; do command -v "$command" >/dev/null; done
run_id=$(openssl rand -hex 4)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/opnsense-oidc-${provider}-live.XXXXXX")
state_file="$work_dir/provider.json"
remote_cleanup="/tmp/opnsense-oidc-e2e-live-cleanup-${run_id}.php"
remote_user_state="/tmp/opnsense-oidc-e2e-live-users-${run_id}.json"
remote_package="/tmp/os-openid-connect-e2e-${run_id}.pkg"
public_state="$work_dir/public-inbound.json"
session_state="$work_dir/live-session.json"
application_code=
server_name=
public_driver=
public_origin=
driver_prepared=0
E2E_OPNSENSE_USERNAME=${E2E_OPNSENSE_USERNAME:-root}
E2E_KEEP=${E2E_KEEP:-0}
export E2E_OPNSENSE_USERNAME E2E_PROVIDER_STATE_FILE="$state_file"

cleanup() {
  status=$?
  cleanup_failed=0
  if [ "$E2E_KEEP" = 1 ]; then
    printf 'Live E2E resources retained in %s (exit %s).\n' "$work_dir" "$status" >&2
    exit "$status"
  fi
  if [ "$driver_prepared" = 1 ]; then
    if ! E2E_LIVE_PROVIDER=$provider E2E_LIVE_CONFIG=$E2E_LIVE_CONFIG \
      E2E_PUBLIC_ORIGIN=$public_origin E2E_APPLICATION_CODE=$application_code \
      "$public_driver" cleanup >/dev/null 2>&1; then
      printf '%s public-inbound driver failed during cleanup; hosted registration may require manual removal.\n' \
        "$provider" >&2
      cleanup_failed=1
    fi
  fi
  python3 "$script_dir/public-inbound.py" stop --state "$public_state" >/dev/null 2>&1 || true
  if ! e2e_ssh "php '$remote_cleanup' cleanup '$server_name' '$application_code'" >/dev/null 2>&1; then
    printf '%s remote firewall cleanup failed; remove its disposable authentication server and test-created user manually.\n' \
      "$provider" >&2
    cleanup_failed=1
  fi
  e2e_ssh "rm -f '$remote_cleanup' '$remote_user_state' '$remote_package'" >/dev/null 2>&1 || true
  find "$work_dir" -type f -exec sh -c ': > "$1"' sh {} \; >/dev/null 2>&1 || true
  find "$work_dir" -depth -delete >/dev/null 2>&1 || true
  [ "$status" -ne 0 ] || status=$cleanup_failed
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

invoke_driver() {
  driver_action=$1
  driver_capability=${2:-}
  if ! E2E_LIVE_PROVIDER=$provider E2E_LIVE_CONFIG=$E2E_LIVE_CONFIG \
      E2E_PUBLIC_ORIGIN=$public_origin E2E_APPLICATION_CODE=$application_code \
      E2E_PUBLIC_CAPABILITY=$driver_capability "$public_driver" "$driver_action" >/dev/null 2>&1; then
    printf '%s public-inbound driver failed during %s.\n' "$provider" "$driver_action" >&2
    return 1
  fi
}

python3 "$script_dir/live-config.py" --config "$E2E_LIVE_CONFIG" --provider "$provider" \
  --opnsense-url "$E2E_OPNSENSE_URL" --run-id "$run_id" --state "$state_file"
application_code=$(jq -r .application_code "$state_file")
server_name=$(jq -r .server_name "$state_file")
E2E_LIVE_TIMEOUT=$(($(jq -r .manual_timeout_seconds "$state_file") * 1000))
E2E_LIVE_ARTIFACT_DIR="$work_dir/playwright"
E2E_LIVE_SESSION_STATE=$session_state
export E2E_LIVE_TIMEOUT E2E_LIVE_ARTIFACT_DIR E2E_LIVE_SESSION_STATE

python3 "$repository/packaging/build.py" --version 0.0.0.e2e >/dev/null
package="$repository/packaging/dist/os-openid-connect-0.0.0.e2e.pkg"
e2e_scp_to "$script_dir/remote-cleanup-live.php" "$remote_cleanup"
e2e_scp_to "$package" "$remote_package"
e2e_ssh "chmod 600 '$remote_cleanup'; pkg add -f '$remote_package' && pkg check -s os-openid-connect"
e2e_ssh "php '$remote_cleanup' snapshot '$server_name' '$application_code'" >/dev/null

(cd "$script_dir" && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null)
if [ "$E2E_CLUSTER" = public-inbound ]; then
  public_driver=$(jq -r '.public_inbound.driver // empty' "$state_file")
  [ -n "$public_driver" ] || {
    printf '%s live profile has no public_inbound handoff configuration.\n' "$provider" >&2
    exit 2
  }
  public_origin=$(python3 "$script_dir/public-inbound.py" start --run-id "$run_id" \
    --application-code "$application_code" --opnsense-url "$E2E_OPNSENSE_URL" \
    --work-dir "$work_dir" --state "$public_state")
  python3 "$script_dir/public-inbound-canary.py" --origin "$public_origin" \
    --application-code "$application_code"
  driver_prepared=1
  invoke_driver prepare
  result_arguments=
  for capability in $(jq -r '.public_inbound.capabilities[]' "$state_file"); do
    invoke_driver register "$capability"
    E2E_PUBLIC_PHASE=prepare
    export E2E_PUBLIC_PHASE
    (cd "$script_dir" && npx playwright test --config provider.config.mjs --headed)
    chmod 600 "$session_state"
    invoke_driver trigger "$capability"
    E2E_PUBLIC_PHASE=assert
    export E2E_PUBLIC_PHASE
    (cd "$script_dir" && npx playwright test --config provider.config.mjs)
    result_arguments="$result_arguments --capability $capability=pass"
  done
  if [ -n "${E2E_PROVIDER_RESULT:-}" ]; then
    # Capability names come from live-config.py's closed allow list.
    # shellcheck disable=SC2086
    python3 "$script_dir/provider-result.py" --provider "$provider" --source live \
      --cluster public-inbound --subject-name "$provider" \
      --subject-revision "$(jq -r .provider_revision "$state_file")" --profile "$provider" \
      $result_arguments --output "$E2E_PROVIDER_RESULT"
  fi
  exit 0
fi

E2E_LIVE_HEADED=1
export E2E_LIVE_HEADED
(cd "$script_dir" && npx playwright test --config provider.config.mjs --headed)

if [ -n "${E2E_PROVIDER_RESULT:-}" ]; then
  direct_capabilities="--capability pkce=pass"
  if [ "$provider" != apple ]; then
    direct_capabilities="--capability login=pass $direct_capabilities"
  fi
  # Apple requires an explicit administrator approval before a new live
  # subject can receive a WebGUI session, so this reusable run does not claim
  # login evidence merely because its test-only callback succeeded.
  # shellcheck disable=SC2086
  python3 "$script_dir/provider-result.py" --provider "$provider" --source live --cluster direct \
    --subject-name "$provider" --subject-revision "$(jq -r .provider_revision "$state_file")" \
    --profile "$provider" $direct_capabilities --output "$E2E_PROVIDER_RESULT"
fi
