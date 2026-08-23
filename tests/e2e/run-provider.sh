#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_dir/../.." && pwd)
. "$script_dir/ssh.sh"
provider=
canary=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --provider) provider=${2:-}; shift 2 ;;
    --canary) canary=1; shift ;;
    *) printf 'unknown provider-run argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "$provider" in authentik|authelia|dex|pocketid) ;; *) exit 2 ;; esac

: "${E2E_OPNSENSE_URL:?Set the HTTPS origin of the disposable OPNsense instance}"
: "${E2E_OPNSENSE_SSH:?Set the certificate-authenticated SSH target}"
: "${E2E_OPNSENSE_PASSWORD:?Set the local WebGUI password}"
: "${E2E_PROVIDER_HOST:?Set a provider host reachable from OPNsense and this runner}"

for command in docker curl jq openssl python3 ssh scp npm node; do command -v "$command" >/dev/null; done

case "$provider" in
  authentik) provider_port=${E2E_AUTHENTIK_PORT:-28443} ;;
  authelia) provider_port=${E2E_AUTHELIA_PORT:-38443} ;;
  dex) provider_port=${E2E_DEX_PORT:-48443} ;;
  pocketid) provider_port=${E2E_POCKETID_PORT:-58443} ;;
esac

run_id=$(openssl rand -hex 4)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/opnsense-oidc-${provider}.XXXXXX")
state_file="$work_dir/provider.json"
provider_url="https://${E2E_PROVIDER_HOST}:${provider_port}"
remote_ca="/usr/local/share/certs/opnsense-oidc-e2e-${run_id}.crt"
remote_cleanup="/tmp/opnsense-oidc-e2e-cleanup-${run_id}.php"
remote_package="/tmp/os-openid-connect-e2e-${run_id}.pkg"

E2E_OPNSENSE_USERNAME=${E2E_OPNSENSE_USERNAME:-root}
E2E_KEEP=${E2E_KEEP:-0}
E2E_TEST_USERNAME="oidc-e2e-${run_id}"
E2E_TEST_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')
E2E_CLIENT_ID="opnsense-e2e-${run_id}"
E2E_CLIENT_SECRET=$(openssl rand -base64 36 | tr -d '\n')
E2E_APPLICATION_CODE="e2e-${run_id}"
E2E_SERVER_NAME="${provider} E2E ${run_id}"
E2E_CALLBACK_URL="${E2E_OPNSENSE_URL}/api/openidconnect/auth/callback/${E2E_APPLICATION_CODE}"
E2E_ADMIN_TOKEN=$(openssl rand -hex 32)
E2E_DATABASE_PASSWORD=$(openssl rand -hex 24)
E2E_SERVICE_SECRET=$(openssl rand -hex 32)
E2E_SESSION_SECRET=$(openssl rand -hex 32)
E2E_STORAGE_SECRET=$(openssl rand -hex 32)
E2E_OIDC_SECRET=$(openssl rand -hex 32)
export E2E_OPNSENSE_USERNAME E2E_KEEP E2E_TEST_USERNAME E2E_TEST_PASSWORD
export E2E_CLIENT_ID E2E_CLIENT_SECRET E2E_APPLICATION_CODE E2E_SERVER_NAME E2E_CALLBACK_URL
export E2E_ADMIN_TOKEN E2E_DATABASE_PASSWORD E2E_SERVICE_SECRET E2E_SESSION_SECRET
export E2E_STORAGE_SECRET E2E_OIDC_SECRET E2E_PROVIDER_STATE_FILE="$state_file"

cleanup() {
  status=$?
  if [ "$E2E_KEEP" = 1 ]; then
    printf 'E2E resources retained in %s (exit %s).\n' "$work_dir" "$status" >&2
    exit "$status"
  fi
  e2e_ssh \
    "php '$remote_cleanup' '$E2E_TEST_USERNAME' '$E2E_APPLICATION_CODE'" >/dev/null 2>&1 || true
  e2e_ssh \
    "rm -f '$remote_cleanup' '$remote_ca' '$remote_package'; certctl rehash" >/dev/null 2>&1 || true
  python3 "$script_dir/providers/stack.py" stop --state "$state_file" >/dev/null 2>&1 || true
  # The directory contains only this run's random secrets and diagnostics.
  find "$work_dir" -type f -exec sh -c ': > "$1"' sh {} \; >/dev/null 2>&1 || true
  find "$work_dir" -depth -delete >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

canary_argument=
[ "$canary" = 0 ] || canary_argument=--canary
python3 "$script_dir/providers/stack.py" start --provider "$provider" --run-id "$run_id" \
  --url "$provider_url" --work-dir "$work_dir" --state "$state_file" $canary_argument
chmod 600 "$state_file"

e2e_scp_to "$work_dir/ca.crt" "$remote_ca"
e2e_scp_to "$script_dir/remote-cleanup.php" "$remote_cleanup"
e2e_ssh "chmod 600 '$remote_ca' '$remote_cleanup'; certctl rehash"

python3 "$repository/packaging/build.py" --version 0.0.0.e2e >/dev/null
package="$repository/packaging/dist/os-openid-connect-0.0.0.e2e.pkg"
e2e_scp_to "$package" "$remote_package"
e2e_ssh "pkg add -f '$remote_package' && pkg check -s os-openid-connect"

(cd "$script_dir" && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null)
(cd "$script_dir" && npx playwright test --config provider.config.mjs)
