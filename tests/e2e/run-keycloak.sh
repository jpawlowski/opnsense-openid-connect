#!/bin/sh

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_dir/../.." && pwd)
. "$script_dir/ssh.sh"
E2E_AUDIT_EXECUTION_STARTED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

if [ -n "${E2E_AUDIT_EVIDENCE:-}" ] && [ -n "${E2E_DOCUMENTATION_SCREENSHOTS:-}" ]; then
  printf '%s\n' 'E2E_AUDIT_EVIDENCE and E2E_DOCUMENTATION_SCREENSHOTS cannot be used together.' >&2
  exit 2
fi

if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
  case "$E2E_AUDIT_EVIDENCE" in
    /*) ;;
    *) printf 'E2E_AUDIT_EVIDENCE must be an absolute caller-supplied path.\n' >&2; exit 2 ;;
  esac
  test -d "$(dirname -- "$E2E_AUDIT_EVIDENCE")" || {
    printf 'The E2E audit evidence directory does not exist.\n' >&2
    exit 2
  }
  # A failed rerun must not leave an older successful result available to the
  # audit generator. This removes only the exact path the caller supplied.
  rm -f -- "$E2E_AUDIT_EVIDENCE"
fi
export E2E_AUDIT_EXECUTION_STARTED_AT

: "${E2E_OPNSENSE_URL:?Set the HTTPS origin of the disposable OPNsense instance}"
: "${E2E_OPNSENSE_SSH:?Set the certificate-authenticated SSH target, for example root@firewall}"
: "${E2E_OPNSENSE_PASSWORD:?Set the local WebGUI password in the environment}"
: "${E2E_KEYCLOAK_URL:?Set an HTTPS origin reachable by OPNsense and this host}"

E2E_OPNSENSE_USERNAME=${E2E_OPNSENSE_USERNAME:-root}
E2E_BACKCHANNEL_PORT=${E2E_BACKCHANNEL_PORT:-19443}
E2E_SSF_PORT=${E2E_SSF_PORT:-20443}
E2E_KEEP=${E2E_KEEP:-0}

command -v docker >/dev/null
command -v curl >/dev/null
command -v jq >/dev/null
command -v openssl >/dev/null
command -v python3 >/dev/null
command -v ssh >/dev/null
command -v scp >/dev/null
command -v npm >/dev/null

run_id=$(openssl rand -hex 4)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/opnsense-oidc-e2e.XXXXXX")
keycloak_container="opnsense-oidc-keycloak-${run_id}"
proxy_container="opnsense-oidc-proxy-${run_id}"
zap_container="opnsense-oidc-zap-${run_id}"
ssf_container="opnsense-oidc-ssf-${run_id}"
remote_ca="/usr/local/share/certs/opnsense-oidc-e2e-${run_id}.crt"
remote_cleanup="/tmp/opnsense-oidc-e2e-cleanup-${run_id}.php"
public_inbound_state="$work_dir/public-inbound.json"

E2E_RUN_ID=$run_id
documentation_screenshot_output=${E2E_DOCUMENTATION_SCREENSHOTS:-}
documentation_screenshot_names='login-and-recovery.png connection-health.png test-sign-in.png bound-identities.png pending-approvals.png'
documentation_publish_phase=idle
if [ -n "${E2E_DOCUMENTATION_SCREENSHOTS:-}" ]; then
  case "$E2E_DOCUMENTATION_SCREENSHOTS" in
    /*) ;;
    *) printf 'E2E_DOCUMENTATION_SCREENSHOTS must be an absolute path.\n' >&2; exit 2 ;;
  esac
  mkdir -p "$documentation_screenshot_output"
  E2E_KEYCLOAK_REALM=opnsense-documentation
  E2E_KEYCLOAK_ADMIN_USERNAME=documentation-admin
  E2E_KEYCLOAK_CLIENT_ID=opnsense-webgui
  E2E_TEST_USERNAME=alex
  E2E_SSF_SUBJECT=2fa29e39-2b28-4770-9706-47ed6affb628
  E2E_SERVER_NAME='Company identity'
  E2E_APPLICATION_CODE=webgui
else
  E2E_KEYCLOAK_REALM="opnsense-e2e-${run_id}"
  E2E_KEYCLOAK_ADMIN_USERNAME="e2e-admin-${run_id}"
  E2E_KEYCLOAK_CLIENT_ID="opnsense-e2e-${run_id}"
  E2E_TEST_USERNAME="oidc-e2e-${run_id}"
  E2E_SSF_SUBJECT=$(python3 -c 'import uuid; print(uuid.uuid4())')
  E2E_SERVER_NAME="Keycloak E2E ${run_id}"
  E2E_APPLICATION_CODE="e2e-${run_id}"
fi
E2E_KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
E2E_TEST_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
E2E_SSF_AUDIENCE="opnsense-ssf-${run_id}"
E2E_SSF_PUSH_SECRET=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')
E2E_SSF_TRIGGER_SECRET=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '=\n')

export E2E_RUN_ID E2E_OPNSENSE_USERNAME E2E_KEYCLOAK_REALM E2E_KEYCLOAK_ADMIN_USERNAME
export E2E_KEYCLOAK_ADMIN_PASSWORD E2E_KEYCLOAK_CLIENT_ID
export E2E_TEST_USERNAME E2E_TEST_PASSWORD E2E_SERVER_NAME E2E_APPLICATION_CODE
export E2E_SSF_SUBJECT

if [ -n "$documentation_screenshot_output" ]; then
  E2E_DOCUMENTATION_SCREENSHOTS="$work_dir/documentation-screenshots"
  mkdir -p "$E2E_DOCUMENTATION_SCREENSHOTS"
  export E2E_DOCUMENTATION_SCREENSHOTS
fi

url_parts=$(node -e \
  'const u=new URL(process.argv[1]); console.log([u.hostname,u.port||"443",u.origin].join("\n"))' \
  "$E2E_KEYCLOAK_URL")
keycloak_host=$(printf '%s\n' "$url_parts" | sed -n '1p')
keycloak_port=$(printf '%s\n' "$url_parts" | sed -n '2p')
keycloak_origin=$(printf '%s\n' "$url_parts" | sed -n '3p')
opnsense_origin=$(node -e \
  'const u=new URL(process.argv[1]); if(u.protocol!=="https:") process.exit(2); console.log(u.origin)' \
  "$E2E_OPNSENSE_URL")
opnsense_authority=$(node -e 'console.log(new URL(process.argv[1]).host)' "$E2E_OPNSENSE_URL")
opnsense_host=$(node -e 'console.log(new URL(process.argv[1]).hostname)' "$E2E_OPNSENSE_URL")
opnsense_port=$(node -e 'const u=new URL(process.argv[1]); console.log(u.port||"443")' "$E2E_OPNSENSE_URL")

keycloak_curl() {
  if [ -n "${E2E_PROVIDER_BROWSER_IP:-}" ]; then
    command curl --resolve "${keycloak_host}:${keycloak_port}:${E2E_PROVIDER_BROWSER_IP}" "$@"
  else
    command curl "$@"
  fi
}

case "$keycloak_host" in
  *:*) certificate_san="IP:${keycloak_host}" ;;
  *[!0-9.]*) certificate_san="DNS:${keycloak_host}" ;;
  *) certificate_san="IP:${keycloak_host}" ;;
esac
case "$opnsense_host" in
  *:*) certificate_san="${certificate_san},IP:${opnsense_host}" ;;
  *[!0-9.]*) certificate_san="${certificate_san},DNS:${opnsense_host}" ;;
  *) certificate_san="${certificate_san},IP:${opnsense_host}" ;;
esac

E2E_KEYCLOAK_URL=$keycloak_origin
export E2E_KEYCLOAK_URL

cleanup() {
  status=$?
  if [ -n "$documentation_screenshot_output" ]; then
    if [ "$documentation_publish_phase" = backing-up ]; then
      for screenshot_name in $documentation_screenshot_names; do
        screenshot_backup="$documentation_screenshot_output/.${screenshot_name}.${run_id}.backup"
        if [ -e "$screenshot_backup" ]; then
          mv "$screenshot_backup" "$documentation_screenshot_output/$screenshot_name" || true
        fi
      done
    elif [ "$documentation_publish_phase" = publishing ]; then
      for screenshot_name in $documentation_screenshot_names; do
        screenshot_backup="$documentation_screenshot_output/.${screenshot_name}.${run_id}.backup"
        rm -f "$documentation_screenshot_output/$screenshot_name" || true
        if [ -e "$screenshot_backup" ]; then
          mv "$screenshot_backup" "$documentation_screenshot_output/$screenshot_name" || true
        fi
      done
    fi
    for screenshot_name in $documentation_screenshot_names; do
      rm -f "$documentation_screenshot_output/.${screenshot_name}.${run_id}.tmp" || true
      rm -f "$documentation_screenshot_output/.${screenshot_name}.${run_id}.backup" || true
    done
  fi
  if [ "$E2E_KEEP" = "1" ]; then
    printf 'E2E resources retained for inspection in %s (exit %s).\n' "$work_dir" "$status" >&2
    exit "$status"
  fi
  e2e_ssh \
    "php '$remote_cleanup' '$E2E_TEST_USERNAME' '$E2E_APPLICATION_CODE'" >/dev/null 2>&1 || true
  remote_package="/tmp/os-openid-connect-e2e-${run_id}.pkg"
  e2e_ssh "rm -f '$remote_cleanup' '$remote_ca' '$remote_package'; certctl rehash" \
    >/dev/null 2>&1 || true
  docker rm -f "$keycloak_container" "$proxy_container" "$zap_container" "$ssf_container" \
    >/dev/null 2>&1 || true
  python3 "$script_dir/public-inbound.py" stop --state "$public_inbound_state" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:3072 -nodes -days 2 \
  -subj "/CN=OPNsense OIDC E2E ${run_id}" \
  -keyout "$work_dir/ca.key" -out "$work_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -subj "/CN=${keycloak_host}" \
  -addext "subjectAltName=${certificate_san}" \
  -keyout "$work_dir/server.key" -out "$work_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -days 2 -in "$work_dir/server.csr" \
  -CA "$work_dir/ca.crt" -CAkey "$work_dir/ca.key" -CAcreateserial \
  -copy_extensions copy \
  -out "$work_dir/server.crt" >/dev/null 2>&1

jq -n \
  --arg realm "$E2E_KEYCLOAK_REALM" \
  --arg admin "$E2E_KEYCLOAK_ADMIN_USERNAME" \
  --arg username "$E2E_TEST_USERNAME" \
  --arg password "$E2E_TEST_PASSWORD" \
  --arg subject "$E2E_SSF_SUBJECT" \
  '{
    realm: $realm,
    enabled: true,
    users: [{
      id: $subject,
      username: $username,
      email: ($username + "@example.com"),
      emailVerified: true,
      firstName: "OIDC",
      lastName: "E2E",
      enabled: true,
      credentials: [{type: "password", value: $password, temporary: false}]
    }]
  }' \
  > "$work_dir/realm.json"

if [ "${E2E_CLUSTER:-direct}" = public-inbound ]; then
  E2E_BACKCHANNEL_URL=$(python3 "$script_dir/public-inbound.py" start \
    --run-id "$run_id" --application-code "$E2E_APPLICATION_CODE" \
    --opnsense-url "$opnsense_origin" --work-dir "$work_dir" --state "$public_inbound_state")
  python3 "$script_dir/public-inbound-canary.py" --origin "$E2E_BACKCHANNEL_URL" \
    --application-code "$E2E_APPLICATION_CODE"
else
  E2E_BACKCHANNEL_URL="https://${keycloak_host}:${E2E_BACKCHANNEL_PORT}"
fi
export E2E_BACKCHANNEL_URL

if [ "${E2E_CLUSTER:-direct}" = public-inbound ]; then
  E2E_SSF_ISSUER="https://${keycloak_host}:${E2E_SSF_PORT}/ssf"
  E2E_SSF_OIDC_ISSUER="${keycloak_origin}/realms/${E2E_KEYCLOAK_REALM}"
  E2E_SSF_PUSH_URL="${E2E_BACKCHANNEL_URL}/api/openidconnect/ssf/push/${E2E_APPLICATION_CODE}"
  ssf_image=$(python3 "$script_dir/providers/image.py" node)
  docker run -d --name "$ssf_container" -p "${E2E_SSF_PORT}:4443" \
    -e "E2E_SSF_ISSUER=${E2E_SSF_ISSUER}" \
    -e "E2E_SSF_AUDIENCE=${E2E_SSF_AUDIENCE}" \
    -e "E2E_SSF_PUSH_SECRET=${E2E_SSF_PUSH_SECRET}" \
    -e "E2E_SSF_TRIGGER_SECRET=${E2E_SSF_TRIGGER_SECRET}" \
    -e "E2E_SSF_OIDC_ISSUER=${E2E_SSF_OIDC_ISSUER}" \
    -e "E2E_SSF_SUBJECT=${E2E_SSF_SUBJECT}" \
    -e "E2E_SSF_PUSH_URL=${E2E_SSF_PUSH_URL}" \
    -e E2E_SSF_CERTIFICATE=/tls/server.crt -e E2E_SSF_KEY=/tls/server.key \
    -v "$work_dir/server.crt:/tls/server.crt:ro" \
    -v "$work_dir/server.key:/tls/server.key:ro" \
    -v "$script_dir/ssf-transmitter.mjs:/e2e/ssf-transmitter.mjs:ro" \
    "$ssf_image" node /e2e/ssf-transmitter.mjs >/dev/null
  attempt=0
  until keycloak_curl -ksSf --resolve \
      "${keycloak_host}:${E2E_SSF_PORT}:${E2E_PROVIDER_BROWSER_IP:-127.0.0.1}" \
      "https://${keycloak_host}:${E2E_SSF_PORT}/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 30 ] || { docker logs "$ssf_container" >&2; exit 1; }
    sleep 1
  done
  export E2E_SSF_ISSUER E2E_SSF_AUDIENCE E2E_SSF_SUBJECT E2E_SSF_PUSH_SECRET E2E_SSF_TRIGGER_SECRET
fi

proxy_origin_listener=
[ "$opnsense_port" = 8443 ] || proxy_origin_listener="listen ${opnsense_port} ssl;"
cat > "$work_dir/nginx.conf" <<EOF
events {}
http {
  access_log off;
  error_log /dev/null crit;
  server {
    listen 8443 ssl;
    ${proxy_origin_listener}
    ssl_certificate /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;
    location / {
      proxy_pass ${opnsense_origin};
      proxy_ssl_verify off;
      proxy_set_header Host ${opnsense_authority};
    }
  }
}
EOF

nginx_image='nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236'
proxy_publish=
[ "${E2E_CLUSTER:-direct}" = public-inbound ] || proxy_publish="-p ${E2E_BACKCHANNEL_PORT}:8443"
# shellcheck disable=SC2086 -- the optional publication is one numeric port mapping.
docker run -d --name "$proxy_container" $proxy_publish \
  --add-host "${opnsense_host}:host-gateway" \
  -v "$work_dir/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$work_dir/server.crt:/etc/nginx/tls/server.crt:ro" \
  -v "$work_dir/server.key:/etc/nginx/tls/server.key:ro" \
  "$nginx_image" >/dev/null

keycloak_repository='quay.io/keycloak/keycloak'
default_keycloak_image="${keycloak_repository}@sha256:831330513f55695572286e521f94fcd3c7e285250ed5b848090265a33192f669"
keycloak_image=${E2E_KEYCLOAK_IMAGE:-$default_keycloak_image}
docker run -d --name "$keycloak_container" -p "${keycloak_port}:8443" \
  --add-host "${keycloak_host}:host-gateway" \
  -e "KC_BOOTSTRAP_ADMIN_USERNAME=${E2E_KEYCLOAK_ADMIN_USERNAME}" \
  -e "KC_BOOTSTRAP_ADMIN_PASSWORD=${E2E_KEYCLOAK_ADMIN_PASSWORD}" \
  -e KC_TRUSTSTORE_PATHS=/opt/keycloak/conf/e2e-ca.crt \
  -v "$work_dir/server.crt:/opt/keycloak/conf/e2e-server.crt:ro" \
  -v "$work_dir/server.key:/opt/keycloak/conf/e2e-server.key:ro" \
  -v "$work_dir/ca.crt:/opt/keycloak/conf/e2e-ca.crt:ro" \
  -v "$work_dir/realm.json:/opt/keycloak/data/import/${E2E_KEYCLOAK_REALM}-realm.json:ro" \
  "$keycloak_image" \
  start-dev --import-realm \
  --https-certificate-file=/opt/keycloak/conf/e2e-server.crt \
  --https-certificate-key-file=/opt/keycloak/conf/e2e-server.key \
  --hostname="$keycloak_origin" --hostname-strict=true --http-enabled=false >/dev/null

attempt=0
discovery_path="/realms/${E2E_KEYCLOAK_REALM}/.well-known/openid-configuration"
until keycloak_curl -ksSf "${keycloak_origin}${discovery_path}" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$(docker inspect -f '{{.State.Running}}' "$keycloak_container")" != "true" ]; then
    docker logs "$keycloak_container" >&2
    exit 1
  fi
  [ "$attempt" -lt 60 ] || { docker logs "$keycloak_container" >&2; exit 1; }
  sleep 1
done

# Imported users do not receive the realm's default role automatically. The
# account console needs its inherited account roles for the IdP-initiated
# front-channel logout scenario, so grant exactly that generated default role.
admin_token=$(keycloak_curl -ksSf \
  --data-urlencode grant_type=password \
  --data-urlencode client_id=admin-cli \
  --data-urlencode "username=${E2E_KEYCLOAK_ADMIN_USERNAME}" \
  --data-urlencode "password=${E2E_KEYCLOAK_ADMIN_PASSWORD}" \
  "${keycloak_origin}/realms/master/protocol/openid-connect/token" | jq -r .access_token)
users_api="${keycloak_origin}/admin/realms/${E2E_KEYCLOAK_REALM}/users"
test_user_id=$(keycloak_curl -ksSf -H "Authorization: Bearer ${admin_token}" \
  "${users_api}?username=${E2E_TEST_USERNAME}&exact=true" | jq -r '.[0].id')
default_role=$(keycloak_curl -ksSf -H "Authorization: Bearer ${admin_token}" \
  "${keycloak_origin}/admin/realms/${E2E_KEYCLOAK_REALM}/roles/default-roles-${E2E_KEYCLOAK_REALM}")
printf '%s\n' "$default_role" | jq '[.]' | keycloak_curl -ksSf -o /dev/null -X POST \
  -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' \
  --data-binary @- \
  "${keycloak_origin}/admin/realms/${E2E_KEYCLOAK_REALM}/users/${test_user_id}/role-mappings/realm"

e2e_scp_to "$work_dir/ca.crt" "$remote_ca"
e2e_scp_to "$script_dir/remote-cleanup.php" "$remote_cleanup"
e2e_ssh "chmod 600 '$remote_ca' '$remote_cleanup'; certctl rehash"
if [ "$keycloak_host" = provider.opnsense.test ]; then
  # Late boot services may regenerate /etc/hosts after vm.py first prepared it.
  # Reassert only the fixed disposable-lab mapping at the actual network boundary.
  e2e_ssh \
    "grep -q '[[:space:]]provider\\.opnsense\\.test' /etc/hosts || printf '10.0.2.2\\tprovider.opnsense.test\\n' >> /etc/hosts"
fi
e2e_ssh "fetch -qo- '${keycloak_origin}/realms/${E2E_KEYCLOAK_REALM}/.well-known/openid-configuration' >/dev/null"
e2e_ssh \
  "fetch -qo- '${keycloak_origin}/realms/${E2E_KEYCLOAK_REALM}/.well-known/openid-configuration' >/dev/null"

python3 "$repository/packaging/build.py" --version 0.0.0.e2e >/dev/null
package="$repository/packaging/dist/os-openid-connect-0.0.0.e2e.pkg"
if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
  command -v git >/dev/null
  E2E_AUDIT_PACKAGE_NAME=os-openid-connect
  E2E_AUDIT_PACKAGE_VERSION=0.0.0.e2e
  E2E_AUDIT_PACKAGE_SHA256=$(openssl dgst -sha256 "$package" | awk '{print $NF}')
  E2E_AUDIT_SOURCE_REVISION=$(git -C "$repository" rev-parse HEAD)
  if git -C "$repository" diff --quiet --exit-code \
      && git -C "$repository" diff --cached --quiet --exit-code \
      && test -z "$(git -C "$repository" ls-files --others --exclude-standard)"; then
    E2E_AUDIT_SOURCE_DIRTY=false
  else
    E2E_AUDIT_SOURCE_DIRTY=true
  fi
fi
e2e_scp_to "$package" "/tmp/os-openid-connect-e2e-${run_id}.pkg"
e2e_ssh \
  "pkg add -f '/tmp/os-openid-connect-e2e-${run_id}.pkg' && pkg check -s os-openid-connect"
if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
  E2E_AUDIT_OPNSENSE_VERSION=$(e2e_ssh \
    "opnsense-version -v 2>/dev/null || pkg query '%v' os-core" | sed -n '1p')
fi

# ZAP sees only traffic deliberately sent through its local proxy. The image is
# pinned because passive-rule changes must arrive as reviewed test changes, not
# silently turn a later run red. Its API is exposed on a random loopback port
# without a key; nothing outside this runner can reach it.
zap_image="ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
zap_host_args=
case "$opnsense_host" in
  *:*) ;;
  *[!0-9.]*)
    if [ -n "${E2E_PROVIDER_BROWSER_IP:-}" ]; then
      opnsense_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "$proxy_container")
    else
      opnsense_address=$(python3 -c \
        'import socket,sys; print(socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)[0][4][0])' \
        "$opnsense_host")
    fi
    zap_host_args="--add-host=${opnsense_host}:${opnsense_address}"
    ;;
esac
# shellcheck disable=SC2086 -- the optional argument is one URL-validated host mapping
# ZAP reaches the nginx relay directly inside Docker. Only nginx crosses Docker
# Desktop's route to QEMU, avoiding an unstable pooled ZAP origin connection.
docker run -d --name "$zap_container" -p 127.0.0.1::8080 $zap_host_args \
  "$zap_image" zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true \
  -config 'api.addrs.addr.name=.*' \
  -config api.addrs.addr.regex=true >/dev/null
zap_port=$(docker port "$zap_container" 8080/tcp | sed -n '1s/.*://p')
test -n "$zap_port"
E2E_ZAP_PROXY="http://127.0.0.1:${zap_port}"
E2E_ZAP_API=$E2E_ZAP_PROXY
E2E_ZAP_API_HOST='127.0.0.1:8080'
E2E_ZAP_REPORT="$work_dir/security-headers.json"
export E2E_ZAP_PROXY E2E_ZAP_API E2E_ZAP_API_HOST E2E_ZAP_REPORT

attempt=0
until curl -fsS -H "Host: ${E2E_ZAP_API_HOST}" \
  "${E2E_ZAP_API}/JSON/core/view/version/" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$(docker inspect -f '{{.State.Running}}' "$zap_container")" != "true" ]; then
    docker logs "$zap_container" >&2
    exit 1
  fi
  [ "$attempt" -lt 90 ] || { docker logs "$zap_container" >&2; exit 1; }
  sleep 1
done

# Low thresholds make redirects and error responses visible to the focused
# rules. The report applies endpoint-aware exceptions afterwards.
for scanner in 10015 10019 10020 10021 10038 10055; do
  curl -fsS -H "Host: ${E2E_ZAP_API_HOST}" \
    "${E2E_ZAP_API}/JSON/pscan/action/setScannerAlertThreshold/?id=${scanner}&alertThreshold=LOW" \
    | jq -e '.Result == "OK"' >/dev/null
done

# ZAP's API can be ready before its first proxied TLS connection to the newly
# started WebGUI succeeds. Warm that exact browser path so a transient origin
# 502 cannot become the first Playwright assertion.
attempt=0
until curl -ksSf --noproxy '' --proxy "$E2E_ZAP_PROXY" \
  "${E2E_OPNSENSE_URL}/api/openidconnect/auth/formscript" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$(docker inspect -f '{{.State.Running}}' "$zap_container")" != "true" ]; then
    docker logs "$zap_container" >&2
    exit 1
  fi
  [ "$attempt" -lt 30 ] || { docker logs "$zap_container" >&2; exit 1; }
  sleep 1
done

(cd "$script_dir" && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null)
if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
  E2E_PLAYWRIGHT_AUDIT_RESULT="$work_dir/playwright-audit.json"
  export E2E_PLAYWRIGHT_AUDIT_RESULT
fi
(cd "$script_dir" && npx playwright test --config playwright.config.mjs)
if [ -z "${E2E_DOCUMENTATION_SCREENSHOTS:-}" ]; then
  (cd "$script_dir" && node zap-report.mjs)
fi

if [ -n "${E2E_AUDIT_EVIDENCE:-}" ]; then
  E2E_AUDIT_KEYCLOAK_IMAGE=$keycloak_image
  E2E_AUDIT_ZAP_IMAGE=$zap_image
  E2E_AUDIT_PLAYWRIGHT_VERSION=$(cd "$script_dir" && npx playwright --version | sed 's/^Version //')
  export E2E_AUDIT_EVIDENCE E2E_AUDIT_SOURCE_REVISION E2E_AUDIT_SOURCE_DIRTY
  export E2E_AUDIT_PACKAGE_NAME E2E_AUDIT_PACKAGE_VERSION E2E_AUDIT_PACKAGE_SHA256
  export E2E_AUDIT_OPNSENSE_VERSION E2E_AUDIT_KEYCLOAK_IMAGE E2E_AUDIT_ZAP_IMAGE
  export E2E_AUDIT_PLAYWRIGHT_VERSION
  (cd "$script_dir" && node audit-evidence.mjs)
fi

if [ -n "${E2E_PROVIDER_RESULT:-}" ]; then
  provider_capabilities='--capability back_logout=pass'
  if [ "${E2E_CLUSTER:-direct}" = direct ]; then
    provider_capabilities="$provider_capabilities --capability login=pass --capability pkce=pass"
    provider_capabilities="$provider_capabilities --capability rp_logout=pass --capability front_logout=pass"
  else
    provider_capabilities="$provider_capabilities --capability shared_signals=pass"
  fi
  # shellcheck disable=SC2086 -- capability arguments are fixed above.
  python3 "$script_dir/provider-result.py" --provider keycloak --source local \
    --cluster "${E2E_CLUSTER:-direct}" --subject-name keycloak \
    --subject-revision "version:$(python3 "$script_dir/providers/image.py" keycloak --metadata | jq -r .tag)" \
    --profile keycloak $provider_capabilities --output "$E2E_PROVIDER_RESULT"
fi

if [ -n "$documentation_screenshot_output" ]; then
  for screenshot_name in $documentation_screenshot_names; do
    test -s "$E2E_DOCUMENTATION_SCREENSHOTS/$screenshot_name"
    cp "$E2E_DOCUMENTATION_SCREENSHOTS/$screenshot_name" \
      "$documentation_screenshot_output/.${screenshot_name}.${run_id}.tmp"
  done

  # The five maintained images form one documentation artifact. Move every old
  # member aside before publishing any new member, and let the EXIT/signal trap
  # restore the complete old set if either phase stops part-way through.
  documentation_publish_phase=backing-up
  for screenshot_name in $documentation_screenshot_names; do
    screenshot_target="$documentation_screenshot_output/$screenshot_name"
    screenshot_backup="$documentation_screenshot_output/.${screenshot_name}.${run_id}.backup"
    if [ -e "$screenshot_target" ]; then
      mv "$screenshot_target" "$screenshot_backup"
    fi
  done
  documentation_publish_phase=publishing
  for screenshot_name in $documentation_screenshot_names; do
    mv "$documentation_screenshot_output/.${screenshot_name}.${run_id}.tmp" \
      "$documentation_screenshot_output/$screenshot_name"
  done
  documentation_publish_phase=published
  for screenshot_name in $documentation_screenshot_names; do
    rm -f "$documentation_screenshot_output/.${screenshot_name}.${run_id}.backup" || true
  done
fi
