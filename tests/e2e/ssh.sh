#!/bin/sh

# The local VM runner writes a short-lived OpenSSH configuration so ports,
# host-key pinning and the generated test key never have to be flattened into
# a shell string. Prepared lab firewalls keep using E2E_OPNSENSE_SSH directly.
e2e_ssh() {
  if [ -n "${E2E_OPNSENSE_SSH_CONFIG:-}" ]; then
    command ssh -F "$E2E_OPNSENSE_SSH_CONFIG" opnsense-e2e "$@"
  else
    command ssh -o BatchMode=yes "$E2E_OPNSENSE_SSH" "$@"
  fi
}

e2e_scp_to() {
  source_path=$1
  destination_path=$2
  if [ -n "${E2E_OPNSENSE_SSH_CONFIG:-}" ]; then
    command scp -q -F "$E2E_OPNSENSE_SSH_CONFIG" "$source_path" "opnsense-e2e:$destination_path"
  else
    command scp -q "$source_path" "$E2E_OPNSENSE_SSH:$destination_path"
  fi
}
