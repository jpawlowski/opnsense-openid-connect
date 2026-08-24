# Install or remove the beta package

Copyright (C) 2026 Julian Pawlowski. All rights reserved. BSD-2-Clause, see
LICENSE at the repository root.

The beta is a manually installed package. It does not add a package repository
or enable automatic updates.

## Before installing

- Keep a working local OPNsense administrator account.
- Download the `.pkg` file and published checksum from the matching immutable
  GitHub release onto an administrator workstation.
- Verify that the package was built by this repository's release workflow.

GitHub CLI can verify the keyless build provenance:

```sh
gh attestation verify /tmp/os-openid-connect-<version>.pkg \
  -R jpawlowski/opnsense-openid-connect \
  --signer-workflow jpawlowski/opnsense-openid-connect/.github/workflows/build.yml \
  --deny-self-hosted-runners
```

Also compare the downloaded bytes with the checksum shown by the release:

```sh
sha256 -c <expected-checksum> /tmp/os-openid-connect-<version>.pkg
```

A checksum detects a changed download. The attestation additionally binds those
bytes to this repository, the release workflow and its source revision.

## Install

Copy the verified package to the firewall, then install that exact file:

```sh
pkg add /tmp/os-openid-connect-<version>.pkg
```

No restart is required. Continue with the [step-by-step setup](README.md) and
keep the provider disabled until Discovery, sign-in and local recovery have all
been tested.

## Remove

```sh
pkg delete os-openid-connect
```

Removing the package leaves its settings in `/conf/config.xml`. The local
username/password login remains available.

The release and offline-signature design is documented in
[packaging/README.md](../../packaging/README.md).
