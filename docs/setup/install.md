# Install or remove the package

This is a manually installed package. It does not add a package repository or
enable automatic updates.

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

When replacing one of the historical `v1.0.0-betaN` packages with `v1.0.0`,
use `pkg add -f` for this one upgrade. Those beta packages used a legacy package
version that FreeBSD sorts after `1.0.0`; the installed paths and settings did
not change.

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
