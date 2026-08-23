# Support and compatibility

## Release gates

| Target | Required evidence |
|---|---|
| OPNsense CE 26.1 | syntax/package checks and review of touched core interfaces; live test when a machine is available |
| OPNsense CE 26.7 | install/upgrade/remove, settings UI, login page, discovery, callback/error and watchdog checks on a real machine |
| authentik | complete Authorization Code login and logout test before first supported release |
| Microsoft Entra ID | documentation/conformance first; live login when a tenant test is available |
| other named profiles | official-document review; mark live results individually |

Passing local tests is necessary but not sufficient for a release. A provider
guide saying “documentation implemented” is not a claim that every provider
version has been tested.

## Current evidence (23 August 2026)

| Target | Result |
|---|---|
| OPNsense CE 26.7.2_2 | package lifecycle, WebGUI/API smoke, runtime crypto/indexes, public errors and watchdog passed |
| Google, Apple, JumpCloud US | live exact-issuer Discovery passed from OPNsense |
| OPNsense CE 26.1 | pending live machine |
| authentik | pending tenant/client details and trusted browser access |
| Microsoft Entra ID | documentation reviewed; live login pending |

## Compatibility reports

Please include:

- OPNsense and plugin versions;
- provider name/version/region and the exact issuer with sensitive tenant names
  replaced consistently;
- selected provider profile, claims source, response mode and token auth method;
- discovery test summary and browser error reference;
- relevant OIDC log lines with secrets, tokens and personal values removed.

Do not change validation to make a provider pass. A provider-specific profile
may select correct defaults or produce a useful diagnostic, but may not relax
issuer, signature, audience, nonce, time, subject binding, HTTPS or redirect
checks.

## Recovery

Keep a tested local administrator account. The password form remains present.
If the plugin prevents the login page from loading, remove it over SSH/console:

```sh
pkg delete -y os-openid-connect
```
