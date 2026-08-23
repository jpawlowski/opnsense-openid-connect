# Comparison with OPNsense Business Edition OpenID Connect

This comparison is limited to published functionality. “Not documented” means
the public OPNsense manual does not state the behaviour; it does **not** mean the
commercial implementation lacks an internal control.

## Scope

| | This plugin | OPNsense Business Edition |
|---|---|---|
| WebGUI / Admin login | yes | yes |
| Captive Portal | intentionally no | yes |
| OPNWAF / reverse-proxy authentication | intentionally no | yes |
| Availability | community package installed manually | Business Edition feature |

The official manual describes three service choices and their distinct
endpoints: WebGUI/Admin, Captive Portal and OPNWAF. The extra two are useful but
outside this project's explicit purpose.

## WebGUI feature comparison

| Area | This plugin | Published Business Edition behaviour |
|---|---|---|
| Configuration location | System > Access > Servers | System > Access > OpenID Connect |
| Discovery/client basics | issuer/discovery, client ID/secret | provider URL, client ID/secret |
| Token client authentication | follow metadata or require Basic/POST | Basic, POST, or follow provider |
| Provider presets/guides | 25 complete named presets plus Generic; fixed invariants are locked and all values have guides | no public provider profile matrix documented |
| Provider onboarding | generated, no-secret authentik Blueprint and Keycloak partial import; complete manual guides remain | no public import/onboarding generator documented |
| Callback separation | unique application code per provider | application code per provider |
| PKCE S256, nonce, state | always; documented and tested | not documented publicly |
| Multi-issuer mix-up controls | distinct callbacks, frozen metadata, RFC 9207 when advertised | not documented publicly |
| Signature algorithms/claim validation | explicit RSA/PSS/ECDSA and strict claim policy | not documented publicly |
| Claims source | ID Token, UserInfo, or automatic | user identification from UserInfo is documented |
| Stable local identity | persistent exact `(issuer, sub)` to numeric UID | name claim plus documented user creation/update; stable subject binding not documented |
| Existing/JIT users | strict or administrator-approved admission, opt-in automatic matching/JIT, disabled/expired/root checks | create/update local users documented |
| Groups | off by default, explicit assignable scope | group claim, create/update groups documented |
| WebGUI address policy | follows OPNsense names, actual local addresses, virtual IPs and WebGUI port by default, with additions or an exact provider-specific replacement | not documented publicly |
| Logout | local, RP-initiated, revocation, front/back-channel | public WebGUI section does not document logout controls |
| Shared Signals | optional signed SSF push receiver for selected CAEP/RISC events; session termination only | not documented publicly |
| Diagnostics | authenticated discovery probe, non-mutating full browser sign-in test, generic public errors, audit references, watchdog | general setup fields documented; equivalent diagnostics not documented |
| Core integration/support | external plugin; compatibility watchdog and best-effort project support | vendor-integrated commercial firmware path |

The packages use separate configuration keys, authentication-server types,
namespaces and API paths. The plugin also redirects the Lobby logout menu only
for a session it created, leaving local and other integrations' session paths
alone. Parallel installation with Business Edition is nevertheless described
as structurally compatible rather than practically verified until it has been
tested on a licensed disposable installation.

## Cost and operational trade-off

As checked in August 2026, the official shop lists Business Edition at €149 per
year for one installation. It includes a selective commercial update track and
other professional features; OIDC is not presented as a separately purchased
standalone package. The commercial option therefore buys more than WebGUI OIDC,
including vendor integration and the two extra OIDC service areas.

This plugin is the more focused choice when only WebGUI login is wanted and the
operator values transparent protocol policy, provider-specific guidance and
community review. The commercial edition is the stronger operational choice
when Captive Portal/OPNWAF coverage, official integration, or a commercial
firmware/support relationship matters.

## Sources

- [Official OPNsense OpenID Connect manual](https://docs.opnsense.org/vendor/deciso/oidc.html)
- [Official OPNWAF manual](https://docs.opnsense.org/vendor/deciso/opnwaf.html)
- [OPNsense user-management manual](https://docs.opnsense.org/manual/users.html)
- [Official Business Edition shop page](https://shop.opnsense.com/product/opnsense-business-edition/)
