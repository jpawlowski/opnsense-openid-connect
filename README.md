# OpenID Connect sign-in for the OPNsense web interface

Adds a "Login with …" entry to the OPNsense login page and turns a successful
OpenID Connect exchange into a web interface session. Local sign-in with a
username and password is untouched and always remains available.

OPNsense itself offers OpenID Connect only in the Business Edition
([`opnsense/core#6110`][core6110] is closed as not planned), which is why this
exists.

## What it does

* Authorization Code flow with PKCE (`S256`) against any provider that publishes
  a discovery document.
* Maps the signed-in person to a **local** account, by the configured claim or by a
  verified e-mail address. Creating accounts on first sight is possible and off by
  default; an account that is disabled or expired locally is refused here as it is at
  the password form, and `root` is out of the provider's reach unless asked for.
* Ends the session at the provider as well, not only here.
* Everything an installation differs on is a setting under
  *System > Access > Servers*; nothing is compiled in.

**Privileges stay local unless you say otherwise.** No group claim is consumed
until one is configured, so out of the box, taking over the identity provider
does not by itself grant anyone rights on the firewall. Group mapping is there
if you want it — see *Group claim* below — but it is a deliberate decision,
because it hands part of this firewall's privilege assignment to the provider.

## What it checks

The exchange is carried out by the bundled [Jumbojett client][jumbojett], which
refuses `alg: none` and a key smuggled in through the token header, verifies TLS
peer and host, and keeps the implicit flow off. What that library leaves to its
caller is decided here, in `RelyingParty`, and deliberately **not** exposed as a
setting — this is what the protocol asks for, not a matter of local taste:

| | |
|---|---|
| Signature algorithm | decided from what the provider advertises, asymmetric only. `HS*` keys the signature with the client secret, a different trust model — and the algorithm is named in the attacker-supplied token header. |
| `exp`, `nonce` | required on the id_token. The library checks each only where the claim is present, so a token that simply leaves one out would pass. |
| `azp` | required once a token names several audiences, [OIDC Core 3.1.3.7][core3137]. The library is satisfied by this firewall being among them, which a token minted for a neighbouring client would be too. |
| `state` | checked before the answer is acted on, rather than after the code has been handed to the token endpoint. |
| UserInfo subject | bound to the id_token subject, [OIDC Core 5.3.2][core532]. The library does this for a signed UserInfo response but not for the plain JSON one — which is the usual case, and the response the local account is identified from. |
| Redirect address | chosen from an allow list by matching the name the browser used. A name that is not listed is refused, rather than the browser being sent off to finish somewhere it has no session. The list is required: without one, the address handed to the provider would be whatever name a browser asked under. |
| Session id | rotated once the session gains privileges. |
| Refusals | one sentence and one status code for every local-account outcome — no account, disabled, expired, root, an address the provider would not vouch for. Which one it was goes to the log alone, so a refusal answers nothing about who exists here. |
| Local account | disabled, expired, and `root` are refused, the way core's own password login refuses them. Nothing looks at this again once a session exists. |
| Provider addresses | every address out of the discovery document is fetched over http or https and nothing else; curl speaks a good deal more. |
| `max_age` | optional; when set, the returned `auth_time` is checked rather than trusted, because a provider may ignore the request. |
| Timeouts | every call to the provider is bounded, so nothing it does can hold the web interface open. |

## Setting it up

Step-by-step guides per provider are in [`docs/`](docs/):
[Microsoft Entra ID](docs/entra-id.md) ·
[authentik](docs/authentik.md) ·
[Keycloak](docs/keycloak.md) ·
[Authelia](docs/authelia.md) ·
[Zitadel](docs/zitadel.md).
The [index](docs/README.md) covers what every provider has to offer, how someone
becomes a local account, and what the refusal messages mean.

## Settings

Under *System > Access > Servers*, add a server of type **OpenID Connect**.

| Setting | |
|---|---|
| Provider URL | the issuer, or its discovery document |
| Client ID / Secret | this firewall is a confidential client |
| Username claim | which claim names the local account |
| Match by e-mail address | whether the `email` claim may name it too, and whether the provider has to have verified it |
| Scopes | requested alongside `openid` |
| Accepted redirect URLs | the addresses the provider may return to; required, an empty list accepts nothing |
| Maximum authentication age | seconds; empty accepts any session the provider has |
| Authentication method | how the firewall proves itself at the token endpoint; follow the provider unless it advertises something it will not accept |
| Create an account on first login | off by default, with the groups a new account starts in |
| Allow the built-in root account | off by default |
| Group claim | which claim carries group names; empty means membership is decided locally |
| Assignable groups | the only local groups the provider may grant or withdraw |
| Trace the exchange | writes the shape of a login to syslog while you work out why one is refused |
| Redirect the Log Out menu entry | points *Lobby > Log Out* at the provider-aware logout |
| Return here after logout | the provider must accept this firewall as a post logout redirect URI |
| Login button style, Icon URL, Icon markup, Icon rendering | how the entry is drawn |
| Custom button markup | full control, `%name%` `%url%` `%icon%` are filled in |

The provider needs `https://{firewall}/api/openidconnect/auth/callback` as a redirect URI.

### The icon

An **Icon URL** may be an absolute address (fetched by the firewall and handed
on), a path on the firewall itself such as
`/ui/themes/<theme>/build/images/icon-logo.svg` (served directly, no third-party
request from the login page), or a `data:` URI. **Icon markup** takes SVG source
instead, for when there is nowhere to host a file; it becomes a `data:` URI and
is never inlined into the page, so it is only ever treated as an image.

*Single colour* rendering redraws the icon in the button's text colour, which is
what makes a dark provider logo readable on a coloured button in a light and a
dark theme alike. It works for line art; a logo with a filled background becomes
a solid block.

### What this deliberately does not do

The Business Edition module covers three services; this one covers the web
interface. **Captive Portal** and **OPNWAF** are not implemented — the first
because writing an integration nobody here can exercise would be guesswork
rather than work, the second because it is a Business Edition product.

Tracing never writes tokens, secrets or claim values that are not needed to
follow the flow. A trace that ends up in a support mail should not carry
material that grants access.

## Logging out

`/api/openidconnect/auth/logout` ends the local session and continues into the provider's
`end_session` endpoint, handing back the tokens on the way. The *Lobby > Log Out*
menu entry can be pointed at it with a setting.

**The link in the page header cannot be.** It is written into core's
`authgui.inc`, out of a plugin's reach, and always ends locally.

## Installing

Download the `.pkg` from the [releases](../../releases) and install it:

```sh
pkg add /tmp/os-openid-connect-<version>.pkg
```

`pkg` checks nothing about a file handed to it directly, so a release carries a
`.sha256` next to the package, and a signature where a release key is
configured. [`packaging/README.md`](packaging/README.md) says how to check both.

No restart, no service touched — PHP reads the files on the next request. The
only runtime dependency beyond OPNsense itself is `phpseclib3`, which OPNsense
already ships.

Building it yourself needs neither FreeBSD nor `pkg`: `packaging/build.py`
writes the package with nothing but the Python standard library. The version
comes from the git tag, so it is stated in exactly one place. See
[`packaging/README.md`](packaging/README.md) for that, for the watchdog that
fetches the login page every night, and for the way back.

The watchdog has nothing to configure. Findings go to the system log, and to
`root` by mail where the machine has a mail transport — OPNsense ships none, so
that means `os-postfix` or another package. Where to send root's mail is that
package's own question, and asking it twice would not help.

## Tests

    ./tests/run.sh

Syntax for every language in the tree, behaviour checks against stand-ins for
the OPNsense classes, what a commit message may be, and checks on the package
that gets built — including that nothing of whoever built it travels along with
it. No Composer, no PHPUnit, no network, no OPNsense needed. See
[`tests/README.md`](tests/README.md) for what is covered and what deliberately
is not, and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the shape a commit message
has and why the release note depends on it.

## Licence

BSD-2-Clause, see [`LICENSE`](LICENSE). One third-party file is bundled under
Apache-2.0; its provenance and update rules are in
[`packaging/VENDOR.md`](packaging/VENDOR.md).

[core6110]: https://github.com/opnsense/core/issues/6110
[core532]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
[core3137]: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
[jumbojett]: https://github.com/jumbojett/OpenID-Connect-PHP
