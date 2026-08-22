# Tests

    ./tests/run.sh

The same command the pipeline runs, so a failure looks the same in both places.
Nothing here needs Composer, PHPUnit, a network or an OPNsense: the point of a
test suite for this plugin is that it can be run by whoever is about to change
something, wherever they are.

## What is covered

**`tests/unit/`** exercises the parts that decide things, through stand-ins for
the OPNsense classes (`tests/stubs/`):

| | |
|---|---|
| `settings.php` | reading a settings field: list parsing, the shapes a group claim arrives in, finding the issuer in whatever was typed, every default, which addresses may be fetched, and what the settings form refuses |
| `redirects.php` | choosing the address the provider returns to — the allow list, near-miss names, the empty-list fallback, a Host header that is not a host name, and whom a token was issued for |
| `claims.php` | reading claims from the id_token as well as UserInfo, and keeping protocol claims out |
| `exchange.php` | what is insisted on before an answer is acted on: the state, whom a token was issued for, and where the provider may send this firewall — the checks that would stop firing silently when the bundled library is updated |
| `accounts.php` | which local account a login is, and whether it may be used at all: disabled, expired, root, matching by a verified address, and creating one on first sight |
| `groups.php` | what is handed to core when group membership is synced — the spelling it compares against, and the scope it is allowed to act in |
| `loginpage.php` | what the login page is handed: which icon, which markup, and that a provider name cannot open a tag |

**`tests/convention.py`** checks the rule that decides what a commit message
may be, and what a release note makes of one. It is checked because the two
sides fail in opposite directions: a rule too strict refuses a message somebody
is trying to write, and a rule too loose lets a change reach a release with
nothing said about it in the note. The second is the one nobody notices.

**`tests/package.py`** builds the package and checks the result: the archive
shape `pkg` expects, that every file is listed with a matching checksum,
permissions and ownership, that the bundled licence text ships and documentation
does not — and that nothing carries the naming, addresses or hosts of whoever
built it, that everything is English, and that every file of ours says who wrote
it.

That last part is there because this package is meant to be handed to strangers.
It is a check, not a courtesy.

**It names nothing.** A check written as a list of the names to keep out is
itself a list of those names, published with the package — which is worse than
the thing it prevents. So it tests properties instead: an address literal that
is not the loopback or a documentation range, a host that is not the one the
manifest already declares, a mailbox that is not the declared maintainer. The
copyright line it looks for is read from `LICENSE` rather than written out.

That is also the stronger check. It catches whatever a future author leaves
behind, not only what this one happened to think of.

## What is deliberately not covered

Anything that only exists inside OPNsense: session handling, the dispatcher, the
real login page, and what core does with a group sync once it has been handed
one. A stub that grew far enough to test those would start passing tests the
real thing would fail.

The stubs do keep a list of local accounts and record what was asked of core,
because *what this plugin decides* about an account — which one a claim is,
whether it may be used, which groups core is allowed to touch — is exactly the
part worth checking, and none of it needs an OPNsense to be true.

That side is watched where it is real. `openid-connect-watch` runs on the
firewall every night and fetches the actual login page — see
[`../packaging/README.md`](../packaging/README.md).

## Adding a check

The Python checks share `tests/harness.py`, which is the same three things
`harness.php` is: a name per check, a readable failure, a non-zero exit code.

`Checks::that(what, actual, expected)` and `Checks::throws(what, callable)`.
`inspect($object, 'method', ...)` reaches a private one, `connector([...])`
builds a configured authentication server without a config file,
`directory([...], [...])` gives the machine some local accounts, and
`claims([...])` is the shape a verified answer arrives in. Name the check
after the behaviour, not the method — a failure should read like a sentence
about what broke.

Regression checks are worth their weight here. Two of the bugs this suite
covers — Entra ID's claims living only in the id_token, and a group claim
arriving as a map rather than a list — were found by writing documentation, not
by running code.
