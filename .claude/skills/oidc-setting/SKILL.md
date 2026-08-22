---
name: oidc-setting
description: Add, change or remove a setting of the OpenID Connect authentication server (a field under System > Access > Servers, an openidconnect_* key in config.xml). Use when a request needs a new option, a changed default, different help text, or a field retired - the field itself is the smallest part of the work, and the places that go stale are not next to it.
---

# Changing a setting

A field is cheap to add and expensive to add *incompletely*: the accessor, the
two documentation tables, the tests and the upgrade note all live away from the
field, and none of them fail when they are forgotten. Work through the list.

## Before anything

Ask whether it should be a setting at all. What the protocol decides is not an
installation's to differ on — algorithms, `exp`, `nonce`, `azp`, the subject
binding — and those live in `RelyingParty.php` as checks, not as fields. A
setting is for what genuinely differs between installations: an address, a
claim name, whether to trust something a particular provider does not send.

If it widens what an identity provider can reach on the firewall, it is off by
default and its help text says why.

## The field

`OpenIDConnect::getConfigurationOptions()` in
`src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php`.

- The key carries the `openidconnect_` prefix, because core stores these flat,
  as siblings of the `refid`, `type` and `name` it writes itself, in one
  `<authserver>` entry shared with every other kind of authentication server.
  A renamed key is a key an existing configuration no longer has, so whether a
  rename is worth it — and whether the old name is worth reading as a fallback —
  is a decision about what has already been released, and belongs to whoever is
  making the change.
- `type` is `text`, `dropdown` or `checkbox`. Anything richer is upgraded in the
  browser by `assets/settings-form.js`, delivered through the last, contentless
  `__openidconnect_form` entry — which must stay last in the array.
- `validate` returns a list of messages, empty when it is fine. Refuse at the
  form what would otherwise fail at a login: it is the difference between a
  message while somebody is configuring and a message while somebody is locked
  out. Reuse `isFetchableUrl()` / `hasControlCharacters()` rather than writing a
  fourth regex.
- The help text says what it does *and*, where it matters, what it costs. This
  form is read by people who are about to hand part of a firewall's privilege
  assignment to somebody else's server.

## The accessor

Same file, the `/* settings */` section. One accessor per field, so that every
default sits in exactly one place and no caller sees a half-parsed value. Use
`text()`, `flag()` or `choice()` — do not read `$this->settings` directly.

Two traps that have already cost something here:

- `empty('0')` is true in PHP, so a typed zero silently means "unset". Use an
  explicit comparison, as `maximumAuthenticationAge()` does.
- Group names reach core lower case and nothing else, because
  `setGroupMembership()` compares against `strtolower()` of the local name. A
  name with a capital matches nothing and disables the sync in silence. See
  `defaultGroups()`.

## The documentation

Both tables, and they are not the same table:

- `README.md`, the settings table — one line, what it is.
- `docs/README.md`, *What to fill in on the firewall* — what to actually put
  there, and a section of its own if the choice needs explaining.
- The provider pages under `docs/` when a particular provider forces the
  choice. Microsoft Entra ID is usually the one.

## The tests

`tests/unit/settings.php`: the default when the field is empty, a nonsense
value falling back to the default, and what the validator refuses. If the
setting changes who gets in, it belongs in `tests/unit/accounts.php`; if it
changes group membership, in `tests/unit/groups.php` — assert what reaches
`setGroupMembership()`, which is what core acts on.

    ./tests/run.sh

## If a default changes

A default that changes can turn a login that worked into one that does not, on
the next release somebody installs. Then:

- the commit is `fix(auth)!:` or `feat(auth)!:` with a `BREAKING CHANGE:`
  footer saying **what to set**, not that something changed — it goes verbatim
  to the top of the release note, which is where an operator reads it;
- the refusal at runtime says enough for somebody to find the setting, while
  still saying nothing about which accounts exist (see `CLAUDE.md`).
