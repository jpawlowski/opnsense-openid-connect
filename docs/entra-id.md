# Microsoft Entra ID

Entra ID needs one setting that differs from every other provider here, and the
reason is worth reading before it costs an evening.

## The one thing that is different

Microsoft's UserInfo endpoint returns **only** `sub`, `name`, `family_name`,
`given_name`, `picture` and `email` — their documentation states that those are
all it can ever return and that it cannot be customised. `preferred_username`
is **not among them**; it lives in the id_token.

This plugin therefore reads the id_token and the UserInfo response together, so
`preferred_username` works anyway. Anything that only calls UserInfo — including
several other OIDC plugins — cannot see it.

`email` is only present when the user actually has a mailbox address and the
`email` scope is consented. For accounts without one, use `preferred_username`.

Entra ID also sends no `email_verified`, ever. So *Match by e-mail address*
stays at its default — *Only a verified address* — and matching by address
simply never happens, which is the right outcome while `preferred_username`
names the account. Where an installation does need the address to match, the
setting has to be moved to *Any address the provider reports*, and that means
accepting whatever Entra says the address is: worth a thought where guest
accounts from other tenants can appear in the directory.

## At Entra ID

**App registrations > New registration.**

| Setting | Value |
|---|---|
| Supported account types | whichever suits; single tenant for an appliance |
| Redirect URI | platform **Web**, one entry per address, each ending in `/api/openidconnect/auth/callback` |

Platform **Web** matters: it is the confidential kind. A "Single-page
application" registration has no client secret and cannot be used here.

**Certificates & secrets > New client secret.** Note the *Value*, not the
*Secret ID*. Note its expiry date too — Entra secrets expire, and when one does
the login stops with a token request failure.

**API permissions.** The delegated Microsoft Graph permissions `openid`,
`profile` and `email`. These are the ones the UserInfo endpoint needs.

**Token configuration** is not required. Optional claims change the id_token,
which this plugin does read, but nothing here depends on them.

## On the firewall

| Field | Value |
|---|---|
| Provider URL | `https://login.microsoftonline.com/<tenant id>/v2.0` |
| Username claim | `preferred_username` (from the id_token) or `email` |
| Scopes | `openid,email,profile` |

Use the tenant-specific issuer, not `/common/`: `/common/` issues tokens whose
`iss` differs per tenant, and the issuer check will refuse them.

## Worth knowing

**Do not add scopes for other APIs.** UserInfo is hosted by Microsoft Graph and
is called with the access token this exchange produced. Ask for a scope
belonging to some other resource and the access token is issued for that
resource instead, at which point Graph answers the UserInfo call with 401 and
the login fails.

**`sub` is pairwise.** Entra derives it per application registration, so the same
person has a different `sub` in a different app. It is stable for this one, which
is all the subject binding needs — but it is not an identifier to match accounts
on across systems. Match on `preferred_username` or `email`.

**Signing** is RS256 and not configurable, so the algorithm check is never in the
way here.
