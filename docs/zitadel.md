# Zitadel

Zitadel is the one provider here that can be configured to sign with a key this
plugin cannot verify. Everything else about it is unremarkable.

## At Zitadel

**Create a project** if you have none, then *Applications > New*.

| Step | Setting | Value |
|---|---|---|
| Name and type | Type | **WEB** — the confidential kind |
| Authentication method | | **Basic** (or **Post**; both are supported) |
| Redirect settings | Redirect URIs | one entry per address, each ending in `/api/openidconnect/auth/callback` |
| | Post logout URIs | `https://<firewall>/` if you want *Return here after logout* |

Do **not** pick *PKCE* as the authentication method: that is the public-client
option and issues no client secret, which this plugin requires. It sends PKCE
regardless — the two are independent.

The final step shows the **Client ID** and **Client Secret** once. Take them
then; the secret is not shown again.

Who may sign in is decided by the project's authorizations, as with any other
Zitadel application.

## On the firewall

| Field | Value |
|---|---|
| Provider URL | `https://<instance>.zitadel.cloud` or your own domain |
| Username claim | `preferred_username` |
| Scopes | `openid,email,profile` |

## Worth knowing

**Keep the signing key RSA.** Zitadel's web keys can be RSA, ECDSA or ED25519.
RSA 2048 with SHA-256 is what it creates when nothing is specified, and it is the
only one of the three that works here — a login signed with ECDSA or ED25519 is
refused with `Refusing a token signed with ...`. If you have ever created a web
key by hand, check which one is active.

**Profile claims are not in the id_token by default**, and they do not need to
be. Zitadel follows the specification strictly: when an access token is issued,
the id_token carries no claims from the `profile`, `email`, `phone` or `address`
scopes. They come from the UserInfo endpoint, which this plugin always calls.
The application setting *User Info inside ID Token* is therefore unnecessary —
harmless if it is on, since claims from both places are read anyway.

**Group mapping uses roles**, which Zitadel returns in a shape of its own: the
claim is named after the project
(`urn:zitadel:iam:org:project:<project id>:roles`) and its value is an object
keyed by role name rather than a list. That is understood — the keys are taken as
the names — so putting that claim in *Group claim* works, provided the roles are
named like the local OPNsense groups. Add `urn:zitadel:iam:org:projects:roles`
to the scopes so the claim is issued at all, and set *Assignable groups* to keep
the provider from touching anything you did not intend.
