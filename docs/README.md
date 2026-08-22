# Setting this up

One page per identity provider:

* [Microsoft Entra ID](entra-id.md)
* [authentik](authentik.md)
* [Keycloak](keycloak.md)
* [Authelia](authelia.md)
* [Zitadel](zitadel.md)

They differ in the wording of their forms and in a few real quirks; what the
firewall needs is the same everywhere, and that part is here.

## What the firewall needs from a provider

| | |
|---|---|
| **A confidential client** | with a client secret. Public clients — PKCE without a secret — are not supported. |
| **A discovery document** | at `<issuer>/.well-known/openid-configuration`, reachable *from the firewall*. Everything else is read from there. |
| **RSA signatures** | `RS256` (or `RS384`, `RS512`, `PS256`, `PS512`). **ECDSA and EdDSA cannot be verified** and a login signed with one is refused. RS256 is every provider's default; only a deliberate change breaks this. |
| **A UserInfo endpoint** | it is called on every login, and its `sub` must match the `sub` of the id_token. |
| **This redirect URI** | `https://<firewall>/api/openidconnect/auth/callback` |

## What to fill in on the firewall

*System > Access > Servers*, add a server of type **OpenID Connect**.

| Field | Value |
|---|---|
| Descriptive name | anything; it appears on the login button and in the login URL |
| Provider URL | the issuer, or its discovery document |
| Client ID / Client Secret | from the provider |
| Username claim | the claim naming the local account — see the provider's page |
| Match by e-mail address | leave at *Only a verified address*, unless the provider sends no `email_verified` — see below |
| Scopes | `openid,email,profile` unless the provider's page says otherwise |
| Accepted redirect URLs | every address the web interface is reached under, one entry each — required |

Then *System > Settings > Administration* is **not** involved: the entry appears
on the login page by itself. Local sign-in with a username and password stays
where it is.

### Accepted redirect URLs

An allow list, and it is required. The address sent to the provider is picked
from it by matching the name the browser used; a name that is not listed is
refused with a message saying which ones are. So a firewall reachable under
several names keeps working — list them all, one entry each, and list the same
addresses at the provider as redirect URIs.

An empty list accepts nothing. Building the address from the `Host` header
instead would leave the address this firewall names to the provider up to
whoever is asking, with nothing but the provider's own strictness between a
browser and finishing somewhere else with an authorization code. Signing in
with a username and password does not depend on this field.

## How someone becomes a local account

There is no shadow user database. A successful login is mapped to a **local**
OPNsense account, in this order:

1. an account whose **name** equals the *username claim*
2. an account whose **e-mail address** equals the `email` claim — see below
3. otherwise: refused — unless *Create an account on first login* is on, in which case one
   is created (through the same mechanism OPNsense uses everywhere) and given the
   *Groups for a new account*

Privileges come from that local account. No group claim is consumed until *Group
claim* is filled in, which is a deliberate decision: it hands part of the
firewall's privilege assignment to the provider.

### Finding an account is not the same as being allowed to use it

Whoever the provider says somebody is, the local account still decides whether
they get in. Three things are refused here exactly as they are refused at the
password form:

* an account marked **disabled** — the usual way to end someone's access
* an account whose **expiry date** has passed
* **root**, and anything else with uid 0, unless *Allow the built-in root
  account* is switched on. It is the account the interface hands everything to
  without asking the privilege system, and it is the way back in when single
  sign-on is what broke.

Nothing re-checks any of this afterwards: once a session exists, OPNsense only
watches the clock. So it is checked on the way in.

### Matching by e-mail address

An address says who somebody is only where the provider has checked that it is
theirs. Wherever a person can type their own — self-registration, guest
accounts, a federated identity — an unverified address is a way onto somebody
else's local account. So *Match by e-mail address* has three settings and starts
at the middle one:

| | |
|---|---|
| Only a verified address | the default. The provider has to send `email_verified` |
| Any address the provider reports | for a provider that sends no such claim at all — **Microsoft Entra ID is one** |
| Never | the username claim decides alone |

### A refusal says nothing about who exists here

Why a login was refused is in the firewall's log and never in the answer the
browser gets. No local account of that name, an account that is disabled,
expired or `root`, an address the provider would not vouch for: every one of
them ends in the same sentence and the same status code, and they differ only in
the log line written just before it.

That is deliberate. Anyone who can sign in at the identity provider can reach
the callback, and a refusal that said *which* of those it was would answer the
question of which accounts this firewall has, and what state they are in, to
whoever asked. So the reason goes where the person running the firewall can read
it, and nowhere else.

### Group names are compared in lower case

Which is what OPNsense itself does: `setGroupMembership()` matches against
`strtolower()` of the local group name. A name typed with a capital in *Groups
for a new account* or *Assignable groups* therefore matches nothing, and the
sync does nothing at all without saying so. Write them as the group is written.

### Claims are read from both places

Providers disagree about where a claim belongs. So the claim set is the id_token
and the UserInfo response taken together, with UserInfo winning where they
overlap. Both are verified first — the id_token by signature, issuer, audience,
nonce and expiry, the UserInfo response by its subject matching that id_token.

That is why *Username claim* can name something a provider only ever puts in one
of the two. Entra ID is the case that forces it: its UserInfo response cannot
carry `preferred_username` at all.

## When a login is refused

Turn on **Trace the exchange** on the server, try again, and read the system log:

```sh
grep 'OIDC' /var/log/system/system_$(date +%Y%m%d).log
```

A trace shows the provider, the addresses, which claims arrived and which
account they resolved to. It never contains tokens or secrets. Turn it off
afterwards.

The log is also the only place the reason appears — see *A refusal says nothing
about who exists here* above. The messages below are what to look for there; the
browser is told one and the same thing.

Logins themselves need no tracing: they are written where OPNsense writes every
other login, with the address they came from, and turn up under *System > Log
Files > General* alongside the ones from the password form.

| Message | What it means |
|---|---|
| `Single sign-on is not offered under this address` | the browser reached the interface under a name that is not in *Accepted redirect URLs* |
| `Single sign-on is not set up` / `this server has no accepted redirect URLs configured` | *Accepted redirect URLs* is empty; add the addresses this web interface is reached under |
| `Refusing a token signed with ES256` | the provider signs with a key this plugin cannot verify; switch it to RSA |
| `The UserInfo subject does not match the id_token subject` | the two answers describe different people; almost always a proxy or a misrouted issuer |
| `There is no local account for this user, or it may not be used` | no name and no e-mail address matched and automatic creation is off, or the account that matched is disabled, expired or root — the log line before it says which |
| `not matching by e-mail address` | the provider reports no verified address; see *Matching by e-mail address* above |
| `refusing a login begun under a Host header that is not a host name` | something between the browser and the firewall is rewriting the Host header |
| `refusing an id_token that carries no usable expiry` / `whose nonce does not match` | the provider is not returning what it was asked for |

The way back is always `pkg delete os-openid-connect`; the local login
form is rendered before the single sign-on button and never depends on it.
