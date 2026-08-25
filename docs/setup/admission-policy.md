# Admission policy and identity approvals

Authentication proves which external identity completed OpenID Connect.
Admission decides whether that identity may become an OPNsense WebGUI user.
These are deliberately separate decisions: a valid Apple, Microsoft or Google
account is not automatically a firewall administrator.

The stable identity key is the exact pair `(issuer, sub)`. Display names,
usernames and e-mail addresses are hints only. Once admitted, the pair is bound
to the local numeric user ID, so later provider claim changes and local account
renames cannot silently redirect it.

## Choose a policy

| Policy | Unknown identity | Recommended use |
|---|---|---|
| Strict: pre-linked subjects only | refused | environments where the provider subject is known in advance |
| Administrator approval | queued without a WebGUI session | recommended for social login, Apple Private Relay and any provider where first identities are not known safely |
| Bootstrap by exact local username | automatically bound to an equal local username | controlled enterprise directories with immutable, unique names |
| Bootstrap by unique verified e-mail | automatically bound to the only local account with that verified address | providers that reliably assert `email_verified=true` |
| Username or verified e-mail | tries both automatic rules | migration convenience after both claim sources have been assessed |

Strict and Administrator approval never create a local account. **Create an
account on first login** is available only with an automatic admission policy.
It remains off by default. The built-in root account is never eligible unless
**Allow the built-in root account** is separately enabled.

The form also enforces a provider-population boundary:

- Apple, LinkedIn, ORCID and Yahoo accept globally available personal
  identities. They offer only Strict or Administrator approval and never offer
  automatic local-account creation.
- GitLab.com and the Microsoft Organizations, Consumers and Common audiences
  have the same restrictions. A self-managed GitLab issuer and one specific
  Entra tenant retain the assessed automatic choices.
- Google and Slack may be restricted to a Workspace organization or installed
  workspace outside OPNsense. Automatic matching therefore remains available,
  but automatic local-account creation does not: this form cannot prove that
  the external restriction is complete.

These are security constraints rather than profile defaults. Server-side
validation rejects a crafted unsafe form submission, and the login path treats
an older saved automatic policy as Administrator approval and ignores an older
account-creation flag when its provider population is not eligible. Generic
and other directory profiles remain the administrator's explicit assessment.

## Manage bindings and approve unknown identities

Open a saved OpenID Connect server under **System > Access > Servers** and
select **Manage identities**. The modal window deliberately combines the two
sides of admission:

- **Bound identities** lists every durable exact issuer/subject binding. An
  administrator can add, edit or remove a binding. A new binding can target an
  eligible existing local account or create a new one in place.
- **Pending administrator approvals** lists identities that completed a valid
  provider sign-in but received no WebGUI session. They can be approved into a
  binding with an existing or newly created local account, or denied.

The raw storage representation is intentionally not exposed as a server-form
field. Closing or saving the ordinary server form cannot overwrite a change
made in the manager.

Reading the manager requires OPNsense's existing **System: Authentication
Servers** privilege. Every create, edit, removal, approval and denial also
honours **user-config-readonly**. These checks are repeated by the API; hiding
or showing the button is not the security boundary. Inline local-account
creation additionally requires **System: Access: Management**.

When **Add an identity** creates an account, it receives a scrambled password
and starts with no local-password access. The same editor can optionally select
zero, one or several existing local groups. Selecting an existing account shows
its current memberships first, so saving an unchanged selection preserves them;
changing the selection replaces only that account's memberships. This workflow
never creates a group and never copies provider claims into local groups. Group
privileges can grant WebGUI access, while direct user privileges remain managed
under **System > Access > Users**.

### Recommended first-login workflow

1. Select **Administrator approval for unknown identities**, save the server,
   and leave **Offer on the login page** disabled until testing is complete.
2. The user completes a real login. OPNsense creates no session and displays
   the uniform styled result with a fresh sign-in reference. The administrator
   can correlate that public reference with the audit entry and, when approval
   was queued, its separate internal request ID. The browser deliberately cannot
   distinguish other unusable-account outcomes or recognize a repeated request.
3. An authenticated administrator opens the saved server under **System >
   Access > Servers** and selects **Manage identities**.
4. Compare the displayed provider hints, exact issuer and exact subject with
   information obtained from the user through a separate trusted channel.
5. Choose an existing local account or **Create a new local account**, then
   select **Approve and bind**; alternatively, select **Deny**. Approval does
   not copy provider privileges; the local account and its local groups still
   decide authorization.
6. The user starts a new login. Only the approved exact issuer/subject pair can
   use that binding.

### Add a binding manually

Select **Add identity binding**, choose an existing local account or **Create a
new local account**, and enter the exact issuer and exact case-sensitive `sub`
claim from a verified ID Token. The manager supplies provider-specific guidance
and checks the issuer against the saved server. It also rejects an empty
subject, control characters, overlong values, unavailable accounts and any
attempt to bind an already-known `(issuer, sub)` to another account.

OIDC defines `sub` as an opaque identifier. Its visible form is not a portable
validation rule: pairwise subject policies, federation and provider mappings
can alter it. The manager therefore validates bounds and provenance, not a
provider-looking regular expression. A pending real sign-in is safer than
manual entry because it supplies the issuer and subject from a token the plugin
has already verified.

For Microsoft Entra, do not enter the directory Object ID (`oid`). The OIDC
binding uses the exact client-scoped `sub` claim together with `iss`; `oid` is
an Entra directory identifier with different cross-application semantics.

Pending requests are stored locally with file mode `0600`, limited to 100
records and removed after seven days. Repeated attempts for the same identity
update one record. No token or client secret is stored. Provider-controlled
attempts never modify `config.xml`; only an authenticated administrator's
approval writes the durable binding.

## Apple Private Relay and first-login claims

Apple can return a private relay e-mail address and supplies some profile data
only on the first authorization. The approval queue retains a bounded copy of
that address as an administrator hint. It never uses the address to link an
account automatically. Approval binds Apple's stable `sub`, so later logins
continue to work if Apple no longer repeats the address or the user changes
relay settings.

The same rule covers every provider with an unfamiliar first identity: approve
the stable protocol identity, not a mutable display value. For Google the
subject may look numeric; for authentik or Keycloak it may look like a UUID;
neither appearance should be guessed. For ORCID, prefer the authenticated
subject captured by a sign-in over transcribing an identifier manually.

## Local WebGUI authorization still applies

Admission binds the external identity to a local OPNsense account; it does not
by itself grant that account access to the WebGUI. Give the local user at least
one suitable WebGUI privilege either directly under **System > Access > Users**
or through a local group. Direct user privileges and group privileges are both
honoured. A group's optional source-network restriction must also include the
address from which the administrator connects.

After a successful provider authentication, the plugin checks those effective
OPNsense ACLs before it creates a session. If the originally requested page is
not allowed but another WebGUI page is, the browser is sent to that authorized
landing page. If no usable page is authorized, no session is created and the
browser receives an explicit **WebGUI access denied** page. This avoids
OPNsense's otherwise silent fallback through its technical logout endpoint.

References: [OpenID Connect Core subject identifier](https://openid.net/specs/openid-connect-core-1_0-final.html#SubjectIDTypes),
[Microsoft ID Token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference),
[Google OpenID Connect claims](https://developers.google.com/identity/openid-connect/reference),
[authentik subject modes](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/token_exchange/),
and [ORCID authenticated iDs](https://info.orcid.org/documentation/integration-guide/orcid-oauth-sign-in-guidelines/).
