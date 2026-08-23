# GitLab as OpenID Provider

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in GitLab

GitLab explicitly supports acting as an OIDC provider on GitLab.com, GitLab
Self-Managed and GitLab Dedicated, including the Free tier where that offering
has tiers. GitLab.com users can register an application from their own account.
A self-managed administrator can disable user-owned applications, in which case
an instance administrator must create or permit the client.

1. Create an OAuth application at the appropriate instance/group/user level.
2. Add the exact OPNsense callback URI and select at least `openid`; include
   `profile` and `email` as needed.
3. Copy application ID and secret. Restrict who may use the application through
   GitLab's available instance/group controls.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | GitLab.com / self-managed GitLab · Social / workforce |
| Exact issuer URL | `https://gitlab.com` or the exact Self-Managed/Dedicated instance root, such as `https://gitlab.example.com` |
| Username claim | `preferred_username` |
| Claims source | Automatic (UserInfo will normally be needed) |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

GitLab documents most user profile claims at UserInfo. The `email` claim is
available only with the `email` scope and the user's public e-mail conditions.
Group paths are available as `groups` at UserInfo; direct groups and role-specific
URI claims are also documented but differ in location. Choose the exact claim
that expresses the intended policy and constrain local assignable groups.

For GitLab.com discovery is
`https://gitlab.com/.well-known/openid-configuration`; configure the issuer
`https://gitlab.com`, not that document URL.

For Self-Managed or Dedicated, configure the public instance root as issuer.
For example, issuer `https://gitlab.example.com` has Discovery at
`https://gitlab.example.com/.well-known/openid-configuration`. The profile
initially fills `https://gitlab.com`, but deliberately leaves it editable for
this reason. Do not enter the Discovery URL itself.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [GitLab as OpenID Connect provider](https://docs.gitlab.com/integration/openid_connect_provider/)
and [OAuth application registration](https://docs.gitlab.com/api/oauth2/).
