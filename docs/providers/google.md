# Google and Google Workspace

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in Google Cloud

Creating a Google Cloud project and OAuth web client is self-service; Google
does not document a separate registration fee. For the basic `openid`, `email`
and `profile` scopes used here, Google's audience rules exempt users from the
test-user warning/expiry behavior. Sensitive or restricted Google API scopes
would introduce verification requirements and should not be added for firewall
login.

1. Configure the OAuth consent screen for the intended Workspace organization
   or users.
2. Create an OAuth client of type **Web application**.
3. Add the exact OPNsense callback to **Authorized redirect URIs** and copy the
   client ID and secret.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Google / Google Workspace |
| Exact issuer URL | `https://accounts.google.com` |
| Username claim | `email` |
| Claims source | ID Token only |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Authorization response mode | Query |

Google documents `sub` as the unique, never-reused account identifier; that is
what the stable local binding uses. Do not use e-mail itself as the durable key.
For a Workspace-only firewall, enforce organization access in Google and
pre-create/bind local accounts; the `hd` claim is a login hint/tenant signal and
is not used here as an authorization rule.

Automatic matching remains selectable when Workspace access and the relevant
claim have been assessed. **Create an account on first login** is unavailable:
the OPNsense form cannot prove that the Google client is Internal or that every
presented identity belongs to the intended organization.

Google's discovery/API reference notes a legacy non-HTTPS issuer value that old
integrations may encounter. This plugin accepts only the exact modern HTTPS
issuer from discovery and will not add a legacy exception.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

Reference: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect),
[Google app audience rules](https://support.google.com/cloud/answer/15549945),
[ID Token reference](https://developers.google.com/identity/openid-connect/reference).
