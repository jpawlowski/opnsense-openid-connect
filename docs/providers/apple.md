# Apple

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

Apple differs from ordinary enterprise IdPs: the “client secret” is a signed,
short-lived JWT created with an Apple private key, and the authorization answer
for requested user data uses `form_post`.

This is the least home-lab-friendly supported social provider. Apple requires
paid Developer Program membership (USD 99 per membership year), and the web
Services ID must be associated with an existing primary Apple-platform App ID.
Do not start with this profile if the firewall is the only service or app you
operate; Apple does not offer a stand-alone free web client for that case.

## Quick setup in Apple Developer

1. Enable Sign in with Apple on a primary App ID.
2. Create a **Services ID** for the WebGUI client and associate it with that App
   ID. The Services ID is the OIDC client ID.
3. Configure the WebGUI domain and exact return/callback URL.
4. Create a Sign in with Apple private key. Generate a client-secret JWT with
   your Team ID as issuer, Services ID as subject, `https://appleid.apple.com`
   as audience, and a validity no longer than Apple's limit. Rotate it before
   expiry. Never place the `.p8` private key on the firewall solely for this
   plugin; generate the JWT in an appropriate secret-management process.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Apple |
| Exact issuer URL | `https://appleid.apple.com` |
| Client ID | Services ID |
| Client Secret | the generated client-secret JWT |
| Username claim | `email` |
| Claims source | ID Token only |
| Authorization response mode | Form POST |
| Scopes | `openid,email,name` |
| Authentication method | Insist on POST (fixed by the profile, as Apple Discovery requires) |

OPNsense's WebGUI session cookie is intentionally `SameSite=Lax`, so it is not
sent with Apple's cross-site POST. The plugin handles this response mode through
a short-lived, one-time server-side transaction and does not change the cookie
to `SameSite=None`.

Apple may provide a private relay address and some profile data only on the
first authorization. Select **Administrator approval for unknown identities**:
the address is retained as a bounded administrator hint, never used to grant a
session, and approval binds Apple's stable `sub`. Later logins therefore remain
bound even when Apple no longer repeats the address. See the [admission policy
guide](../setup/admission-policy.md).

Because any Apple account can be presented to this client, the profile offers
only Strict or Administrator approval. **Create an account on first login** is
unavailable; approval may still create and bind an account as an explicit
administrator action.

Because the client-secret JWT expires, an expired secret produces token-endpoint
failures even though discovery remains healthy. Record its rotation date.

## Defaults and remaining settings

For the first login, use **Administrator approval**, keep **Match by e-mail
address** at **Only a verified address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Configure Sign in with Apple for the web](https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/),
[Apple Developer Program membership](https://developer.apple.com/programs/whats-included/),
[Sign in with Apple REST API](https://developer.apple.com/documentation/signinwithapplerestapi).
