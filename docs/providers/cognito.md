# AWS Cognito user pools

Complete the [common setup](../setup/README.md) first. Besides the
provider-specific values below, every connection needs a unique **Application
code** and confidential **Client ID** and **Client Secret**. By default, the
callback address follows the WebGUI name already accepted by OPNsense; a custom
origin list is needed only for an intentional restriction or unusual proxy.

## Quick setup in AWS Cognito

1. In a user pool create an app client with a client secret for a server-side
   confidential application.
2. Enable the Authorization Code grant and the `openid`, `email`, `profile`
   scopes. Disable implicit flow unless another client needs it.
3. Add the exact OPNsense callback URL and configure a user-pool domain for
   hosted/managed login.
4. Select the identity providers that users may use.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | AWS Cognito |
| Exact issuer URL | `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>` |
| Username claim | `cognito:username` |
| Claims source | Automatic |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |

The issuer is the user-pool API URL above, **not** the hosted-login custom
domain. Discovery names the hosted domain's authorize/token endpoints while
retaining the user-pool issuer; that split is normal and is safely bound by the
discovery document.

Cognito emits pool groups in `cognito:groups`. Configure it only if group-based
OPNsense authorization is intended, and constrain the assignable groups.

## Defaults and remaining settings

For the first login, keep **Match by e-mail address** at **Only a verified
address**, **Maximum authentication age** at **14400 seconds (four hours)**, account creation off, root
access off, **Group claim** empty, tracing off, and both optional logout switches
off. The table above contains the provider profile values to enter or verify.
Change another setting only for the documented reason in the [complete settings
reference](../setup/settings-reference.md).

References: [Cognito authorization endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html),
[app clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html).
