# Microsoft Entra ID and personal Microsoft accounts

Complete the [common setup](../setup/README.md) first. The Microsoft profile
supports one tenant, every Entra organization, personal Microsoft accounts, or
both. One saved authentication server produces one login button; create
separate servers when personal and work identities need distinct buttons,
labels or admission policies.

## Choose the button's account audience

| Microsoft account audience | Who the button accepts | Microsoft authority used by OPNsense | Matching app registration audience |
|---|---|---|---|
| One specific Entra tenant | members and permitted guests of one tenant | exact `https://login.microsoftonline.com/<tenant-id>/v2.0` | Accounts in this organizational directory only |
| Any Entra organization | work/school accounts from any Entra tenant | `organizations` | Accounts in any organizational directory |
| Personal Microsoft accounts only | personal Outlook/Live/Microsoft accounts | `consumers` | Personal Microsoft accounts |
| Entra organizations and personal Microsoft accounts | both populations behind one button | `common` | Accounts in any organizational directory and personal Microsoft accounts |

The app registration's **Supported account types** (`signInAudience`) must
agree with the selected mode. If separate buttons are desired, create separate
app registrations and OPNsense servers, for example “Company Microsoft” with a
tenant issuer and “Personal Microsoft” with Consumers. If one button is
preferred, use Common and one matching registration.

## Quick setup in Microsoft Entra

App registration itself is available with Entra Free and has no product
charge. A newly created billing account may require a credit card for identity
verification, and an organization's tenant policy may reserve app registration
or consent for administrators.

1. Create an app registration with the supported account type selected above.
2. Under **Authentication**, add a **Web** redirect URI equal to the exact
   authorization redirect URI displayed by OPNsense.
3. Create a client secret and copy its **Value** before leaving the page.
4. Optional for a tenant/workforce configuration: define app roles or filtered
   group claims and assign only intended firewall administrators.

## Optional authentication-strength enforcement

This is available only with **One specific Entra tenant**. Authentication
context identifiers `c1` through `c25` are defined inside a tenant and cannot
carry one trustworthy meaning across Organizations, Consumers or Common.

1. Create or select a Conditional Access authentication context in Entra.
2. Attach a Conditional Access policy whose grant control requires the intended
   authentication strength: multifactor authentication, or a phishing-resistant
   strength based on FIDO2 security keys, Passkeys, Windows Hello for Business or
   certificate-based authentication.
3. Configure the app registration to include the optional `amr` claim in its ID
   Token. The plugin requests and verifies `acrs`, but still requires the ID Token
   to report the method that satisfied it.
4. In OPNsense select **Required authentication** and the same `c1`-`c25` value.
   Run **Test sign-in** before offering the provider on the login page.

OPNsense accepts the result only when the signature-verified ID Token contains
both the requested `acrs` context and suitable `amr` evidence. MFA requires
`mfa`. Phishing-resistant authentication requires `mfa` together with Entra's
documented `fido`, `hwk` or `x509` method; `x509` alone is also emitted for
single-factor and device authentication and therefore never suffices. A context
without complete method evidence is refused, even if Entra completed an
otherwise valid login. Conditional Access requires a compatible Entra license;
Microsoft currently documents it as an Entra ID P1 capability.

## Enter or change these OPNsense values

| Field | Value |
|---|---|
| Provider profile | Microsoft Entra ID / Microsoft account · Social / workforce |
| Microsoft account audience | the mode selected above |
| Exact issuer URL | tenant-specific v2 issuer for **One specific tenant**; automatically managed for the other modes |
| Username claim | `preferred_username` |
| Claims source | ID Token only |
| Authorization response mode | Query |
| Scopes | `openid,email,profile` |
| Authentication method | Follow the provider |
| Required authentication | Provider policy only, unless the tenant context above is configured |
| Admission policy | Strict/controlled username matching for one tenant; Administrator approval for broad or personal audiences |

Tenant-independent Microsoft Discovery publishes the issuer template
`https://login.microsoftonline.com/{tenantid}/v2.0`. The plugin handles this
documented exception only inside the Microsoft profile: it requires a GUID
`tid`, requires that GUID in the exact signed-token issuer, validates a signing
key's issuer when supplied, and enforces the selected Consumers/Organizations
population. Other providers retain byte-for-byte issuer matching.

Do not rely on e-mail matching for broad Microsoft audiences. Entra commonly
omits `email_verified`, names can change, and a personal Microsoft account is a
different trust population from a managed tenant. The Administrator approval
policy ensures that owning any Microsoft account is insufficient for firewall
access.

## Which Microsoft identifier to bind

Use **Manage identities** and bind the exact `sub` claim from the ID Token, not
the Microsoft Entra Object ID (`oid`). Microsoft documents `sub` as an
immutable, pairwise identifier for one application ID, while `oid` identifies
the directory object across applications in one tenant. This plugin implements
the OpenID Connect identity key and therefore persists the exact `(iss, sub)`
pair it validated. The approval workflow obtains both values safely from the
real login; manual entry is intended only when they were independently verified
from an ID Token issued to this OPNsense client.

## Groups and roles

Entra group claims are usually object IDs. Set **Group claim** to `groups` and
map only explicit IDs, or create app roles and use claim `roles` for clearer,
application-specific authorization.

JWT group claims have an overage limit. Above it Entra omits `groups` and emits
`hasgroups` or `_claim_names` instructions to query Microsoft Graph. This plugin
deliberately does not grant partial memberships or call Graph; the login is
refused with an actionable log message. Filter groups or use app roles.

Front/back-channel logout support depends on the app registration and published
metadata. Register only the endpoint type the portal supports; logout endpoints
are never additional authorization redirect URIs.

References: [Microsoft OIDC account authorities](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[Microsoft Entra Free](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/microsoft-entra-id-free),
[supported account types](https://learn.microsoft.com/en-us/entra/identity-platform/v2-supported-account-types),
[multitenant issuer validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens),
[ID Token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference),
[authentication context](https://learn.microsoft.com/en-us/entra/identity-platform/developer-guide-conditional-access-authentication-context),
[optional claims and AMR values](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference),
and [group claims](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims).
