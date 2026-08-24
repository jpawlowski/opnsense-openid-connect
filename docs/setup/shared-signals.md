# Shared Signals receiver

The optional receiver accepts signed Security Event Tokens through the Shared
Signals Framework (SSF) push delivery profile. It ends matching WebGUI sessions
created by this package. It does not disable or delete local accounts, change
identity bindings or groups, or affect password login.

## Configure the firewall

1. Open the saved OpenID Connect server under **System > Access > Servers**.
2. Enable **Receive Shared Signals**.
3. Enter the transmitter's exact HTTPS **Shared Signals transmitter issuer**.
   This is not necessarily the OpenID Connect issuer.
4. Enter the stream's exact, case-sensitive **Shared Signals audience**.
5. Select **Generate secret**. Save the server and keep the displayed complete
   `Authorization` header available while creating the stream.
6. Run **Test Shared Signals**. This validates SSF discovery, its exact issuer,
   HTTPS signing-key address and push support without changing a session.

The form displays a receiver URL such as:

```text
https://firewall.example.com/api/openidconnect/ssf/push/main
```

Create the stream manually at the transmitter. Its delivery object has this
shape; replace both values with those shown by the firewall:

```json
{
  "method": "urn:ietf:rfc:8935",
  "endpoint_url": "https://firewall.example.com/api/openidconnect/ssf/push/main",
  "authorization_header": "Bearer generated-secret"
}
```

Request only these event type URIs:

- `https://schemas.openid.net/secevent/caep/event-type/session-revoked`
- `https://schemas.openid.net/secevent/caep/event-type/token-claims-change`
- `https://schemas.openid.net/secevent/caep/event-type/credential-change`
- `https://schemas.openid.net/secevent/caep/event-type/assurance-level-change`
- `https://schemas.openid.net/secevent/caep/event-type/risk-level-change`
- `https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required`
- `https://schemas.openid.net/secevent/risc/event-type/account-purged`
- `https://schemas.openid.net/secevent/risc/event-type/account-disabled`
- `https://schemas.openid.net/secevent/risc/event-type/credential-compromise`
- `https://schemas.openid.net/secevent/risc/event-type/recovery-activated`
- `https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed`
- `https://schemas.openid.net/secevent/risc/event-type/sessions-revoked`

The last event is retained for existing RISC transmitters even though the final
profile deprecates it. Prefer the CAEP `session-revoked` event when creating a
new stream.

Polling and automatic stream-management credentials are deliberately not
implemented. Rotating the delivery secret requires updating the transmitter
before it can deliver another event.

## Event and subject behavior

The receiver can match an `iss_sub` user to the exact configured OpenID Connect
issuer and indexed subject. For session events it can also match an `opaque`
identifier to the provider `sid` stored with the local session. A complex CAEP
subject is actionable only when every member is locally indexable: `user`,
`session`, or both. Another non-critical member is acknowledged without a
broader CAEP action; an unsupported critical member rejects the event. RISC
actions remain user-wide and consume only an exact `user` member, so another
non-critical member neither widens nor narrows their consequence.

| CAEP event | Actionable subject and local consequence |
|---|---|
| `session-revoked` | Exact user, provider session, or both: end the matching pre-event sessions. |
| `token-claims-change` | Exact user, optionally constrained by provider session: end the matching pre-event sessions so new claims are required. |
| `credential-change` | Exact user: end matching pre-event sessions. |
| `assurance-level-change` | Exact user, optionally constrained by provider session: end matching pre-event sessions so authentication evidence is renewed. |
| `device-compliance-change` | No device index exists, so the event is acknowledged without broadening it to every user session. |
| `session-established`, `session-presented` | Observational events are acknowledged without creating or changing local state. |
| `risk-level-change` | `MEDIUM` or `HIGH` risk for an exact `USER` or `SESSION` ends matching pre-event sessions; `LOW` and other principals are informational. |

| RISC event | Actionable subject and local consequence |
|---|---|
| `account-credential-change-required`, `account-purged`, `account-disabled`, `credential-compromise` | Exact user: end matching pre-event sessions. |
| `recovery-activated`, `recovery-information-changed` | Exact user: end matching pre-event sessions. |
| `sessions-revoked` | Exact user: end matching pre-event sessions; this event type is deprecated in favor of CAEP. |
| `account-enabled`, `opt-in`, `opt-out-initiated`, `opt-out-cancelled`, `opt-out-effective` | No safe attenuating local action; acknowledge only. |
| `identifier-changed`, `identifier-recycled` | E-mail and phone identifiers do not replace the stable issuer/subject binding; acknowledge only. |

The complete RISC event audit is:

| RISC event | Subject profile | Receiver consequence |
|---|---|---|
| Account credential change required, account purged, account disabled, credential compromise | An SSF subject; only a matching `iss_sub` user is actionable | End matching pre-event sessions |
| Recovery activated, recovery information changed | An SSF subject; only a matching `iss_sub` user is actionable | End matching pre-event sessions |
| Sessions revoked | An SSF subject; only a matching `iss_sub` user is actionable | End matching pre-event sessions; accepted for deprecated-profile compatibility |
| Account enabled | An SSF subject | Acknowledge only; never enable or re-authorize a local account |
| Identifier changed, identifier recycled | RISC requires `email` or `phone` | Acknowledge only; these mutable identifiers cannot safely select an indexed session |
| Opt in, opt out initiated, opt out cancelled, opt out effective | An SSF subject | Acknowledge only; no local RISC participation or account state is stored |

`credential-compromise` is rejected when its required `credential_type` is
missing or malformed. Event-level subjects must resolve to the same identity as
the primary subject. These checks prevent a syntactically valid SET from
turning a malformed or mismatched event into a session action.

A valid supported event ends every matching session that existed when its
`event_timestamp`, otherwise its SET `iat`, occurred. A delayed event cannot end a later sign-in. Duplicate
`jti` values are idempotent. Distinct event types combined in one SET are
refused as ambiguous; unknown single events receive `202 Accepted` without
changing anything so transmitters do not retry them indefinitely.

Known event-specific claims are type-checked before the replay marker or local
session index changes. The receiver never uses event content to create, enable,
disable, delete or rebind a local account, or to change groups or privileges.

The Okta provider profile also accepts Okta's documented legacy event-level
`subject` and millisecond timestamp shape. The Google provider profile accepts
the final RISC profile's documented legacy `subject_type` spelling when
`format` is absent; a conforming `format` always takes precedence. All
signature, issuer, audience and replay checks remain mandatory.

This is a focused SSF 1.0 / RFC 8935 receiver subset, not a claim of full CAEP
interoperability certification.
