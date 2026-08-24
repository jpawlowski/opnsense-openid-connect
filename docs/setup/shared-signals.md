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
- `https://schemas.openid.net/secevent/caep/event-type/credential-change`
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

## Subject and session behavior

The receiver acts only on an `iss_sub` primary subject, directly or as the
`user` member of a complex subject. Its issuer must be the exact OpenID Connect
issuer configured for this server and also match the indexed session; other
issuers and identifier formats are safely acknowledged without action. An
unsupported critical complex-subject member rejects the event.

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
`event_timestamp`, or otherwise its SET `iat`, occurred. A delayed event cannot
end a later sign-in. Duplicate `jti` values are idempotent. Valid unsupported
events receive `202 Accepted` without changing anything so transmitters do not
retry them indefinitely.

The Okta provider profile also accepts Okta's documented legacy event-level
`subject` and millisecond timestamp shape. The Google provider profile accepts
the final RISC profile's documented legacy `subject_type` spelling when
`format` is absent; a conforming `format` always takes precedence. All
signature, issuer, audience and replay checks remain mandatory.

This is a focused SSF 1.0 / RFC 8935 receiver subset, not a claim of full CAEP
interoperability certification.
