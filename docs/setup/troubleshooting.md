# Troubleshooting

The browser receives a generic message and a random reference. The detailed
reason is written to the OPNsense audit/system log so the callback cannot be
used to enumerate accounts or configuration.

Temporarily enable **Trace the exchange**, reproduce once, then disable it. The
trace records flow shape and claim names, not tokens, secrets or unnecessary
claim values.

Check these first:

- The exact issuer, including path and trailing slash, equals Discovery's
  `issuer` value.
- The callback ends in the configured **Application code**.
- Under the default WebGUI address policy, the browser name is the configured
  OPNsense hostname/domain, an alternate hostname, a local interface address or
  a virtual IP, and the browser port is OPNsense's configured WebGUI port.
  An additional or custom address contains only an origin such as
  `https://firewall.example.com`, not `/api/openidconnect/...`.
- The browser trusts or has accepted the WebGUI certificate.
- The provider allows Authorization Code, PKCE `S256` and the selected response
  mode.
- **Authentication method** matches the method accepted by the provider's
  application.
- The username and optional group claims exist in the selected claims source.
- OPNsense and the provider have correct time.

## System > Access > Tester still asks for a password

That OPNsense page supports only authentication connectors which receive a
username and password in one request. It validates both fields before it calls
the selected connector, while OIDC requires multiple browser redirects and has
no OPNsense password to submit. Selecting an OIDC server there is therefore not
a valid test and will always fail.

Edit the saved OIDC server and use **Test discovery** for provider metadata or
**Test sign-in** for the complete browser flow. Test sign-in does not establish
a WebGUI session and does not create or modify local users, bindings or groups.
Save or revert every form change before starting it; the action deliberately
tests only the saved connector and returns to the same edit form afterward.

## A callback is shown twice

A current plugin version normalizes an accidentally pasted callback to its
origin in the on-screen endpoint reference, but saving still rejects the wrong
value. Replace it with the origin only:

```text
wrong: https://firewall.example.com/api/openidconnect/auth/callback/main
right: https://firewall.example.com
```

## Self-signed certificates

There is no “accept insecure TLS” setting. The WebGUI address policy determines
which browser-facing names may be used; it does not relax
certificate validation. Trust the private CA or certificate in every involved
browser. For back-channel logout, the provider server also needs that trust.

## The OPNsense WebGUI uses HTTP behind a reverse proxy

An enabled OIDC server is deliberately blocked on native HTTP. Prefer changing
OPNsense itself to HTTPS. If TLS is intentionally terminated at one trusted
proxy, enable **Trusted reverse-proxy TLS offloading**, select **Custom origins
for this provider**, and enter the exact public HTTPS origin. The server may be
saved disabled before these pieces are complete.

If sign-in still fails, verify that the backend cannot be reached around the
proxy, the proxy preserves the public `Host`, the name is accepted by OPNsense's
alternate-hostname checks, and `PHPSESSID` leaves the proxy with `Secure`,
`HttpOnly` and `SameSite=Lax`. Supplying `X-Forwarded-Proto: https` does not
enable the exception and is intentionally ignored.

HAProxy PROXY protocol is optional and separate. When manually configured in
both the proxy and lighttpd it can retain the client address without an HTTP
client-IP header. This matters when OPNsense privileges contain source-network
restrictions; without trusted address propagation those rules see the proxy.
PROXY protocol still does not replace the HTTP `Host`, exact HTTPS origin or
offloading switch. Never enable it on only one side of a listener.

## Sign-in succeeds but WebGUI access is denied

This means the OpenID Connect response and local identity mapping succeeded,
but the mapped OPNsense account has no usable WebGUI privilege from the current
source address. The plugin deliberately creates no session in this case and
shows a 403 page instead of returning silently to the login form.

Under **System > Access**, check the mapped local user and its local groups:

- assign at least one WebGUI privilege directly to the user or through a group;
- check group source-network restrictions against the administrator's address;
- remember that approving an identity or mapping provider groups does not by
  itself guarantee a navigable WebGUI page.

If only the initially requested page is forbidden, the plugin automatically
uses another OPNsense-authorized landing page. The audit log distinguishes this
authorization denial from a failed identity-provider authentication.

## Recovery

Use local password login. From SSH or the console the package can also be
removed with:

```sh
pkg delete os-openid-connect
```

Removing the package does not erase its settings from `/conf/config.xml`.
