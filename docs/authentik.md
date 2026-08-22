# authentik

Verified against authentik 2026.8.

## At authentik

**Create a provider.** *Applications > Providers > Create > OAuth2/OpenID
Provider*.

| Setting | Value |
|---|---|
| Client type | **Confidential** |
| Client ID / Client Secret | keep them, they go on the firewall |
| Redirect URIs | one `Strict` entry per address the interface is reached under, each ending in `/api/openidconnect/auth/callback` |
| Signing Key | any RSA certificate — authentik's self-signed one is fine |
| Authorization flow | implicit consent is the sensible choice for an appliance you administer yourself; explicit consent works but asks every time |
| Invalidation flow | the default provider invalidation flow, so that signing out ends the session here too |

Leave *Subject mode*, *Issuer mode* and the token validities alone unless you
have a reason. `Based on the User's hashed ID` and `Each provider has a
different issuer` are both fine — the plugin only needs `sub` to be the same in
the id_token and the UserInfo response, which authentik always does.

**Create an application.** *Applications > Applications > Create*, bind the
provider to it, and set the launch URL so the tile in authentik lands somewhere
useful:

```
https://<firewall>/api/openidconnect/auth/login?provider=<descriptive name>
```

Clicking that while already signed in to the firewall simply lands on the
dashboard — the plugin treats an existing session as success, not as an error.

Restrict who may use it with the application's policy bindings, the same way as
any other authentik application.

## On the firewall

| Field | Value |
|---|---|
| Provider URL | `https://<authentik>/application/o/<application slug>/` |
| Username claim | `preferred_username`, or `email` if you prefer to match on the address |
| Scopes | `openid,email,profile` |

## Worth knowing

**A block in authentik does not end a session here.** Like most OpenID Connect
applications, this one asks the provider once, at sign-in, and then holds its
own session. Taking someone's access away means doing it in both places.

**Group mapping** needs `groups` added to the scopes and *Group claim* set to
`groups`. It is off by default on purpose — see the [index](README.md).

**The icon on the login button.** authentik's own mark sits at
`https://<authentik>/static/dist/assets/icons/icon.svg` and can go straight into
*Icon URL*. Brand assets uploaded to authentik cannot: it serves them under
`/files/media/...` with a signed, expiring token, which is no use as a fixed
address. Host your own logo somewhere stable, or paste the SVG into *Icon
markup*.
