# Authelia

Authelia is configured in a file rather than a console, and it is the only one of
the five that will not take a plaintext client secret.

## At Authelia

The client secret has to be **hashed** in Authelia's configuration, while the
firewall gets the plaintext. Generate both at once:

```sh
authelia crypto hash generate pbkdf2 --variant sha512 --random --random.length 72
```

It prints the random secret and its digest. The **Random Password** goes on the
firewall; the **Digest** — the `$pbkdf2-sha512$...` string — goes in the file.

Then, under `identity_providers.oidc.clients`:

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: 'opnsense'
        client_name: 'OPNsense'
        client_secret: '$pbkdf2-sha512$310000$...'
        public: false
        authorization_policy: 'two_factor'
        redirect_uris:
          - 'https://firewall.example.net/api/openidconnect/auth/callback'
        scopes:
          - 'openid'
          - 'email'
          - 'profile'
        response_types:
          - 'code'
        grant_types:
          - 'authorization_code'
        token_endpoint_auth_method: 'client_secret_basic'
        userinfo_signed_response_alg: 'none'
        consent_mode: 'implicit'
```

List one `redirect_uris` entry per address the interface is reached under.

## On the firewall

| Field | Value |
|---|---|
| Provider URL | `https://<authelia>` |
| Username claim | `preferred_username` |
| Scopes | `openid,email,profile` |
| Authentication method | *Follow the provider*, or *Insist on Basic* to match `client_secret_basic` |

## Worth knowing

**`token_endpoint_auth_method` must agree.** Authelia holds the client to
whatever is configured. Leaving the firewall on *Follow the provider* works,
because it then picks what Authelia advertises. If the two ever disagree, set
the firewall's *Authentication method* to the matching one and the argument is
over.

**`consent_mode: 'implicit'`** skips the consent screen. For an appliance you
administer yourself that is usually what you want; `explicit` asks on every
login.

**`authorization_policy`** decides how hard someone has to work to get in.
`two_factor` is a sensible floor for a firewall.

**`userinfo_signed_response_alg`.** `none` returns plain JSON. Setting it to
`RS256` returns a signed JWT instead, which is also handled — it is verified
against the same algorithm rules as the id_token. Do not set it to an ECDSA
algorithm.

**Group mapping**, if you want it: add `groups` to the client's `scopes` and set
*Group claim* to `groups` on the firewall. Authelia sends the groups from your
user backend, so name the OPNsense groups to match, and use *Assignable groups*
to keep the provider from touching anything else.
