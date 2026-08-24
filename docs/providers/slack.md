# Sign in with Slack

Create a Slack app and configure **Sign in with Slack**. Under the app's OAuth
settings add the exact OPNsense authorization redirect URI. Install or
distribute the app only to the workspaces that should be able to present an
identity to this client.

App creation is self-service in an existing workspace; Slack also offers a free
developer sandbox. A single-workspace app needs no Marketplace listing.
Unlisted multi-workspace distribution is possible after completing Slack's
distribution checklist; an app whose only purpose is Sign in with Slack is not
eligible for a Marketplace listing, but a listing is unnecessary here.

| Field | Value |
|---|---|
| Provider profile | Slack · Social / workforce |
| Exact issuer URL | `https://slack.com` |
| Username claim | `email` |
| Claims source | ID Token only |
| Scopes | `openid,email,profile` |
| Admission policy | Administrator approval unless workspace access is independently controlled |

Slack's OpenID Connect flow is separate from legacy Slack OAuth scopes and
uses the `openid`, `email` and `profile` scopes. App installation alone is not
a firewall admission decision; an approved exact subject binding remains the
safe home-lab default. Assessed automatic matching remains selectable for a
deliberately restricted workspace, but **Create an account on first login** is
unavailable because OPNsense cannot prove that external restriction.

References: [Sign in with Slack](https://api.slack.com/authentication/sign-in-with-slack)
[Slack app distribution](https://docs.slack.dev/app-management/distribution/),
and [Slack Discovery](https://slack.com/.well-known/openid-configuration).
