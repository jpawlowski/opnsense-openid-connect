# Sign in to OPNsense with your identity provider

Use the account you already trust at Microsoft, Google, Okta, Keycloak,
authentik or another OpenID Connect provider to access the OPNsense WebGUI.
Your normal local OPNsense login remains available as the recovery path.

This plugin is for WebGUI administration. It does not change Captive Portal or
OPNWAF authentication and it does not replace OPNsense core files.

## What this gives you

| If you run… | You can… |
|---|---|
| a HomeLab | use one familiar login, require MFA at your provider and keep a local break-glass account |
| a small team | approve each identity, stop future sign-ins centrally and keep OPNsense permissions local |
| a security-conscious environment | require verified MFA or phishing-resistant authentication, limit provider-controlled groups and use provider logout or security events where supported |
| several firewalls or identity systems | start from provider-specific profiles while keeping the same conservative validation rules |

The provider proves who the person is. OPNsense still decides which local
account and permissions that identity receives. Unknown identities are refused
by default or wait for explicit administrator approval.

## Is it a good fit?

Choose this plugin when:

- administrators should sign in through OpenID Connect;
- local OPNsense accounts and privileges should remain authoritative;
- the local password form must remain available during an IdP outage;
- you want strict defaults without operating a separate OIDC proxy.

It is not intended for:

- Captive Portal or OPNWAF users;
- replacing OPNsense authorization with cloud-managed roles;
- providers that offer only social OAuth login and no OpenID Connect flow;
- eliminating every local emergency administrator account.

## Providers

Named profiles are available for common hosted, self-hosted and social identity
providers, including Microsoft Entra ID, Google Workspace, Okta, Auth0,
Keycloak, authentik, Authelia, ZITADEL, GitLab and many others. A Generic OpenID
Connect profile covers standards-compatible providers without a named preset.

Provider documentation, retained live interoperability tests and standards
conformance are deliberately shown as different confidence levels. Check the
[security and conformance report](docs/reference/security-and-conformance.md)
before choosing a provider or depending on a specific security feature. The
[provider guides](docs/providers/README.md) contain the matching setup steps and
known limitations.

## A safe first setup

1. [Install the beta package](docs/setup/install.md).
2. Open **System > Access > Servers** and add an **OpenID Connect** server.
3. Select the provider profile and copy the displayed redirect addresses into
   a confidential web application at the provider.
4. Keep the server disabled while running **Test discovery** and **Test
   sign-in**.
5. Approve or bind the verified identity to a local OPNsense account.
6. Enable the server only after the local password login has been tested in a
   separate browser session.

The [step-by-step setup guide](docs/setup/README.md) explains each step without
assuming prior OpenID Connect knowledge. The
[settings reference](docs/setup/settings-reference.md) is available when you
need to go deeper.

## Security without guesswork

The plugin uses the Authorization Code flow, PKCE, exact issuer validation,
asymmetric token signatures and one-time login transactions. Optional features
such as signed JARM authorization responses, PAR, provider-initiated logout,
MFA evidence and Shared Signals remain subject to provider support.

The generated
[security and conformance report](docs/reference/security-and-conformance.md)
is the single source for:

- supported, partial and intentionally unsupported standards;
- provider capability and interoperability evidence;
- the verified security comparison between providers;
- threats, controls and accepted residual risks;
- implementation properties backed by the required test tiers.

A feature is not marked conformant merely because it appears to work. Green
requires the complete applicable normative inventory and traceable evidence.

## Current maturity

This is a pre-release package for OPNsense Community Edition 26.1 and 26.7. It
is installed manually and does not register an automatic package repository.
The package includes a watchdog for relevant OPNsense core changes, but upgrades
should still be tested before they reach the only administrative firewall.

Keep at least one tested local administrator account. Removing the plugin does
not remove its saved settings and does not disable local password login.

## Learn more

- [Documentation index](docs/README.md)
- [Architecture and trust boundaries](docs/reference/architecture.md)
- [Troubleshooting and recovery](docs/setup/troubleshooting.md)
- [Support](SUPPORT.md) and [security reporting](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

BSD-2-Clause, see [LICENSE](LICENSE).

Copyright (C) 2026 Julian Pawlowski. All rights reserved.
