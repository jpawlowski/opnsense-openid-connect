# Provider icons and branding

OpenID Connect Discovery does not define an interoperable provider-logo field.
Some products expose branding through a separate administration API or a
theme-specific path, but that address is not portable between installations or
versions and may require an administrator token. The plugin therefore does not
guess a favicon or fetch branding while applying a provider profile.

Every provider profile starts with a small package-owned SVG at
`/api/openidconnect/auth/builtinicon/{profile}`. The icon is available before
login, contains no script or external resource and needs no outbound request.
All bundled marks use the same 24 by 24 pixel button slot and follow the button
text colour by default. Their visible bounds are optically normalized, and
light interior details are transparent cut-outs rather than opaque white
layers. Original colours remain selectable. **Generic OpenID Connect** uses
the official OpenID `i+D` mark rather than an invented `OIDC` letter tile.

Generated authentik applications and Keycloak clients use the reviewed OPNsense
SVG from OPNsense Core revision `01fc795f34dae4184de79a710105f00a69c90400` through
its commit-pinned `raw.githubusercontent.com` URL. Keeping application branding on
a public address prevents a public identity-provider dashboard from requesting
Local Network Access merely because the WebGUI FQDN resolves to a private address.
The administrator may replace or remove that external URL in the provider.

## Installation-specific branding

**Icon URL** remains editable. Use one of these forms:

- an absolute path on the firewall, for example `/ui/themes/example/idp.svg`;
- a self-contained `data:image/...` URI; or
- a stable public HTTPS image owned by the IdP installation.

Remote images are fetched by the firewall and returned through the icon proxy;
the unauthenticated browser does not contact the third-party image host. The
proxy applies HTTPS, redirect, media-type and size restrictions and sends the
image with a sandbox policy. A URL from an authenticated branding API is not
suitable because the icon fetch deliberately carries no administrator token.

For authentik, the current brand API exposes `branding_logo` and
`branding_favicon`, but that API is authenticated. For GitLab, the Appearance
API similarly requires administrator access. If an administrator publishes a
stable logo at a separate unauthenticated HTTPS address, that exact address can
be entered manually.

## Bundled asset provenance

Every profile uses provider artwork rather than an invented letter tile. The
SVGs are self-contained. Marks which otherwise collapse into a solid CSS mask
use transparent cut-outs; intrinsically wide wordmarks use an official compact
symbol or a compact brand-colour tile. This keeps the visible mark at a
consistent scale without stretching its defining geometry.

The assets were retrieved on 24 August 2026 from these sources:

- authentik: [official press kit, Icon — color](https://goauthentik.io/press/).
- OpenID Connect: [OpenID Foundation logo guidelines](https://openid.net/policies/) and the
  OpenID glyph from [Simple Icons 13.21.0][simple-icons].
- Dex: [official source tree](https://github.com/dexidp/dex/tree/master/docs/logos), commit `ab64ed7`,
  Apache-2.0.
- Cisco Duo: [official website icon](https://duo.com/images/favicon/favicon-192x192.png).
- Microsoft: [official sign-in symbol and guidance][microsoft-sign-in].
- IBM Security Verify: [official IBM Design Language app icon][ibm-app-icons].
- JumpCloud: [official press kit and website symbol](https://jumpcloud.com/press), placed in a
  compact inverse-colour tile for equal button sizing.
- OneLogin: [official press-kit logomark](https://www.onelogin.com/press-center/press-kit).
- Ping Identity: [official website mark](https://www.pingidentity.com/).
- WSO2: [official brand icon](https://wso2.com/about/brand).
- Auth0, Amazon Cognito and ORCID: [Simple Icons 13.21.0][simple-icons], CC0-1.0 collection.
- Apple, Authelia, FusionAuth, GitLab, Google, Keycloak, LinkedIn, Okta, Oracle, Pocket ID,
  Slack, Yahoo and ZITADEL: [Dashboard Icons][dashboard-icons], commit `8223c9c`, Apache-2.0
  collection. Keycloak retains its coloured interlocking ribbons without the opaque faceted
  backdrop; Oracle places its official oval in a compact inverse-colour tile.
- Generated OPNsense application tile: [official OPNsense core artwork][opnsense-icon], commit
  `01fc795f34dae4184de79a710105f00a69c90400`, BSD-2-Clause.

Collection licences do not waive third-party trademark or brand-guideline
restrictions. Names and marks remain trademarks of their respective owners.
They identify the compatible provider profile and do not imply affiliation or
endorsement. An installation may still replace a bundled mark through
**Icon URL** when it needs installation-specific branding.

[dashboard-icons]: https://github.com/homarr-labs/dashboard-icons
[ibm-app-icons]: https://www.ibm.com/design/language/iconography/app-icons/library/
[microsoft-sign-in]: https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-branding-in-apps
[opnsense-icon]: https://github.com/opnsense/core/blob/01fc795f34dae4184de79a710105f00a69c90400/src/opnsense/www/themes/opnsense/build/images/icon-logo.svg
[simple-icons]: https://github.com/simple-icons/simple-icons/tree/13.21.0
