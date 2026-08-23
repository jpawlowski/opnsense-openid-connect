# Provider icons and branding

OpenID Connect Discovery does not define an interoperable provider-logo field.
Some products expose branding through a separate administration API or a
theme-specific path, but that address is not portable between installations or
versions and may require an administrator token. The plugin therefore does not
guess a favicon or fetch branding while applying a provider profile.

Every named provider profile starts with a small package-owned SVG at
`/api/openidconnect/auth/builtinicon/{profile}`. The icon is available before
login, contains no script or external resource and needs no outbound request.
**Generic OpenID Connect** remains unbranded because the plugin cannot infer
which product is behind a generic issuer.

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

All bundled assets are small project-created letter marks. They are not copies
of vendor artwork. This keeps the package self-contained and avoids implying
that a third-party icon collection's licence also grants the trademark or
redistribution rights for every individual brand asset. An installation that
has permission to use an official or custom mark may replace the neutral asset
through **Icon URL**.

Names and marks remain trademarks of their respective owners. They identify
the compatible provider profile and do not imply endorsement.
