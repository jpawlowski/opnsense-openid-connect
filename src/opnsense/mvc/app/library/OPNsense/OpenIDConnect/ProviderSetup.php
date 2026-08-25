<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/**
 * Builds reviewable provider-side setup files from an unfinished OPNsense form.
 *
 * These files deliberately contain no credential.  The identity provider creates its
 * own client secret, and the administrator copies that and the resulting client ID and
 * issuer back into the disabled OPNsense draft.  Generation is pure: it neither contacts
 * nor changes the provider, so either side of the connection may be prepared first.
 */
final class ProviderSetup
{
    public const PROFILES = ['authentik', 'keycloak'];
    public const LOGOUT_CHANNELS = ['backchannel', 'frontchannel'];

    /**
     * Setup starts from an unsaved form, before the connector accessors can apply their
     * defaults.  Mirroring those defaults here makes the downloaded side deterministic
     * without accepting the client secret or persisting a half-finished server first.
     */
    private const SETTING_DEFAULTS = [
        'openidconnect_scopes' => 'openid,email,profile',
        'openidconnect_username_claim' => 'preferred_username',
        'openidconnect_group_claim' => '',
        'openidconnect_required_authentication' => '',
        'openidconnect_acr_request' => '',
        'openidconnect_acr_values' => '',
        'openidconnect_amr_values' => '',
    ];

    private const AUTHENTIK_SCOPE_MAPPINGS = [
        'openid' => 'goauthentik.io/providers/oauth2/scope-openid',
        'profile' => 'goauthentik.io/providers/oauth2/scope-profile',
    ];

    private const SUPPORTED_SCOPES = ['openid', 'email', 'profile'];

    private const STANDARD_CLAIM_SCOPES = [
        'sub' => 'openid',
        'email' => 'email',
        'email_verified' => 'email',
        'name' => 'profile',
        'given_name' => 'profile',
        'family_name' => 'profile',
        'preferred_username' => 'profile',
        'nickname' => 'profile',
        'picture' => 'profile',
    ];

    /**
     * @param array<string,string> $settings provider-relevant values from the unsaved form
     * @return array{filename:string,media_type:string,content:string,client_id_hint:string,issuer_hint:string}
     */
    public static function generate(
        string $profile,
        string $applicationCode,
        string $displayName,
        array $origins,
        bool $postLogoutRedirect,
        string $logoutChannel = 'backchannel',
        string $sectorOrigin = '',
        array $settings = [],
        string $preferredOrigin = ''
    ): array {
        $profile = strtolower(trim($profile));
        if (!in_array($profile, self::PROFILES, true)) {
            throw new \InvalidArgumentException('This provider profile has no downloadable setup file.');
        }

        $applicationCode = trim($applicationCode);
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $applicationCode)
            || in_array($applicationCode, ['.', '..'], true)) {
            throw new \InvalidArgumentException('The application code is not URL-safe.');
        }

        $displayName = trim($displayName);
        if ($displayName === '') {
            throw new \InvalidArgumentException(
                'Enter the authentication server name before downloading provider setup.'
            );
        }
        if (strlen($displayName) > 160 || self::hasControlCharacters($displayName)) {
            throw new \InvalidArgumentException('The server name is too long or contains control characters.');
        }

        $origins = self::normaliseOrigins($origins);
        if ($origins === []) {
            throw new \InvalidArgumentException('Open this form through HTTPS or enter at least one custom WebGUI origin.');
        }
        $origins = self::preferOrigin($origins, $preferredOrigin);
        if (!in_array($logoutChannel, self::LOGOUT_CHANNELS, true)) {
            throw new \InvalidArgumentException('Unknown logout channel.');
        }
        $sectorOrigin = trim($sectorOrigin);
        if ($sectorOrigin !== '' && !in_array($sectorOrigin, $origins, true)) {
            throw new \InvalidArgumentException('The pairwise subject sector is not an accepted WebGUI origin.');
        }
        $projection = self::providerProjection($profile, $settings);

        $slug = self::slug($applicationCode);
        return $profile === 'authentik'
            ? self::authentik(
                $applicationCode,
                $slug,
                $displayName,
                $origins,
                $postLogoutRedirect,
                $logoutChannel,
                $projection
            )
            : self::keycloak(
                $applicationCode,
                $slug,
                $displayName,
                $origins,
                $postLogoutRedirect,
                $logoutChannel,
                $sectorOrigin,
                $projection
            );
    }

    /** @return array{scopes:string[],username_claim:string,group_claim:string} */
    private static function providerProjection(string $profile, array $given): array
    {
        $unknown = array_diff(array_keys($given), array_keys(self::SETTING_DEFAULTS));
        if ($unknown !== []) {
            throw new \InvalidArgumentException('The provider setup contains an unknown OpenID Connect setting.');
        }
        $settings = array_replace(self::SETTING_DEFAULTS, $given);
        $scopes = self::settingList($settings['openidconnect_scopes']);
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        $scopes = array_values(array_unique($scopes));
        if (array_diff($scopes, self::SUPPORTED_SCOPES) !== []) {
            throw new \InvalidArgumentException(
                'The generated provider setup does not yet support every configured scope.'
            );
        }

        $usernameClaim = trim((string)$settings['openidconnect_username_claim']);
        $claimScope = self::STANDARD_CLAIM_SCOPES[$usernameClaim] ?? '';
        if ($claimScope === '' || !in_array($claimScope, $scopes, true)) {
            throw new \InvalidArgumentException(
                'The generated provider setup does not emit the configured username claim.'
            );
        }

        $groupClaim = trim((string)$settings['openidconnect_group_claim']);
        if ($groupClaim !== '') {
            if ($profile !== 'authentik' || $groupClaim !== 'groups' || !in_array('profile', $scopes, true)) {
                throw new \InvalidArgumentException(
                    'The generated provider setup does not yet emit the configured group claim.'
                );
            }
        }

        if (trim((string)$settings['openidconnect_required_authentication']) !== '') {
            /**
             * Emitting requested acr/amr strings is not evidence.  A future adapter has to
             * configure a provider flow which enforces the methods before it may map the
             * resulting context into a token accepted by AuthenticationRequirement.
             */
            throw new \InvalidArgumentException(
                'The generated provider setup cannot yet enforce the configured authentication requirement.'
            );
        }

        return [
            'scopes' => $scopes,
            'username_claim' => $usernameClaim,
            'group_claim' => $groupClaim,
        ];
    }

    /** @return string[] */
    private static function settingList($value): array
    {
        $parts = is_array($value) ? $value : preg_split('/[\s,]+/', (string)$value);
        $items = [];
        foreach ($parts ?: [] as $part) {
            $part = trim((string)$part);
            if ($part !== '') {
                $items[] = $part;
            }
        }
        return $items;
    }

    /** @return string[] */
    private static function normaliseOrigins(array $origins): array
    {
        $accepted = [];
        foreach ($origins as $origin) {
            $origin = rtrim(trim((string)$origin), '/');
            if (!self::isHttpsOrigin($origin)) {
                throw new \InvalidArgumentException(sprintf('%s is not an HTTPS origin.', $origin ?: '(empty)'));
            }
            $accepted[$origin] = true;
        }
        return array_keys($accepted);
    }

    /** @param string[] $origins @return string[] */
    private static function preferOrigin(array $origins, string $preferred): array
    {
        $preferred = trim($preferred);
        if ($preferred === '') {
            return $origins;
        }
        $normalised = self::normaliseOrigins([$preferred])[0];
        $index = array_search($normalised, $origins, true);
        if ($index === false) {
            throw new \InvalidArgumentException(
                'The WebGUI origin used to download this setup is not in the accepted origin list.'
            );
        }
        if ($index > 0) {
            array_splice($origins, $index, 1);
            array_unshift($origins, $normalised);
        }
        return $origins;
    }

    private static function loginUrl(string $origin, string $displayName): string
    {
        return $origin . '/api/openidconnect/auth/login?provider=' . rawurlencode($displayName);
    }

    private static function isHttpsOrigin(string $value): bool
    {
        if ($value === '' || self::hasControlCharacters($value) || !filter_var($value, FILTER_VALIDATE_URL)) {
            return false;
        }
        $parts = parse_url($value);
        return strtolower((string)($parts['scheme'] ?? '')) === 'https'
            && isset($parts['host']) && !isset($parts['user']) && !isset($parts['pass'])
            && !isset($parts['query']) && !isset($parts['fragment'])
            && (($parts['path'] ?? '') === '');
    }

    private static function hasControlCharacters(string $value): bool
    {
        return (bool)preg_match('/[\x00-\x1F\x7F]/', $value);
    }

    private static function slug(string $applicationCode): string
    {
        $slug = strtolower(preg_replace('/[^A-Za-z0-9]+/', '-', $applicationCode) ?? '');
        $slug = trim($slug, '-');
        return 'opnsense-' . ($slug !== '' ? $slug : 'webgui');
    }

    private static function yamlString(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }

    /** @return array{filename:string,media_type:string,content:string,client_id_hint:string,issuer_hint:string} */
    private static function authentik(
        string $applicationCode,
        string $slug,
        string $displayName,
        array $origins,
        bool $postLogoutRedirect,
        string $logoutChannel,
        array $projection
    ): array {
        $providerId = $slug . '-provider';
        $emailMappingId = $slug . '-verified-email-scope';
        $providerName = 'OPNsense WebGUI (' . $slug . ')';
        $loginUrl = self::loginUrl($origins[0], $displayName);
        $redirects = [];
        foreach ($origins as $origin) {
            $redirects[] = [
                'url' => $origin . '/api/openidconnect/auth/callback/' . rawurlencode($applicationCode),
                'type' => 'authorization',
            ];
            if ($postLogoutRedirect) {
                $redirects[] = ['url' => $origin . '/', 'type' => 'logout'];
            }
        }
        $logoutUri = $origins[0] . '/api/openidconnect/auth/' . $logoutChannel . '/'
            . rawurlencode($applicationCode);

        $lines = [
            '# Generated by the OPNsense OpenID Connect plugin.',
            '# Review before importing. No client credential is contained in this file.',
            '# authentik generates the Client ID and Client Secret when it creates the provider.',
            '# Validated against the authentik 2026.8.0 Blueprint schema.',
            '# yaml-language-server: $schema=https://version-2026-8.goauthentik.io/blueprints/schema.json',
            'version: 1',
            'metadata:',
            '  name: ' . self::yamlString($displayName),
            'entries:',
        ];
        if (in_array('email', $projection['scopes'], true)) {
            $lines = array_merge($lines, [
                '  - model: authentik_providers_oauth2.scopemapping',
                '    id: ' . self::yamlString($emailMappingId),
                '    identifiers:',
                '      name: ' . self::yamlString('OPNsense verified e-mail (' . $slug . ')'),
                '    state: created',
                '    attrs:',
                '      scope_name: email',
                '      description: Verified e-mail address',
                '      expression: |',
                '        verified = request.user.attributes.get("email_verified", False)',
                '        return {',
                '            "email": request.user.email,',
                '            "email_verified": verified is True',
                '        }',
            ]);
        }
        $lines = array_merge($lines, [
            '  - model: authentik_providers_oauth2.oauth2provider',
            '    id: ' . self::yamlString($providerId),
            '    identifiers:',
            '      name: ' . self::yamlString($providerName),
            '    state: created',
            '    attrs:',
            '      authentication_flow: !Find [authentik_flows.flow, [slug, default-authentication-flow]]',
            '      authorization_flow: !Find [authentik_flows.flow, [slug, default-provider-authorization-implicit-consent]]',
            '      invalidation_flow: !Find [authentik_flows.flow, [slug, default-provider-invalidation-flow]]',
            '      client_type: confidential',
            '      grant_types:',
            '        - authorization_code',
            '      include_claims_in_id_token: true',
            '      issuer_mode: per_provider',
            '      sub_mode: hashed_user_id',
            '      property_mappings:',
        ]);
        foreach ($projection['scopes'] as $scope) {
            if ($scope === 'email') {
                $lines[] = '        - !KeyOf ' . self::yamlString($emailMappingId);
            } else {
                $lines[] = '        - !Find [authentik_providers_oauth2.scopemapping, [managed, '
                    . self::AUTHENTIK_SCOPE_MAPPINGS[$scope] . ']]';
            }
        }
        $lines = array_merge($lines, [
            "      signing_key: !Find [authentik_crypto.certificatekeypair, [name, 'authentik Self-signed Certificate']]",
            '      redirect_uris:',
        ]);
        foreach ($redirects as $redirect) {
            $lines[] = '        - matching_mode: strict';
            $lines[] = '          redirect_uri_type: ' . $redirect['type'];
            $lines[] = '          url: ' . self::yamlString($redirect['url']);
        }
        $lines = array_merge($lines, [
            '      logout_method: ' . $logoutChannel,
            '      logout_uri: ' . self::yamlString($logoutUri),
            '  - model: authentik_core.application',
            '    id: ' . self::yamlString($slug . '-application'),
            '    identifiers:',
            '      slug: ' . self::yamlString($slug),
            '    state: created',
            '    attrs:',
            '      name: ' . self::yamlString($displayName),
            '      provider: !KeyOf ' . self::yamlString($providerId),
            '      meta_launch_url: ' . self::yamlString($loginUrl),
            '      policy_engine_mode: any',
            '',
        ]);

        return [
            'filename' => $slug . '-authentik-blueprint.yaml',
            'media_type' => 'application/yaml',
            'content' => implode("\n", $lines),
            'client_id_hint' => 'Copy `Client ID` and `Client Secret` from the generated authentik ' .
                '`OAuth2/OpenID` provider.',
            'issuer_hint' => 'Use the provider issuer ending in `/application/o/' . $slug . '/` and copy it exactly.',
        ];
    }

    /** @return array{filename:string,media_type:string,content:string,client_id_hint:string,issuer_hint:string} */
    private static function keycloak(
        string $applicationCode,
        string $slug,
        string $displayName,
        array $origins,
        bool $postLogoutRedirect,
        string $logoutChannel,
        string $sectorOrigin,
        array $projection
    ): array {
        $callbacks = [];
        $postLogout = [];
        foreach ($origins as $origin) {
            $callbacks[] = $origin . '/api/openidconnect/auth/callback/' . rawurlencode($applicationCode);
            if ($postLogoutRedirect) {
                $postLogout[] = $origin . '/';
            }
        }
        $attributes = [
            'pkce.code.challenge.method' => 'S256',
            // Keycloak advertises ES256 DPoP realm-wide. The RP therefore binds
            // its authorization code and token request to a proof key and refuses
            // a Bearer downgrade; the generated client must opt into the matching
            // token type instead of looking complete and then failing at exchange.
            'dpop.bound.access.tokens' => 'true',
            'frontchannel.logout' => $logoutChannel === 'frontchannel' ? 'true' : 'false',
            'frontchannel.logout.session.required' => 'true',
            'frontchannel.logout.url' => $origins[0] . '/api/openidconnect/auth/frontchannel/'
                . rawurlencode($applicationCode),
            'backchannel.logout.session.required' => 'true',
            'backchannel.logout.revoke.offline.tokens' => 'false',
        ];
        if ($logoutChannel === 'backchannel') {
            $attributes['backchannel.logout.url'] = $origins[0]
                . '/api/openidconnect/auth/backchannel/' . rawurlencode($applicationCode);
        }
        if ($postLogout !== []) {
            $attributes['post.logout.redirect.uris'] = implode('##', $postLogout);
            // Keycloak 26.5 introduced an independent confirmation landing page.
            // Leaving it enabled would consume a valid post_logout_redirect_uri
            // until the user clicks again, contradicting OPNsense's explicit
            // Return here after logout setting.
            $attributes['logout.confirmation.enabled'] = 'false';
        }

        $client = [
            'clientId' => $slug,
            'name' => $displayName,
            'description' => 'OPNsense WebGUI login through OpenID Connect',
            'rootUrl' => $origins[0],
            'baseUrl' => self::loginUrl($origins[0], $displayName),
            'alwaysDisplayInConsole' => true,
            'enabled' => true,
            'protocol' => 'openid-connect',
            'clientAuthenticatorType' => 'client-secret',
            'publicClient' => false,
            'standardFlowEnabled' => true,
            'implicitFlowEnabled' => false,
            'directAccessGrantsEnabled' => false,
            'serviceAccountsEnabled' => false,
            'frontchannelLogout' => $logoutChannel === 'frontchannel',
            'redirectUris' => $callbacks,
            'webOrigins' => $origins,
            'attributes' => $attributes,
            // Keycloak 25 moved the mandatory sub and max_age/auth_time evidence
            // into this built-in default scope. Omitting it produces a valid-looking
            // client which the RP must refuse after the first authorization response.
            'defaultClientScopes' => ['basic'],
            'optionalClientScopes' => array_values(array_diff($projection['scopes'], ['openid'])),
        ];
        if ($sectorOrigin !== '') {
            $client['protocolMappers'] = [[
                'name' => 'Pairwise subject identifier',
                'protocol' => 'openid-connect',
                'protocolMapper' => 'oidc-sha256-pairwise-sub-mapper',
                'consentRequired' => false,
                'config' => [
                    'sectorIdentifierUri' => $sectorOrigin . '/api/openidconnect/auth/sector/'
                        . rawurlencode($applicationCode),
                ],
            ]];
        }

        $document = [
            /* Used by kcadm/direct API imports. The Admin Console asks separately. */
            'ifResourceExists' => 'SKIP',
            'clients' => [$client],
        ];
        $content = json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($content)) {
            throw new \RuntimeException('The Keycloak setup file could not be encoded.');
        }

        return [
            'filename' => $slug . '-keycloak-partial-import.json',
            'media_type' => 'application/json',
            'content' => $content . "\n",
            'client_id_hint' => 'The generated `Client ID` is `' . $slug . '`; copy its generated secret from the ' .
                '`Credentials` tab.',
            'issuer_hint' => 'Copy the exact issuer of the Keycloak realm into `Exact issuer URL` in OPNsense.',
        ];
    }
}
