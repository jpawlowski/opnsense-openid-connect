<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\ProviderSetup;

Checks::group('Provider setup files from an unfinished form');

$authentik = ProviderSetup::generate(
    'authentik',
    'private-fw',
    "OPNsense administrator's WebGUI",
    ['https://192.0.2.10:8443', 'https://firewall.example.com'],
    true,
    'backchannel',
    '',
    [],
    'https://firewall.example.com'
);
Checks::that('authentik receives a YAML blueprint', $authentik['media_type'], 'application/yaml');
Checks::that('the authentik filename is stable', $authentik['filename'], 'opnsense-private-fw-authentik-blueprint.yaml');
Checks::that('the authentik schema is pinned to the tested 2026.8 line', str_contains(
    $authentik['content'],
    '$schema=https://version-2026-8.goauthentik.io/blueprints/schema.json'
), true);
Checks::that('the authentik provider identity is stable across display-name changes', str_contains(
    $authentik['content'],
    "name: 'OPNsense WebGUI (opnsense-private-fw)'"
), true);
Checks::that('the blueprint never contains a client secret field', str_contains($authentik['content'], 'client_secret:'), false);
Checks::that('the blueprint lets authentik generate the client ID too', str_contains($authentik['content'], 'client_id:'), false);
Checks::that('the blueprint preserves generated resources on a repeat import', substr_count(
    $authentik['content'],
    'state: created'
), 3);
Checks::that('the provider identifier is not duplicated in attrs', substr_count(
    $authentik['content'],
    "name: 'OPNsense WebGUI (opnsense-private-fw)'"
), 1);
Checks::that('the application identifier is not duplicated in attrs', substr_count(
    $authentik['content'],
    "slug: 'opnsense-private-fw'"
), 1);
Checks::that('authentik uses an asymmetric signing key', str_contains($authentik['content'], 'signing_key: !Find'), true);
Checks::that('authentik gets exact callback one', str_contains(
    $authentik['content'],
    'https://firewall.example.com/api/openidconnect/auth/callback/private-fw'
), true);
Checks::that('authentik gets exact callback two', str_contains(
    $authentik['content'],
    'https://192.0.2.10:8443/api/openidconnect/auth/callback/private-fw'
), true);
Checks::that('authentik keeps the download origin callback first', strpos(
    $authentik['content'],
    'https://firewall.example.com/api/openidconnect/auth/callback/private-fw'
) < strpos(
    $authentik['content'],
    'https://192.0.2.10:8443/api/openidconnect/auth/callback/private-fw'
), true);
Checks::that('authentik explicitly launches the canonical local login start', str_contains(
    $authentik['content'],
    "meta_launch_url: 'https://firewall.example.com/api/openidconnect/auth/login?provider="
        . "OPNsense%20administrator%27s%20WebGUI'"
), true);
Checks::that('authentik gets typed post logout addresses', substr_count(
    $authentik['content'],
    'redirect_uri_type: logout'
), 2);
Checks::that('authentik uses only the canonical origin for its notification', str_contains(
    $authentik['content'],
    'logout_uri: \'https://firewall.example.com/api/openidconnect/auth/backchannel/private-fw\''
), true);
Checks::that('YAML single quotes in a name are escaped', str_contains(
    $authentik['content'],
    "name: 'OPNsense administrator''s WebGUI'"
), true);
Checks::that('authentik receives a dedicated verified e-mail scope mapping', str_contains(
    $authentik['content'],
    "name: 'OPNsense verified e-mail (opnsense-private-fw)'"
), true);
Checks::that('authentik e-mail verification fails closed unless its boolean user attribute is true', [
    str_contains($authentik['content'], 'verified = request.user.attributes.get("email_verified", False)'),
    str_contains($authentik['content'], '"email_verified": verified is True'),
    str_contains($authentik['content'], 'goauthentik.io/providers/oauth2/scope-email'),
], [true, true, false]);
Checks::that('the authentik provider uses the dedicated e-mail mapping', str_contains(
    $authentik['content'],
    "- !KeyOf 'opnsense-private-fw-verified-email-scope'"
), true);

$authentikWithoutEmail = ProviderSetup::generate(
    'authentik',
    'minimal',
    'Minimal OPNsense WebGUI',
    ['https://firewall.example.com'],
    false,
    'backchannel',
    '',
    [
        'openidconnect_scopes' => 'openid,profile',
        'openidconnect_username_claim' => 'preferred_username',
    ]
);
Checks::that('authentik receives only the configured standard scope mappings', [
    str_contains($authentikWithoutEmail['content'], 'scope-openid'),
    str_contains($authentikWithoutEmail['content'], 'scope-profile'),
    str_contains($authentikWithoutEmail['content'], 'verified-email-scope'),
    str_contains($authentikWithoutEmail['content'], 'email_verified'),
], [true, true, false, false]);

$keycloak = ProviderSetup::generate(
    'keycloak',
    'Main_ONE',
    'OPNsense WebGUI',
    ['https://backup.example.net', 'https://firewall.example.net'],
    false,
    'frontchannel',
    '',
    [],
    'https://firewall.example.net'
);
$keycloakJson = json_decode($keycloak['content'], true, 32, JSON_THROW_ON_ERROR);
$client = $keycloakJson['clients'][0];
Checks::that('Keycloak receives a partial realm import', $keycloak['media_type'], 'application/json');
Checks::that('a repeat Keycloak import preserves the client', $keycloakJson['ifResourceExists'], 'SKIP');
Checks::that('the derived Keycloak client ID is portable', $client['clientId'], 'opnsense-main-one');
Checks::that('Keycloak generates its own secret', array_key_exists('secret', $client), false);
Checks::that('Keycloak retains its required basic scope and links requested scopes as optional', [
    $client['defaultClientScopes'],
    $client['optionalClientScopes'],
], [['basic'], ['email', 'profile']]);
Checks::that('Keycloak is a confidential client', $client['publicClient'], false);
Checks::that('only authorization code is enabled', [
    $client['standardFlowEnabled'], $client['implicitFlowEnabled'], $client['directAccessGrantsEnabled'],
], [true, false, false]);
Checks::that('Keycloak keeps the download origin first in callbacks and web origins', [
    $client['redirectUris'],
    $client['webOrigins'],
], [[
    'https://firewall.example.net/api/openidconnect/auth/callback/Main_ONE',
    'https://backup.example.net/api/openidconnect/auth/callback/Main_ONE',
], [
    'https://firewall.example.net',
    'https://backup.example.net',
]]);
Checks::that('Keycloak explicitly exposes the canonical local login start', [
    $client['rootUrl'],
    $client['baseUrl'],
    $client['alwaysDisplayInConsole'],
], [
    'https://firewall.example.net',
    'https://firewall.example.net/api/openidconnect/auth/login?provider=OPNsense%20WebGUI',
    true,
]);
Checks::that('Keycloak binds access tokens to the proof key required by its advertised DPoP path',
    $client['attributes']['dpop.bound.access.tokens'], 'true');
Checks::that('no unused post logout address is registered', isset(
    $client['attributes']['post.logout.redirect.uris']
), false);
Checks::that('no Keycloak logout-page preference is imposed without a return address', isset(
    $client['attributes']['logout.confirmation.enabled']
), false);
Checks::that('front-channel is selected consistently', [
    $client['frontchannelLogout'],
    $client['attributes']['frontchannel.logout'],
    isset($client['attributes']['backchannel.logout.url']),
], [true, 'true', false]);
Checks::that('Keycloak public subjects remain unchanged unless a sector is selected',
    array_key_exists('protocolMappers', $client), false);

$minimalKeycloak = ProviderSetup::generate(
    'keycloak',
    'minimal',
    'Minimal OPNsense WebGUI',
    ['https://firewall.example.net'],
    false,
    'backchannel',
    '',
    [
        'openidconnect_scopes' => 'openid,profile',
        'openidconnect_username_claim' => 'preferred_username',
    ]
);
$minimalKeycloakClient = json_decode($minimalKeycloak['content'], true, 32, JSON_THROW_ON_ERROR)['clients'][0];
Checks::that('Keycloak does not link an unrequested e-mail scope', [
    $minimalKeycloakClient['defaultClientScopes'],
    $minimalKeycloakClient['optionalClientScopes'],
], [['basic'], ['profile']]);

$returningKeycloak = ProviderSetup::generate(
    'keycloak',
    'returning',
    'Returning OPNsense WebGUI',
    ['https://firewall.example.net'],
    true,
    'backchannel'
);
$returningKeycloakClient = json_decode(
    $returningKeycloak['content'],
    true,
    32,
    JSON_THROW_ON_ERROR
)['clients'][0];
Checks::that('Keycloak returns immediately when the generated setup requests it', [
    $returningKeycloakClient['attributes']['post.logout.redirect.uris'],
    $returningKeycloakClient['attributes']['logout.confirmation.enabled'],
], ['https://firewall.example.net/', 'false']);

$pairwiseKeycloak = ProviderSetup::generate(
    'keycloak',
    'pairwise',
    'Pairwise OPNsense WebGUI',
    ['https://firewall.example.net', 'https://backup.example.net'],
    false,
    'backchannel',
    'https://firewall.example.net'
);
$pairwiseClient = json_decode($pairwiseKeycloak['content'], true, 32, JSON_THROW_ON_ERROR)['clients'][0];
$pairwiseMapper = $pairwiseClient['protocolMappers'][0];
Checks::that('Keycloak receives its built-in SHA-256 pairwise subject mapper', [
    $pairwiseMapper['protocolMapper'],
    $pairwiseMapper['config']['sectorIdentifierUri'],
], [
    'oidc-sha256-pairwise-sub-mapper',
    'https://firewall.example.net/api/openidconnect/auth/sector/pairwise',
]);
Checks::that('Keycloak generates and persists its own pairwise salt',
    array_key_exists('pairwiseSubAlgorithmSalt', $pairwiseMapper['config']), false);

Checks::throws('a provider without an importer is refused', function (): void {
    ProviderSetup::generate('entra', 'main', 'Firewall', ['https://firewall.example.com'], false);
}, 'no downloadable setup file');
Checks::throws('a launch URL cannot be generated from a synthetic server name', function (): void {
    ProviderSetup::generate('keycloak', 'main', '', ['https://firewall.example.com'], false);
}, 'authentication server name');
Checks::throws('an origin with a path is refused', function (): void {
    ProviderSetup::generate('authentik', 'main', 'Firewall', ['https://firewall.example.com/callback'], false);
}, 'not an HTTPS origin');
Checks::throws('HTTP is refused', function (): void {
    ProviderSetup::generate('keycloak', 'main', 'Firewall', ['http://firewall.example.com'], false);
}, 'not an HTTPS origin');
Checks::throws('an unsafe application code is refused', function (): void {
    ProviderSetup::generate('keycloak', '../main', 'Firewall', ['https://firewall.example.com'], false);
}, 'not URL-safe');
Checks::throws('a URL dot segment cannot become a provider callback path', function (): void {
    ProviderSetup::generate('keycloak', '..', 'Firewall', ['https://firewall.example.com'], false);
}, 'not URL-safe');
Checks::throws('an unknown logout channel is refused', function (): void {
    ProviderSetup::generate('keycloak', 'main', 'Firewall', ['https://firewall.example.com'], false, 'both');
}, 'Unknown logout channel');
Checks::throws('a pairwise sector outside the accepted origins is refused', function (): void {
    ProviderSetup::generate(
        'keycloak',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        'https://other.example.com'
    );
}, 'not an accepted WebGUI origin');
Checks::throws('authentik setup refuses an unenforced authentication requirement', function (): void {
    ProviderSetup::generate(
        'authentik',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        ['openidconnect_required_authentication' => 'phishing-resistant']
    );
}, 'cannot yet enforce the configured authentication requirement');
Checks::throws('Keycloak setup refuses an unenforced authentication requirement', function (): void {
    ProviderSetup::generate(
        'keycloak',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        ['openidconnect_required_authentication' => 'multi-factor']
    );
}, 'cannot yet enforce the configured authentication requirement');
Checks::throws('provider setup refuses a scope it cannot project', function (): void {
    ProviderSetup::generate(
        'authentik',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        ['openidconnect_scopes' => 'openid,custom']
    );
}, 'does not yet support every configured scope');
Checks::throws('provider setup refuses a username claim absent from its scopes', function (): void {
    ProviderSetup::generate(
        'keycloak',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        [
            'openidconnect_scopes' => 'openid,profile',
            'openidconnect_username_claim' => 'email',
        ]
    );
}, 'does not emit the configured username claim');
Checks::throws('provider setup refuses a preferred download origin outside its accepted list', function (): void {
    ProviderSetup::generate(
        'keycloak',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        [],
        'https://unaccepted.example.com'
    );
}, 'not in the accepted origin list');
Checks::throws('Keycloak setup refuses an unprojected group claim', function (): void {
    ProviderSetup::generate(
        'keycloak',
        'main',
        'Firewall',
        ['https://firewall.example.com'],
        false,
        'backchannel',
        '',
        ['openidconnect_group_claim' => 'groups']
    );
}, 'does not yet emit the configured group claim');
