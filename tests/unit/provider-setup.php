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
    ['https://firewall.example.com', 'https://192.0.2.10:8443'],
    true,
    'backchannel'
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
Checks::that('the blueprint preserves generated credentials on a repeat import', substr_count($authentik['content'], 'state: created'), 2);
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

$keycloak = ProviderSetup::generate(
    'keycloak',
    'Main_ONE',
    'OPNsense WebGUI',
    ['https://firewall.example.net'],
    false,
    'frontchannel'
);
$keycloakJson = json_decode($keycloak['content'], true, 32, JSON_THROW_ON_ERROR);
$client = $keycloakJson['clients'][0];
Checks::that('Keycloak receives a partial realm import', $keycloak['media_type'], 'application/json');
Checks::that('a repeat Keycloak import preserves the client', $keycloakJson['ifResourceExists'], 'SKIP');
Checks::that('the derived Keycloak client ID is portable', $client['clientId'], 'opnsense-main-one');
Checks::that('Keycloak generates its own secret', array_key_exists('secret', $client), false);
Checks::that('Keycloak is a confidential client', $client['publicClient'], false);
Checks::that('only authorization code is enabled', [
    $client['standardFlowEnabled'], $client['implicitFlowEnabled'], $client['directAccessGrantsEnabled'],
], [true, false, false]);
Checks::that('Keycloak receives exact web origins', $client['webOrigins'], ['https://firewall.example.net']);
Checks::that('no unused post logout address is registered', isset(
    $client['attributes']['post.logout.redirect.uris']
), false);
Checks::that('front-channel is selected consistently', [
    $client['frontchannelLogout'],
    $client['attributes']['frontchannel.logout'],
    isset($client['attributes']['backchannel.logout.url']),
], [true, 'true', false]);
Checks::that('Keycloak public subjects remain unchanged unless a sector is selected',
    array_key_exists('protocolMappers', $client), false);

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
