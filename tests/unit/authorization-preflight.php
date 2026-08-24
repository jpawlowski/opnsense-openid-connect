<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\AuthorizationPreflight;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\ProviderMetadata;

Checks::group('Authorization registration preflight');

$preflightIssuer = 'https://preflight.example.net';
$preflightMetadataValues = [
    'issuer' => $preflightIssuer,
    'authorization_endpoint' => $preflightIssuer . '/authorize',
    'token_endpoint' => $preflightIssuer . '/token',
    'jwks_uri' => $preflightIssuer . '/keys',
    'response_types_supported' => ['code'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
    'code_challenge_methods_supported' => ['S256'],
];
$preflightMetadata = ProviderMetadata::fromArray($preflightMetadataValues);
$preflightSettings = connector([
    'openidconnect_provider_url' => $preflightIssuer,
    'openidconnect_client_id' => 'current-client',
    'openidconnect_client_secret' => 'secret-never-sent-to-authorization',
    'openidconnect_par_mode' => 'disabled',
]);
$preflightCallback = 'https://firewall.example.net/api/openidconnect/auth/callback/current';
$preflightRequest = '';
$acceptedPreflight = new AuthorizationPreflight(new HttpClient(static function (
    string $method,
    string $url
) use (&$preflightRequest, $preflightCallback): array {
    $preflightRequest = $url;
    parse_str((string)parse_url($url, PHP_URL_QUERY), $parameters);
    return [
        'status' => 302,
        'content_type' => 'text/html',
        'body' => '',
        'location' => $preflightCallback . '?error=login_required&state=' . rawurlencode($parameters['state']),
    ];
}));
$accepted = $acceptedPreflight->check($preflightSettings, $preflightMetadata, $preflightCallback);
Checks::that('a silent exact callback proves the public client registration', $accepted['status'], 'success');
parse_str((string)parse_url($preflightRequest, PHP_URL_QUERY), $preflightParameters);
Checks::that('the registration check requests no provider user interface', $preflightParameters['prompt'], 'none');
Checks::that('the registration check retains PKCE S256', $preflightParameters['code_challenge_method'], 'S256');
Checks::that('the registration check sends no client secret', str_contains(
    $preflightRequest,
    'secret-never-sent-to-authorization'
), false);

$rejected = (new AuthorizationPreflight(new HttpClient(static fn(): array => [
    'status' => 400,
    'content_type' => 'text/html',
    'body' => '<html>untrusted provider detail</html>',
    'location' => '',
])))->check($preflightSettings, $preflightMetadata, $preflightCallback);
Checks::that('an authorization-endpoint rejection blocks the browser test', $rejected['status'], 'error');
Checks::that('an untrusted provider error body is not reflected', str_contains(
    json_encode($rejected, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
    'untrusted provider detail'
), false);

$wrongCallback = (new AuthorizationPreflight(new HttpClient(static function (
    string $method,
    string $url
) use ($preflightCallback): array {
    parse_str((string)parse_url($url, PHP_URL_QUERY), $parameters);
    return [
        'status' => 302,
        'content_type' => 'text/html',
        'body' => '',
        'location' => $preflightCallback . '/lookalike?state=' . rawurlencode($parameters['state']),
    ];
})))->check($preflightSettings, $preflightMetadata, $preflightCallback);
Checks::that('a lookalike callback is inconclusive rather than accepted', $wrongCallback['status'], 'warning');

$parRequests = 0;
$parMetadata = ProviderMetadata::fromArray($preflightMetadataValues + [
    'pushed_authorization_request_endpoint' => $preflightIssuer . '/par',
]);
$parSettings = connector([
    'openidconnect_provider_url' => $preflightIssuer,
    'openidconnect_client_id' => 'current-client',
    'openidconnect_client_secret' => 'current-secret',
    'openidconnect_par_mode' => 'auto',
]);
$parCovered = (new AuthorizationPreflight(new HttpClient(static function () use (&$parRequests): array {
    $parRequests++;
    return [];
})))->check($parSettings, $parMetadata, $preflightCallback);
Checks::that('health lets authenticated PAR cover the same registration', $parCovered['verification'], 'skipped');
Checks::that('the reduced authorization request is not duplicated beside PAR', $parRequests, 0);
