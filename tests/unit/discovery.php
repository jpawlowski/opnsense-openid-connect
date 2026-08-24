<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;
use OPNsense\OpenIDConnect\Api\DiscoveryController;
use OPNsense\OpenIDConnect\ProviderMetadata;

/** @return array{label:string,value:string,status:string,note:string} */
function discoveryCheck(array $checks, string $label): array
{
    foreach ($checks as $check) {
        if ($check['label'] === $label) {
            return $check;
        }
    }
    throw new RuntimeException('The expected Discovery check is absent');
}

/** @return array<string,mixed> */
function discoveryMetadata(array $extra = []): array
{
    return $extra + [
        'issuer' => 'https://id.example.net',
        'authorization_endpoint' => 'https://id.example.net/authorize',
        'token_endpoint' => 'https://id.example.net/token',
        'jwks_uri' => 'https://id.example.net/keys',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['S256'],
    ];
}

Checks::group('Discovery connectivity authentication readiness');

$discoveryController = new DiscoveryController(new Request(), new Session());
$tlsOnlyMetadata = ProviderMetadata::fromArray(discoveryMetadata([
    'token_endpoint_auth_methods_supported' => ['tls_client_auth'],
]));
$secretOnlySettings = connector([
    'openidconnect_client_id' => 'secret-client',
    'openidconnect_client_secret' => 'secret',
]);
$secretOnlyChecks = inspect(
    $discoveryController,
    'checks',
    $tlsOnlyMetadata,
    $secretOnlySettings,
    'general',
    'query',
    'auto'
);
Checks::that(
    'a provider-only mTLS method is not reported usable without a configured certificate',
    array_intersect_key(discoveryCheck($secretOnlyChecks, 'Client authentication'), [
        'value' => true,
        'status' => true,
    ]),
    ['value' => 'None supported', 'status' => 'warning']
);
Checks::that(
    'automatic authentication is warned when no method matches the configured credential',
    discoveryCheck($secretOnlyChecks, 'Selected authentication method')['status'],
    'warning'
);

$missingSecretChecks = inspect(
    $discoveryController,
    'checks',
    ProviderMetadata::fromArray(discoveryMetadata([
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
    ])),
    connector(['openidconnect_client_id' => 'incomplete-secret-client']),
    'general',
    'query',
    'auto'
);
Checks::that(
    'a secret method is not reported usable without its configured secret',
    discoveryCheck($missingSecretChecks, 'Client authentication')['status'],
    'warning'
);

installClientCertificate('discovery-mtls', 'Discovery mTLS certificate');
$mtlsSettings = connector([
    'openidconnect_client_id' => 'mtls-client',
    'openidconnect_client_certificate' => 'discovery-mtls',
]);
$mtlsChecks = inspect(
    $discoveryController,
    'checks',
    $tlsOnlyMetadata,
    $mtlsSettings,
    'general',
    'query',
    'auto'
);
Checks::that(
    'the same provider authentication is usable with its selected certificate',
    array_intersect_key(discoveryCheck($mtlsChecks, 'Client authentication'), [
        'value' => true,
        'status' => true,
    ]),
    ['value' => 'tls_client_auth', 'status' => 'success']
);
