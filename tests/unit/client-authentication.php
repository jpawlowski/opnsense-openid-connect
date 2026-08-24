<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\ClientAssertion;
use OPNsense\OpenIDConnect\ClientAuthenticator;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProtocolException;
use OPNsense\OpenIDConnect\ProviderMetadata;

function clientAuthenticationMetadata(array $extra = []): ProviderMetadata
{
    return ProviderMetadata::fromArray($extra + [
        'issuer' => 'https://id.example.net',
        'authorization_endpoint' => 'https://id.example.net/authorize',
        'token_endpoint' => 'https://id.example.net/token',
        'jwks_uri' => 'https://id.example.net/keys',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
        'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
    ]);
}

function testClientAssertion(OPNsense\Auth\OpenIDConnect $settings): ClientAssertion
{
    return new class($settings) extends ClientAssertion {
        protected function certificate(string $reference)
        {
            return $reference === '0123456789abc' ? ['crt' => 'certificate', 'prv' => 'private-key'] : false;
        }

        protected function loadPrivateKey(string $privateKey): object
        {
            return (object)['private' => $privateKey];
        }

        protected function certificateThumbprint(string $certificate): string
        {
            return hash('sha256', $certificate, true);
        }

        protected function selectAlgorithm(object $key, array $advertisedAlgorithms): string
        {
            if (!in_array('RS256', $advertisedAlgorithms, true)) {
                throw new ProtocolException('no shared test algorithm');
            }
            return 'RS256';
        }

        protected function sign(object $key, string $algorithm, string $input): string
        {
            return hash('sha256', $algorithm . "\0" . $input, true);
        }
    };
}

/** @return array{array<string,mixed>,array<string,mixed>} */
function clientAssertionParts(string $assertion): array
{
    $parts = explode('.', $assertion);
    return [
        json_decode(JwtVerifier::base64UrlDecode($parts[0]), true, 16, JSON_THROW_ON_ERROR),
        json_decode(JwtVerifier::base64UrlDecode($parts[1]), true, 16, JSON_THROW_ON_ERROR),
    ];
}

Checks::group('Private-key JWT client assertions');

$assertionSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_token_auth' => 'private_key_jwt',
    'openidconnect_signing_certificate' => '0123456789abc',
]);
$assertionFactory = testClientAssertion($assertionSettings);
$firstAssertion = $assertionFactory->create('https://id.example.net/token', ['RS256'], 2000000000);
$secondAssertion = $assertionFactory->create('https://id.example.net/token', ['RS256'], 2000000000);
[$assertionHeader, $assertionClaims] = clientAssertionParts($firstAssertion);
[, $secondClaims] = clientAssertionParts($secondAssertion);
Checks::that('the certificate thumbprint and negotiated algorithm identify the signing key', [
    $assertionHeader['alg'],
    $assertionHeader['x5t#S256'],
], ['RS256', JwtVerifier::base64UrlEncode(hash('sha256', 'certificate', true))]);
Checks::that('issuer and subject both identify the OAuth client', [
    $assertionClaims['iss'], $assertionClaims['sub'], $assertionClaims['aud'],
], ['client-id', 'client-id', 'https://id.example.net/token']);
Checks::that('the assertion has a tightly bounded validity window', [
    $assertionClaims['iat'], $assertionClaims['exp'],
], [2000000000, 2000000000 + ClientAssertion::LIFETIME]);
Checks::that('every request receives a fresh replay identifier',
    $assertionClaims['jti'] === $secondClaims['jti'], false);
Checks::throws(
    'an assertion is refused when the provider and key share no algorithm',
    fn() => $assertionFactory->create('https://id.example.net/token', ['ES256'], 2000000000),
    'shared test algorithm'
);

Checks::group('Endpoint client authentication');

$authenticator = new ClientAuthenticator($assertionSettings, $assertionFactory);
$fields = ['grant_type' => 'authorization_code'];
$headers = [];
$authenticator->authenticate(
    clientAuthenticationMetadata(),
    'https://id.example.net/token',
    ClientAuthenticator::TOKEN,
    $fields,
    $headers
);
[, $tokenClaims] = clientAssertionParts($fields['client_assertion']);
Checks::that('the token request carries exactly one assertion credential', [
    $fields['client_id'],
    $fields['client_assertion_type'],
    $tokenClaims['aud'],
    isset($fields['client_secret']),
    count($headers),
], [
    'client-id', ClientAssertion::TYPE, 'https://id.example.net/token', false, 0,
]);

$followingSettings = connector([
    'openidconnect_client_id' => 'following-client',
    'openidconnect_client_secret' => 'still-configured',
    'openidconnect_signing_certificate' => '0123456789abc',
]);
$followingFields = [];
$followingHeaders = [];
(new ClientAuthenticator($followingSettings, testClientAssertion($followingSettings)))->authenticate(
    clientAuthenticationMetadata(),
    'https://id.example.net/token',
    ClientAuthenticator::TOKEN,
    $followingFields,
    $followingHeaders
);
Checks::that(
    'RFC9700-2.5-ASYMMETRIC-CLIENT-AUTH positive: Follow the provider prefers an available private-key credential',
    isset($followingFields['client_assertion']),
    true
);

$secretFallbackSettings = connector([
    'openidconnect_client_id' => 'fallback-client',
    'openidconnect_client_secret' => 'fallback-secret',
    'openidconnect_signing_certificate' => '0123456789abc',
]);
$secretFallbackFields = [];
$secretFallbackHeaders = [];
(new ClientAuthenticator($secretFallbackSettings, testClientAssertion($secretFallbackSettings)))->authenticate(
    clientAuthenticationMetadata([
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
    ]),
    'https://id.example.net/token',
    ClientAuthenticator::TOKEN,
    $secretFallbackFields,
    $secretFallbackHeaders
);
Checks::that(
    'RFC9700-2.5-ASYMMETRIC-CLIENT-AUTH negative: provider incompatibility permits static-secret fallback',
    [
        isset($secretFallbackFields['client_assertion']),
        count(array_filter($secretFallbackHeaders, static fn(string $header): bool =>
            str_starts_with($header, 'Authorization: Basic '))),
    ],
    [false, 1]
);

$missingCertificateSettings = connector([
    'openidconnect_client_id' => 'fallback-client',
    'openidconnect_client_secret' => 'fallback-secret',
]);
$missingCertificateFields = [];
$missingCertificateHeaders = [];
(new ClientAuthenticator(
    $missingCertificateSettings,
    testClientAssertion($missingCertificateSettings)
))->authenticate(
    clientAuthenticationMetadata([
        'token_endpoint_auth_methods_supported' => ['private_key_jwt', 'client_secret_basic'],
    ]),
    'https://id.example.net/token',
    ClientAuthenticator::TOKEN,
    $missingCertificateFields,
    $missingCertificateHeaders
);
Checks::that(
    'RFC9700-2.5-ASYMMETRIC-CLIENT-AUTH negative: a missing certificate permits static-secret fallback',
    [
        isset($missingCertificateFields['client_assertion']),
        count(array_filter($missingCertificateHeaders, static fn(string $header): bool =>
            str_starts_with($header, 'Authorization: Basic '))),
    ],
    [false, 1]
);

Checks::throws(
    'an explicit private-key method must still be advertised',
    function () use ($authenticator): void {
        $fields = [];
        $headers = [];
        $authenticator->authenticate(
            clientAuthenticationMetadata(['token_endpoint_auth_methods_supported' => ['client_secret_basic']]),
            'https://id.example.net/token',
            ClientAuthenticator::TOKEN,
            $fields,
            $headers
        );
    },
    'not advertised'
);

$parFields = ['response_type' => 'code'];
$parHeaders = [];
$authenticator->authenticate(
    clientAuthenticationMetadata(),
    'https://id.example.net/par',
    ClientAuthenticator::TOKEN,
    $parFields,
    $parHeaders,
    'https://id.example.net'
);
[, $parClaims] = clientAssertionParts($parFields['client_assertion']);
Checks::that('PAR uses the authorization-server issuer as its assertion audience',
    $parClaims['aud'], 'https://id.example.net');

$revocationFields = ['token' => 'grant'];
$revocationHeaders = [];
$authenticator->authenticate(
    clientAuthenticationMetadata([
        'revocation_endpoint' => 'https://id.example.net/revoke',
        'revocation_endpoint_auth_methods_supported' => ['private_key_jwt'],
        'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256'],
    ]),
    'https://id.example.net/revoke',
    ClientAuthenticator::REVOCATION,
    $revocationFields,
    $revocationHeaders
);
[, $revocationClaims] = clientAssertionParts($revocationFields['client_assertion']);
Checks::that('revocation negotiates its endpoint-specific metadata and audience',
    $revocationClaims['aud'], 'https://id.example.net/revoke');

$introspectionFields = ['token' => 'grant'];
$introspectionHeaders = [];
$authenticator->authenticate(
    clientAuthenticationMetadata([
        'introspection_endpoint' => 'https://id.example.net/introspect',
        'introspection_endpoint_auth_methods_supported' => ['private_key_jwt'],
        'introspection_endpoint_auth_signing_alg_values_supported' => ['RS256'],
    ]),
    'https://id.example.net/introspect',
    ClientAuthenticator::INTROSPECTION,
    $introspectionFields,
    $introspectionHeaders
);
[, $introspectionClaims] = clientAssertionParts($introspectionFields['client_assertion']);
Checks::that('the shared authenticator is ready for endpoint-specific introspection',
    $introspectionClaims['aud'], 'https://id.example.net/introspect');

$missingAlgorithms = clientAuthenticationMetadata()->toArray();
unset($missingAlgorithms['token_endpoint_auth_signing_alg_values_supported']);
Checks::throws(
    'Generic refuses private-key JWT when Discovery supplies no negotiable algorithm',
    function () use ($authenticator, $missingAlgorithms): void {
        $fields = [];
        $headers = [];
        $authenticator->authenticate(
            ProviderMetadata::fromArray($missingAlgorithms),
            'https://id.example.net/token',
            ClientAuthenticator::TOKEN,
            $fields,
            $headers
        );
    },
    'shared test algorithm'
);

Checks::throws(
    'private-key authentication is refused without a selected signing certificate',
    function (): void {
        $settings = connector([
            'openidconnect_client_id' => 'client-id',
            'openidconnect_token_auth' => 'private_key_jwt',
        ]);
        $authenticator = new ClientAuthenticator($settings, testClientAssertion($settings));
        $fields = [];
        $headers = [];
        $authenticator->authenticate(
            clientAuthenticationMetadata(),
            'https://id.example.net/token',
            ClientAuthenticator::TOKEN,
            $fields,
            $headers
        );
    },
    'no signing certificate'
);
