<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;
use OPNsense\OpenIDConnect\DpopProof;
use OPNsense\OpenIDConnect\DpopKeyStore;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\RelyingParty;

/** @return array<string,mixed> */
function dpopMetadata(array $extra = []): array
{
    return $extra + [
        'issuer' => 'https://dpop.example.net',
        'authorization_endpoint' => 'https://dpop.example.net/authorize',
        'token_endpoint' => 'https://dpop.example.net/token?tenant=one',
        'jwks_uri' => 'https://dpop.example.net/keys',
        'userinfo_endpoint' => 'https://resource.example.net/userinfo?format=json',
        'revocation_endpoint' => 'https://dpop.example.net/revoke',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        'code_challenge_methods_supported' => ['S256'],
        'dpop_signing_alg_values_supported' => ['ES256'],
    ];
}

/** @param array<string,mixed> $value @param array<string,mixed> $headers */
function dpopAnswer(array $value, int $status = 200, array $headers = []): array
{
    return [
        'status' => $status,
        'content_type' => 'application/json',
        'body' => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        'location' => '',
        'headers' => $headers,
    ];
}

/** @param string[] $headers */
function dpopRequestHeader(array $headers): string
{
    foreach ($headers as $header) {
        if (str_starts_with($header, 'DPoP: ')) {
            return substr($header, strlen('DPoP: '));
        }
    }
    return '';
}

/** @return array{header:array<string,mixed>,claims:array<string,mixed>} */
function decodedDpop(string $proof): array
{
    $parts = explode('.', $proof);
    if (count($parts) !== 3) {
        return ['header' => [], 'claims' => []];
    }
    return [
        'header' => json_decode(JwtVerifier::base64UrlDecode($parts[0]), true, 16, JSON_THROW_ON_ERROR),
        'claims' => json_decode(JwtVerifier::base64UrlDecode($parts[1]), true, 16, JSON_THROW_ON_ERROR),
    ];
}

function dpopSettings(string $applicationCode, string $clientId = 'dpop-client'): OPNsense\Auth\OpenIDConnect
{
    return connector([
        'openidconnect_client_id' => $clientId,
        'openidconnect_client_secret' => 'secret',
        'openidconnect_provider_url' => 'https://dpop.example.net',
        'openidconnect_redirect_urls' => 'https://firewall.example.net',
        'openidconnect_app_code' => $applicationCode,
    ]);
}

$dpopJwk = [
    'kty' => 'EC',
    'crv' => 'P-256',
    'x' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'y' => 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
];
$dpopProof = DpopProof::forTesting($dpopJwk, static fn(string $input): string => str_repeat("\x01", 64));
$paddedDpopJwk = $dpopJwk;
$paddedDpopJwk['x'] .= '=';
$paddedDpopJwk['y'] .= '=';
$paddedDpopProof = DpopProof::forTesting(
    $paddedDpopJwk,
    static fn(string $input): string => str_repeat("\x01", 64)
);

Checks::group('RFC 9449 DPoP proofs');

Checks::that(
    'the padded JWK form emitted by OPNsense phpseclib is canonicalized',
    [$paddedDpopProof->publicKey(), $paddedDpopProof->keyId()],
    [$dpopJwk, $dpopProof->keyId()]
);

$firstProof = decodedDpop($dpopProof->proof(
    'post',
    'https://dpop.example.net/token?tenant=one',
    'access-token',
    'server-nonce',
    1700000000
));
$secondProof = decodedDpop($dpopProof->proof(
    'GET',
    'https://dpop.example.net/token?different=query',
    'access-token',
    null,
    1700000000
));
$rootProof = decodedDpop($dpopProof->proof('POST', 'https://dpop.example.net?tenant=one', null, null, 1700000000));
Checks::that('a proof is explicitly typed', $firstProof['header']['typ'], 'dpop+jwt');
Checks::that('only the supported asymmetric algorithm is used', $firstProof['header']['alg'], 'ES256');
Checks::that('the public proof key is embedded without private material', $firstProof['header']['jwk'], $dpopJwk);
Checks::that('the proof binds the actual HTTP method', $firstProof['claims']['htm'], 'POST');
Checks::that('the proof URI omits query data', $firstProof['claims']['htu'], 'https://dpop.example.net/token');
Checks::that(
    'the proof URI includes the effective root path',
    $rootProof['claims']['htu'],
    'https://dpop.example.net/'
);
Checks::that(
    'the proof binds the presented access token',
    $firstProof['claims']['ath'],
    JwtVerifier::base64UrlEncode(hash('sha256', 'access-token', true))
);
Checks::that('a server nonce is bound exactly', $firstProof['claims']['nonce'], 'server-nonce');
Checks::that('a different method produces a method-bound proof', $secondProof['claims']['htm'], 'GET');
Checks::that(
    'repeating a request still receives a replay-distinct identifier',
    $firstProof['claims']['jti'] !== $secondProof['claims']['jti'],
    true
);
Checks::throws(
    'an invalid nonce is never reflected into a proof',
    fn() => $dpopProof->proof('POST', 'https://dpop.example.net/token', null, "bad nonce"),
    'invalid DPoP nonce'
);
$orphanBinding = str_repeat('f', 64);
$orphanPath = (string)constant('OPENIDCONNECT_TEST_DPOP_DIRECTORY') . '/key-' . $orphanBinding . '.json';
file_put_contents($orphanPath, '{}');
touch($orphanPath, 1700000000 - DpopKeyStore::RETAIN_RETIRED_FOR - 1);
DpopKeyStore::pruneUnused([], null, 1700000000);
Checks::that('an unused provider key is removed only after the grant-retention window',
    is_file($orphanPath), false);
Checks::that(
    'editing the local application code keeps the provider proof-key store',
    DpopKeyStore::forSettings(dpopSettings('route-before'))->bindingId(),
    DpopKeyStore::forSettings(dpopSettings('route-after'))->bindingId()
);
$originalClientStore = DpopKeyStore::forSettings(dpopSettings('client-binding', 'client-before'));
$replacementClientStore = DpopKeyStore::forSettings(dpopSettings('client-binding', 'client-after'));
Checks::that(
    'changing the client ID selects a different provider proof-key store',
    $originalClientStore->bindingId() !== $replacementClientStore->bindingId(),
    true
);
Checks::that(
    'a session binding reopens the provider proof-key store from before a client-ID edit',
    DpopKeyStore::fromBindingId($originalClientStore->bindingId())->statePath(),
    $originalClientStore->statePath()
);
Checks::throws(
    'an invalid session binding cannot select a proof-key store',
    fn() => DpopKeyStore::fromBindingId('not-a-binding'),
    'valid DPoP provider binding identifier'
);

$rotationGeneration = 0;
$rotationGenerator = static function (int $created) use (&$rotationGeneration): array {
    $rotationGeneration++;
    $public = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => JwtVerifier::base64UrlEncode(hash('sha256', 'rotation-x-' . $rotationGeneration, true)),
        'y' => JwtVerifier::base64UrlEncode(hash('sha256', 'rotation-y-' . $rotationGeneration, true)),
    ];
    return [
        'id' => DpopProof::thumbprint($public),
        'created' => $created,
        'private_key' => 'not-loaded-by-this-rotation-test',
        'public_jwk' => $public,
    ];
};
$rotationStore = DpopKeyStore::forBinding('rotation-retention', null, $rotationGenerator);
$rotationState = ['version' => 1, 'active' => $rotationGenerator(0), 'retired' => []];
$oldestRotationKey = $rotationState['active']['id'];
for ($rotation = 1; $rotation <= 5; $rotation++) {
    $rotationState = inspect(
        $rotationStore,
        'rotatedState',
        $rotationState,
        $rotation * DpopKeyStore::ROTATE_AFTER
    );
}
Checks::that(
    'five rotations retain the oldest key through the stated grant window',
    in_array($oldestRotationKey, array_column($rotationState['retired'], 'id'), true),
    true
);

Checks::group('DPoP discovery and authorization-code binding');

$authorizationSession = new Session();
$authorizationController = new Controller(new Request('https', 'firewall.example.net'), $authorizationSession);
$authorizationParty = new RelyingParty(
    dpopSettings('dpop-authorization'),
    $authorizationController,
    new HttpClient(fn() => dpopAnswer(dpopMetadata())),
    null,
    null,
    $dpopProof
);
$authorizationUrl = $authorizationParty->authorizationUrl('dpop', '/');
parse_str((string)parse_url($authorizationUrl, PHP_URL_QUERY), $authorizationParameters);
Checks::that('Discovery negotiation binds the authorization code to the proof key',
    $authorizationParameters['dpop_jkt'], $dpopProof->keyId());
$storedTransactions = json_decode(
    (string)$authorizationSession->get('openidconnect_transactions_v2'),
    true,
    16,
    JSON_THROW_ON_ERROR
);
$storedTransaction = reset($storedTransactions);
Checks::that('the pending login freezes the exact proof-key generation',
    $storedTransaction['dpop_key'], $dpopProof->keyId());
Checks::that(
    'the completed exchange exposes the exact proof-key store binding for the session',
    $authorizationParty->getDpopBindingId(),
    DpopKeyStore::forSettings(dpopSettings('dpop-authorization'))->bindingId()
);

$bearerController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$bearerMetadata = dpopMetadata();
unset($bearerMetadata['dpop_signing_alg_values_supported']);
$bearerUrl = (new RelyingParty(
    dpopSettings('dpop-not-advertised'),
    $bearerController,
    new HttpClient(fn() => dpopAnswer($bearerMetadata))
))->authorizationUrl('bearer', '/');
parse_str((string)parse_url($bearerUrl, PHP_URL_QUERY), $bearerParameters);
Checks::that('DPoP is not guessed when Discovery does not advertise it',
    array_key_exists('dpop_jkt', $bearerParameters), false);
Checks::throws(
    'malformed DPoP algorithm metadata is refused',
    fn() => ProviderMetadata::fromArray(dpopMetadata(['dpop_signing_alg_values_supported' => ['ES256', 1]])),
    'invalid dpop_signing_alg_values_supported'
);

$parBody = '';
$parController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$parParty = new RelyingParty(
    dpopSettings('dpop-par'),
    $parController,
    new HttpClient(function (string $method, string $url, ?string $body) use (&$parBody): array {
        if (str_ends_with($url, ProviderMetadata::DISCOVERY_SUFFIX)) {
            return dpopAnswer(dpopMetadata([
                'pushed_authorization_request_endpoint' => 'https://dpop.example.net/par',
            ]));
        }
        $parBody = (string)$body;
        return dpopAnswer(['request_uri' => 'urn:example:request', 'expires_in' => 60], 201);
    }),
    null,
    null,
    $dpopProof
);
$parParty->authorizationUrl('dpop-par', '/');
parse_str($parBody, $parFields);
Checks::that('PAR carries the same authorization-code proof-key thumbprint',
    $parFields['dpop_jkt'], $dpopProof->keyId());

Checks::group('DPoP token and protected-resource requests');

$tokenProofs = [];
$tokenCalls = 0;
$tokenParty = new RelyingParty(
    dpopSettings('dpop-token-nonce'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(function ($method, $url, $body, $headers) use (&$tokenProofs, &$tokenCalls): array {
        $tokenProofs[] = decodedDpop(dpopRequestHeader($headers));
        $tokenCalls++;
        return $tokenCalls === 1
            ? dpopAnswer(['error' => 'use_dpop_nonce'], 400, ['dpop-nonce' => 'token-nonce'])
            : dpopAnswer(['access_token' => 'dpop-access', 'token_type' => 'DPoP']);
    }),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty = new ReflectionProperty(RelyingParty::class, 'metadata');
$dpopMetadataProperty->setValue($tokenParty, ProviderMetadata::fromArray(dpopMetadata()));
$issuedTokens = inspect($tokenParty, 'exchangeCode', 'code', 'verifier');
Checks::that('a valid nonce challenge is retried once', $tokenCalls, 2);
Checks::that('the retry uses the server nonce', $tokenProofs[1]['claims']['nonce'], 'token-nonce');
Checks::that('the retry never replays the challenged proof',
    $tokenProofs[0]['claims']['jti'] !== $tokenProofs[1]['claims']['jti'], true);
Checks::that('a DPoP token type is accepted after a DPoP request', $issuedTokens['token_type'], 'DPoP');
Checks::that(
    'a DPoP access token is serialized only as one token68 credential',
    inspect($tokenParty, 'dpopAuthorization', 'AZaz09-._~+/=='),
    'Authorization: DPoP AZaz09-._~+/=='
);
Checks::throws(
    'a DPoP access token that cannot be serialized safely is refused',
    fn() => inspect($tokenParty, 'dpopAuthorization', 'token with space'),
    'cannot be used as a DPoP token'
);
$laterTokens = inspect($tokenParty, 'exchangeCode', 'later-code', 'later-verifier');
Checks::that('a later request cannot omit a nonce the server already supplied',
    $tokenProofs[2]['claims']['nonce'], 'token-nonce');
Checks::that('the later nonce-bound token response remains usable', $laterTokens['token_type'], 'DPoP');

$downgradeParty = new RelyingParty(
    dpopSettings('dpop-downgrade'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(fn() => dpopAnswer(['access_token' => 'bearer-access', 'token_type' => 'Bearer'])),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty->setValue($downgradeParty, ProviderMetadata::fromArray(dpopMetadata()));
Checks::throws(
    'a DPoP request cannot be downgraded to a bearer access token',
    fn() => inspect($downgradeParty, 'exchangeCode', 'code', 'verifier'),
    'downgraded'
);

$userinfoProofs = [];
$userinfoAuthorizations = [];
$userinfoCalls = 0;
$userinfoParty = new RelyingParty(
    dpopSettings('dpop-userinfo-nonce'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(function ($method, $url, $body, $headers) use (
        &$userinfoProofs,
        &$userinfoAuthorizations,
        &$userinfoCalls
    ): array {
        $userinfoProofs[] = decodedDpop(dpopRequestHeader($headers));
        $userinfoAuthorizations[] = current(array_values(array_filter(
            $headers,
            static fn(string $header): bool => str_starts_with($header, 'Authorization: ')
        )));
        $userinfoCalls++;
        return $userinfoCalls === 1
            ? dpopAnswer([], 401, [
                'www-authenticate' => 'DPoP error="use_dpop_nonce"',
                'dpop-nonce' => 'resource-nonce',
            ])
            : dpopAnswer(['sub' => 'stable-subject']);
    }),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty->setValue($userinfoParty, ProviderMetadata::fromArray(dpopMetadata()));
$tokensProperty = new ReflectionProperty(RelyingParty::class, 'tokens');
$tokensProperty->setValue($userinfoParty, ['access_token' => 'dpop-access', 'token_type' => 'DPoP']);
$userinfo = inspect(
    $userinfoParty,
    'requestUserInfo',
    'https://resource.example.net/userinfo?format=json',
    'dpop-access'
);
Checks::that('a DPoP access token is never sent with the bearer scheme',
    $userinfoAuthorizations, ['Authorization: DPoP dpop-access', 'Authorization: DPoP dpop-access']);
Checks::that('UserInfo retries one valid resource-server nonce challenge', $userinfoCalls, 2);
Checks::that('the resource retry binds its own nonce',
    $userinfoProofs[1]['claims']['nonce'], 'resource-nonce');
Checks::that('the protected-resource proof binds the access-token hash',
    $userinfoProofs[1]['claims']['ath'], JwtVerifier::base64UrlEncode(hash('sha256', 'dpop-access', true)));
Checks::that('the nonce-bound UserInfo response remains usable', $userinfo['sub'], 'stable-subject');

$duplicateNonceParty = new RelyingParty(
    dpopSettings('dpop-duplicate-nonce'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(fn() => dpopAnswer(
        ['error' => 'use_dpop_nonce'],
        400,
        ['dpop-nonce' => ['first', 'second']]
    )),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty->setValue($duplicateNonceParty, ProviderMetadata::fromArray(dpopMetadata()));
Checks::throws(
    'more than one DPoP nonce in a response is refused',
    fn() => inspect($duplicateNonceParty, 'exchangeCode', 'code', 'verifier'),
    'more than one DPoP nonce'
);

$missingNonceParty = new RelyingParty(
    dpopSettings('dpop-missing-challenge-nonce'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(fn() => dpopAnswer(['error' => 'use_dpop_nonce'], 400)),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty->setValue($missingNonceParty, ProviderMetadata::fromArray(dpopMetadata()));
Checks::throws(
    'a nonce challenge without the required response header is refused without retry',
    fn() => inspect($missingNonceParty, 'exchangeCode', 'code', 'verifier'),
    'without supplying one'
);

$revocationProof = [];
$revocationBody = '';
$revocationParty = new RelyingParty(
    dpopSettings('dpop-revocation'),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(function ($method, $url, $body, $headers) use (&$revocationProof, &$revocationBody): array {
        $revocationProof = decodedDpop(dpopRequestHeader($headers));
        $revocationBody = (string)$body;
        return dpopAnswer([], 204);
    }),
    null,
    null,
    $dpopProof
);
$dpopMetadataProperty->setValue($revocationParty, ProviderMetadata::fromArray(dpopMetadata()));
$revocationParty->revokeToken('dpop-access', 'access_token');
parse_str($revocationBody, $revocationFields);
Checks::that('revocation returns the token through the authenticated form body',
    $revocationFields['token'], 'dpop-access');
Checks::that('revocation carries a fresh POST proof for its exact endpoint', [
    $revocationProof['claims']['htm'],
    $revocationProof['claims']['htu'],
], ['POST', 'https://dpop.example.net/revoke']);
Checks::that('a revocation proof does not pretend the body token is resource Authorization',
    array_key_exists('ath', $revocationProof['claims']), false);
