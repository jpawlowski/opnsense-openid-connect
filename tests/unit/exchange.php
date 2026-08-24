<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\RelyingParty;

function metadata(array $extra = []): array
{
    return $extra + [
        'issuer' => 'https://id.example.net',
        'authorization_endpoint' => 'https://id.example.net/authorize',
        'token_endpoint' => 'https://id.example.net/token',
        'jwks_uri' => 'https://id.example.net/keys',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        'code_challenge_methods_supported' => ['S256'],
    ];
}

function metadataWithout(string $name): array
{
    $values = metadata();
    unset($values[$name]);
    return $values;
}

function jsonAnswer(array $value, int $status = 200, array $headers = []): array
{
    return [
        'status' => $status,
        'content_type' => 'application/json',
        'body' => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        'location' => '',
        'headers' => $headers,
    ];
}

function compactJwt(array $claims, array $header = ['alg' => 'RS256', 'kid' => 'test-key']): string
{
    return JwtVerifier::base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)) . '.'
        . JwtVerifier::base64UrlEncode(json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)) . '.'
        . JwtVerifier::base64UrlEncode('test-signature');
}

Checks::group('Strict provider discovery');

$http = new HttpClient(fn() => jsonAnswer(metadata()));
$discovered = ProviderMetadata::discover('https://id.example.net', $http);
Checks::that('the exact configured issuer is retained', $discovered->issuer(), 'https://id.example.net');
Checks::that('the authorization endpoint is read from discovery', $discovered->authorizationEndpoint(), 'https://id.example.net/authorize');
Checks::that('query response mode uses the RFC 8414 omission default', (function () use ($discovered): bool {
    $discovered->assertAuthorizationCapabilities('query');
    return true;
})(), true);
Checks::that('an explicitly advertised form_post response mode is accepted', (function (): bool {
    ProviderMetadata::fromArray(metadata(['response_modes_supported' => ['form_post']]))
        ->assertAuthorizationCapabilities('form_post');
    return true;
})(), true);
Checks::that('token endpoint authentication uses the RFC 8414 omission default',
    ProviderMetadata::fromArray(metadataWithout('token_endpoint_auth_methods_supported'))
        ->tokenEndpointAuthMethod(), 'client_secret_basic');
Checks::that('revocation authentication is negotiated independently from token authentication',
    ProviderMetadata::fromArray(metadata([
        'revocation_endpoint_auth_methods_supported' => ['client_secret_post'],
    ]))->revocationEndpointAuthMethod(), 'client_secret_post');
Checks::that('unknown metadata extensions remain safely ignorable',
    ProviderMetadata::fromArray(metadata(['future_extension' => ['nested' => true]]))->issuer(),
    'https://id.example.net');
Checks::throws(
    'form_post cannot override the RFC 8414 omission default',
    fn() => $discovered->assertAuthorizationCapabilities('form_post'),
    'response mode'
);
Checks::throws(
    'configured client authentication must be advertised',
    fn() => $discovered->tokenEndpointAuthMethod('client_secret_post'),
    'not advertised'
);
Checks::throws(
    'unsupported token authentication capabilities fail before an exchange',
    fn() => ProviderMetadata::fromArray(metadata([
        'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
    ]))->tokenEndpointAuthMethod(),
    'no supported client authentication method'
);
Checks::throws(
    'an empty advertised capability list is malformed rather than an omission default',
    fn() => ProviderMetadata::fromArray(metadata(['response_modes_supported' => []])),
    'invalid response_modes_supported'
);
Checks::throws(
    'an explicit null capability is malformed rather than an omission default',
    fn() => ProviderMetadata::fromArray(metadata(['code_challenge_methods_supported' => null])),
    'invalid code_challenge_methods_supported'
);

Checks::group('Validated provider cache');
$cacheIssuer = 'https://cache.example.net';
$cacheUrl = $cacheIssuer . ProviderMetadata::DISCOVERY_SUFFIX;
$cacheCalls = 0;
$cacheHttp = new HttpClient(function () use (&$cacheCalls, $cacheIssuer): array {
    $cacheCalls++;
    return jsonAnswer(metadata(['issuer' => $cacheIssuer]), 200, [
        'cache-control' => 'public, max-age=600',
        'etag' => '"metadata-one"',
    ]);
}, true);
ProviderMetadata::discover($cacheIssuer, $cacheHttp);
ProviderMetadata::discover($cacheIssuer, $cacheHttp);
Checks::that('fresh validated Discovery is reused without another network wait', $cacheCalls, 1);
$cachePath = constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY')
    . '/oidc-discovery-' . hash('sha256', $cacheUrl) . '.json';
Checks::that('cached public metadata is private to the service account', decoct(fileperms($cachePath) & 0777), '600');

$etagSeen = false;
$etagHttp = new HttpClient(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$etagSeen): array {
    $etagSeen = in_array('If-None-Match: "metadata-one"', $headers, true);
    return ['status' => 304, 'content_type' => '', 'body' => '', 'location' => '', 'headers' => []];
}, true);
ProviderMetadata::discover($cacheIssuer, $etagHttp, null, true);
Checks::that('an expired or forced cache entry is revalidated with its ETag', $etagSeen, true);

$acceptedCache = (string)file_get_contents($cachePath);
Checks::throws(
    'invalid live Discovery never replaces the previously validated cache entry',
    fn() => ProviderMetadata::discover(
        $cacheIssuer,
        new HttpClient(fn() => jsonAnswer(metadata(['issuer' => 'https://attacker.example.net'])), true),
        null,
        true
    ),
    'exactly match'
);
Checks::that('the accepted Discovery cache survives a rejected refresh',
    (string)file_get_contents($cachePath), $acceptedCache);

$cacheEntry = json_decode((string)file_get_contents($cachePath), true, 16, JSON_THROW_ON_ERROR);
$cacheEntry['fresh_until'] = time() - 1;
$cacheEntry['stale_until'] = time() + 600;
file_put_contents($cachePath, json_encode($cacheEntry, JSON_THROW_ON_ERROR));
$stale = new HttpClient(
    fn() => throw new OPNsense\OpenIDConnect\ProviderUnavailableException('temporary network failure'),
    true
);
$staleResponse = $stale->getCached($cacheUrl, ProviderMetadata::MAX_BYTES, 'oidc-discovery', 86400);
Checks::that('temporary failure may use still-bounded stale Discovery', $staleResponse->source, 'cache-stale');

$noStoreCalls = 0;
$noStoreUrl = 'https://no-store.example.net/metadata';
$noStoreHttp = new HttpClient(function () use (&$noStoreCalls): array {
    $noStoreCalls++;
    return jsonAnswer(['value' => true], 200, ['cache-control' => 'no-store']);
}, true);
$noStoreHttp->getCached($noStoreUrl, 1024, 'oidc-discovery', 86400);
$noStoreHttp->getCached($noStoreUrl, 1024, 'oidc-discovery', 86400);
Checks::that('no-store responses are never persisted', $noStoreCalls, 2);

$noCacheCalls = 0;
$noCacheUrl = 'https://no-cache.example.net/metadata';
$noCacheHttp = new HttpClient(function () use (&$noCacheCalls): array {
    $noCacheCalls++;
    return jsonAnswer(['value' => true], 200, ['cache-control' => 'no-cache', 'etag' => '"always-check"']);
}, true);
$noCacheHttp->getCached($noCacheUrl, 1024, 'oidc-discovery', 86400);
$noCacheHttp->getCached($noCacheUrl, 1024, 'oidc-discovery', 86400);
Checks::that('no-cache responses are revalidated before every use', $noCacheCalls, 2);

$sharedUrl = 'https://shared-cache.example.net/metadata';
$sharedHttp = new HttpClient(fn() => jsonAnswer(['value' => true], 200, [
    'cache-control' => 'max-age=600, s-maxage=120',
    'age' => '30',
]), true);
$sharedHttp->getCached($sharedUrl, 1024, 'oidc-discovery', 86400);
$sharedPath = constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY')
    . '/oidc-discovery-' . hash('sha256', $sharedUrl) . '.json';
$sharedEntry = json_decode((string)file_get_contents($sharedPath), true, 16, JSON_THROW_ON_ERROR);
$sharedRemaining = (int)$sharedEntry['fresh_until'] - time();
Checks::that('shared-cache freshness prefers s-maxage and subtracts Age',
    $sharedRemaining >= 88 && $sharedRemaining <= 90, true);

$revalidateUrl = 'https://must-revalidate.example.net/metadata';
$revalidateLive = new HttpClient(fn() => jsonAnswer(
    ['value' => true],
    200,
    ['cache-control' => 'max-age=60, must-revalidate']
), true);
$revalidateLive->getCached($revalidateUrl, 1024, 'oidc-discovery', 86400);
$revalidatePath = constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY')
    . '/oidc-discovery-' . hash('sha256', $revalidateUrl) . '.json';
$revalidateEntry = json_decode((string)file_get_contents($revalidatePath), true, 16, JSON_THROW_ON_ERROR);
$revalidateEntry['fresh_until'] = time() - 1;
$revalidateEntry['stale_until'] = time() + 600;
file_put_contents($revalidatePath, json_encode($revalidateEntry, JSON_THROW_ON_ERROR));
Checks::throws(
    'must-revalidate is never served stale after a network failure',
    fn() => (new HttpClient(
        fn() => throw new OPNsense\OpenIDConnect\ProviderUnavailableException('temporary network failure'),
        true
    ))->getCached($revalidateUrl, 1024, 'oidc-discovery', 86400),
    'temporary network failure'
);

$microsoftTemplate = 'https://login.microsoftonline.com/{tenantid}/v2.0';
$microsoftDiscovery = metadata(['issuer' => $microsoftTemplate]);
Checks::that(
    'Microsoft tenant-independent discovery accepts only its documented issuer template',
    ProviderMetadata::discover(
        'https://login.microsoftonline.com/common/v2.0',
        new HttpClient(fn() => jsonAnswer($microsoftDiscovery)),
        $microsoftTemplate
    )->issuer(),
    $microsoftTemplate
);
Checks::throws(
    'a different issuer cannot use the Microsoft template exception',
    fn() => ProviderMetadata::discover(
        'https://login.microsoftonline.com/common/v2.0',
        new HttpClient(fn() => jsonAnswer(metadata(['issuer' => 'https://attacker.example.net']))),
        $microsoftTemplate
    ),
    'exactly match'
);

Checks::throws(
    'a discovery document for a look-alike issuer is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['issuer' => 'https://id.example.net/other'])))
    ),
    'exactly match'
);
Checks::throws(
    'a provider that does not advertise the code flow is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['response_types_supported' => ['id_token']])))
    ),
    'authorization code flow'
);
Checks::throws(
    'a provider without a supported subject identifier type is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['subject_types_supported' => ['opaque']])))
    ),
    'subject identifier type'
);
Checks::throws(
    'JARM signing algorithms in discovery must be a bounded string list',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['authorization_signing_alg_values_supported' => 'RS256'])))
    ),
    'authorization_signing_alg_values_supported'
);
Checks::throws(
    'a discovery document served as the wrong media type is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => [
            'status' => 200, 'content_type' => 'text/plain',
            'body' => json_encode(metadata(), JSON_THROW_ON_ERROR), 'location' => '',
        ])
    ),
    'application/json'
);
Checks::throws(
    'an insecure endpoint inside otherwise valid discovery is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['token_endpoint' => 'http://id.example.net/token'])))
    ),
    'HTTPS'
);
Checks::throws(
    'an insecure pushed authorization request endpoint is refused',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata([
            'pushed_authorization_request_endpoint' => 'http://id.example.net/par',
        ])))
    ),
    'HTTPS'
);
Checks::throws(
    'a provider cannot require PAR without publishing its endpoint',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['require_pushed_authorization_requests' => true])))
    ),
    'offers no endpoint'
);
Checks::throws(
    'the PAR requirement in discovery must be a boolean',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => jsonAnswer(metadata(['require_pushed_authorization_requests' => 'true'])))
    ),
    'invalid pushed authorization request requirement'
);
Checks::throws(
    'an issuer carrying a query is refused before discovery',
    fn() => ProviderMetadata::discover('https://id.example.net?tenant=x', $http),
    'query'
);
Checks::that(
    'a complete discovery URL is normalized before exact issuer validation',
    ProviderMetadata::discover(
        'https://id.example.net/.well-known/openid-configuration',
        new HttpClient(fn() => jsonAnswer(metadata()))
    )->issuer(),
    'https://id.example.net'
);
Checks::that(
    'a trailing slash remains part of the exact issuer',
    ProviderMetadata::locations('https://id.example.net/application/o/firewall/'),
    ['https://id.example.net/application/o/firewall/', 'https://id.example.net/application/o/firewall/.well-known/openid-configuration']
);

Checks::group('Bounded HTTPS transport');
Checks::throws(
    'the client never fetches a local file',
    fn() => (new HttpClient(fn() => jsonAnswer([])))->get('file:///conf/config.xml', 100),
    'HTTPS'
);
Checks::throws(
    'nor plain HTTP',
    fn() => (new HttpClient(fn() => jsonAnswer([])))->get('http://id.example.net/keys', 100),
    'HTTPS'
);
$redirects = 0;
$redirected = new HttpClient(function ($method, $url) use (&$redirects): array {
    $redirects++;
    return $url === 'https://id.example.net/start'
        ? ['status' => 302, 'content_type' => '', 'body' => '', 'location' => '/finish']
        : ['status' => 200, 'content_type' => 'application/json', 'body' => '{}', 'location' => ''];
});
Checks::that('a relative HTTPS redirect is resolved manually', $redirected->get('https://id.example.net/start', 100)->url, 'https://id.example.net/finish');
Checks::that('each redirect target is fetched separately', $redirects, 2);
Checks::throws(
    'a redirect cannot downgrade transport security',
    fn() => (new HttpClient(fn() => [
        'status' => 302, 'content_type' => '', 'body' => '',
        'location' => 'http://id.example.net/finish',
    ]))->get('https://id.example.net/start', 100),
    'HTTPS'
);
Checks::throws(
    'a bearer token is never carried through a redirect',
    fn() => (new HttpClient(fn() => [
        'status' => 302, 'content_type' => '', 'body' => '',
        'location' => 'https://elsewhere.example.net/finish',
    ]))->get('https://id.example.net/userinfo', 100, ['Authorization: Bearer token']),
    'credential-bearing'
);
Checks::throws(
    'a token request is never redirected with its client secret',
    fn() => (new HttpClient(fn() => [
        'status' => 307, 'content_type' => '', 'body' => '',
        'location' => 'https://elsewhere.example.net/token',
    ]))->postForm('https://id.example.net/token', ['client_secret' => 'secret'], 100),
    'credential-bearing'
);
Checks::throws(
    'the response limit is enforced even by an alternate transport',
    fn() => (new HttpClient(fn() => [
        'status' => 200, 'content_type' => 'application/json', 'body' => '12345', 'location' => '',
    ]))->get('https://id.example.net/data', 4),
    'oversized'
);

Checks::group('Strict endpoint responses and logout binding');
$endpointController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$endpointSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
]);
$endpointMetadata = ProviderMetadata::fromArray(metadata());
$metadataProperty = new ReflectionProperty(RelyingParty::class, 'metadata');

$missingType = new RelyingParty(
    $endpointSettings,
    $endpointController,
    new HttpClient(fn() => jsonAnswer(['access_token' => 'access']))
);
$metadataProperty->setValue($missingType, $endpointMetadata);
Checks::throws(
    'an access token without its required token type is refused',
    fn() => inspect($missingType, 'exchangeCode', 'code', 'verifier'),
    'omitted the access token type'
);

$wrongUserInfoType = new RelyingParty(
    $endpointSettings,
    $endpointController,
    new HttpClient(fn() => [
        'status' => 200, 'content_type' => 'text/plain',
        'body' => '{"sub":"stable-subject"}', 'location' => '',
    ])
);
$metadataProperty->setValue($wrongUserInfoType, $endpointMetadata);
Checks::throws(
    'plain JSON disguised as another UserInfo media type is refused',
    fn() => inspect($wrongUserInfoType, 'requestUserInfo', 'https://id.example.net/userinfo', 'access'),
    'application/json or application/jwt'
);

$changedIssuer = new RelyingParty(
    $endpointSettings,
    $endpointController,
    new HttpClient(fn() => jsonAnswer(metadata()))
);
Checks::throws(
    'stored grants cannot be sent after the session issuer changed',
    fn() => $changedIssuer->requireIssuer('https://former.example.net'),
    'issuer changed'
);

$sameIssuer = new RelyingParty(
    $endpointSettings,
    $endpointController,
    new HttpClient(fn() => jsonAnswer(metadata()))
);
$sameIssuer->requireIssuer('https://id.example.net');
Checks::that(
    'stored grants remain usable only after the exact session issuer is rediscovered',
    $sameIssuer->issuer(),
    'https://id.example.net'
);

$noProviderLogout = new RelyingParty($endpointSettings, $endpointController, new HttpClient());
$metadataProperty->setValue($noProviderLogout, $endpointMetadata);
$noProviderLogout->signOut('id-token', null);
Checks::that(
    'logout returns locally when discovery advertises no end-session endpoint',
    $endpointController->response->redirectedTo,
    '/'
);

$revocationRequest = [];
$revocationParty = new RelyingParty(
    $endpointSettings,
    $endpointController,
    new HttpClient(
        function (string $method, string $url, ?string $body, array $headers) use (&$revocationRequest): array {
            $revocationRequest = compact('method', 'url', 'body', 'headers');
            return jsonAnswer([], 200);
        }
    )
);
$metadataProperty->setValue($revocationParty, ProviderMetadata::fromArray(metadata([
    'revocation_endpoint' => 'https://id.example.net/revoke',
    'revocation_endpoint_auth_methods_supported' => ['client_secret_post'],
])));
$revocationParty->revokeToken('refresh-token', 'refresh_token');
parse_str((string)$revocationRequest['body'], $revocationFields);
Checks::that('revocation uses its own advertised client authentication capability', [
    $revocationRequest['url'],
    $revocationFields['client_secret'] ?? null,
    count(array_filter($revocationRequest['headers'], static fn(string $header): bool =>
        str_starts_with($header, 'Authorization:'))),
], ['https://id.example.net/revoke', 'secret', 0]);

Checks::group('Login transactions, PKCE and mix-up protection');

$settings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'authentik-main',
]);
$session = new Session();
$controller = new Controller(new Request('https', 'firewall.example.net'), $session);
$party = new RelyingParty($settings, $controller, new HttpClient(fn() => jsonAnswer(metadata())));
$party->begin('authentik', '/ui/dashboard');
$authorization = $controller->response->redirectedTo;
parse_str((string)parse_url($authorization, PHP_URL_QUERY), $parameters);

Checks::that('the browser is sent only to the discovered endpoint', strtok($authorization, '?'), 'https://id.example.net/authorize');
Checks::that('the response type is authorization code', $parameters['response_type'], 'code');
Checks::that('PKCE S256 is mandatory', $parameters['code_challenge_method'], 'S256');
Checks::that('a nonce is always sent', is_string($parameters['nonce']) && strlen($parameters['nonce']) >= 32, true);
Checks::that('account selection is not requested by default', array_key_exists('prompt', $parameters), false);
Checks::that('the default asks for an authentication no older than four hours', $parameters['max_age'], '14400');
Checks::that(
    'the callback is distinct for this provider configuration',
    $parameters['redirect_uri'],
    'https://firewall.example.net/api/openidconnect/auth/callback/authentik-main'
);

$alwaysFreshController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$alwaysFreshSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'always-fresh',
    'openidconnect_max_age' => '0',
]);
(new RelyingParty(
    $alwaysFreshSettings,
    $alwaysFreshController,
    new HttpClient(fn() => jsonAnswer(metadata()))
))->begin('always-fresh', '/');
parse_str(
    (string)parse_url($alwaysFreshController->response->redirectedTo, PHP_URL_QUERY),
    $alwaysFreshParameters
);
Checks::that('zero is sent to request active re-authentication', $alwaysFreshParameters['max_age'], '0');

$selectAccountController = new Controller(new Request('https', 'firewall.example.net'), new Session());
(new RelyingParty(connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'choose-account',
    'openidconnect_select_account' => '1',
]), $selectAccountController, new HttpClient(fn() => jsonAnswer(metadata()))))->begin('choose-account', '/');
parse_str(
    (string)parse_url($selectAccountController->response->redirectedTo, PHP_URL_QUERY),
    $selectAccountParameters
);
Checks::that('account selection sends the standard prompt value', $selectAccountParameters['prompt'], 'select_account');

$noPkceController = new Controller(new Request('https', 'firewall.example.net'), new Session());
Checks::throws(
    'an explicit provider declaration that omits S256 is refused before redirect',
    fn() => (new RelyingParty(
        $settings,
        $noPkceController,
        new HttpClient(fn() => jsonAnswer(metadata(['code_challenge_methods_supported' => ['plain']])))
    ))->begin('authentik', '/'),
    'PKCE S256'
);
Checks::throws(
    'omitted PKCE metadata means that the provider does not support PKCE',
    fn() => (new RelyingParty(
        $settings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadataWithout('code_challenge_methods_supported')))
    ))->begin('authentik', '/'),
    'PKCE S256'
);

$formPostSettings = connector([
    'openidconnect_client_id' => 'form-post-client',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'form-post',
    'openidconnect_response_mode' => 'form_post',
]);
Checks::throws(
    'form_post is refused when Discovery relies on the query-and-fragment default',
    fn() => (new RelyingParty(
        $formPostSettings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata()))
    ))->begin('form-post', '/'),
    'response mode'
);

$postAuthSettings = connector([
    'openidconnect_client_id' => 'post-client',
    'openidconnect_client_secret' => 'post-secret',
    'openidconnect_token_auth' => 'client_secret_post',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'post-auth',
]);
Checks::throws(
    'a configured token authentication method is refused before redirect when not advertised',
    fn() => (new RelyingParty(
        $postAuthSettings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata()))
    ))->begin('post-auth', '/'),
    'not advertised'
);

$unsupportedJarmSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'unsupported-jarm',
    'openidconnect_response_mode' => 'query.jwt',
]);
Checks::throws(
    'JARM is refused before redirect when discovery advertises no supported signing algorithm',
    fn() => (new RelyingParty(
        $unsupportedJarmSettings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata([
            'response_modes_supported' => ['query.jwt'],
            'authorization_signing_alg_values_supported' => ['EdDSA'],
        ])))
    ))->begin('unsupported-jarm', '/'),
    'JARM signing algorithm'
);

$parRequest = [];
$parSession = new Session();
$parController = new Controller(new Request('https', 'firewall.example.net'), $parSession);
$parParty = new RelyingParty($settings, $parController, new HttpClient(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$parRequest): array {
    if ($method === 'GET') {
        return jsonAnswer(metadata([
            'pushed_authorization_request_endpoint' => 'https://id.example.net/par',
            'require_pushed_authorization_requests' => true,
        ]));
    }
    $parRequest = compact('url', 'body', 'headers');
    return jsonAnswer([
        'request_uri' => 'urn:ietf:params:oauth:request_uri:example',
        'expires_in' => 90,
    ], 201);
}));
$parParty->begin('authentik', '/ui/dashboard');
parse_str((string)parse_url($parController->response->redirectedTo, PHP_URL_QUERY), $parBrowserParameters);
parse_str((string)$parRequest['body'], $parParameters);
Checks::that('PAR sends the complete authorization request directly to its discovered endpoint', [
    $parRequest['url'],
    $parParameters['response_type'],
    $parParameters['code_challenge_method'],
    $parParameters['redirect_uri'],
], [
    'https://id.example.net/par',
    'code',
    'S256',
    'https://firewall.example.net/api/openidconnect/auth/callback/authentik-main',
]);
Checks::that('PAR reuses Basic client authentication without putting the secret in its body', [
    array_key_exists('client_secret', $parParameters),
    count(array_filter($parRequest['headers'], static fn(string $header): bool =>
        str_starts_with($header, 'Authorization: Basic '))),
], [false, 1]);
Checks::that('the browser sees only the PAR request reference and client ID', $parBrowserParameters, [
    'client_id' => 'client-id',
    'request_uri' => 'urn:ietf:params:oauth:request_uri:example',
]);
$parPostRequest = [];
$parPostSettings = connector([
    'openidconnect_client_id' => 'post-client',
    'openidconnect_client_secret' => 'post-secret',
    'openidconnect_token_auth' => 'client_secret_post',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'par-post',
]);
(new RelyingParty(
    $parPostSettings,
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(function (string $method, string $url, ?string $body, array $headers) use (&$parPostRequest): array {
        if ($method === 'GET') {
            return jsonAnswer(metadata([
                'pushed_authorization_request_endpoint' => 'https://id.example.net/par',
                'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            ]));
        }
        $parPostRequest = compact('body', 'headers');
        return jsonAnswer(['request_uri' => 'urn:example:post', 'expires_in' => 60], 201);
    })
))->begin('par-post', '/');
parse_str((string)$parPostRequest['body'], $parPostParameters);
Checks::that('PAR reuses POST client authentication when configured', [
    $parPostParameters['client_secret'],
    count(array_filter($parPostRequest['headers'], static fn(string $header): bool =>
        str_starts_with($header, 'Authorization:'))),
], ['post-secret', 0]);
$parTransaction = RelyingParty::consumeTransaction(
    $parSession,
    ['state' => $parParameters['state']],
    'authentik-main'
);
Checks::that('a successful PAR stores the normal server-side login transaction', $parTransaction['target'],
    '/ui/dashboard');

$failedParState = '';
$failedParSession = new Session();
$failedParController = new Controller(new Request('https', 'firewall.example.net'), $failedParSession);
Checks::throws('a failed PAR request is never replaced with a browser authorization request', function () use (
    $settings,
    $failedParController,
    &$failedParState
): void {
    (new RelyingParty($settings, $failedParController, new HttpClient(function (
        string $method,
        string $url,
        ?string $body
    ) use (&$failedParState): array {
        if ($method === 'GET') {
            return jsonAnswer(metadata([
                'pushed_authorization_request_endpoint' => 'https://id.example.net/par',
            ]));
        }
        parse_str((string)$body, $posted);
        $failedParState = (string)($posted['state'] ?? '');
        return jsonAnswer(['error' => 'invalid_request'], 400);
    })))->begin('authentik', '/');
}, 'returned HTTP 400');
Checks::that('a failed PAR leaves the browser where it was', $failedParController->response->redirectedTo, null);
Checks::throws(
    'a failed PAR leaves no pending transaction behind',
    fn() => RelyingParty::consumeTransaction(
        $failedParSession,
        ['state' => $failedParState],
        'authentik-main'
    ),
    'pending login'
);

$fallbackSettings = connector([
    'openidconnect_client_id' => 'fallback-client',
    'openidconnect_client_secret' => 'fallback-secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'par-fallback',
    'openidconnect_par_mode' => 'auto',
]);
$fallbackPosts = 0;
$fallbackTransport = function (string $method) use (&$fallbackPosts): array {
    if ($method === 'GET') {
        return jsonAnswer(metadata(['pushed_authorization_request_endpoint' => 'https://id.example.net/par']));
    }
    $fallbackPosts++;
    throw new OPNsense\OpenIDConnect\ProviderUnavailableException('PAR timed out');
};
$fallbackController = new Controller(new Request('https', 'firewall.example.net'), new Session());
(new RelyingParty($fallbackSettings, $fallbackController, new HttpClient($fallbackTransport)))
    ->begin('fallback', '/');
parse_str((string)parse_url($fallbackController->response->redirectedTo, PHP_URL_QUERY), $fallbackParameters);
Checks::that('automatic PAR falls back only after a temporary availability failure', [
    $fallbackPosts,
    $fallbackParameters['response_type'] ?? null,
    isset($fallbackParameters['request_uri']),
], [1, 'code', false]);
$secondFallback = new Controller(new Request('https', 'firewall.example.net'), new Session());
(new RelyingParty($fallbackSettings, $secondFallback, new HttpClient($fallbackTransport)))
    ->begin('fallback', '/');
Checks::that('a remembered PAR bypass removes the timeout from later logins', $fallbackPosts, 1);

$requiredPar = connector([
    'openidconnect_client_id' => 'required-client',
    'openidconnect_client_secret' => 'required-secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'par-required',
    'openidconnect_par_mode' => 'required',
]);
Checks::throws(
    'required PAR never turns a provider outage into a browser authorization request',
    fn() => (new RelyingParty(
        $requiredPar,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient($fallbackTransport)
    ))->begin('required', '/'),
    'timed out'
);

$disabledPar = connector([
    'openidconnect_client_id' => 'disabled-client',
    'openidconnect_client_secret' => 'disabled-secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'par-disabled',
    'openidconnect_par_mode' => 'disabled',
]);
$disabledController = new Controller(new Request('https', 'firewall.example.net'), new Session());
(new RelyingParty($disabledPar, $disabledController, new HttpClient(fn() => jsonAnswer(metadata([
    'pushed_authorization_request_endpoint' => 'https://id.example.net/par',
])))))->begin('disabled', '/');
parse_str((string)parse_url($disabledController->response->redirectedTo, PHP_URL_QUERY), $disabledParameters);
Checks::that('disabled PAR deliberately uses the complete browser authorization request',
    $disabledParameters['response_type'] ?? null, 'code');
Checks::throws(
    'a local disabled setting cannot override provider-required PAR',
    fn() => (new RelyingParty(
        $disabledPar,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata([
            'pushed_authorization_request_endpoint' => 'https://id.example.net/par',
            'require_pushed_authorization_requests' => true,
        ])))
    ))->begin('disabled', '/'),
    'requires pushed authorization requests'
);

foreach ([
    ['answer' => ['request_uri' => "bad\nuri", 'expires_in' => 90], 'message' => 'usable request URI'],
    ['answer' => ['request_uri' => 'urn:example', 'expires_in' => 0], 'message' => 'valid expiry'],
] as $invalidPar) {
    Checks::throws('a malformed PAR success response is refused', fn() => (new RelyingParty(
        $settings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn(string $method) => $method === 'GET'
            ? jsonAnswer(metadata(['pushed_authorization_request_endpoint' => 'https://id.example.net/par']))
            : jsonAnswer($invalidPar['answer'], 201))
    ))->begin('authentik', '/'), $invalidPar['message']);
}

$transaction = RelyingParty::consumeTransaction($session, ['state' => $parameters['state']], 'authentik-main');
Checks::that('the exact discovery issuer is frozen into the transaction', $transaction['issuer'], 'https://id.example.net');
Checks::that('the negotiated token authentication method is frozen into the transaction',
    $transaction['token_auth_method'], 'client_secret_basic');
Checks::that('the intended local destination is retained server-side', $transaction['target'], '/ui/dashboard');
Checks::that('an ordinary authorization transaction is marked as a login', $transaction['purpose'], 'login');
Checks::throws(
    'the same response state is one-time use',
    fn() => RelyingParty::consumeTransaction($session, ['state' => $parameters['state']], 'authentik-main'),
    'pending login'
);

$testSession = new Session();
$testController = new Controller(new Request('https', 'firewall.example.net'), $testSession);
$testParty = new RelyingParty($settings, $testController, new HttpClient(fn() => jsonAnswer(metadata())));
$testAuthorization = $testParty->authorizationUrl('authentik', '/system_authservers.php', true);
parse_str((string)parse_url($testAuthorization, PHP_URL_QUERY), $testParameters);
Checks::that(
    'a sign-in test receives the same provider authorization endpoint',
    strtok($testAuthorization, '?'),
    'https://id.example.net/authorize'
);
Checks::that(
    'preparing a sign-in test returns its address without redirecting the API request',
    $testController->response->redirectedTo,
    null
);
$testTransaction = RelyingParty::consumeTransaction(
    $testSession,
    ['state' => $testParameters['state']],
    'authentik-main'
);
Checks::that('a sign-in test is marked server-side and not by a browser parameter', $testTransaction['purpose'], 'test');

$strengthSession = new Session();
$strengthController = new Controller(new Request('https', 'firewall.example.net'), $strengthSession);
$strengthSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'strong-login',
    'openidconnect_required_authentication' => 'multi-factor',
]);
$strengthParty = new RelyingParty(
    $strengthSettings,
    $strengthController,
    new HttpClient(fn() => jsonAnswer(metadata()))
);
$strengthAuthorization = $strengthParty->authorizationUrl('strong', '/', true);
parse_str((string)parse_url($strengthAuthorization, PHP_URL_QUERY), $strengthParameters);
$strengthClaims = json_decode($strengthParameters['claims'], true, 16, JSON_THROW_ON_ERROR);
Checks::that(
    'Generic MFA requests the REFEDS context as an essential ID Token claim',
    $strengthClaims['id_token']['acr']['values'],
    ['https://refeds.org/profile/mfa']
);
$strengthTransaction = RelyingParty::consumeTransaction(
    $strengthSession,
    ['state' => $strengthParameters['state']],
    'strong-login'
);
Checks::that(
    'the exact authentication requirement is frozen into the one-time transaction',
    $strengthTransaction['authentication_requirement'],
    $strengthSettings->authenticationRequirement()->toArray()
);
Checks::that('the authentication requirement remains server-side', isset($strengthParameters['authentication_requirement']), false);

$oktaStrengthController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$oktaStrengthSettings = connector([
    'openidconnect_provider_profile' => 'okta',
    'openidconnect_provider_url' => 'https://id.example.net',
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'okta-strong',
    'openidconnect_required_authentication' => 'multi-factor',
]);
$oktaStrengthUrl = (new RelyingParty(
    $oktaStrengthSettings,
    $oktaStrengthController,
    new HttpClient(fn() => jsonAnswer(metadata()))
))->authorizationUrl('okta', '/');
parse_str((string)parse_url($oktaStrengthUrl, PHP_URL_QUERY), $oktaStrengthParameters);
Checks::that(
    'Okta receives its documented MFA acr_values parameter',
    $oktaStrengthParameters['acr_values'],
    'urn:okta:loa:2fa:any'
);
Checks::that('Okta is not also sent a conflicting essential acr request', isset($oktaStrengthParameters['claims']), false);

$entraStrengthController = new Controller(new Request('https', 'firewall.example.net'), new Session());
$entraStrengthSettings = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_provider_url' => 'https://id.example.net',
    'openidconnect_microsoft_audience' => 'tenant',
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'entra-strong',
    'openidconnect_required_authentication' => 'phishing-resistant',
    'openidconnect_entra_auth_context' => 'c3',
]);
$entraStrengthUrl = (new RelyingParty(
    $entraStrengthSettings,
    $entraStrengthController,
    new HttpClient(fn() => jsonAnswer(metadata()))
))->authorizationUrl('entra', '/');
parse_str((string)parse_url($entraStrengthUrl, PHP_URL_QUERY), $entraStrengthParameters);
$entraStrengthClaims = json_decode($entraStrengthParameters['claims'], true, 16, JSON_THROW_ON_ERROR);
Checks::that(
    'Entra receives its tenant-local context as an essential ID Token claim',
    $entraStrengthClaims['id_token']['acrs'],
    ['essential' => true, 'value' => 'c3']
);
Checks::that('Entra is not sent a generic acr_values parameter', isset($entraStrengthParameters['acr_values']), false);

$secondController = new Controller(new Request('https', 'firewall.example.net'), $session);
$secondParty = new RelyingParty($settings, $secondController, new HttpClient(fn() => jsonAnswer(metadata())));
$secondParty->begin('authentik', '/');
parse_str((string)parse_url($secondController->response->redirectedTo, PHP_URL_QUERY), $secondParameters);
Checks::throws(
    'a callback for another provider application code is refused',
    fn() => RelyingParty::consumeTransaction($session, ['state' => $secondParameters['state']], 'other-provider'),
    'pending login'
);

Checks::group('JWT-secured authorization responses');

$jarmNow = time();
$jarmKey = ['kty' => 'RSA', 'kid' => 'test-key', 'alg' => 'RS256', 'use' => 'sig'];
$jarmMetadata = ProviderMetadata::fromArray(metadata([
    'response_modes_supported' => ['query.jwt', 'form_post.jwt'],
    'authorization_signing_alg_values_supported' => ['RS256'],
]));
$jarmVerifier = new class(new HttpClient(fn() => jsonAnswer(['keys' => [$jarmKey]]))) extends JwtVerifier {
    public bool $signatureAccepted = true;
    protected function verifySignature(string $algorithm, array $jwk, string $payload, string $signature): bool
    {
        return $this->signatureAccepted;
    }
};
$jarmClaims = [
    'iss' => 'https://id.example.net', 'aud' => 'client-id', 'exp' => $jarmNow + 300,
    'iat' => $jarmNow, 'state' => 'transaction-state', 'code' => 'authorization-code',
];
$verifiedJarm = $jarmVerifier->verifyAuthorizationResponse(
    compactJwt($jarmClaims),
    $jarmMetadata,
    'client-id',
    null,
    $jarmNow
);
Checks::that('a signed JARM code response is accepted', $verifiedJarm['code'], 'authorization-code');
Checks::throws(
    'a JARM response from another issuer is refused before key use',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt(array_replace($jarmClaims, ['iss' => 'https://attacker.example.net'])),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'different issuer'
);
Checks::throws(
    'a JARM response for another client is refused',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt(array_replace($jarmClaims, ['aud' => 'other-client'])),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'this client'
);
Checks::throws(
    'an expired JARM response is refused',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt(array_replace($jarmClaims, ['exp' => $jarmNow - JwtVerifier::CLOCK_TOLERANCE - 1])),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'expired'
);
Checks::throws(
    'a future JARM issue time is refused',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt(array_replace($jarmClaims, ['iat' => $jarmNow + JwtVerifier::CLOCK_TOLERANCE + 1])),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'issue time'
);
Checks::throws(
    'a JARM algorithm not advertised for authorization responses is refused',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt($jarmClaims, ['alg' => 'PS256', 'kid' => 'test-key']),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'not advertised'
);
Checks::throws(
    'a symmetric JARM algorithm cannot downgrade asymmetric verification',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt($jarmClaims, ['alg' => 'HS256', 'kid' => 'test-key']),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'unsupported signing algorithm'
);
$jarmVerifier->signatureAccepted = false;
Checks::throws(
    'a forged JARM signature is refused',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        compactJwt($jarmClaims),
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'signature is invalid'
);
$jarmVerifier->signatureAccepted = true;
Checks::throws(
    'encrypted JARM remains outside the supported profile',
    fn() => $jarmVerifier->verifyAuthorizationResponse(
        'one.two.three.four.five',
        $jarmMetadata,
        'client-id',
        null,
        $jarmNow
    ),
    'Encrypted JARM'
);

$jarmSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
    'openidconnect_claims_source' => 'id_token',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'jarm-login',
    'openidconnect_response_mode' => 'query.jwt',
]);
$issuedIdToken = '';
$exchangedCode = '';
$jarmHttp = new HttpClient(function (string $method, string $url, ?string $body) use (
    $jarmKey,
    &$issuedIdToken,
    &$exchangedCode
): array {
    if ($url === 'https://id.example.net/keys') {
        return jsonAnswer(['keys' => [$jarmKey]]);
    }
    if ($method === 'POST') {
        parse_str((string)$body, $fields);
        $exchangedCode = (string)($fields['code'] ?? '');
        return jsonAnswer(['id_token' => $issuedIdToken]);
    }
    return jsonAnswer(metadata([
        'response_modes_supported' => ['query.jwt'],
        'authorization_signing_alg_values_supported' => ['RS256'],
    ]));
});
$jarmFlowVerifier = new class($jarmHttp) extends JwtVerifier {
    protected function verifySignature(string $algorithm, array $jwk, string $payload, string $signature): bool
    {
        return true;
    }
};
$jarmSession = new Session();
$jarmStartController = new Controller(new Request('https', 'firewall.example.net'), $jarmSession);
$jarmAuthorization = (new RelyingParty(
    $jarmSettings,
    $jarmStartController,
    $jarmHttp,
    $jarmFlowVerifier
))->authorizationUrl('jarm-provider', '/ui/dashboard');
parse_str((string)parse_url($jarmAuthorization, PHP_URL_QUERY), $jarmParameters);
Checks::that('JARM negotiation sends the exact signed response mode', $jarmParameters['response_mode'], 'query.jwt');
$jarmResponse = compactJwt([
    'iss' => 'https://id.example.net', 'aud' => 'client-id', 'exp' => time() + 300,
    'state' => $jarmParameters['state'], 'code' => 'signed-code',
]);
$jarmTransaction = RelyingParty::consumeTransaction(
    $jarmSession,
    ['response' => $jarmResponse],
    'jarm-login'
);
Checks::that('the requested JARM mode is frozen into the transaction', $jarmTransaction['response_mode'], 'query.jwt');
Checks::throws(
    'a signed authorization response is one-time use',
    fn() => RelyingParty::consumeTransaction($jarmSession, ['response' => $jarmResponse], 'jarm-login'),
    'pending login'
);
$issuedIdToken = compactJwt([
    'iss' => 'https://id.example.net', 'sub' => 'jarm-subject', 'aud' => 'client-id',
    'exp' => time() + 300, 'iat' => time(), 'nonce' => $jarmParameters['nonce'],
    'auth_time' => time(), 'preferred_username' => 'jarm-user',
]);
$jarmCompleteController = new Controller(
    new Request('https', 'firewall.example.net', ['response' => $jarmResponse]),
    $jarmSession
);
$jarmIdentity = (new RelyingParty(
    $jarmSettings,
    $jarmCompleteController,
    $jarmHttp,
    $jarmFlowVerifier
))->complete($jarmTransaction, ['response' => $jarmResponse]);
Checks::that('only a verified signed code reaches the token endpoint', $exchangedCode, 'signed-code');
Checks::that('a verified JARM flow reaches the normal identity claims', $jarmIdentity->preferred_username, 'jarm-user');

$errorSession = new Session();
$errorController = new Controller(new Request('https', 'firewall.example.net'), $errorSession);
$errorUrl = (new RelyingParty(
    $jarmSettings,
    $errorController,
    $jarmHttp,
    $jarmFlowVerifier
))->authorizationUrl('jarm-provider', '/');
parse_str((string)parse_url($errorUrl, PHP_URL_QUERY), $errorParameters);
$errorResponse = compactJwt([
    'iss' => 'https://id.example.net', 'aud' => 'client-id', 'exp' => time() + 300,
    'state' => $errorParameters['state'], 'error' => 'access_denied',
]);
$errorTransaction = RelyingParty::consumeTransaction(
    $errorSession,
    ['response' => $errorResponse],
    'jarm-login'
);
Checks::throws(
    'a signed JARM provider error is verified before it is reported',
    fn() => (new RelyingParty(
        $jarmSettings,
        new Controller(new Request('https', 'firewall.example.net', ['response' => $errorResponse]), $errorSession),
        $jarmHttp,
        $jarmFlowVerifier
    ))->complete($errorTransaction, ['response' => $errorResponse]),
    'access_denied'
);

$hybridSession = new Session();
$hybridController = new Controller(new Request('https', 'firewall.example.net'), $hybridSession);
$hybridUrl = (new RelyingParty(
    $jarmSettings,
    $hybridController,
    $jarmHttp,
    $jarmFlowVerifier
))->authorizationUrl('jarm-provider', '/');
parse_str((string)parse_url($hybridUrl, PHP_URL_QUERY), $hybridParameters);
$hybridResponse = compactJwt([
    'iss' => 'https://id.example.net', 'aud' => 'client-id', 'exp' => time() + 300,
    'state' => $hybridParameters['state'], 'code' => 'signed-code', 'access_token' => 'browser-token',
]);
$hybridTransaction = RelyingParty::consumeTransaction(
    $hybridSession,
    ['response' => $hybridResponse],
    'jarm-login'
);
Checks::throws(
    'a signed JARM response cannot smuggle a front-channel token',
    fn() => (new RelyingParty(
        $jarmSettings,
        new Controller(new Request('https', 'firewall.example.net', ['response' => $hybridResponse]), $hybridSession),
        $jarmHttp,
        $jarmFlowVerifier
    ))->complete($hybridTransaction, ['response' => $hybridResponse]),
    'front-channel token'
);

Checks::throws(
    'a signed state from another transaction cannot select a pending login',
    fn() => RelyingParty::consumeTransaction(
        new Session(),
        ['response' => compactJwt(array_replace($jarmClaims, ['state' => 'other-state']))],
        'jarm-login'
    ),
    'pending login'
);

$downgradeSession = new Session();
$downgradeController = new Controller(new Request('https', 'firewall.example.net'), $downgradeSession);
$downgradeUrl = (new RelyingParty(
    $jarmSettings,
    $downgradeController,
    $jarmHttp,
    $jarmFlowVerifier
))->authorizationUrl('jarm-provider', '/');
parse_str((string)parse_url($downgradeUrl, PHP_URL_QUERY), $downgradeParameters);
$downgradeTransaction = RelyingParty::consumeTransaction(
    $downgradeSession,
    ['state' => $downgradeParameters['state'], 'code' => 'unsigned-code'],
    'jarm-login'
);
Checks::throws(
    'an unsigned authorization response cannot downgrade a JARM transaction',
    fn() => (new RelyingParty(
        $jarmSettings,
        $downgradeController,
        $jarmHttp,
        $jarmFlowVerifier
    ))->complete($downgradeTransaction, [
        'state' => $downgradeParameters['state'],
        'code' => 'unsigned-code',
    ]),
    'requested JARM'
);

Checks::group('ID token claim validation');
$now = 2000000000;
$valid = [
    'iss' => 'https://id.example.net', 'sub' => 'stable-subject',
    'aud' => 'client-id', 'exp' => $now + 300, 'iat' => $now - 5, 'nonce' => 'nonce',
];
JwtVerifier::validateClaims($valid, 'https://id.example.net', 'client-id', 'nonce', null, $now);
Checks::that('a complete, exact set of claims is accepted', true, true);
Checks::throws(
    'issuer matching is byte-for-byte exact',
    fn() => JwtVerifier::validateClaims($valid, 'https://elsewhere.example.net', 'client-id', 'nonce', null, $now),
    'issuer'
);
Checks::throws(
    'an expired token is refused',
    fn() => JwtVerifier::validateClaims(array_replace($valid, ['exp' => $now - 61]), 'https://id.example.net', 'client-id', 'nonce', null, $now),
    'expired'
);
Checks::throws(
    'a nonce from another transaction is refused',
    fn() => JwtVerifier::validateClaims($valid, 'https://id.example.net', 'client-id', 'other', null, $now),
    'nonce'
);
Checks::throws(
    'multiple audiences require this client as authorized party',
    fn() => JwtVerifier::validateClaims(array_replace($valid, ['aud' => ['client-id', 'other']]), 'https://id.example.net', 'client-id', 'nonce', null, $now),
    'authorized party'
);
Checks::throws(
    'an optional authorized party must still name this client',
    fn() => JwtVerifier::validateClaims(array_replace($valid, ['azp' => 'other']), 'https://id.example.net', 'client-id', 'nonce', null, $now),
    'authorized party'
);
Checks::throws(
    'claim types are not coerced from strings',
    fn() => JwtVerifier::validateClaims(array_replace($valid, ['exp' => (string)($now + 300)]), 'https://id.example.net', 'client-id', 'nonce', null, $now),
    'expiry'
);

Checks::group('Back-channel logout token claims');
$logoutClaims = [
    'iss' => 'https://id.example.net', 'aud' => 'client-id', 'iat' => $now,
    'exp' => $now + 300,
    'sid' => 'provider-session', 'jti' => 'logout-once',
    'events' => ['http://schemas.openid.net/event/backchannel-logout' => []],
];
$logoutVerifier = new class(new HttpClient()) extends JwtVerifier {
    public array $claims = [];
    public function verifySignedClaims(
        string $jwt,
        ProviderMetadata $metadata,
        string $advertisedField = 'userinfo_signing_alg_values_supported',
        ?callable $issuerValidator = null
    ): array {
        if ($issuerValidator !== null) {
            $issuerValidator($this->claims, []);
        }
        return $this->claims;
    }
};
$logoutMetadata = ProviderMetadata::fromArray(metadata());
$logoutVerifier->claims = $logoutClaims;
Checks::that(
    'a signed logout event may identify a provider session',
    $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now)['sid'],
    'provider-session'
);
$logoutVerifier->claims = $logoutClaims + ['nonce' => 'must-not-be-here'];
Checks::throws(
    'a logout token carrying a login nonce is refused',
    fn() => $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now),
    'nonce'
);
$logoutVerifier->claims = $logoutClaims;
unset($logoutVerifier->claims['exp']);
Checks::throws(
    'a logout token without an expiry is refused',
    fn() => $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now),
    'valid expiry'
);
$logoutVerifier->claims = array_replace($logoutClaims, ['exp' => (string)($now + 300)]);
Checks::throws(
    'a logout token expiry is never coerced from a string',
    fn() => $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now),
    'valid expiry'
);
$logoutVerifier->claims = array_replace($logoutClaims, ['events' => []]);
Checks::throws(
    'a generic JWT is not a logout token',
    fn() => $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now),
    'logout event'
);
$logoutVerifier->claims = $logoutClaims;
unset($logoutVerifier->claims['jti']);
Checks::throws(
    'a logout token without a replay identifier is refused',
    fn() => $logoutVerifier->verifyLogoutToken('signed', $logoutMetadata, 'client-id', $now),
    'token identifier'
);

Checks::group('Whom a token was issued for');
Checks::that('one audience needs nothing further', RelyingParty::issuedForThisFirewall((object)['aud' => 'client-id'], 'client-id'), true);
Checks::that(
    'several audiences and the authorized party is this firewall',
    RelyingParty::issuedForThisFirewall((object)['aud' => ['client-id', 'other'], 'azp' => 'client-id'], 'client-id'),
    true
);
Checks::that(
    'several audiences and it is somebody else',
    RelyingParty::issuedForThisFirewall((object)['aud' => ['client-id', 'other'], 'azp' => 'other'], 'client-id'),
    false
);
