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
    ];
}

function jsonAnswer(array $value, int $status = 200): array
{
    return [
        'status' => $status,
        'content_type' => 'application/json',
        'body' => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        'location' => '',
    ];
}

Checks::group('Strict provider discovery');

$http = new HttpClient(fn() => jsonAnswer(metadata()));
$discovered = ProviderMetadata::discover('https://id.example.net', $http);
Checks::that('the exact configured issuer is retained', $discovered->issuer(), 'https://id.example.net');
Checks::that('the authorization endpoint is read from discovery', $discovered->authorizationEndpoint(), 'https://id.example.net/authorize');

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

$transaction = RelyingParty::consumeTransaction($session, ['state' => $parameters['state']], 'authentik-main');
Checks::that('the exact discovery issuer is frozen into the transaction', $transaction['issuer'], 'https://id.example.net');
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

$secondController = new Controller(new Request('https', 'firewall.example.net'), $session);
$secondParty = new RelyingParty($settings, $secondController, new HttpClient(fn() => jsonAnswer(metadata())));
$secondParty->begin('authentik', '/');
parse_str((string)parse_url($secondController->response->redirectedTo, PHP_URL_QUERY), $secondParameters);
Checks::throws(
    'a callback for another provider application code is refused',
    fn() => RelyingParty::consumeTransaction($session, ['state' => $secondParameters['state']], 'other-provider'),
    'pending login'
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
