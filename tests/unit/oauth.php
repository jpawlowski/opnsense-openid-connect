<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;
use OPNsense\OpenIDConnect\Api\AuthController;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\RelyingParty;

/** Build the exact confidential-client token path without completing ID Token verification. */
function oauthProfileParty(callable $transport, array $extra = []): RelyingParty
{
    $settings = connector($extra + [
        'openidconnect_client_id' => 'client id',
        'openidconnect_client_secret' => 'secret value',
        'openidconnect_redirect_urls' => 'https://firewall.example.net',
        'openidconnect_app_code' => 'oauth-profile-' . bin2hex(random_bytes(4)),
    ]);
    $party = new RelyingParty(
        $settings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient($transport)
    );
    $provider = metadata();
    $provider['token_endpoint_auth_methods_supported'] = ['client_secret_basic', 'client_secret_post'];
    (new ReflectionProperty(RelyingParty::class, 'metadata'))->setValue(
        $party,
        ProviderMetadata::fromArray($provider)
    );
    return $party;
}

/** @return array<string,mixed> */
function oauthTokenAnswer(array $extra = []): array
{
    return $extra + [
        'access_token' => 'access-token',
        'token_type' => 'Bearer',
        'id_token' => 'header.payload.signature',
    ];
}

Checks::group('RFC 6749 confidential web client profile');

$basicRequest = [];
$basicParty = oauthProfileParty(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$basicRequest): array {
    $basicRequest = compact('method', 'url', 'body', 'headers');
    return jsonAnswer(oauthTokenAnswer());
}, ['openidconnect_app_code' => 'rfc6749-token']);
$basicTokens = inspect($basicParty, 'exchangeCode', 'authorization-code', 'pkce-verifier');
parse_str((string)$basicRequest['body'], $basicFields);
$basicHeaders = array_values(array_filter(
    $basicRequest['headers'],
    static fn(string $header): bool => str_starts_with($header, 'Authorization:')
));
Checks::that(
    'RFC6749-2.3-MUST-NOT-MULTIPLE-AUTH positive: Basic is the single client authentication method',
    [count($basicHeaders), isset($basicFields['client_secret'])],
    [1, false]
);
Checks::that(
    'RFC6749-2.3-MUST-NOT-MULTIPLE-AUTH negative: an authenticated request has no second body credential',
    isset($basicFields['client_id']) || isset($basicFields['client_secret']),
    false
);
Checks::that(
    'RFC6749-2.3.1-MAY-BASIC positive: Basic credentials use form encoding before base64',
    $basicHeaders,
    ['Authorization: Basic ' . base64_encode('client+id:secret+value')]
);
Checks::that(
    'RFC6749-2.3.1-MAY-BASIC negative: Basic credentials never appear in the form body',
    array_intersect_key($basicFields, ['client_id' => true, 'client_secret' => true]),
    []
);
Checks::that(
    'RFC6749-2.3.1-SHOULD-LIMIT-BODY positive: automatic authentication prefers HTTP Basic',
    count($basicHeaders),
    1
);

$postRequest = [];
$postParty = oauthProfileParty(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$postRequest): array {
    $postRequest = compact('method', 'url', 'body', 'headers');
    return jsonAnswer(oauthTokenAnswer());
}, ['openidconnect_token_auth' => 'client_secret_post']);
inspect($postParty, 'exchangeCode', 'authorization-code', 'pkce-verifier');
parse_str((string)$postRequest['body'], $postFields);
Checks::that(
    'RFC6749-2.3.1-SHOULD-LIMIT-BODY negative: explicit POST authentication stays one bounded method',
    [
        $postFields['client_id'] ?? null,
        $postFields['client_secret'] ?? null,
        count(array_filter(
            $postRequest['headers'],
            static fn(string $header): bool => str_starts_with($header, 'Authorization:')
        )),
    ],
    ['client id', 'secret value', 0]
);

$authorizationSession = new Session();
$authorizationController = new Controller(new Request('https', 'firewall.example.net'), $authorizationSession);
$authorizationSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'client-secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'rfc6749-authorization',
]);
$authorizationParty = new RelyingParty(
    $authorizationSettings,
    $authorizationController,
    new HttpClient(fn() => jsonAnswer(metadata([
        'authorization_endpoint' => 'https://id.example.net/authorize?tenant=one',
    ])))
);
$authorizationUrl = $authorizationParty->authorizationUrl('rfc6749', '/ui/dashboard');
parse_str((string)parse_url($authorizationUrl, PHP_URL_QUERY), $authorizationFields);
Checks::that(
    'RFC6749-3.1-MUST-AUTH-ENDPOINT positive: existing authorization endpoint query is retained',
    $authorizationFields['tenant'] ?? null,
    'one'
);
Checks::throws(
    'RFC6749-3.1-MUST-AUTH-ENDPOINT negative: an authorization endpoint fragment is refused',
    fn() => ProviderMetadata::fromArray(metadata([
        'authorization_endpoint' => 'https://id.example.net/authorize#fragment',
    ])),
    'fragment'
);
Checks::that(
    'RFC6749-3.1-MUST-NOT-REPEAT positive: every authorization request parameter is emitted once',
    count($authorizationFields),
    count(array_unique(array_keys($authorizationFields)))
);
Checks::throws(
    'RFC6749-3.1-MUST-NOT-REPEAT negative: an endpoint query cannot duplicate a protocol parameter',
    fn() => (new RelyingParty(
        $authorizationSettings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata([
            'authorization_endpoint' => 'https://id.example.net/authorize?client_id=other',
        ])))
    ))->authorizationUrl('rfc6749', '/'),
    'duplicate a protocol parameter'
);
Checks::that(
    'RFC6749-3.1.1-MUST-CODE positive: the authorization request asks only for a code',
    $authorizationFields['response_type'] ?? null,
    'code'
);
Checks::throws(
    'RFC6749-3.1.1-MUST-CODE negative: a provider without the code response type is refused',
    fn() => ProviderMetadata::fromArray(metadata(['response_types_supported' => ['token']])),
    'code flow'
);
Checks::that(
    'RFC6749-3.1.2.1-SHOULD-TLS-REDIRECT positive: the registered callback uses HTTPS',
    str_starts_with((string)$authorizationFields['redirect_uri'], 'https://'),
    true
);
Checks::throws(
    'RFC6749-3.1.2.1-SHOULD-TLS-REDIRECT negative: a plain HTTP callback origin is refused',
    fn() => new RelyingParty(
        $authorizationSettings,
        new Controller(new Request('http', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata()))
    ),
    'origin'
);
Checks::that(
    'RFC6749-3.1.2.3-MUST-REDIRECT-URI positive: the exact callback is included in the authorization request',
    $authorizationFields['redirect_uri'] ?? null,
    'https://firewall.example.net/api/openidconnect/auth/callback/rfc6749-authorization'
);
$authorizationTransaction = RelyingParty::consumeTransaction(
    $authorizationSession,
    ['state' => $authorizationFields['state']],
    'rfc6749-authorization'
);
$changedRedirect = $authorizationTransaction;
$changedRedirect['redirect_uri'] = 'https://elsewhere.example.net/callback';
Checks::throws(
    'RFC6749-3.1.2.3-MUST-REDIRECT-URI negative: a changed callback binding is refused',
    fn() => $authorizationParty->complete($changedRedirect, ['code' => 'code']),
    'no longer matches'
);
Checks::that(
    'RFC6749-3.3-MUST-SCOPE-SYNTAX positive: configured scopes use the OAuth scope-token grammar',
    $authorizationFields['scope'],
    'openid email profile'
);
$invalidScopeSettings = connector([
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'client-secret',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_app_code' => 'rfc6749-invalid-scope',
    'openidconnect_scopes' => 'openid,bad"scope',
]);
Checks::throws(
    'RFC6749-3.3-MUST-SCOPE-SYNTAX negative: an invalid configured scope token is refused',
    fn() => (new RelyingParty(
        $invalidScopeSettings,
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => jsonAnswer(metadata()))
    ))->authorizationUrl('rfc6749', '/'),
    'not valid scope tokens'
);

Checks::that(
    'RFC6749-3.2-MUST-TOKEN-POST positive: the authorization code is exchanged with POST over HTTPS',
    [$basicRequest['method'], $basicRequest['url']],
    ['POST', 'https://id.example.net/token']
);
Checks::throws(
    'RFC6749-3.2-MUST-TOKEN-POST negative: a non-HTTPS token request is refused before transport',
    fn() => (new HttpClient(fn() => jsonAnswer(oauthTokenAnswer())))->postForm(
        'http://id.example.net/token',
        ['grant_type' => 'authorization_code'],
        1024
    ),
    'HTTPS'
);
Checks::that(
    'RFC6749-3.2-MUST-NOT-REPEAT positive: every token request form parameter is emitted once',
    count($basicFields),
    count(array_unique(array_keys($basicFields)))
);
Checks::throws(
    'RFC6749-3.2-MUST-NOT-REPEAT negative: a token endpoint query cannot duplicate a form parameter',
    fn() => (new HttpClient(fn() => jsonAnswer(oauthTokenAnswer())))->postForm(
        'https://id.example.net/token?code=other',
        ['grant_type' => 'authorization_code', 'code' => 'code'],
        1024
    ),
    'duplicate a protocol parameter'
);
Checks::that(
    'RFC6749-3.2.1-MUST-AUTHENTICATE positive: the confidential client authenticates at the token endpoint',
    count($basicHeaders),
    1
);
$unsupportedAuth = oauthProfileParty(fn() => jsonAnswer(oauthTokenAnswer()));
(new ReflectionProperty(RelyingParty::class, 'metadata'))->setValue(
    $unsupportedAuth,
    ProviderMetadata::fromArray(metadata(['token_endpoint_auth_methods_supported' => ['private_key_jwt']]))
);
Checks::throws(
    'RFC6749-3.2.1-MUST-AUTHENTICATE negative: no unauthenticated token request is attempted',
    fn() => inspect($unsupportedAuth, 'exchangeCode', 'code', 'verifier'),
    'no supported client authentication method for the token endpoint'
);

Checks::that(
    'RFC6749-4.1.1-SHOULD-STATE positive: a random opaque state binds the authorization request',
    is_string($authorizationFields['state']) && strlen($authorizationFields['state']) >= 32,
    true
);
Checks::throws(
    'RFC6749-4.1.1-SHOULD-STATE negative: a callback without state is refused',
    fn() => RelyingParty::consumeTransaction(new Session(), [], 'rfc6749-authorization'),
    'no usable state'
);
Checks::that(
    'RFC6749-4.1.2-MUST-SINGLE-USE-CODE positive: the matching transaction is consumed once',
    $authorizationTransaction['provider'],
    'rfc6749'
);
Checks::throws(
    'RFC6749-4.1.2-MUST-SINGLE-USE-CODE negative: replaying the same response state is refused',
    fn() => RelyingParty::consumeTransaction(
        $authorizationSession,
        ['state' => $authorizationFields['state']],
        'rfc6749-authorization'
    ),
    'pending login'
);

$unknownController = new AuthController(new Request(
    'https',
    'firewall.example.net',
    ['state' => 'state-value', 'code' => 'code-value', 'extension' => 'ignored']
), new Session());
Checks::that(
    'RFC6749-4.1.2-MUST-IGNORE-UNKNOWN positive: unknown authorization response names are ignored',
    inspect($unknownController, 'authorizationResponse'),
    ['state' => 'state-value', 'code' => 'code-value']
);
$unknownOnlyController = new AuthController(new Request(
    'https',
    'firewall.example.net',
    ['extension' => 'not-state']
), new Session());
Checks::throws(
    'RFC6749-4.1.2-MUST-IGNORE-UNKNOWN negative: an extension cannot replace required state',
    fn() => RelyingParty::consumeTransaction(
        new Session(),
        inspect($unknownOnlyController, 'authorizationResponse'),
        'rfc6749-authorization'
    ),
    'no usable state'
);
$authorizationError = $authorizationParty;
Checks::throws(
    'RFC6749-4.1.2.1-MUST-SAFE-ERROR positive: a bounded authorization error is classified safely',
    fn() => $authorizationError->complete($authorizationTransaction, ['error' => 'access_denied']),
    'access_denied'
);
Checks::throws(
    'RFC6749-4.1.2.1-MUST-SAFE-ERROR negative: malformed authorization errors are not reflected',
    fn() => $authorizationError->complete($authorizationTransaction, ['error' => "denied\nsecret"]),
    'provider_error'
);

Checks::that(
    'RFC6749-4.1.3-MUST-TOKEN-PARAMETERS positive: the token form carries the exact code grant binding',
    array_intersect_key($basicFields, [
        'grant_type' => true,
        'code' => true,
        'redirect_uri' => true,
        'code_verifier' => true,
    ]),
    [
        'grant_type' => 'authorization_code',
        'code' => 'authorization-code',
        'redirect_uri' => 'https://firewall.example.net/api/openidconnect/auth/callback/rfc6749-token',
        'code_verifier' => 'pkce-verifier',
    ]
);
Checks::that(
    'RFC6749-4.1.3-MUST-TOKEN-PARAMETERS negative: Basic authentication omits the unauthenticated client_id field',
    isset($basicFields['client_id']),
    false
);

Checks::that(
    'RFC6749-5.1-MUST-TOKEN-RESPONSE positive: a complete Bearer token response is accepted',
    [$basicTokens['access_token'], $basicTokens['token_type']],
    ['access-token', 'Bearer']
);
$missingAccess = oauthProfileParty(fn() => jsonAnswer([
    'token_type' => 'Bearer',
    'id_token' => 'header.payload.signature',
]));
Checks::throws(
    'RFC6749-5.1-MUST-TOKEN-RESPONSE negative: a success response without an access token is refused',
    fn() => inspect($missingAccess, 'exchangeCode', 'code', 'verifier'),
    'no access token'
);
foreach ([
    [
        'label' => 'an unsupported token type is refused',
        'answer' => oauthTokenAnswer(['token_type' => 'MAC']),
        'message' => 'unsupported token type',
    ],
    [
        'label' => 'a non-numeric access token lifetime is refused',
        'answer' => oauthTokenAnswer(['expires_in' => '3600']),
        'message' => 'invalid access token lifetime',
    ],
    [
        'label' => 'a malformed returned scope is refused',
        'answer' => oauthTokenAnswer(['scope' => "openid\nadmin"]),
        'message' => 'invalid access token scope',
    ],
] as $invalidTokenAnswer) {
    Checks::throws(
        'RFC6749-5.1-MUST-TOKEN-RESPONSE negative: ' . $invalidTokenAnswer['label'],
        fn() => inspect(
            oauthProfileParty(fn() => jsonAnswer($invalidTokenAnswer['answer'])),
            'exchangeCode',
            'code',
            'verifier'
        ),
        $invalidTokenAnswer['message']
    );
}
$unknownTokenAnswer = oauthTokenAnswer();
for ($index = 0; $index < 40; $index++) {
    $unknownTokenAnswer['extension_' . $index] = str_repeat('x', $index + 1);
}
$unknownTokens = inspect(
    oauthProfileParty(fn() => jsonAnswer($unknownTokenAnswer)),
    'exchangeCode',
    'code',
    'verifier'
);
Checks::that(
    'RFC6749-5.1-MUST-IGNORE-UNKNOWN positive: arbitrary extension response names do not fail the exchange',
    $unknownTokens['access_token'],
    'access-token'
);
Checks::that(
    'RFC6749-5.1-MUST-IGNORE-UNKNOWN negative: ignored extension values never enter retained token state',
    array_filter(array_keys($unknownTokens), static fn(string $name): bool => str_starts_with($name, 'extension_')),
    []
);

$safeError = oauthProfileParty(fn() => jsonAnswer([
    'error' => 'invalid_grant',
    'error_description' => 'authorization code and secret must never be copied',
], 400));
Checks::throws(
    'RFC6749-5.2-MUST-SAFE-ERROR positive: a standard token error is classified by its bounded code',
    fn() => inspect($safeError, 'exchangeCode', 'code', 'verifier'),
    'invalid_grant'
);
$unsafeError = oauthProfileParty(fn() => jsonAnswer([
    'error' => "invalid\ngrant",
    'error_description' => 'must-not-appear',
], 400));
Checks::throws(
    'RFC6749-5.2-MUST-SAFE-ERROR negative: malformed error fields are not reflected',
    fn() => inspect($unsafeError, 'exchangeCode', 'code', 'verifier'),
    'HTTP 400'
);
$mislabelledError = oauthProfileParty(fn() => jsonAnswer([
    'error' => 'invalid_grant',
    'access_token' => 'access-token',
    'token_type' => 'Bearer',
    'id_token' => 'header.payload.signature',
]));
Checks::throws(
    'RFC6749-5.2-MUST-SAFE-ERROR negative: an error object cannot masquerade as a success response',
    fn() => inspect($mislabelledError, 'exchangeCode', 'code', 'verifier'),
    'invalid_grant'
);

Checks::that(
    'RFC6749-10.1-MUST-PROTECT-CREDENTIALS positive: client credentials stay in one HTTPS request',
    [$basicRequest['url'], isset($basicFields['client_secret'])],
    ['https://id.example.net/token', false]
);
Checks::throws(
    'RFC6749-10.1-MUST-PROTECT-CREDENTIALS negative: credential-bearing redirects are refused',
    fn() => (new HttpClient(fn() => [
        'status' => 307,
        'content_type' => '',
        'body' => '',
        'location' => 'https://elsewhere.example.net/token',
    ]))->postForm('https://id.example.net/token', ['client_secret' => 'secret'], 1024),
    'credential-bearing'
);

$userInfoRequest = [];
$userInfoParty = oauthProfileParty(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$userInfoRequest): array {
    $userInfoRequest = compact('method', 'url', 'body', 'headers');
    return jsonAnswer(['sub' => 'subject']);
});
$userInfo = inspect($userInfoParty, 'requestUserInfo', 'https://id.example.net/userinfo', 'access-token');
Checks::that(
    'RFC6749-10.3-MUST-PROTECT-ACCESS-TOKEN positive: the access token reaches only its HTTPS resource',
    [$userInfoRequest['url'], $userInfo['sub']],
    ['https://id.example.net/userinfo', 'subject']
);
Checks::throws(
    'RFC6749-10.3-MUST-PROTECT-ACCESS-TOKEN negative: access tokens are never carried through redirects',
    fn() => inspect(
        oauthProfileParty(fn() => [
            'status' => 302,
            'content_type' => '',
            'body' => '',
            'location' => 'https://elsewhere.example.net/userinfo',
        ]),
        'requestUserInfo',
        'https://id.example.net/userinfo',
        'access-token'
    ),
    'credential-bearing'
);

$revocationRequest = [];
$revocationMetadata = metadata(['revocation_endpoint' => 'https://id.example.net/revoke']);
$revocationParty = oauthProfileParty(function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$revocationRequest): array {
    $revocationRequest = compact('method', 'url', 'body', 'headers');
    return ['status' => 200, 'content_type' => '', 'body' => '', 'location' => ''];
});
(new ReflectionProperty(RelyingParty::class, 'metadata'))->setValue(
    $revocationParty,
    ProviderMetadata::fromArray($revocationMetadata)
);
$revocationParty->revokeToken('refresh-token', 'refresh_token');
parse_str((string)$revocationRequest['body'], $revocationFields);
Checks::that(
    'RFC6749-10.4-MUST-PROTECT-REFRESH-TOKEN positive: refresh tokens leave only in an HTTPS revocation body',
    [$revocationRequest['url'], $revocationFields['token']],
    ['https://id.example.net/revoke', 'refresh-token']
);
Checks::throws(
    'RFC6749-10.4-MUST-PROTECT-REFRESH-TOKEN negative: a refresh token is not followed through a redirect',
    fn() => (new HttpClient(fn() => [
        'status' => 307,
        'content_type' => '',
        'body' => '',
        'location' => 'https://elsewhere.example.net/revoke',
    ]))->postForm('https://id.example.net/revoke', ['token' => 'refresh-token'], 1024),
    'credential-bearing'
);

Checks::that(
    'RFC6749-10.5-MUST-TLS-CALLBACK positive: sign-in callbacks are exact HTTPS resources',
    str_starts_with((string)$authorizationFields['redirect_uri'], 'https://'),
    true
);
Checks::throws(
    'RFC6749-10.5-MUST-TLS-CALLBACK negative: callback construction refuses cleartext WebGUI transport',
    fn() => RelyingParty::intendedOrigin(new Request('http', 'firewall.example.net')),
    'HTTPS'
);
Checks::that(
    'RFC6749-10.8-MUST-NOT-CLEARTEXT positive: every credential-bearing provider request is HTTPS',
    str_starts_with($basicRequest['url'], 'https://') && str_starts_with($userInfoRequest['url'], 'https://'),
    true
);
Checks::throws(
    'RFC6749-10.8-MUST-NOT-CLEARTEXT negative: provider credentials cannot be posted over HTTP',
    fn() => (new HttpClient(fn() => jsonAnswer([])))->postForm(
        'http://id.example.net/token',
        ['client_secret' => 'secret'],
        1024
    ),
    'HTTPS'
);
Checks::that(
    'RFC6749-10.8-SHOULD-NOT-SENSITIVE-STATE positive: state is independent random data',
    !str_contains($authorizationFields['state'], 'dashboard')
        && !str_contains($authorizationFields['state'], 'rfc6749'),
    true
);
Checks::that(
    'RFC6749-10.8-SHOULD-NOT-SENSITIVE-STATE negative: the local target never enters browser parameters',
    in_array('/ui/dashboard', $authorizationFields, true),
    false
);
$transportSecurity = inspect(new HttpClient(), 'transportSecurityOptions');
Checks::that(
    'RFC6749-10.9-MUST-VALIDATE-TLS positive: provider transport verifies the certificate and host',
    [$transportSecurity[CURLOPT_SSL_VERIFYPEER], $transportSecurity[CURLOPT_SSL_VERIFYHOST]],
    [true, 2]
);
Checks::throws(
    'RFC6749-10.9-MUST-VALIDATE-TLS negative: a provider endpoint without server-authenticated TLS is refused',
    fn() => HttpClient::assertHttpsUrl('http://id.example.net/token'),
    'HTTPS'
);
Checks::that(
    'RFC6749-10.12-MUST-CSRF positive: callback state resolves only its server-side transaction',
    $authorizationTransaction['redirect_uri'],
    $authorizationFields['redirect_uri']
);
Checks::throws(
    'RFC6749-10.12-MUST-CSRF negative: attacker-selected state has no transaction',
    fn() => RelyingParty::consumeTransaction(new Session(), ['state' => 'attacker-state'], 'rfc6749-authorization'),
    'pending login'
);
Checks::that(
    'RFC6749-10.14-MUST-VALIDATE-INPUT positive: a bounded authorization code reaches the token request',
    $basicFields['code'],
    'authorization-code'
);
Checks::throws(
    'RFC6749-10.14-MUST-VALIDATE-INPUT negative: a control character in an authorization code is refused',
    fn() => $authorizationParty->complete($authorizationTransaction, ['code' => "code\nsecond"]),
    'no usable code'
);

Checks::group('RFC 6750 bearer token client profile');

$authorizationHeaders = array_values(array_filter(
    $userInfoRequest['headers'],
    static fn(string $header): bool => str_starts_with($header, 'Authorization:')
));
Checks::that(
    'RFC6750-2-MUST-NOT-MULTIPLE-METHODS positive: UserInfo receives one bearer transmission method',
    count($authorizationHeaders),
    1
);
Checks::that(
    'RFC6750-2-MUST-NOT-MULTIPLE-METHODS negative: the bearer token is absent from URL and body',
    [str_contains($userInfoRequest['url'], 'access-token'), $userInfoRequest['body']],
    [false, null]
);
Checks::that(
    'RFC6750-2.1-SHOULD-AUTHORIZATION-HEADER positive: UserInfo uses the Bearer authorization scheme',
    $authorizationHeaders,
    ['Authorization: Bearer access-token']
);
Checks::throws(
    'RFC6750-2.1-SHOULD-AUTHORIZATION-HEADER negative: bearer credentials are not redirected to another resource',
    fn() => (new HttpClient(fn() => [
        'status' => 302,
        'content_type' => '',
        'body' => '',
        'location' => 'https://elsewhere.example.net/userinfo',
    ]))->get('https://id.example.net/userinfo', 1024, ['Authorization: Bearer access-token']),
    'credential-bearing'
);
Checks::that(
    'RFC6750-2.1-MUST-B64TOKEN-SYNTAX positive: every allowed bearer credential character is accepted',
    inspect($userInfoParty, 'bearerAuthorization', 'AZaz09-._~+/=='),
    'Authorization: Bearer AZaz09-._~+/=='
);
Checks::throws(
    'RFC6750-2.1-MUST-B64TOKEN-SYNTAX negative: whitespace in a bearer credential is refused',
    fn() => inspect($userInfoParty, 'bearerAuthorization', 'token with space'),
    'cannot be used as a bearer token'
);
Checks::that(
    'RFC6750-2.2-SHOULD-NOT-FORM-BODY positive: bearer credentials are never form encoded',
    $userInfoRequest['body'],
    null
);
Checks::that(
    'RFC6750-2.2-SHOULD-NOT-FORM-BODY negative: no access_token body parameter accompanies UserInfo',
    str_contains((string)$userInfoRequest['body'], 'access_token='),
    false
);
Checks::that(
    'RFC6750-2.3-SHOULD-NOT-QUERY positive: the protected-resource URL contains no bearer query',
    parse_url($userInfoRequest['url'], PHP_URL_QUERY),
    null
);
Checks::that(
    'RFC6750-2.3-SHOULD-NOT-QUERY negative: the bearer token is not exposed in a page URL',
    str_contains($userInfoRequest['url'], 'access-token'),
    false
);
Checks::that(
    'RFC6750-5.2-5.3-MUST-SAFEGUARD positive: the bearer token is shared only with the discovered HTTPS resource',
    [$userInfoRequest['url'], $authorizationHeaders],
    ['https://id.example.net/userinfo', ['Authorization: Bearer access-token']]
);
Checks::throws(
    'RFC6750-5.2-5.3-MUST-SAFEGUARD negative: an unintended redirect cannot receive the bearer token',
    fn() => inspect(
        oauthProfileParty(fn() => [
            'status' => 302,
            'content_type' => '',
            'body' => '',
            'location' => 'https://unintended.example.net/resource',
        ]),
        'requestUserInfo',
        'https://id.example.net/userinfo',
        'access-token'
    ),
    'credential-bearing'
);
Checks::that(
    'RFC6750-5.2-5.3-MUST-TLS positive: bearer transport accepts an HTTPS protected resource',
    $userInfoRequest['url'],
    'https://id.example.net/userinfo'
);
Checks::throws(
    'RFC6750-5.2-5.3-MUST-TLS negative: bearer transport refuses a cleartext protected resource',
    fn() => inspect($userInfoParty, 'requestUserInfo', 'http://id.example.net/userinfo', 'access-token'),
    'HTTPS'
);
Checks::that(
    'RFC6750-5.2-5.3-MUST-VALIDATE-CERT positive: bearer transport validates certificate and host identity',
    [$transportSecurity[CURLOPT_SSL_VERIFYPEER], $transportSecurity[CURLOPT_SSL_VERIFYHOST]],
    [true, 2]
);
Checks::that(
    'RFC6750-5.2-5.3-MUST-VALIDATE-CERT negative: no transport option disables peer or host verification',
    $transportSecurity[CURLOPT_SSL_VERIFYPEER] === false
        || $transportSecurity[CURLOPT_SSL_VERIFYHOST] === 0,
    false
);
Checks::that(
    'RFC6750-5.2-5.3-MUST-NOT-CLEAR-COOKIE positive: bearer requests contain no Cookie header',
    count(array_filter(
        $userInfoRequest['headers'],
        static fn(string $header): bool => str_starts_with($header, 'Cookie:')
    )),
    0
);
Checks::throws(
    'RFC6750-5.2-5.3-MUST-NOT-CLEAR-COOKIE negative: a sensitive cookie is not followed through redirects',
    fn() => (new HttpClient(fn() => [
        'status' => 302,
        'content_type' => '',
        'body' => '',
        'location' => 'https://elsewhere.example.net/resource',
    ]))->get('https://id.example.net/resource', 1024, ['Cookie: access_token=access-token']),
    'credential-bearing'
);
Checks::that(
    'RFC6750-5.3-SHOULD-NOT-PAGE-URL positive: bearer tokens use a request header instead of the URI',
    [$authorizationHeaders[0], str_contains($userInfoRequest['url'], 'access-token')],
    ['Authorization: Bearer access-token', false]
);
Checks::that(
    'RFC6750-5.3-SHOULD-NOT-PAGE-URL negative: no browser-facing authorization URL contains a bearer token',
    str_contains($authorizationUrl, 'access-token'),
    false
);
