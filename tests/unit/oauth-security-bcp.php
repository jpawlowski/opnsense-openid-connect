<?php

use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;
use OPNsense\OpenIDConnect\Api\AuthController;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\RelyingParty;

/** @return array<string,mixed> */
function securityBcpMetadata(array $extra = []): array
{
    return $extra + [
        'issuer' => 'https://id.example.net',
        'authorization_endpoint' => 'https://id.example.net/authorize',
        'token_endpoint' => 'https://id.example.net/token',
        'userinfo_endpoint' => 'https://id.example.net/userinfo',
        'jwks_uri' => 'https://id.example.net/keys',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        'code_challenge_methods_supported' => ['S256'],
        'authorization_response_iss_parameter_supported' => true,
    ];
}

/** @param array<string,mixed> $value @return array<string,mixed> */
function securityBcpJson(array $value): array
{
    return [
        'status' => 200,
        'content_type' => 'application/json',
        'body' => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        'location' => '',
        'headers' => [],
    ];
}

function securityBcpSettings(array $extra = []): OPNsense\Auth\OpenIDConnect
{
    return connector($extra + [
        'openidconnect_client_id' => 'bcp-client',
        'openidconnect_client_secret' => 'bcp-secret',
        'openidconnect_redirect_urls' => 'https://firewall.example.net',
        'openidconnect_app_code' => 'security-bcp',
    ]);
}

Checks::group('RFC 9700 confidential web relying-party profile');

$localTarget = new AuthController(
    new Request('https', 'firewall.example.net', ['redir' => '/ui/dashboard?section=system']),
    new Session()
);
Checks::that(
    'RFC9700-2.1-NO-OPEN-REDIRECT positive: a local post-login target remains usable',
    inspect($localTarget, 'requestedTarget'),
    '/ui/dashboard?section=system'
);
$externalTarget = new AuthController(
    new Request('https', 'firewall.example.net', ['redir' => 'https://attacker.example/collect']),
    new Session()
);
Checks::that(
    'RFC9700-2.1-NO-OPEN-REDIRECT negative: an external post-login target is replaced locally',
    inspect($externalTarget, 'requestedTarget'),
    '/'
);

$transactionSession = new Session();
$transactionController = new Controller(new Request('https', 'firewall.example.net'), $transactionSession);
$tokenRequest = [];
$transactionParty = new RelyingParty(
    securityBcpSettings(),
    $transactionController,
    new HttpClient(function (
        string $method,
        string $url,
        ?string $body,
        array $headers
    ) use (&$tokenRequest): array {
        if ($method === 'GET') {
            return securityBcpJson(securityBcpMetadata());
        }
        $tokenRequest = compact('url', 'body', 'headers');
        return securityBcpJson([
            'access_token' => 'bcp-access-token',
            'token_type' => 'Bearer',
            'id_token' => 'signed-id-token',
        ]);
    })
);
$authorizationUrl = $transactionParty->authorizationUrl('Security BCP', '/ui/dashboard');
parse_str((string)parse_url($authorizationUrl, PHP_URL_QUERY), $authorizationParameters);
$transaction = RelyingParty::consumeTransaction(
    $transactionSession,
    ['state' => $authorizationParameters['state']],
    'security-bcp'
);
Checks::that(
    'RFC9700-2.1-CSRF positive: issued state selects its server-side browser transaction',
    $transaction['target'],
    '/ui/dashboard'
);
Checks::throws(
    'RFC9700-2.1-CSRF negative: unissued state cannot reach an authorization transaction',
    fn() => RelyingParty::consumeTransaction(new Session(), ['state' => 'unissued-state'], 'security-bcp'),
    'pending login'
);

$metadataProperty = new ReflectionProperty(RelyingParty::class, 'metadata');
$metadataProperty->setValue($transactionParty, ProviderMetadata::fromArray(securityBcpMetadata()));
Checks::that(
    'RFC9700-2.1-MIX-UP positive: the exact response issuer releases the authorization code',
    [
        $transaction['issuer'],
        inspect($transactionParty, 'authorizationCode', [
            'iss' => 'https://id.example.net',
            'code' => 'authorization-code',
        ]),
    ],
    ['https://id.example.net', 'authorization-code']
);
Checks::throws(
    'RFC9700-2.1-MIX-UP negative: a response issuer from another provider is refused',
    fn() => inspect($transactionParty, 'authorizationCode', [
        'iss' => 'https://attacker.example',
        'code' => 'authorization-code',
    ]),
    'different issuer'
);

$expectedChallenge = OPNsense\OpenIDConnect\JwtVerifier::base64UrlEncode(
    hash('sha256', $transaction['code_verifier'], true)
);
Checks::that(
    'RFC9700-2.1.1-CODE-INJECTION positive: the browser challenge commits to its server-side verifier',
    $authorizationParameters['code_challenge'],
    $expectedChallenge
);
Checks::throws(
    'RFC9700-2.1.1-CODE-INJECTION negative: state from another browser session cannot inject a code',
    fn() => RelyingParty::consumeTransaction(
        new Session(),
        ['state' => $authorizationParameters['state'], 'code' => 'injected-code'],
        'security-bcp'
    ),
    'pending login'
);

Checks::that(
    'RFC9700-2.1.1-PKCE positive: the confidential client uses the non-disclosing S256 method',
    $authorizationParameters['code_challenge_method'],
    'S256'
);
Checks::throws(
    'RFC9700-2.1.1-PKCE negative: explicit absence of provider S256 support fails before redirect',
    fn() => (new RelyingParty(
        securityBcpSettings(['openidconnect_app_code' => 'no-s256']),
        new Controller(new Request('https', 'firewall.example.net'), new Session()),
        new HttpClient(fn() => securityBcpJson(securityBcpMetadata([
            'code_challenge_methods_supported' => ['plain'],
        ])))
    ))->authorizationUrl('No S256', '/'),
    'PKCE S256'
);

$secondSession = new Session();
$secondParty = new RelyingParty(
    securityBcpSettings(['openidconnect_app_code' => 'security-bcp-second']),
    new Controller(new Request('https', 'firewall.example.net'), $secondSession),
    new HttpClient(fn() => securityBcpJson(securityBcpMetadata()))
);
$secondUrl = $secondParty->authorizationUrl('Security BCP second', '/');
parse_str((string)parse_url($secondUrl, PHP_URL_QUERY), $secondParameters);
Checks::that(
    'RFC9700-2.1.1-TRANSACTION-BINDING positive: each login receives distinct state nonce and PKCE values',
    [
        $authorizationParameters['state'] !== $secondParameters['state'],
        $authorizationParameters['nonce'] !== $secondParameters['nonce'],
        $authorizationParameters['code_challenge'] !== $secondParameters['code_challenge'],
    ],
    [true, true, true]
);
Checks::throws(
    'RFC9700-2.1.1-TRANSACTION-BINDING negative: another provider callback cannot consume the transaction',
    fn() => RelyingParty::consumeTransaction(
        $secondSession,
        ['state' => $secondParameters['state']],
        'different-application'
    ),
    'pending login'
);

Checks::that(
    'RFC9700-2.1.2-NO-IMPLICIT positive: the browser requests no token-bearing response type',
    $authorizationParameters['response_type'],
    'code'
);
Checks::throws(
    'RFC9700-2.1.2-NO-IMPLICIT negative: a front-channel access token invalidates the response',
    fn() => inspect($transactionParty, 'authorizationCode', [
        'iss' => 'https://id.example.net',
        'code' => 'authorization-code',
        'access_token' => 'exposed-token',
        'token_type' => 'Bearer',
    ]),
    'front-channel token'
);
$frontChannelController = new AuthController(new Request('https', 'firewall.example.net', [
    'state' => 'pending-state',
    'code' => 'authorization-code',
    'access_token' => 'exposed-token',
]), new Session());
Checks::that(
    'RFC9700-2.1.2-NO-IMPLICIT negative: the callback preserves a token field for fail-closed validation',
    array_key_exists('access_token', inspect($frontChannelController, 'authorizationResponse')),
    true
);

inspect($transactionParty, 'exchangeCode', 'authorization-code', $transaction['code_verifier']);
parse_str((string)$tokenRequest['body'], $tokenFields);
Checks::that(
    'RFC9700-2.1.1-CODE-INJECTION positive: the token exchange proves the exact browser verifier',
    $tokenFields['code_verifier'],
    $transaction['code_verifier']
);
Checks::that(
    'RFC9700-2.1.2-CODE-FLOW positive: the token endpoint receives an authorization code grant',
    $tokenFields['grant_type'],
    'authorization_code'
);
Checks::throws(
    'RFC9700-2.1.2-CODE-FLOW negative: Discovery without code-flow support is incompatible',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => securityBcpJson(securityBcpMetadata([
            'response_types_supported' => ['id_token'],
        ])))
    ),
    'authorization code flow'
);

Checks::that(
    'RFC9700-2.4-NO-ROPC positive: token exchange identifies only the authorization code grant',
    array_intersect_key($tokenFields, array_flip(['grant_type', 'code', 'code_verifier'])),
    [
        'grant_type' => 'authorization_code',
        'code' => 'authorization-code',
        'code_verifier' => $transaction['code_verifier'],
    ]
);
Checks::that(
    'RFC9700-2.4-NO-ROPC negative: no provider password credential enters the token request',
    array_intersect_key($tokenFields, array_flip(['username', 'password'])),
    []
);

$discovered = ProviderMetadata::discover(
    'https://id.example.net',
    new HttpClient(fn() => securityBcpJson(securityBcpMetadata()))
);
Checks::that(
    'RFC9700-2.6-METADATA positive: exact Discovery configures the provider endpoints',
    [$discovered->issuer(), $discovered->authorizationEndpoint(), $discovered->tokenEndpoint()],
    ['https://id.example.net', 'https://id.example.net/authorize', 'https://id.example.net/token']
);
Checks::throws(
    'RFC9700-2.6-METADATA negative: metadata for another issuer is rejected',
    fn() => ProviderMetadata::discover(
        'https://id.example.net',
        new HttpClient(fn() => securityBcpJson(securityBcpMetadata([
            'issuer' => 'https://attacker.example',
        ])))
    ),
    'exactly match'
);

$httpsClient = new HttpClient(fn() => securityBcpJson(['ok' => true]));
Checks::that(
    'RFC9700-2.6-END-TO-END-TLS positive: provider traffic can use its exact HTTPS endpoint',
    $httpsClient->get('https://id.example.net/resource', 1024)->status,
    200
);
Checks::throws(
    'RFC9700-2.6-END-TO-END-TLS negative: provider traffic cannot use a plaintext endpoint',
    fn() => $httpsClient->get('http://id.example.net/resource', 1024),
    'HTTPS'
);

$httpsSettings = securityBcpSettings(['openidconnect_app_code' => 'https-response']);
Checks::that(
    'RFC9700-2.6-HTTPS-RESPONSE positive: an accepted HTTPS origin yields the exact callback',
    RelyingParty::acceptedRedirectUri(
        $httpsSettings,
        new Request('https', 'firewall.example.net')
    ),
    'https://firewall.example.net/api/openidconnect/auth/callback/https-response'
);
Checks::that(
    'RFC9700-2.6-HTTPS-RESPONSE negative: a plaintext authorization response origin is refused',
    RelyingParty::acceptedRedirectUri($httpsSettings, new Request('http', 'firewall.example.net')),
    null
);

$responseController = new AuthController(new Request(), new Session());
$responseController->beforeExecuteRoute(new class {
    public function getActionName(): string
    {
        return 'callback';
    }
});
$responsePolicy = $responseController->response->headers['Content-Security-Policy'] ?? '';
Checks::that(
    'RFC9700-4.2.4-NO-THIRD-PARTY positive: callback documents deny every default content source',
    str_contains($responsePolicy, "default-src 'none'"),
    true
);
Checks::that(
    'RFC9700-4.2.4-NO-THIRD-PARTY negative: callback policy grants no external network source',
    preg_match('/(?:https?:|\*)/', $responsePolicy),
    0
);

$oneTimeSession = new Session();
$oneTimeParty = new RelyingParty(
    securityBcpSettings(['openidconnect_app_code' => 'one-time-state']),
    new Controller(new Request('https', 'firewall.example.net'), $oneTimeSession),
    new HttpClient(fn() => securityBcpJson(securityBcpMetadata()))
);
$oneTimeUrl = $oneTimeParty->authorizationUrl('One-time state', '/');
parse_str((string)parse_url($oneTimeUrl, PHP_URL_QUERY), $oneTimeParameters);
$oneTimeTransaction = RelyingParty::consumeTransaction(
    $oneTimeSession,
    ['state' => $oneTimeParameters['state']],
    'one-time-state'
);
Checks::that(
    'RFC9700-4.2.4-STATE-ONCE positive: first use consumes the matching state',
    $oneTimeTransaction['app_code'],
    'one-time-state'
);
Checks::throws(
    'RFC9700-4.2.4-STATE-ONCE negative: replay of consumed state is refused',
    fn() => RelyingParty::consumeTransaction(
        $oneTimeSession,
        ['state' => $oneTimeParameters['state']],
        'one-time-state'
    ),
    'pending login'
);

$userInfoRequest = [];
$userInfoParty = new RelyingParty(
    securityBcpSettings(['openidconnect_app_code' => 'userinfo-bearer']),
    new Controller(new Request('https', 'firewall.example.net'), new Session()),
    new HttpClient(function (
        string $method,
        string $url,
        ?string $body,
        array $headers
    ) use (&$userInfoRequest): array {
        $userInfoRequest = compact('method', 'url', 'body', 'headers');
        return securityBcpJson(['sub' => 'stable-subject']);
    })
);
$metadataProperty->setValue($userInfoParty, ProviderMetadata::fromArray(securityBcpMetadata()));
inspect($userInfoParty, 'requestUserInfo', 'https://id.example.net/userinfo', 'sensitive-access-token');
Checks::that(
    'RFC9700-4.3.2-NO-QUERY-TOKEN positive: UserInfo receives its bearer token in the header',
    in_array('Authorization: Bearer sensitive-access-token', $userInfoRequest['headers'], true),
    true
);
Checks::that(
    'RFC9700-4.3.2-NO-QUERY-TOKEN negative: the bearer token never enters the request URI',
    str_contains($userInfoRequest['url'], 'sensitive-access-token'),
    false
);
