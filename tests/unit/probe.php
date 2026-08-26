<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Request;
use OPNsense\OpenIDConnect\Api\DiscoveryController;
use OPNsense\OpenIDConnect\Api\HealthController;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\ProviderProbe;

/** @return array<string,mixed> */
function probeRow(array $checks, string $label): array
{
    foreach ($checks as $check) {
        if (($check['label'] ?? null) === $label) {
            return $check;
        }
    }
    throw new RuntimeException('The expected provider probe row is absent');
}

Checks::group('Provider diagnostics');

$issuer = 'https://probe.example.net';
$provider = metadata([
    'issuer' => $issuer,
    'authorization_endpoint' => $issuer . '/authorize',
    'token_endpoint' => $issuer . '/token',
    'userinfo_endpoint' => $issuer . '/userinfo',
    'jwks_uri' => $issuer . '/keys',
    'end_session_endpoint' => $issuer . '/logout',
    'revocation_endpoint' => $issuer . '/revoke',
    'pushed_authorization_request_endpoint' => $issuer . '/par',
    'response_modes_supported' => ['query', 'form_post', 'query.jwt', 'form_post.jwt'],
    'authorization_signing_alg_values_supported' => ['RS256'],
    'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
    'code_challenge_methods_supported' => ['S256'],
    'dpop_signing_alg_values_supported' => ['ES256'],
    'authorization_response_iss_parameter_supported' => true,
]);
$privateKeySettings = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_client_id' => 'private-key-client',
    'openidconnect_signing_certificate' => '0123456789abc',
    'openidconnect_token_auth' => 'private_key_jwt',
    'openidconnect_par_mode' => 'disabled',
]);
$privateKeyProbe = new ProviderProbe(
    new HttpClient(static fn(): array => []),
    static fn(OPNsense\Auth\OpenIDConnect $settings): OPNsense\OpenIDConnect\ClientAssertion =>
        testClientAssertion($settings)
);
$mismatchedPrivateKeyChecks = inspect(
    $privateKeyProbe,
    'metadataChecks',
    $privateKeySettings,
    ProviderMetadata::fromArray(array_replace($provider, [
        'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
        'token_endpoint_auth_signing_alg_values_supported' => ['ES256'],
    ]))
);
$mismatchedPrivateKeyRow = array_values(array_filter(
    $mismatchedPrivateKeyChecks,
    static fn(array $check): bool => $check['label'] === 'Selected authentication method'
))[0];
Checks::that('diagnostics refuse a selected key incompatible with the provider algorithm', [
    $mismatchedPrivateKeyRow['status'],
    $mismatchedPrivateKeyRow['note'],
], ['error', 'no shared test algorithm']);
$matchingPrivateKeyChecks = inspect(
    $privateKeyProbe,
    'metadataChecks',
    $privateKeySettings,
    ProviderMetadata::fromArray(array_replace($provider, [
        'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
        'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
    ]))
);
$matchingPrivateKeyRow = array_values(array_filter(
    $matchingPrivateKeyChecks,
    static fn(array $check): bool => $check['label'] === 'Selected authentication method'
))[0];
Checks::that('diagnostics accept a selected key compatible with the provider algorithm',
    $matchingPrivateKeyRow['status'], 'success');
Checks::that('health readiness accepts a configured private-key credential',
    ProviderProbe::healthReadiness($privateKeySettings, 'https://firewall.example.net')[0]['status'], 'success');

$healthRequests = [];
$healthProvider = array_replace($provider, [
    'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
    'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
]);
$healthTransport = static function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$healthRequests, $issuer, $healthProvider): array {
    $healthRequests[] = compact('method', 'url', 'body', 'headers');
    if ($url === $issuer . '/.well-known/openid-configuration') {
        return jsonAnswer($healthProvider);
    }
    if ($url === $issuer . '/keys') {
        return jsonAnswer(['keys' => [[
            'kty' => 'RSA',
            'kid' => 'probe-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => JwtVerifier::base64UrlEncode("\x80" . str_repeat("\x01", 255)),
            'e' => 'AQAB',
        ]]]);
    }
    if ($url === $issuer . '/par') {
        return jsonAnswer(['request_uri' => 'urn:probe:request', 'expires_in' => 60], 201);
    }
    throw new RuntimeException('Unexpected private-key health request: ' . $url);
};
$healthProbe = new ProviderProbe(
    new HttpClient($healthTransport, true),
    static fn(OPNsense\Auth\OpenIDConnect $settings): OPNsense\OpenIDConnect\ClientAssertion =>
        testClientAssertion($settings)
);
$healthController = new class(new Request(
    'https',
    'firewall.example.net',
    [],
    [
        'openidconnect_provider_url' => $issuer,
        'openidconnect_client_id' => 'private-key-client',
        'openidconnect_signing_certificate' => '0123456789abc',
        'openidconnect_token_auth' => 'private_key_jwt',
        'openidconnect_par_mode' => 'auto',
        'openidconnect_origin_policy' => 'custom',
        'openidconnect_redirect_urls' => 'https://firewall.example.net',
        'openidconnect_tls_offloading' => '1',
        'openidconnect_app_code' => 'private-key-health',
    ],
    [],
    '',
    'POST'
), $healthProbe) extends HealthController {
    public function __construct(Request $request, private ProviderProbe $probe)
    {
        parent::__construct($request);
    }

    protected function providerProbe(): ProviderProbe
    {
        return $this->probe;
    }
};
$healthAnswer = $healthController->probeAction();
$healthParRows = array_values(array_filter(
    $healthAnswer['checks'],
    static fn(array $check): bool => $check['label'] === 'PAR endpoint'
));
Checks::that('a certificate-only health controller reaches Discovery, JWKS and PAR',
    array_column($healthRequests, 'url'), [
        $issuer . '/.well-known/openid-configuration',
        $issuer . '/keys',
        $issuer . '/par',
    ]);
Checks::that('a certificate-only health controller exercises its client assertion live',
    $healthParRows[0]['verification'], 'live');
Checks::that('connection health shows the exact browser origins accepted for sign-in',
    probeRow($healthAnswer['checks'], 'Effective WebGUI origins'), [
        'label' => 'Effective WebGUI origins',
        'value' => 'https://firewall.example.net',
        'status' => 'success',
        'note' => 'OpenID Connect sign-in can start from exactly these browser origins.',
        'actors' => ['browser', 'opnsense'],
        'verification' => 'configuration',
        'purpose' => 'This limits which browser addresses are allowed to start a sign-in for this firewall.',
        'standards' => [
            [
                'title' => 'OpenID Connect Core 1.0 — Authentication Request',
                'url' => 'https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest',
            ],
            [
                'title' => 'RFC 9700, section 2.1 — Protecting Redirect-Based Flows',
                'url' => 'https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1',
            ],
        ],
    ]);

$discoveryController = new class(new Request(
    'https',
    'firewall.example.net',
    [],
    [
        'openidconnect_provider_url' => $issuer,
        'openidconnect_client_id' => 'private-key-client',
        'openidconnect_signing_certificate' => '0123456789abc',
        'openidconnect_token_auth' => 'private_key_jwt',
        'openidconnect_par_mode' => 'auto',
        'openidconnect_origin_policy' => 'custom',
        'openidconnect_redirect_urls' => 'https://firewall.example.net',
        'openidconnect_app_code' => 'private-key-discovery',
    ],
    [],
    '',
    'POST'
), $healthProbe) extends DiscoveryController {
    public function __construct(Request $request, private ProviderProbe $probe)
    {
        parent::__construct($request);
    }

    protected function providerProbe(): ProviderProbe
    {
        return $this->probe;
    }
};
$discoveryAnswer = $discoveryController->probeAction();
Checks::that('discovery shows the same exact browser origins accepted for sign-in',
    probeRow($discoveryAnswer['checks'], 'Effective WebGUI origins')['value'],
    'https://firewall.example.net');

$legacyDiscoveryController = new DiscoveryController(new Request(
    'https',
    'firewall.example.net',
    [],
    ['url' => $issuer],
    [],
    '',
    'POST'
));
$legacyDiscoveryValues = inspect($legacyDiscoveryController, 'formValues');
Checks::that('the authenticated discovery API retains its legacy URL parameter',
    ProviderProbe::settings($legacyDiscoveryValues)->issuerUrl(), $issuer);

$httpFailureIssuer = 'https://http-failure.example.net';
$httpFailureValues = [
    'openidconnect_provider_url' => $httpFailureIssuer,
    'openidconnect_client_id' => 'http-failure-client',
    'openidconnect_client_secret' => 'http-failure-secret',
    'openidconnect_par_mode' => 'disabled',
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_tls_offloading' => '1',
];
$httpFailureProbe = new ProviderProbe(new HttpClient(static fn(): array => [
    'status' => 502,
    'content_type' => 'text/html',
    'body' => '<html>untrusted reverse-proxy page</html>',
    'location' => '',
]));
$httpFailureDiscovery = new class(new Request(
    'https',
    'firewall.example.net',
    [],
    $httpFailureValues,
    [],
    '',
    'POST'
), $httpFailureProbe) extends DiscoveryController {
    public function __construct(Request $request, private ProviderProbe $probe)
    {
        parent::__construct($request);
    }

    protected function providerProbe(): ProviderProbe
    {
        return $this->probe;
    }
};
$httpFailureDiscoveryAnswer = $httpFailureDiscovery->probeAction();
Checks::that('Discovery exposes safe HTTP status and media-type failure basics', [
    str_contains($httpFailureDiscoveryAnswer['message'], 'HTTP 502; Content-Type: text/html'),
    str_contains($httpFailureDiscoveryAnswer['message'], 'untrusted reverse-proxy page'),
], [true, false]);

$httpFailureHealth = new class(new Request(
    'https',
    'firewall.example.net',
    [],
    $httpFailureValues,
    [],
    '',
    'POST'
), $httpFailureProbe) extends HealthController {
    public function __construct(Request $request, private ProviderProbe $probe)
    {
        parent::__construct($request);
    }

    protected function providerProbe(): ProviderProbe
    {
        return $this->probe;
    }
};
$httpFailureHealthAnswer = $httpFailureHealth->probeAction();
$httpFailureHealthRow = probeRow($httpFailureHealthAnswer['checks'], 'Live provider preflight');
Checks::that('Connection health exposes the same safe HTTP failure basics', [
    str_contains($httpFailureHealthRow['note'], 'HTTP 502; Content-Type: text/html'),
    str_contains($httpFailureHealthRow['note'], 'untrusted reverse-proxy page'),
], [true, false]);

$requests = [];
$transport = static function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$requests, $issuer, $provider): array {
    $requests[] = compact('method', 'url', 'body', 'headers');
    if ($url === $issuer . '/.well-known/openid-configuration') {
        return jsonAnswer($provider);
    }
    if ($url === $issuer . '/keys') {
        return jsonAnswer(['keys' => [[
            'kty' => 'RSA',
            'kid' => 'probe-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => JwtVerifier::base64UrlEncode("\x80" . str_repeat("\x01", 255)),
            'e' => 'AQAB',
        ]]]);
    }
    if ($url === $issuer . '/par') {
        return jsonAnswer(['request_uri' => 'urn:probe:request', 'expires_in' => 60], 201);
    }
    throw new RuntimeException('Unexpected diagnostic request: ' . $url);
};

$draft = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_provider_profile' => 'general',
    'openidconnect_par_mode' => 'auto',
    'openidconnect_response_mode' => 'query',
    'openidconnect_claims_source' => 'auto',
]);
$draftChecks = (new ProviderProbe(new HttpClient($transport, true)))->checks($draft, null);
Checks::that('a draft probes Discovery and JWKS without client credentials', count($requests), 2);
Checks::that(
    'a draft reports authenticated PAR as not tested',
    $draftChecks[array_key_last($draftChecks)]['verification'],
    'not-tested'
);
Checks::that('every diagnostic check names its actors', count(array_filter(
    $draftChecks,
    static fn(array $check): bool => is_array($check['actors'] ?? null) && $check['actors'] !== []
)), count($draftChecks));
Checks::that('every diagnostic check names how it was verified', count(array_filter(
    $draftChecks,
    static fn(array $check): bool => in_array(
        $check['verification'] ?? '',
        ['live', 'metadata', 'configuration', 'not-tested', 'skipped'],
        true
    )
)), count($draftChecks));
$documentedChecks = array_merge(
    ProviderProbe::healthReadiness($draft, null),
    $draftChecks,
    [ProviderProbe::credentialsCheck($draftChecks[array_key_last($draftChecks)])]
);
Checks::that('every diagnostic detail explains its purpose in one short sentence', count(array_filter(
    $documentedChecks,
    static fn(array $check): bool => is_string($check['purpose'] ?? null)
        && str_ends_with($check['purpose'], '.')
        && !str_contains($check['purpose'], "\n")
        && str_word_count($check['purpose']) <= 20
)), count($documentedChecks));
Checks::that('every diagnostic detail links at least one named authoritative standard', count(array_filter(
    $documentedChecks,
    static fn(array $check): bool => is_array($check['standards'] ?? null)
        && $check['standards'] !== []
        && count(array_filter(
            $check['standards'],
            static fn(array $standard): bool => is_string($standard['title'] ?? null)
                && $standard['title'] !== ''
                && is_string($standard['url'] ?? null)
                && preg_match(
                    '#^https://(?:www\.rfc-editor\.org|openid\.net)/#',
                    $standard['url']
                ) === 1
        )) === count($check['standards'])
)), count($documentedChecks));
Checks::that('diagnostic labels leave data flow to the secondary row', count(array_filter(
    $draftChecks,
    static fn(array $check): bool => str_contains((string)($check['label'] ?? ''), '→')
)), 0);
$draftSemantics = [];
foreach ($draftChecks as $check) {
    $draftSemantics[$check['label']] = [implode(',', $check['actors']), $check['verification']];
}
Checks::that('Discovery names its live firewall request', $draftSemantics['Discovery'], ['opnsense,idp', 'live']);
Checks::that('the provider profile is current-form policy', $draftSemantics['Provider profile'], [
    'opnsense', 'configuration',
]);
Checks::that('authorization is an unexecuted browser path', $draftSemantics['Authorization endpoint'], [
    'browser,idp', 'not-tested',
]);
Checks::that('an advertised authorization endpoint passes readiness without pretending it was called',
    array_values(array_filter(
        $draftChecks,
        static fn(array $check): bool => $check['label'] === 'Authorization endpoint'
    ))[0]['status'], 'success');
Checks::that('an incomplete registration is explicitly left untested', $draftSemantics['Authorization registration'], [
    'opnsense,idp', 'not-tested',
]);
Checks::that('the token endpoint is an unexecuted server path', $draftSemantics['Token endpoint'], [
    'opnsense,idp', 'not-tested',
]);
Checks::that('UserInfo is advertised but unexecuted', $draftSemantics['UserInfo endpoint'], [
    'opnsense,idp', 'not-tested',
]);
Checks::that('signature policy is evaluated locally', $draftSemantics['ID Token signatures'], [
    'opnsense', 'metadata',
]);
Checks::that('client authentication is evaluated locally', $draftSemantics['Client authentication'], [
    'opnsense', 'metadata',
]);
Checks::that('client assertion algorithms are evaluated locally', $draftSemantics['Client assertion signatures'], [
    'opnsense', 'metadata',
]);
Checks::that('certificate-bound token support is evaluated locally',
    $draftSemantics['Certificate-bound access tokens'], ['opnsense', 'metadata']);
Checks::that('PKCE policy is evaluated locally', $draftSemantics['PKCE'], ['opnsense', 'metadata']);
Checks::that('DPoP negotiation is evaluated locally', $draftSemantics['DPoP sender constraint'], [
    'opnsense', 'metadata',
]);
$authentikDraft = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_provider_profile' => 'authentik',
]);
$authentikChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    $authentikDraft,
    ProviderMetadata::fromArray($provider)
);
$authentikDpop = array_values(array_filter(
    $authentikChecks,
    static fn(array $check): bool => $check['label'] === 'DPoP sender constraint'
))[0];
Checks::that('authentik reports its documented ID Token binding instead of claiming DPoP access tokens', [
    $authentikDpop['status'],
    str_contains($authentikDpop['note'], 'ID Token'),
], ['success', true]);
Checks::that('response mode follows the provider response path', $draftSemantics['Authorization response mode'], [
    'idp,browser,opnsense', 'metadata',
]);
Checks::that('the chosen client authentication is local metadata evaluation',
    $draftSemantics['Selected authentication method'], ['opnsense', 'metadata']);
Checks::that('response issuer follows the provider response path', $draftSemantics['Authorization response issuer'], [
    'idp,browser,opnsense', 'metadata',
]);
Checks::that('provider sign-out is an unexecuted browser path', $draftSemantics['Provider sign-out'], [
    'browser,idp', 'not-tested',
]);
Checks::that('revocation is an unexecuted server path', $draftSemantics['Token revocation'], [
    'opnsense,idp', 'not-tested',
]);
Checks::that('signing keys name their live firewall request', $draftSemantics['Signing keys'], [
    'opnsense,idp', 'live',
]);
Checks::that(
    'the Request Object key is evaluated from the current form',
    $draftSemantics['JWT-secured authorization request'],
    ['opnsense', 'configuration']
);
Checks::that('draft PAR names the path it did not execute', $draftSemantics['PAR endpoint'], [
    'opnsense,idp', 'not-tested',
]);

$providerWithoutUserInfo = $provider;
unset($providerWithoutUserInfo['userinfo_endpoint']);
$withoutUserInfoChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    $draft,
    ProviderMetadata::fromArray($providerWithoutUserInfo)
);
$withoutUserInfoRows = array_values(array_filter(
    $withoutUserInfoChecks,
    static fn(array $check): bool => $check['label'] === 'Token endpoint'
));
Checks::that(
    'a token endpoint remains untested when UserInfo is not offered',
    $withoutUserInfoRows[0]['verification'],
    'not-tested'
);
$withoutUserInfoCapability = array_values(array_filter(
    $withoutUserInfoChecks,
    static fn(array $check): bool => $check['label'] === 'UserInfo endpoint'
))[0];
Checks::that('an optional capability absent from Discovery is separated from readiness', [
    $withoutUserInfoCapability['status'],
    $withoutUserInfoCapability['section'] ?? '',
], ['success', 'unsupported']);

$providerWithoutPkce = $provider;
unset($providerWithoutPkce['code_challenge_methods_supported']);
$withoutPkceChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    $draft,
    ProviderMetadata::fromArray($providerWithoutPkce)
);
$withoutPkce = array_values(array_filter(
    $withoutPkceChecks,
    static fn(array $check): bool => $check['label'] === 'PKCE'
))[0];
Checks::that('a missing mandatory capability fails readiness instead of moving to the optional section', [
    $withoutPkce['status'],
    $withoutPkce['section'] ?? '',
], ['error', '']);

$requestObjectDraft = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_request_object_key' => 'unsaved-request-key',
]);
Checks::that(
    'the provider probe preserves the unsaved Request Object key',
    $requestObjectDraft->requestObjectSigningKey(),
    'unsaved-request-key'
);

$tlsOnlyMetadata = ProviderMetadata::fromArray(metadata([
    'token_endpoint_auth_methods_supported' => ['tls_client_auth'],
]));
$secretOnlySettings = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_client_id' => 'secret-client',
    'openidconnect_client_secret' => 'secret',
]);
$secretOnlyChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    $secretOnlySettings,
    $tlsOnlyMetadata
);
Checks::that(
    'provider-only mTLS is not reported usable without a configured certificate',
    array_intersect_key(probeRow($secretOnlyChecks, 'Client authentication'), [
        'value' => true,
        'status' => true,
    ]),
    ['value' => 'None supported', 'status' => 'error']
);
Checks::that(
    'automatic authentication is rejected when no method matches the configured credential',
    probeRow($secretOnlyChecks, 'Selected authentication method')['status'],
    'error'
);

$missingSecretChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    ProviderProbe::settings([
        'openidconnect_provider_url' => $issuer,
        'openidconnect_client_id' => 'incomplete-secret-client',
    ]),
    ProviderMetadata::fromArray(metadata([
        'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
    ]))
);
Checks::that(
    'a secret method is not reported usable without its configured secret',
    probeRow($missingSecretChecks, 'Client authentication')['status'],
    'error'
);

installClientCertificate('probe-mtls', 'Provider probe mTLS certificate');
$mtlsProbeSettings = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_client_id' => 'mtls-client',
    'openidconnect_client_certificate' => 'probe-mtls',
]);
$mtlsChecks = inspect(
    new ProviderProbe(new HttpClient(static fn(): array => [])),
    'metadataChecks',
    $mtlsProbeSettings,
    $tlsOnlyMetadata
);
Checks::that(
    'the same provider authentication is usable with its selected certificate',
    array_intersect_key(probeRow($mtlsChecks, 'Client authentication'), [
        'value' => true,
        'status' => true,
    ]),
    ['value' => 'tls_client_auth', 'status' => 'success']
);
Checks::that(
    'health accepts a complete mutual-TLS client without a secret',
    ProviderProbe::healthReadiness(
        $mtlsProbeSettings,
        'https://firewall.example.net/api/openidconnect/auth/callback/main'
    )[0]['status'],
    'success'
);

$requests = [];
$secret = 'diagnostic-secret-value';
$complete = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_provider_profile' => 'general',
    'openidconnect_client_id' => 'diagnostic-client',
    'openidconnect_client_secret' => $secret,
    'openidconnect_token_auth' => 'client_secret_post',
    'openidconnect_par_mode' => 'auto',
    'openidconnect_scopes' => 'openid,profile',
    'openidconnect_response_mode' => 'query',
    'openidconnect_claims_source' => 'auto',
]);
$completeChecks = (new ProviderProbe(new HttpClient($transport, true)))->checks(
    $complete,
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);
$par = $completeChecks[array_key_last($completeChecks)];
Checks::that('complete current form values exercise authenticated PAR live', $par['verification'], 'live');
Checks::that('the live PAR request succeeds', $par['status'], 'success');
Checks::that('the live probe made Discovery, JWKS and PAR requests', count($requests), 3);
Checks::that('the secret is never returned in diagnostic results', str_contains(
    json_encode($completeChecks, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
    $secret
), false);

$readiness = ProviderProbe::healthReadiness(
    $complete,
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);
Checks::that('health checks current client completeness', $readiness[0]['status'], 'success');
Checks::that('health accepts the current configured WebGUI origin', $readiness[1]['status'], 'success');
Checks::that('health exposes every effective WebGUI origin as a configuration check', $readiness[2],
    ProviderProbe::webGuiOriginsCheck($complete));
$rejectedReadiness = ProviderProbe::healthReadiness($complete, null);
Checks::that('health rejects a current WebGUI origin outside the effective origins', $rejectedReadiness[1], [
    'label' => 'WebGUI transport',
    'value' => 'Blocked',
    'status' => 'error',
    'note' => 'The current WebGUI origin is not accepted by these form values.',
    'actors' => ['browser', 'opnsense'],
    'verification' => 'configuration',
    'purpose' => 'A trusted HTTPS address keeps sign-in responses on the intended firewall connection.',
    'standards' => [[
        'title' => 'RFC 6749 — Endpoint Request Confidentiality',
        'url' => 'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2.1',
    ]],
]);
$credentials = ProviderProbe::credentialsCheck($par);
Checks::that('health says when PAR exercised client credentials', $credentials['verification'], 'live');
$unsupportedProvider = array_replace($provider, [
    'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
]);
$unsupportedRequests = [];
$unsupportedTransport = static function (
    string $method,
    string $url,
    ?string $body,
    array $headers
) use (&$unsupportedRequests, $issuer, $unsupportedProvider): array {
    $unsupportedRequests[] = compact('method', 'url', 'body', 'headers');
    if ($url === $issuer . '/.well-known/openid-configuration') {
        return jsonAnswer($unsupportedProvider);
    }
    if ($url === $issuer . '/keys') {
        return jsonAnswer(['keys' => [[
            'kty' => 'RSA',
            'kid' => 'probe-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => JwtVerifier::base64UrlEncode("\x80" . str_repeat("\x01", 255)),
            'e' => 'AQAB',
        ]]]);
    }
    throw new RuntimeException('The unsupported authentication method must fail before PAR transport');
};
$unsupportedChecks = (new ProviderProbe(new HttpClient($unsupportedTransport, true)))->checks(
    $complete,
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);
$unsupportedPar = $unsupportedChecks[array_key_last($unsupportedChecks)];
Checks::that('an unsupported authentication method fails before the PAR request', count($unsupportedRequests), 2);
Checks::that(
    'a pre-transport PAR failure does not report credentials as exercised',
    ProviderProbe::credentialsCheck($unsupportedPar)['verification'],
    'not-tested'
);
$answer = ProviderProbe::answer(
    array_merge($readiness, $completeChecks, [$credentials]),
    'accepted',
    'accepted with %d warning(s)',
    'failed with %d error(s)'
);
Checks::that('a complete live health result passes', $answer['overall'], 'success');
Checks::that('health results remain secret-free', str_contains(
    json_encode($answer, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
    $secret
), false);
$authorizationFailureProvider = array_replace($provider, [
    'pushed_authorization_request_endpoint' => null,
]);
unset($authorizationFailureProvider['pushed_authorization_request_endpoint']);
$authorizationFailureTransport = static function (string $method, string $url) use (
    $issuer,
    $authorizationFailureProvider
): array {
    if ($url === $issuer . '/.well-known/openid-configuration') {
        return jsonAnswer($authorizationFailureProvider);
    }
    if ($url === $issuer . '/keys') {
        return jsonAnswer(['keys' => [[
            'kty' => 'RSA',
            'kid' => 'probe-key',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => JwtVerifier::base64UrlEncode("\x80" . str_repeat("\x01", 255)),
            'e' => 'AQAB',
        ]]]);
    }
    throw new RuntimeException('authorization transport failed');
};
$authorizationFailureSettings = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_client_id' => 'diagnostic-client',
    'openidconnect_client_secret' => $secret,
    'openidconnect_par_mode' => 'disabled',
    'openidconnect_response_mode' => 'query',
]);
$authorizationFailureChecks = (new ProviderProbe(
    new HttpClient($authorizationFailureTransport, true)
))->checks($authorizationFailureSettings, 'https://firewall.example.net/api/openidconnect/auth/callback/main');
Checks::that('an authorization transport failure remains attributed to registration',
    probeRow($authorizationFailureChecks, 'Authorization registration'), [
        'label' => 'Authorization registration',
        'value' => 'Live check failed',
        'status' => 'error',
        'note' => 'authorization transport failed',
        'actors' => ['opnsense', 'idp'],
        'verification' => 'live',
        'purpose' => 'This catches a wrong Client ID or return address before a user tries to sign in.',
        'standards' => [[
            'title' => 'OpenID Connect Core 1.0 — Authentication Request',
            'url' => 'https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest',
        ]],
    ]);
$jarm = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_provider_profile' => 'general',
    'openidconnect_client_id' => 'diagnostic-client',
    'openidconnect_client_secret' => $secret,
    'openidconnect_token_auth' => 'client_secret_post',
    'openidconnect_par_mode' => 'auto',
    'openidconnect_scopes' => 'openid,profile',
    'openidconnect_response_mode' => 'query.jwt',
    'openidconnect_claims_source' => 'auto',
]);
$jarmChecks = (new ProviderProbe(new HttpClient($transport, true)))->checks(
    $jarm,
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);
$jarmRows = array_values(array_filter(
    $jarmChecks,
    static fn(array $check): bool => $check['label'] === 'JARM signatures'
));
Checks::that('signed response diagnostics retain the JARM capability check', $jarmRows[0], [
    'label' => 'JARM signatures',
    'value' => 'RS256',
    'status' => 'success',
    'note' => 'The signed authorization response can use a supported asymmetric signature.',
    'actors' => ['opnsense'],
    'verification' => 'metadata',
    'purpose' => 'JARM signs the browser response so OPNsense can detect changes before using it.',
    'standards' => [[
        'title' => 'JWT Secured Authorization Response Mode, section 2',
        'url' => 'https://openid.net/specs/oauth-v2-jarm.html#section-2',
    ]],
]);
$failedAnswer = ProviderProbe::answer(
    [ProviderProbe::failureCheck('Live provider preflight', 'unreachable', ['opnsense', 'idp'], 'live')],
    'accepted',
    'accepted with %d warning(s)',
    'failed with %d error(s)'
);
Checks::that('a provider failure retains the structured health result', $failedAnswer['overall'], 'error');
Checks::that('a provider failure retains its actor and method details', $failedAnswer['checks'][0], [
    'label' => 'Live provider preflight',
    'value' => 'Live check failed',
    'status' => 'error',
    'note' => 'unreachable',
    'actors' => ['opnsense', 'idp'],
    'verification' => 'live',
    'purpose' => 'This confirms that OPNsense can securely reach and recognize the configured provider.',
    'standards' => [[
        'title' => 'OpenID Connect Discovery 1.0, section 4.3',
        'url' => 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation',
    ]],
]);
