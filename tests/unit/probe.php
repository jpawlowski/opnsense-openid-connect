<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\ProviderProbe;

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
    'authorization_response_iss_parameter_supported' => true,
]);
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
Checks::that('PKCE policy is evaluated locally', $draftSemantics['PKCE'], ['opnsense', 'metadata']);
Checks::that('PAR availability comes from metadata', $draftSemantics['PAR metadata'], [
    'opnsense,idp', 'metadata',
]);
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

$requestObjectDraft = ProviderProbe::settings([
    'openidconnect_provider_url' => $issuer,
    'openidconnect_request_object_key' => 'unsaved-request-key',
]);
Checks::that(
    'the provider probe preserves the unsaved Request Object key',
    $requestObjectDraft->requestObjectSigningKey(),
    'unsaved-request-key'
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
$rejectedReadiness = ProviderProbe::healthReadiness($complete, null);
Checks::that('health rejects a current WebGUI origin outside the effective origins', $rejectedReadiness[1], [
    'label' => 'WebGUI transport',
    'value' => 'Blocked',
    'status' => 'error',
    'note' => 'The current WebGUI origin is not accepted by these form values.',
    'actors' => ['browser', 'opnsense'],
    'verification' => 'configuration',
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
]);
