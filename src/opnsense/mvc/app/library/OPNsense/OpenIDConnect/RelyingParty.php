<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Session;

/** A focused OpenID Connect relying party for OPNsense WebGUI sessions. */
class RelyingParty
{
    public const SIGNING_ALGORITHMS = JwtVerifier::ALGORITHMS;
    public const REQUEST_TIMEOUT = HttpClient::TOTAL_TIMEOUT;
    public const TRANSACTION_LIFETIME = 600;
    public const MAX_TRANSACTIONS = 5;

    private const TRANSACTIONS = 'openidconnect_transactions_v2';
    private const TOKEN_MAX_BYTES = 1048576;
    private const USERINFO_MAX_BYTES = 1048576;
    private const PROTOCOL_CLAIMS = [
        'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'at_hash', 'c_hash',
        'azp', 'sid', 'typ', 'auth_time', 'acr', 'amr',
    ];
    private const HOST_HEADER = '/^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?'
        . '(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.?'
        . '|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/';

    private OpenIDConnect $settings;
    private Session $session;
    private Request $request;
    private $response;
    private HttpClient $http;
    private JwtVerifier $verifier;
    private string $redirectUri;
    private ?ProviderMetadata $metadata = null;
    /** @var array<string,mixed> */
    private array $tokens = [];
    /** @var array<string,mixed> */
    private array $idTokenClaims = [];

    public function __construct(OpenIDConnect $settings, Controller $controller, ?HttpClient $http = null)
    {
        $this->settings = $settings;
        $this->session = $controller->session;
        $this->request = $controller->request;
        $this->response = $controller->response;
        $this->http = $http ?? new HttpClient();
        $this->verifier = new JwtVerifier($this->http);

        $redirect = static::acceptedRedirectUri($settings, $controller->request);
        if ($redirect === null) {
            throw new ProtocolException('This WebGUI origin is not accepted for OpenID Connect');
        }
        $this->redirectUri = $redirect;
    }

    public static function callbackPath(string $applicationCode): string
    {
        return OpenIDConnect::CALLBACK_PATH . '/' . rawurlencode($applicationCode);
    }

    public static function intendedOrigin(Request $request, bool $trustedTlsOffloading = false): string
    {
        $host = $request->getHeader('HOST');
        if (!preg_match(self::HOST_HEADER, $host)) {
            throw new ProtocolException('The request Host header is not a host name');
        }
        $scheme = strtolower($request->getScheme());
        if ($scheme !== 'https' && !($trustedTlsOffloading && $scheme === 'http')) {
            throw new ProtocolException('OpenID Connect is only available through an HTTPS WebGUI');
        }

        /* In the offloading exception the exact accepted public origin, not a forwarded
         * header supplied by the request, is the authority for rendering HTTPS. */
        return 'https://' . $host;
    }

    public static function intendedRedirectUri(OpenIDConnect $settings, Request $request): string
    {
        return static::intendedOrigin($request, $settings->usesTrustedTlsOffloading())
            . static::callbackPath($settings->applicationCode());
    }

    public static function acceptedRedirectUri(OpenIDConnect $settings, Request $request): ?string
    {
        try {
            $origin = static::intendedOrigin($request, $settings->usesTrustedTlsOffloading());
        } catch (ProtocolException $e) {
            syslog(LOG_NOTICE, 'OIDC: refusing a login begun under an invalid WebGUI origin');
            return null;
        }
        if ($settings->acceptsWebGuiOrigin($origin)) {
            return $origin . static::callbackPath($settings->applicationCode());
        }
        return null;
    }

    /** Begin a normal login transaction and redirect to the authorization endpoint. */
    public function begin(string $providerName, string $target): void
    {
        $this->response->redirect($this->authorizationUrl($providerName, $target));
    }

    /**
     * Prepare an authorization transaction and return the provider address.
     *
     * The authenticated sign-in tester needs the address as JSON so its form can first
     * pass normal WebGUI CSRF protection and only then navigate the browser. A normal
     * login uses the same method through begin(), keeping both paths protocol-identical.
     */
    public function authorizationUrl(string $providerName, string $target, bool $testOnly = false): string
    {
        $metadata = $this->discoverMetadata();
        $pkceMethods = $metadata->get('code_challenge_methods_supported', []);
        if (is_array($pkceMethods) && $pkceMethods !== [] && !in_array('S256', $pkceMethods, true)) {
            throw new ProtocolException('The provider explicitly advertises no PKCE S256 support');
        }
        $responseModes = $metadata->get('response_modes_supported', []);
        if (is_array($responseModes) && $responseModes !== []
            && !in_array($this->settings->responseMode(), $responseModes, true)) {
            throw new ProtocolException('The selected authorization response mode is not advertised');
        }
        $formPost = $this->settings->responseMode() === 'form_post';
        $state = ($formPost ? 'p.' : '') . self::randomValue(32);
        $nonce = self::randomValue(32);
        $verifier = self::randomValue(64);
        $challenge = JwtVerifier::base64UrlEncode(hash('sha256', $verifier, true));

        $transaction = [
            'created' => time(),
            'provider' => $providerName,
            'app_code' => $this->settings->applicationCode(),
            'target' => $target,
            'purpose' => $testOnly ? 'test' : 'login',
            'issuer' => $metadata->issuer(),
            'redirect_uri' => $this->redirectUri,
            'nonce' => $nonce,
            'code_verifier' => $verifier,
            'metadata' => $metadata->toArray(),
        ];
        if ($formPost) {
            TransactionRegistry::store($state, $transaction);
        } else {
            $this->storeTransaction($state, $transaction);
        }

        $parameters = [
            'response_type' => 'code',
            'client_id' => $this->settings->clientId(),
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->settings->scopes()),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];
        /* max_age=0 is meaningful: OIDC Core defines it as active re-authentication. */
        $parameters['max_age'] = (string)$this->settings->maximumAuthenticationAge();
        if ($this->settings->responseMode() === 'form_post') {
            $parameters['response_mode'] = 'form_post';
        }

        $this->settings->trace(sprintf(
            'exchange prepared for exact issuer %s, callback %s, PKCE S256, response mode %s',
            $metadata->issuer(),
            $this->redirectUri,
            $this->settings->responseMode()
        ));
        $separator = str_contains($metadata->authorizationEndpoint(), '?') ? '&' : '?';
        return $metadata->authorizationEndpoint() . $separator
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    public static function consumeTransaction(Session $session, array $parameters, string $applicationCode): array
    {
        $state = $parameters['state'] ?? null;
        if (!is_string($state) || $state === '' || strlen($state) > 512) {
            throw new ProtocolException('The authorization response carries no usable state');
        }
        $transactions = self::readTransactions($session);
        $transaction = $transactions[$state] ?? null;
        if ($transaction === null && str_starts_with($state, 'p.')) {
            return TransactionRegistry::consume($state, $applicationCode);
        }
        if (!is_array($transaction) || !is_int($transaction['created'] ?? null)
            || $transaction['created'] < time() - self::TRANSACTION_LIFETIME
            || !is_string($transaction['app_code'] ?? null)
            || !hash_equals($applicationCode, $transaction['app_code'])) {
            throw new ProtocolException('The authorization response does not match a pending login');
        }
        unset($transactions[$state]);
        self::writeTransactions($session, $transactions);

        return $transaction;
    }

    /** @param array<string,mixed> $transaction @param array<string,mixed> $parameters */
    public function complete(array $transaction, array $parameters): object
    {
        $this->metadata = ProviderMetadata::fromArray((array)$transaction['metadata']);
        if (!hash_equals($this->metadata->issuer(), (string)$transaction['issuer'])
            || !hash_equals($this->redirectUri, (string)$transaction['redirect_uri'])) {
            throw new ProtocolException('The login transaction no longer matches this provider');
        }

        $responseIssuer = $parameters['iss'] ?? null;
        if ($responseIssuer !== null
            && (!is_string($responseIssuer) || !$this->responseIssuerMatches($responseIssuer))) {
            throw new ProtocolException('The authorization response came from a different issuer');
        }
        if ($this->metadata->authorizationResponseIssuerSupported() && $responseIssuer === null) {
            throw new ProtocolException('The authorization response omitted its advertised issuer');
        }
        if (isset($parameters['error'])) {
            $error = is_string($parameters['error']) && preg_match('/^[A-Za-z0-9_.-]{1,80}$/D', $parameters['error'])
                ? $parameters['error'] : 'provider_error';
            throw new ProtocolException('The identity provider declined the request (' . $error . ')');
        }
        $code = $parameters['code'] ?? null;
        if (!is_string($code) || $code === '' || strlen($code) > 16384 || preg_match('/[\x00-\x1f\x7f]/', $code)) {
            throw new ProtocolException('The authorization response carries no usable code');
        }

        $this->tokens = $this->exchangeCode($code, (string)$transaction['code_verifier']);
        $idToken = $this->tokens['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            throw new ProtocolException('The token endpoint returned no ID token');
        }
        $accessToken = is_string($this->tokens['access_token'] ?? null) ? $this->tokens['access_token'] : null;
        $issuerValidator = $this->settings->discoveryIssuerTemplate() === null ? null
            : fn(array $claims, array $key) => $this->settings->validateMicrosoftIssuer($claims, $key);
        $verified = $this->verifier->verify(
            $idToken,
            $this->metadata,
            $this->settings->clientId(),
            (string)$transaction['nonce'],
            $accessToken,
            $issuerValidator
        );
        $this->idTokenClaims = $verified['claims'];

        return $this->claimsForAccount($accessToken);
    }

    /** @return array<string,mixed> */
    private function exchangeCode(string $code, string $verifier): array
    {
        $fields = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->settings->clientId(),
            'code_verifier' => $verifier,
        ];
        $headers = ['Accept: application/json'];
        $method = $this->tokenAuthMethod();
        if ($method === 'client_secret_basic') {
            $credentials = urlencode($this->settings->clientId()) . ':' . urlencode($this->settings->clientSecret());
            $headers[] = 'Authorization: Basic ' . base64_encode($credentials);
        } elseif ($method === 'client_secret_post') {
            $fields['client_secret'] = $this->settings->clientSecret();
        } else {
            throw new ProtocolException('No supported token endpoint authentication method is available');
        }

        $response = $this->http->postForm($this->metadata->tokenEndpoint(), $fields, self::TOKEN_MAX_BYTES, $headers);
        if ($response->status !== 200) {
            throw new ProtocolException(sprintf('The token endpoint returned HTTP %d', $response->status));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('The token endpoint did not return application/json');
        }
        $tokens = $response->jsonObject();
        if (count($tokens) > 32) {
            throw new ProtocolException('The token endpoint returned too many fields');
        }
        foreach (['id_token', 'access_token', 'refresh_token'] as $tokenName) {
            if (isset($tokens[$tokenName])
                && (!is_string($tokens[$tokenName]) || $tokens[$tokenName] === ''
                    || strlen($tokens[$tokenName]) > JwtVerifier::MAX_JWT_BYTES
                    || preg_match('/[\x00-\x1f\x7f]/', $tokens[$tokenName]))) {
                throw new ProtocolException(sprintf('The token endpoint returned an invalid %s', $tokenName));
            }
        }
        if (isset($tokens['access_token']) && !isset($tokens['token_type'])) {
            throw new ProtocolException('The token endpoint omitted the access token type');
        }
        if (isset($tokens['token_type'])
            && (!is_string($tokens['token_type']) || strcasecmp($tokens['token_type'], 'Bearer') !== 0)) {
            throw new ProtocolException('The token endpoint returned an unsupported token type');
        }

        return $tokens;
    }

    private function tokenAuthMethod(): string
    {
        $configured = $this->settings->tokenAuthMethod();
        $advertised = $this->metadata->get('token_endpoint_auth_methods_supported', ['client_secret_basic']);
        $advertised = is_array($advertised) ? $advertised : [];
        if ($configured !== null) {
            return $configured;
        }
        foreach (['client_secret_basic', 'client_secret_post'] as $method) {
            if (in_array($method, $advertised, true)) {
                return $method;
            }
        }

        throw new ProtocolException('The provider offers no supported token endpoint authentication method');
    }

    private function claimsForAccount(?string $accessToken): object
    {
        $source = $this->settings->claimsSource();
        $claims = $this->personClaims($this->idTokenClaims);
        $required = array_filter([
            $this->settings->usernameClaim(),
            $this->settings->emailMatching() === 'off' ? null : 'email',
            $this->settings->groupClaim() ?: null,
        ]);
        $missing = array_filter($required, fn(string $name): bool => !array_key_exists($name, $claims));
        $endpoint = $this->metadata->userInfoEndpoint();
        $callUserInfo = $source === 'userinfo'
            || ($source === 'auto' && $endpoint !== null && $missing !== []);

        if ($callUserInfo) {
            if ($endpoint === null || $accessToken === null) {
                throw new ProtocolException('The configured claims source needs UserInfo, but none is available');
            }
            $reported = $this->requestUserInfo($endpoint, $accessToken);
            $signedSubject = $this->idTokenClaims['sub'];
            if (!is_string($reported['sub'] ?? null) || !hash_equals($signedSubject, $reported['sub'])) {
                throw new ProtocolException('The UserInfo subject does not match the ID token subject');
            }
            $claims = array_replace($claims, $this->personClaims($reported));
        }
        if (count($claims) > 256) {
            throw new ProtocolException('The provider returned too many claims');
        }
        $groupClaim = $this->settings->groupClaim();
        if ($this->settings->providerProfile() === 'entra' && $groupClaim !== ''
            && !array_key_exists($groupClaim, $claims)
            && ($this->idTokenClaims['hasgroups'] ?? false) === true) {
            throw new ProtocolException(
                'Microsoft Entra group overage omitted the configured claim; use application roles or a filtered group claim'
            );
        }
        if ($this->settings->providerProfile() === 'entra' && $groupClaim !== ''
            && !array_key_exists($groupClaim, $claims)
            && is_array($this->idTokenClaims['_claim_names'] ?? null)
            && isset($this->idTokenClaims['_claim_names']['groups'])) {
            throw new ProtocolException(
                'Microsoft Entra group overage omitted the configured claim; use application roles or a filtered group claim'
            );
        }

        return (object)$claims;
    }

    /** @return array<string,mixed> */
    private function requestUserInfo(string $endpoint, string $accessToken): array
    {
        $response = $this->http->get(
            $endpoint,
            self::USERINFO_MAX_BYTES,
            ['Authorization: Bearer ' . $accessToken, 'Accept: application/json, application/jwt']
        );
        if ($response->status !== 200) {
            throw new ProtocolException(sprintf('UserInfo returned HTTP %d', $response->status));
        }
        if ($response->contentType === 'application/jwt') {
            $claims = $this->verifier->verifySignedClaims($response->body, $this->metadata);
            if (isset($claims['iss'])
                && (!is_string($claims['iss']) || !$this->responseIssuerMatches($claims['iss']))) {
                throw new ProtocolException('The signed UserInfo issuer does not match discovery');
            }
            if (isset($claims['aud']) && !self::audienceContains($claims['aud'], $this->settings->clientId())) {
                throw new ProtocolException('The signed UserInfo response was not issued to this client');
            }
            return $claims;
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('UserInfo did not return application/json or application/jwt');
        }
        return $response->jsonObject();
    }

    /** @param array<string,mixed> $claims @return array<string,mixed> */
    private function personClaims(array $claims): array
    {
        $result = [];
        foreach ($claims as $name => $value) {
            if (!is_string($name) || strlen($name) > 128 || in_array($name, self::PROTOCOL_CLAIMS, true)) {
                continue;
            }
            $result[$name] = $value;
        }
        $result['sub'] = $claims['sub'];
        return $result;
    }

    public function revokeToken(string $token, string $hint = ''): void
    {
        $this->metadata ??= $this->discoverMetadata();
        $endpoint = $this->metadata->revocationEndpoint();
        if ($endpoint === null) {
            return;
        }
        $fields = ['token' => $token, 'client_id' => $this->settings->clientId()];
        if ($hint !== '') {
            $fields['token_type_hint'] = $hint;
        }
        $headers = [];
        if ($this->tokenAuthMethod() === 'client_secret_basic') {
            $credentials = urlencode($this->settings->clientId()) . ':' . urlencode($this->settings->clientSecret());
            $headers[] = 'Authorization: Basic ' . base64_encode($credentials);
        } else {
            $fields['client_secret'] = $this->settings->clientSecret();
        }
        $response = $this->http->postForm($endpoint, $fields, 262144, $headers);
        if (!in_array($response->status, [200, 204], true)) {
            throw new ProtocolException(sprintf('Token revocation returned HTTP %d', $response->status));
        }
    }

    /**
     * Freeze logout and revocation to the issuer that created the local session.
     * This must run before any stored grant is sent over the network.
     */
    public function requireIssuer(string $expected): void
    {
        $metadata = $this->discoverMetadata();
        if (!$this->responseIssuerMatches($expected)) {
            throw new ProtocolException('The configured issuer changed since this session was created');
        }
        $this->metadata = $metadata;
    }

    public function signOut(string $idToken, ?string $returnTo): void
    {
        $this->metadata ??= $this->discoverMetadata();
        $endpoint = $this->metadata->endSessionEndpoint();
        if ($endpoint === null) {
            $this->response->redirect($returnTo ?? '/');
            return;
        }
        $parameters = ['id_token_hint' => $idToken];
        if ($returnTo !== null) {
            HttpClient::assertHttpsUrl($returnTo);
            $parameters['post_logout_redirect_uri'] = $returnTo;
        }
        $separator = str_contains($endpoint, '?') ? '&' : '?';
        $this->response->redirect($endpoint . $separator . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986));
    }

    public function ownOrigin(): string { return (string)static::originOf($this->redirectUri); }
    public function authenticationTime(): ?int
    {
        $value = $this->idTokenClaims['auth_time'] ?? null;
        return is_int($value) ? $value : null;
    }
    public function issuer(): string
    {
        return is_string($this->idTokenClaims['iss'] ?? null)
            ? $this->idTokenClaims['iss'] : ($this->metadata?->issuer() ?? '');
    }
    public function subject(): string
    {
        return is_string($this->idTokenClaims['sub'] ?? null) ? $this->idTokenClaims['sub'] : '';
    }
    public function sessionIdentifier(): string
    {
        return is_string($this->idTokenClaims['sid'] ?? null) ? $this->idTokenClaims['sid'] : '';
    }
    public function getIdToken(): string
    {
        return is_string($this->tokens['id_token'] ?? null) ? $this->tokens['id_token'] : '';
    }
    public function getAccessToken(): string
    {
        return is_string($this->tokens['access_token'] ?? null) ? $this->tokens['access_token'] : '';
    }
    public function getRefreshToken(): string
    {
        return is_string($this->tokens['refresh_token'] ?? null) ? $this->tokens['refresh_token'] : '';
    }

    public static function issuedForThisFirewall(object $claims, string $clientId): bool
    {
        $audiences = is_string($claims->aud ?? null) ? [$claims->aud] : ($claims->aud ?? []);
        if (!is_array($audiences) || !in_array($clientId, $audiences, true)) {
            return false;
        }
        return count($audiences) < 2
            || (is_string($claims->azp ?? null) && hash_equals($clientId, $claims->azp));
    }

    private static function audienceContains($audience, string $clientId): bool
    {
        $audiences = is_string($audience) ? [$audience] : $audience;
        return is_array($audiences) && array_is_list($audiences)
            && array_filter($audiences, 'is_string') === $audiences
            && in_array($clientId, $audiences, true);
    }

    public static function fetchOverWeb(string $url, int $maxBytes): array
    {
        try {
            $response = (new HttpClient())->get($url, $maxBytes, ['Accept: image/*, application/json']);
            return ['ok' => true, 'body' => $response->body, 'status' => $response->status,
                'type' => $response->contentType, 'problem' => ''];
        } catch (\Throwable $e) {
            return ['ok' => false, 'body' => '', 'status' => 0, 'type' => '', 'problem' => $e->getMessage()];
        }
    }

    /** @param array<string,mixed> $transaction */
    private function storeTransaction(string $state, array $transaction): void
    {
        $transactions = self::readTransactions($this->session);
        $transactions = array_filter($transactions, fn($item): bool => is_array($item)
            && is_int($item['created'] ?? null)
            && $item['created'] >= time() - self::TRANSACTION_LIFETIME);
        while (count($transactions) >= self::MAX_TRANSACTIONS) {
            array_shift($transactions);
        }
        $transactions[$state] = $transaction;
        self::writeTransactions($this->session, $transactions);
    }

    /** @return array<string,array<string,mixed>> */
    private static function readTransactions(Session $session): array
    {
        $stored = json_decode((string)$session->get(self::TRANSACTIONS, '{}'), true);
        return is_array($stored) ? $stored : [];
    }

    /** @param array<string,array<string,mixed>> $transactions */
    private static function writeTransactions(Session $session, array $transactions): void
    {
        if ($transactions === []) {
            $session->remove(self::TRANSACTIONS);
            return;
        }
        $session->set(self::TRANSACTIONS, json_encode($transactions, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    private static function randomValue(int $bytes): string
    {
        return JwtVerifier::base64UrlEncode(random_bytes($bytes));
    }

    private static function originOf(string $url): ?string
    {
        try {
            HttpClient::assertHttpsUrl($url);
        } catch (ProtocolException $e) {
            return null;
        }
        $parts = parse_url($url);
        return 'https://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }

    private function discoverMetadata(): ProviderMetadata
    {
        return ProviderMetadata::discover(
            $this->settings->issuerUrl(),
            $this->http,
            $this->settings->discoveryIssuerTemplate()
        );
    }

    private function responseIssuerMatches(string $issuer): bool
    {
        return $this->settings->discoveryIssuerTemplate() === null
            ? hash_equals($this->metadata?->issuer() ?? '', $issuer)
            : $this->settings->acceptsMicrosoftIssuerValue($issuer);
    }
}
