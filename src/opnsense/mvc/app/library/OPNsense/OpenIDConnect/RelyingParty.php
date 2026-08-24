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
    private const FRONT_CHANNEL_TOKEN_FIELDS = ['access_token', 'id_token', 'token_type', 'expires_in'];
    private const TOKEN_RESPONSE_FIELDS = [
        'access_token' => true,
        'token_type' => true,
        'expires_in' => true,
        'refresh_token' => true,
        'scope' => true,
        'id_token' => true,
    ];
    private const PROTOCOL_CLAIMS = [
        'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'at_hash', 'c_hash',
        'azp', 'sid', 'typ', 'auth_time', 'acr', 'acrs', 'amr',
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
    private RequestObjectSigner $requestObjectSigner;
    private string $redirectUri;
    private ?ProviderMetadata $metadata = null;
    private ?string $tokenAuthMethod = null;
    private ?ClientAuthentication $clientAuthentication = null;
    /** @var array<string,mixed>|null trusted snapshot retained with an established session */
    private ?array $restoredClientAuthentication;
    /** @var array<string,mixed> */
    private array $tokens = [];
    /** @var array<string,mixed> */
    private array $idTokenClaims = [];

    public function __construct(
        OpenIDConnect $settings,
        Controller $controller,
        ?HttpClient $http = null,
        ?JwtVerifier $verifier = null,
        ?RequestObjectSigner $requestObjectSigner = null,
        ?array $restoredClientAuthentication = null
    ) {
        $this->settings = $settings;
        $this->session = $controller->session;
        $this->request = $controller->request;
        $this->response = $controller->response;
        $this->http = $http ?? new HttpClient();
        $this->verifier = $verifier ?? new JwtVerifier($this->http);
        $this->requestObjectSigner = $requestObjectSigner ?? new RequestObjectSigner();
        $this->restoredClientAuthentication = $restoredClientAuthentication;

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
        $this->metadata = $metadata;
        $responseMode = $this->settings->responseMode();
        $metadata->assertAuthorizationCapabilities($responseMode);
        if (self::isJarmMode($responseMode)
            && array_intersect($metadata->authorizationResponseSigningAlgorithms(), JwtVerifier::ALGORITHMS) === []) {
            throw new ProtocolException('The provider advertises no supported JARM signing algorithm');
        }
        $formPost = self::isFormPostMode($responseMode);
        $state = ($formPost ? 'p.' : '') . self::randomValue(32);
        $nonce = self::randomValue(32);
        $verifier = self::randomValue(64);
        $challenge = JwtVerifier::base64UrlEncode(hash('sha256', $verifier, true));
        $authenticationRequirement = $this->settings->authenticationRequirement();
        $this->clientAuthentication = ClientAuthentication::negotiate($this->settings, $metadata);
        $this->tokenAuthMethod = $this->clientAuthentication->method();

        $transaction = [
            'created' => time(),
            'provider' => $providerName,
            'app_code' => $this->settings->applicationCode(),
            'target' => $target,
            'purpose' => $testOnly ? 'test' : 'login',
            'state' => $state,
            'response_mode' => $responseMode,
            'issuer' => $metadata->issuer(),
            'redirect_uri' => $this->redirectUri,
            'nonce' => $nonce,
            'code_verifier' => $verifier,
            'token_auth_method' => $this->tokenAuthMethod,
            'metadata' => $metadata->toArray(),
            'client_authentication' => $this->clientAuthentication->snapshot(),
        ];
        if ($authenticationRequirement !== null) {
            $transaction['authentication_requirement'] = $authenticationRequirement->toArray();
        }
        $scopes = implode(' ', $this->settings->scopes());
        if (!preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/D', $scopes)) {
            throw new ProtocolException('The configured OAuth scopes are not valid scope tokens');
        }
        $parameters = [
            'response_type' => 'code',
            'client_id' => $this->settings->clientId(),
            'redirect_uri' => $this->redirectUri,
            'scope' => $scopes,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];
        /* max_age=0 is meaningful: OIDC Core defines it as active re-authentication. */
        $parameters['max_age'] = (string)$this->settings->maximumAuthenticationAge();
        if ($responseMode !== 'query') {
            $parameters['response_mode'] = $responseMode;
        }
        if ($authenticationRequirement !== null) {
            $parameters = array_replace($parameters, $authenticationRequirement->authorizationParameters());
        }
        if ($this->settings->selectAccount()) {
            $parameters['prompt'] = 'select_account';
        }

        $usedRequestObject = false;
        $requestObjectKey = $this->settings->requestObjectSigningKey();
        if ($metadata->requiresSignedRequestObject() && $requestObjectKey === '') {
            throw new ProtocolException('Discovery requires signed Request Objects but no signing key is selected');
        }
        if ($requestObjectKey !== '') {
            $parameters = [
                'client_id' => $this->settings->clientId(),
                'request' => $this->requestObjectSigner->sign($this->settings, $metadata, $parameters),
            ];
            $usedRequestObject = true;
        }

        $parEndpoint = $this->clientAuthentication->endpoint($metadata, 'pushed_authorization_request_endpoint');
        $parRequired = $metadata->requiresPushedAuthorizationRequests();
        $parMode = $this->settings->parMode();
        if ($parMode === 'disabled' && $parRequired) {
            throw new ProtocolException('Discovery requires pushed authorization requests but PAR is disabled');
        }
        if ($parMode === 'required' && $parEndpoint === null) {
            throw new ProtocolException('Pushed authorization requests are required but Discovery offers no endpoint');
        }

        $usedPar = false;
        $parKey = $parEndpoint === null ? null : ProviderRuntimeState::parKey($this->settings, $metadata);
        $bypass = $parMode === 'auto' && !$parRequired && $parKey !== null
            && ProviderRuntimeState::parIsBypassed($parKey);
        if ($parEndpoint !== null && $parMode !== 'disabled' && !$bypass) {
            try {
                $authorizationUrl = $this->pushedAuthorizationUrl($metadata, $parEndpoint, $parameters);
                $usedPar = true;
                if ($parKey !== null) {
                    ProviderRuntimeState::parAvailable($parKey);
                }
            } catch (ProviderUnavailableException $e) {
                if ($parMode !== 'auto' || $parRequired || $parKey === null) {
                    throw $e;
                }
                ProviderRuntimeState::parUnavailable($parKey, $e->retryAfter());
                $authorizationUrl = $this->directAuthorizationUrl($metadata, $parameters);
                $this->settings->trace('temporarily bypassing optional PAR while background recovery is pending');
            }
        } else {
            $authorizationUrl = $this->directAuthorizationUrl($metadata, $parameters);
        }

        /* A failed PAR must leave no state that could later be mistaken for a pending login. */
        if ($formPost) {
            TransactionRegistry::store($state, $transaction);
        } else {
            $this->storeTransaction($state, $transaction);
        }

        $this->settings->trace(sprintf(
            'exchange prepared for exact issuer %s, callback %s, PKCE S256, response mode %s%s%s',
            $metadata->issuer(),
            $this->redirectUri,
            $responseMode,
            $usedRequestObject ? ', signed Request Object' : '',
            $usedPar ? ', pushed authorization request' : ''
        ));
        return $authorizationUrl;
    }

    /** @param array<string,string> $parameters */
    private function pushedAuthorizationUrl(
        ProviderMetadata $metadata,
        string $endpoint,
        array $parameters
    ): string {
        $requestUri = (new ParClient($this->settings, $this->http, $this->clientAuthentication))->push(
            $metadata,
            $endpoint,
            $parameters
        );
        $browserParameters = [
            'client_id' => $this->settings->clientId(),
            'request_uri' => $requestUri,
        ];
        return HttpClient::appendQueryParameters($metadata->authorizationEndpoint(), $browserParameters);
    }

    /** @param array<string,string> $parameters */
    private function directAuthorizationUrl(ProviderMetadata $metadata, array $parameters): string
    {
        return HttpClient::appendQueryParameters($metadata->authorizationEndpoint(), $parameters);
    }

    /** @param array<string,mixed> $parameters @return array<string,mixed> */
    public static function consumeTransaction(Session $session, array $parameters, string $applicationCode): array
    {
        $state = self::authorizationResponseState($parameters);
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
        $frozenAuthMethod = $transaction['token_auth_method'] ?? null;
        if (!is_string($frozenAuthMethod)) {
            throw new ProtocolException('The login transaction carries no client authentication method');
        }
        if (!is_array($transaction['client_authentication'] ?? null)) {
            throw new ProtocolException('The pending login carries no client authentication state');
        }
        $this->clientAuthentication = ClientAuthentication::negotiate(
            $this->settings,
            $this->metadata,
            $transaction['client_authentication']
        );
        if (!hash_equals($this->clientAuthentication->method(), $frozenAuthMethod)) {
            throw new ProtocolException('The pending login carries inconsistent client authentication state');
        }
        $this->tokenAuthMethod = $frozenAuthMethod;
        $frozenRequirement = null;
        if (array_key_exists('authentication_requirement', $transaction)) {
            if (!is_array($transaction['authentication_requirement'])) {
                throw new ProtocolException('The login transaction carries an invalid authentication requirement');
            }
            $frozenRequirement = AuthenticationRequirement::fromArray($transaction['authentication_requirement']);
        }
        $currentRequirement = $this->settings->authenticationRequirement();
        if (($frozenRequirement === null) !== ($currentRequirement === null)
            || ($frozenRequirement !== null && !$frozenRequirement->equals($currentRequirement))) {
            throw new ProtocolException('The authentication requirement changed while the login was pending');
        }

        $parameters = $this->validatedAuthorizationResponse($transaction, $parameters);
        $code = $this->authorizationCode($parameters);

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
        if ($frozenRequirement !== null) {
            $frozenRequirement->assertSatisfied($this->idTokenClaims);
            $this->settings->trace(sprintf(
                'the verified ID Token satisfies the %s authentication requirement',
                str_replace('-', ' ', $frozenRequirement->tier())
            ));
        }

        return $this->claimsForAccount($accessToken);
    }

    /** @param array<string,mixed> $parameters */
    private function authorizationCode(array $parameters): string
    {
        /* A token returned through the browser is already exposed even when ignored. Refuse
         * the whole response so an implicit or hybrid provider setup cannot look successful. */
        foreach (self::FRONT_CHANNEL_TOKEN_FIELDS as $name) {
            if (array_key_exists($name, $parameters)) {
                throw new ProtocolException('The authorization response carries a front-channel token');
            }
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

        return $code;
    }

    /** @return array<string,mixed> */
    private function exchangeCode(string $code, string $verifier): array
    {
        $fields = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $verifier,
        ];
        $headers = ['Accept: application/json'];
        $this->authenticateClient($fields, $headers);

        $response = $this->http->postForm(
            (string)$this->clientAuthentication()->endpoint($this->metadata, 'token_endpoint'),
            $fields,
            self::TOKEN_MAX_BYTES,
            $headers,
            $this->clientAuthentication()->certificate()
        );
        if ($response->status !== 200) {
            throw new ProtocolException($this->tokenEndpointError($response));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('The token endpoint did not return application/json');
        }
        $tokens = $response->jsonObject();
        if (array_key_exists('error', $tokens)) {
            throw new ProtocolException($this->tokenEndpointError($response));
        }
        foreach (['id_token', 'access_token', 'refresh_token'] as $tokenName) {
            if (isset($tokens[$tokenName])
                && (!is_string($tokens[$tokenName]) || $tokens[$tokenName] === ''
                    || strlen($tokens[$tokenName]) > JwtVerifier::MAX_JWT_BYTES
                    || preg_match('/[\x00-\x1f\x7f]/', $tokens[$tokenName]))) {
                throw new ProtocolException(sprintf('The token endpoint returned an invalid %s', $tokenName));
            }
        }
        if (!isset($tokens['access_token'])) {
            throw new ProtocolException('The token endpoint returned no access token');
        }
        if (!isset($tokens['token_type'])) {
            throw new ProtocolException('The token endpoint omitted the access token type');
        }
        if (!is_string($tokens['token_type']) || strcasecmp($tokens['token_type'], 'Bearer') !== 0) {
            throw new ProtocolException('The token endpoint returned an unsupported token type');
        }
        self::bearerAuthorization($tokens['access_token']);
        $this->clientAuthentication()->assertAccessTokenBinding($tokens['access_token']);
        if (array_key_exists('expires_in', $tokens)) {
            $lifetime = $tokens['expires_in'];
            if ((!is_int($lifetime) && !is_float($lifetime)) || !is_finite((float)$lifetime) || $lifetime < 0) {
                throw new ProtocolException('The token endpoint returned an invalid access token lifetime');
            }
        }
        if (array_key_exists('scope', $tokens) && (!is_string($tokens['scope'])
            || !preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/D', $tokens['scope']))) {
            throw new ProtocolException('The token endpoint returned an invalid access token scope');
        }

        /* RFC 6749 requires clients to ignore extension response names. Keeping only the
         * fields this RP consumes also prevents an unreviewed value from reaching session state. */
        return array_intersect_key($tokens, self::TOKEN_RESPONSE_FIELDS);
    }

    private function tokenEndpointError(HttpResponse $response): string
    {
        if ($response->contentType === 'application/json') {
            try {
                $answer = $response->jsonObject();
                $error = $answer['error'] ?? null;
                if (is_string($error) && preg_match('/^[A-Za-z0-9_.-]{1,80}$/D', $error)) {
                    return 'The token endpoint declined the request (' . $error . ')';
                }
            } catch (ProtocolException $e) {
                /* The status remains useful; an untrusted error body never belongs in the log. */
            }
        }
        return sprintf('The token endpoint returned HTTP %d', $response->status);
    }

    /** @param array<string,string> $fields @param string[] $headers */
    private function authenticateClient(array &$fields, array &$headers, ?string $method = null): void
    {
        $this->clientAuthentication()->authenticate($this->settings, $fields, $headers, $method);
    }

    private function clientAuthentication(): ClientAuthentication
    {
        if ($this->metadata === null) {
            throw new ProtocolException('Provider metadata is not available for client authentication');
        }
        return $this->clientAuthentication ??= ClientAuthentication::negotiate(
            $this->settings,
            $this->metadata,
            $this->restoredClientAuthentication
        );
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
        $endpoint = $this->clientAuthentication()->endpoint($this->metadata, 'userinfo_endpoint');
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
            [self::bearerAuthorization($accessToken), 'Accept: application/json, application/jwt'],
            $this->clientAuthentication()->certificate()
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

    private static function bearerAuthorization(string $accessToken): string
    {
        if (!preg_match('/^[A-Za-z0-9._~+\/-]+=*$/D', $accessToken)) {
            throw new ProtocolException('The provider returned an access token that cannot be used as a bearer token');
        }
        return 'Authorization: Bearer ' . $accessToken;
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
        $endpoint = $this->clientAuthentication()->endpoint($this->metadata, 'revocation_endpoint');
        if ($endpoint === null) {
            return;
        }
        $fields = ['token' => $token, 'client_id' => $this->settings->clientId()];
        if ($hint !== '') {
            $fields['token_type_hint'] = $hint;
        }
        $headers = [];
        $this->authenticateClient(
            $fields,
            $headers,
            $this->clientAuthentication()->revocationMethod($this->metadata)
        );
        $response = $this->http->postForm(
            $endpoint,
            $fields,
            262144,
            $headers,
            $this->clientAuthentication()->certificate()
        );
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
        $matches = $this->settings->discoveryIssuerTemplate() === null
            ? hash_equals($metadata->issuer(), $expected)
            : $this->settings->acceptsMicrosoftIssuerValue($expected);
        if (!$matches) {
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
        $this->response->redirect(HttpClient::appendQueryParameters($endpoint, $parameters));
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

    /** @return array<string,mixed> */
    public function getClientAuthenticationSnapshot(): array
    {
        return $this->clientAuthentication()->snapshot();
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

    /** @param array<string,mixed> $parameters */
    private static function authorizationResponseState(array $parameters): ?string
    {
        if (!array_key_exists('response', $parameters)) {
            return is_string($parameters['state'] ?? null) ? $parameters['state'] : null;
        }
        if (!is_string($parameters['response'])) {
            throw new ProtocolException('The JARM authorization response is not a JWT');
        }
        [, $claims] = JwtVerifier::decode($parameters['response']);
        return is_string($claims['state'] ?? null) ? $claims['state'] : null;
    }

    /**
     * Verify the frozen response mode before any authorization result is used.
     *
     * @param array<string,mixed> $transaction
     * @param array<string,mixed> $parameters
     * @return array<string,mixed>
     */
    private function validatedAuthorizationResponse(array $transaction, array $parameters): array
    {
        $responseMode = $transaction['response_mode'] ?? 'query';
        if (!is_string($responseMode) || !in_array($responseMode, OpenIDConnect::RESPONSE_MODES, true)) {
            throw new ProtocolException('The login transaction carries an invalid authorization response mode');
        }
        if ($this->request->isPost() !== self::isFormPostMode($responseMode)) {
            throw new ProtocolException('The authorization response used a different transport than requested');
        }

        if (!self::isJarmMode($responseMode)) {
            if (array_key_exists('response', $parameters)) {
                throw new ProtocolException('The provider returned an unexpected JARM authorization response');
            }
            $expectedState = $transaction['state'] ?? $parameters['state'] ?? null;
            if (!is_string($expectedState) || !is_string($parameters['state'] ?? null)
                || !hash_equals($expectedState, $parameters['state'])) {
                throw new ProtocolException('The authorization response state does not match the login transaction');
            }
            return $parameters;
        }

        if (count($parameters) !== 1 || !is_string($parameters['response'] ?? null)) {
            throw new ProtocolException('The provider did not return the requested JARM authorization response');
        }
        $claims = $this->verifier->verifyAuthorizationResponse(
            $parameters['response'],
            $this->metadata,
            $this->settings->clientId(),
            fn(array $candidate): bool => is_string($candidate['iss'] ?? null)
                && $this->responseIssuerMatches($candidate['iss'])
        );
        $expectedState = $transaction['state'] ?? null;
        if (!is_string($expectedState) || !is_string($claims['state'] ?? null)
            || !hash_equals($expectedState, $claims['state'])) {
            throw new ProtocolException('The signed authorization response state does not match the login transaction');
        }

        return array_intersect_key($claims, array_flip([
            'state', 'code', 'iss', 'error', 'error_description', 'error_uri', 'session_state',
            'access_token', 'id_token', 'token_type', 'expires_in',
        ]));
    }

    private static function isJarmMode(string $responseMode): bool
    {
        return str_ends_with($responseMode, '.jwt');
    }

    private static function isFormPostMode(string $responseMode): bool
    {
        return in_array($responseMode, ['form_post', 'form_post.jwt'], true);
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
