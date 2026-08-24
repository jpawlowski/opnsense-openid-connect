<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/** JWS verification and the OIDC ID Token claim checks that use it. */
class JwtVerifier
{
    public const ALGORITHMS = [
        'RS256', 'RS384', 'RS512',
        'PS256', 'PS384', 'PS512',
        'ES256', 'ES384', 'ES512',
    ];
    public const MAX_JWT_BYTES = 1048576;
    public const MAX_JWKS_BYTES = 1048576;
    public const CLOCK_TOLERANCE = 60;

    private static bool $autoloaderReady = false;

    public function __construct(
        private readonly HttpClient $http,
        private readonly string $cacheNamespace = 'oidc-jwks'
    )
    {
        self::prepareRuntimeCryptography();
    }

    /**
     * @return array{header:array<string,mixed>,claims:array<string,mixed>}
     */
    public function verify(
        string $jwt,
        ProviderMetadata $metadata,
        string $clientId,
        ?string $expectedNonce,
        ?string $accessToken = null,
        ?callable $issuerValidator = null
    ): array {
        [$header, $claims, $signingInput, $signature] = self::decode($jwt);
        $algorithm = $header['alg'] ?? null;
        if (!is_string($algorithm) || !in_array($algorithm, self::ALGORITHMS, true)) {
            throw new ProtocolException('The ID token uses an unsupported signing algorithm');
        }

        $advertised = $metadata->get('id_token_signing_alg_values_supported', []);
        if (is_array($advertised) && $advertised !== [] && !in_array($algorithm, $advertised, true)) {
            throw new ProtocolException('The ID token algorithm was not advertised by the provider');
        }

        $key = $this->matchingKey(
            $metadata->jwksUri(),
            $header,
            $algorithm,
            $signingInput,
            $signature,
            'The ID token signature is invalid'
        );

        if ($issuerValidator !== null) {
            $issuerValidator($claims, $key);
        }
        self::validateClaims(
            $claims,
            $issuerValidator === null ? $metadata->issuer() : null,
            $clientId,
            $expectedNonce,
            $accessToken
        );
        if ($accessToken === null && isset($claims['at_hash'])) {
            throw new ProtocolException('The ID token carries an access-token hash but no access token was issued');
        }
        if ($accessToken !== null && isset($claims['at_hash'])) {
            if (!is_string($claims['at_hash'])) {
                throw new ProtocolException('The ID token carries an invalid access-token hash');
            }
            $digest = hash('sha' . substr($algorithm, 2), $accessToken, true);
            $expected = self::base64UrlEncode(substr($digest, 0, intdiv(strlen($digest), 2)));
            if (!hash_equals($expected, $claims['at_hash'])) {
                throw new ProtocolException('The ID token access-token hash does not match');
            }
        }

        return ['header' => $header, 'claims' => $claims];
    }

    /**
     * Signature-only verification for a JWT UserInfo or logout response. The caller
     * applies the claims appropriate to that response type afterwards.
     *
     * @return array<string,mixed>
     */
    public function verifySignedClaims(
        string $jwt,
        ProviderMetadata $metadata,
        string $advertisedField = 'userinfo_signing_alg_values_supported',
        ?callable $issuerValidator = null
    ): array
    {
        $advertised = $metadata->get($advertisedField, []);
        $verified = $this->verifySignedJwt(
            $jwt,
            $metadata->jwksUri(),
            is_array($advertised) ? $advertised : []
        );
        $claims = $verified['claims'];
        if ($issuerValidator !== null) {
            $issuerValidator($claims, $verified['key']);
        }

        return $claims;
    }

    /**
     * Verify one asymmetrically signed JWT against a fixed, already validated key-set URL.
     * Claim policy belongs to the protocol-specific caller.
     *
     * @param string[] $advertisedAlgorithms
     * @return array{header:array<string,mixed>,claims:array<string,mixed>,key:array<string,mixed>}
     */
    public function verifySignedJwt(string $jwt, string $jwksUri, array $advertisedAlgorithms = []): array
    {
        [$header, $claims, $signingInput, $signature] = self::decode($jwt);
        $algorithm = $header['alg'] ?? null;
        if (!is_string($algorithm) || !in_array($algorithm, self::ALGORITHMS, true)) {
            throw new ProtocolException('The JWT uses an unsupported signing algorithm');
        }
        if ($advertisedAlgorithms !== [] && !in_array($algorithm, $advertisedAlgorithms, true)) {
            throw new ProtocolException('The JWT algorithm was not advertised by the issuer');
        }
        $key = $this->matchingKey(
            $jwksUri,
            $header,
            $algorithm,
            $signingInput,
            $signature,
            'The JWT signature is invalid'
        );
        return ['header' => $header, 'claims' => $claims, 'key' => $key];
    }

    /**
     * Verify a signed JARM response against the issuer and key set frozen into the login.
     * Grant-specific claims are deliberately left to RelyingParty after this succeeds.
     *
     * @param null|callable(array<string,mixed>):bool $issuerValidator
     * @return array<string,mixed>
     */
    public function verifyAuthorizationResponse(
        string $jwt,
        ProviderMetadata $metadata,
        string $clientId,
        ?callable $issuerValidator = null,
        ?int $now = null
    ): array {
        if (substr_count($jwt, '.') === 4) {
            throw new ProtocolException('Encrypted JARM authorization responses are not supported');
        }
        [$header, $claims, $signingInput, $signature] = self::decode($jwt);
        if (count($claims) > 64) {
            throw new ProtocolException('The JARM authorization response carries too many claims');
        }
        $algorithm = $header['alg'] ?? null;
        if (!is_string($algorithm) || !in_array($algorithm, self::ALGORITHMS, true)) {
            throw new ProtocolException('The JARM authorization response uses an unsupported signing algorithm');
        }
        if (!in_array($algorithm, $metadata->authorizationResponseSigningAlgorithms(), true)) {
            throw new ProtocolException('The JARM signing algorithm was not advertised by the provider');
        }

        $issuer = $claims['iss'] ?? null;
        $issuerAccepted = is_string($issuer) && ($issuerValidator === null
            ? hash_equals($metadata->issuer(), $issuer) : $issuerValidator($claims));
        if (!$issuerAccepted) {
            throw new ProtocolException('The JARM authorization response came from a different issuer');
        }
        $audiences = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? null);
        if (!is_array($audiences) || $audiences === [] || !array_is_list($audiences)
            || array_filter($audiences, 'is_string') !== $audiences
            || in_array('', $audiences, true) || !in_array($clientId, $audiences, true)) {
            throw new ProtocolException('The JARM authorization response was not issued to this client');
        }

        $now ??= time();
        if (!is_int($claims['exp'] ?? null) || $claims['exp'] < 0
            || $claims['exp'] < $now - self::CLOCK_TOLERANCE) {
            throw new ProtocolException('The JARM authorization response is expired or has no usable expiry');
        }
        if (isset($claims['iat']) && (!is_int($claims['iat']) || $claims['iat'] < 0
            || $claims['iat'] > $now + self::CLOCK_TOLERANCE || $claims['iat'] > $claims['exp'])) {
            throw new ProtocolException('The JARM authorization response has no usable issue time');
        }
        if (isset($claims['nbf']) && (!is_int($claims['nbf']) || $claims['nbf'] < 0
            || $claims['nbf'] > $now + self::CLOCK_TOLERANCE || $claims['nbf'] > $claims['exp'])) {
            throw new ProtocolException('The JARM authorization response is not valid yet');
        }

        $this->matchingKey(
            $metadata->jwksUri(),
            $header,
            $algorithm,
            $signingInput,
            $signature,
            'The JARM authorization response signature is invalid'
        );
        return $claims;
    }

    /** @param array<string,mixed> $header @return array<string,mixed> */
    private function matchingKey(
        string $jwksUri,
        array $header,
        string $algorithm,
        string $signingInput,
        string $signature,
        string $signatureFailure
    ): array {
        $firstFailure = null;
        try {
            $key = self::selectKey($this->keys($jwksUri), $header, $algorithm);
            if ($this->verifySignature($algorithm, $key, $signingInput, $signature)) {
                return $key;
            }
            $firstFailure = new ProtocolException($signatureFailure);
        } catch (ProtocolException $e) {
            $firstFailure = $e;
        }
        if (!$this->http->claimCacheRefresh($this->cacheNamespace, $jwksUri)) {
            throw $firstFailure;
        }
        $key = self::selectKey($this->keys($jwksUri, true), $header, $algorithm);
        if (!$this->verifySignature($algorithm, $key, $signingInput, $signature)) {
            throw new ProtocolException($signatureFailure);
        }
        return $key;
    }

    /** @return array<int,mixed> */
    private function keys(string $jwksUri, bool $force = false): array
    {
        $jwks = $this->http->getCached(
            $jwksUri,
            self::MAX_JWKS_BYTES,
            $this->cacheNamespace,
            3600,
            $force,
            !$force,
            fn(HttpResponse $candidate): array => $this->keysFromResponse($candidate)
        );
        return $this->keysFromResponse($jwks);
    }

    /** @return array<int,mixed> */
    private function keysFromResponse(HttpResponse $jwks): array
    {
        if ($jwks->status !== 200) {
            throw new ProtocolException(sprintf('The provider key set returned HTTP %d', $jwks->status));
        }
        if (!in_array($jwks->contentType, ['application/json', 'application/jwk-set+json'], true)) {
            throw new ProtocolException('The provider key set did not return JSON');
        }
        $keys = $jwks->jsonObject()['keys'] ?? null;
        if (!is_array($keys)) {
            throw new ProtocolException('The provider key set contains no keys');
        }
        if ($keys === [] || count($keys) > 128 || array_filter($keys, 'is_array') !== $keys) {
            throw new ProtocolException('The provider key set contains an invalid key list');
        }
        return $keys;
    }

    /** Force a live key-set fetch for the authenticated setup test, without needing a token. */
    public function probeKeySet(string $jwksUri): int
    {
        $keys = $this->keys($jwksUri, true);
        if ($keys === [] || count($keys) > 128) {
            throw new ProtocolException('The provider key set contains no usable bounded key list');
        }
        $usable = array_filter($keys, static function ($key): bool {
            if (!is_array($key) || !in_array($key['kty'] ?? null, ['RSA', 'EC'], true)) {
                return false;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                return false;
            }
            return !isset($key['alg']) || in_array($key['alg'], self::ALGORITHMS, true);
        });
        if ($usable === []) {
            throw new ProtocolException('The provider key set contains no supported signing key');
        }
        return count($usable);
    }

    /** @return array<string,mixed> verified OpenID Connect Back-Channel Logout claims */
    public function verifyLogoutToken(
        string $jwt,
        ProviderMetadata $metadata,
        string $clientId,
        ?int $now = null,
        ?callable $issuerValidator = null
    ): array {
        $claims = $this->verifySignedClaims(
            $jwt,
            $metadata,
            'id_token_signing_alg_values_supported',
            $issuerValidator
        );
        $now ??= time();
        if ($issuerValidator === null
            && (!is_string($claims['iss'] ?? null) || !hash_equals($metadata->issuer(), $claims['iss']))) {
            throw new ProtocolException('The logout token issuer does not exactly match discovery');
        }
        $audiences = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? null);
        if (!is_array($audiences) || !array_is_list($audiences)
            || array_filter($audiences, 'is_string') !== $audiences
            || !in_array($clientId, $audiences, true)) {
            throw new ProtocolException('The logout token was not issued to this client');
        }
        if (!is_int($claims['iat'] ?? null) || $claims['iat'] < $now - 300
            || $claims['iat'] > $now + self::CLOCK_TOLERANCE) {
            throw new ProtocolException('The logout token has no recent issue time');
        }
        if (!is_int($claims['exp'] ?? null)) {
            throw new ProtocolException('The logout token has no valid expiry');
        }
        if ($claims['exp'] < $now - self::CLOCK_TOLERANCE) {
            throw new ProtocolException('The logout token is expired');
        }
        if (isset($claims['nonce'])) {
            throw new ProtocolException('A logout token may not carry a nonce');
        }
        $event = $claims['events']['http://schemas.openid.net/event/backchannel-logout'] ?? null;
        if (!is_array($claims['events'] ?? null) || !is_array($event) || $event !== []) {
            throw new ProtocolException('The logout token has no valid back-channel logout event');
        }
        $sid = $claims['sid'] ?? null;
        $subject = $claims['sub'] ?? null;
        if (($sid !== null && (!is_string($sid) || $sid === '' || strlen($sid) > 255))
            || ($subject !== null && (!is_string($subject) || $subject === '' || strlen($subject) > 255))
            || ($sid === null && $subject === null)) {
            throw new ProtocolException('The logout token identifies no usable session or subject');
        }
        if (!is_string($claims['jti'] ?? null) || $claims['jti'] === '' || strlen($claims['jti']) > 255
            || preg_match('/[\x00-\x1f\x7f]/', $claims['jti'])) {
            throw new ProtocolException('The logout token has no usable token identifier');
        }

        return $claims;
    }

    /** @return array{array<string,mixed>,array<string,mixed>,string,string} */
    public static function decode(string $jwt): array
    {
        if ($jwt === '' || strlen($jwt) > self::MAX_JWT_BYTES) {
            throw new ProtocolException('The JWT is empty or exceeds its size limit');
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || in_array('', $parts, true)) {
            throw new ProtocolException('The JWT does not have three parts');
        }
        [$encodedHeader, $encodedClaims, $encodedSignature] = $parts;
        $header = self::jsonPart($encodedHeader, 'header');
        $claims = self::jsonPart($encodedClaims, 'claims');
        $signature = self::base64UrlDecode($encodedSignature);
        if ($signature === '') {
            throw new ProtocolException('The JWT carries no signature');
        }
        if (isset($header['jwk']) || isset($header['jku']) || isset($header['x5u'])) {
            throw new ProtocolException('The JWT may not supply its own verification key');
        }
        if (isset($header['crit'])) {
            throw new ProtocolException('The JWT uses unsupported critical header parameters');
        }

        return [$header, $claims, $encodedHeader . '.' . $encodedClaims, $signature];
    }

    /** @param array<string,mixed> $claims */
    public static function validateClaims(
        array $claims,
        ?string $issuer,
        string $clientId,
        ?string $expectedNonce,
        ?string $accessToken = null,
        ?int $now = null
    ): void {
        $now ??= time();
        if ($issuer !== null
            && (!isset($claims['iss']) || !is_string($claims['iss']) || !hash_equals($issuer, $claims['iss']))) {
            throw new ProtocolException('The ID token issuer does not exactly match discovery');
        }
        $subject = $claims['sub'] ?? null;
        if (!is_string($subject) || $subject === '' || strlen($subject) > 255 || preg_match('/[\x00-\x1f\x7f]/', $subject)) {
            throw new ProtocolException('The ID token has no usable subject');
        }

        $audiences = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? null);
        if (!is_array($audiences) || $audiences === [] || !array_is_list($audiences)
            || array_filter($audiences, 'is_string') !== $audiences
            || in_array('', $audiences, true)
            || !in_array($clientId, $audiences, true)) {
            throw new ProtocolException('The ID token was not issued to this client');
        }
        if (count($audiences) > 1
            && (!is_string($claims['azp'] ?? null) || !hash_equals($clientId, $claims['azp']))) {
            throw new ProtocolException('The ID token has multiple audiences but no matching authorized party');
        }
        if (isset($claims['azp'])
            && (!is_string($claims['azp']) || !hash_equals($clientId, $claims['azp']))) {
            throw new ProtocolException('The ID token authorized party is not this client');
        }

        if (!is_int($claims['exp'] ?? null) || $claims['exp'] < 0
            || $claims['exp'] < $now - self::CLOCK_TOLERANCE) {
            throw new ProtocolException('The ID token is expired or has no usable expiry');
        }
        if (!is_int($claims['iat'] ?? null) || $claims['iat'] < 0
            || $claims['iat'] > $now + self::CLOCK_TOLERANCE) {
            throw new ProtocolException('The ID token has no usable issue time');
        }
        if (isset($claims['nbf'])
            && (!is_int($claims['nbf']) || $claims['nbf'] < 0
                || $claims['nbf'] > $now + self::CLOCK_TOLERANCE)) {
            throw new ProtocolException('The ID token is not valid yet');
        }
        if ($expectedNonce !== null
            && (!is_string($claims['nonce'] ?? null) || !hash_equals($expectedNonce, $claims['nonce']))) {
            throw new ProtocolException('The ID token nonce does not match the login transaction');
        }
        if (isset($claims['auth_time'])
            && (!is_int($claims['auth_time']) || $claims['auth_time'] < 0
                || $claims['auth_time'] > $now + self::CLOCK_TOLERANCE)) {
            throw new ProtocolException('The ID token carries an invalid authentication time');
        }
    }

    /** @param array<int,mixed> $keys @param array<string,mixed> $header @return array<string,mixed> */
    private static function selectKey(array $keys, array $header, string $algorithm): array
    {
        $kid = $header['kid'] ?? null;
        if ($kid !== null && (!is_string($kid) || strlen($kid) > 255 || preg_match('/[\x00-\x1f\x7f]/', $kid))) {
            throw new ProtocolException('The JWT key identifier is invalid');
        }
        if (count($keys) > 128) {
            throw new ProtocolException('The provider key set contains too many keys');
        }
        $wantedType = str_starts_with($algorithm, 'ES') ? 'EC' : 'RSA';
        $matches = [];
        foreach ($keys as $key) {
            if (!is_array($key) || ($key['kty'] ?? null) !== $wantedType) {
                continue;
            }
            if ($kid !== null && (!isset($key['kid']) || !is_string($key['kid']) || !hash_equals($kid, $key['kid']))) {
                continue;
            }
            if (isset($key['alg']) && $key['alg'] !== $algorithm) {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            if (isset($key['key_ops']) && (!is_array($key['key_ops']) || !in_array('verify', $key['key_ops'], true))) {
                continue;
            }
            if ($wantedType === 'EC') {
                $curve = ['ES256' => 'P-256', 'ES384' => 'P-384', 'ES512' => 'P-521'][$algorithm];
                if (($key['crv'] ?? null) !== $curve) {
                    continue;
                }
            }
            $matches[] = $key;
        }
        if (count($matches) !== 1) {
            throw new ProtocolException(count($matches) === 0
                ? 'No provider key matches the JWT header'
                : 'Several provider keys match a JWT without a unique key identifier');
        }

        return $matches[0];
    }

    /** @param array<string,mixed> $jwk */
    protected function verifySignature(string $algorithm, array $jwk, string $payload, string $signature): bool
    {
        try {
            $key = PublicKeyLoader::load(json_encode($jwk, JSON_THROW_ON_ERROR));
            $hash = 'sha' . substr($algorithm, 2);
            if (str_starts_with($algorithm, 'R') || str_starts_with($algorithm, 'P')) {
                if (!method_exists($key, 'getLength') || $key->getLength() < 2048) {
                    throw new ProtocolException('The provider RSA signing key is shorter than 2048 bits');
                }
            }
            $key = $key->withHash($hash);
            if (str_starts_with($algorithm, 'PS')) {
                $key = $key->withMGFHash($hash)
                    ->withSaltLength(strlen(hash($hash, '', true)))
                    ->withPadding(RSA::SIGNATURE_PSS);
            } elseif (str_starts_with($algorithm, 'RS')) {
                $key = $key->withPadding(RSA::SIGNATURE_PKCS1);
            } elseif (str_starts_with($algorithm, 'ES')) {
                $key = $key->withSignatureFormat('IEEE');
            }

            return $key->verify($payload, $signature);
        } catch (\Throwable $e) {
            throw new ProtocolException('The provider key could not be used', 0, $e);
        }
    }

    /** @return array<string,mixed> */
    private static function jsonPart(string $encoded, string $part): array
    {
        try {
            $value = json_decode(self::base64UrlDecode($encoded), true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ProtocolException(sprintf('The JWT %s is invalid JSON', $part), 0, $e);
        }
        if (!is_array($value) || array_is_list($value)) {
            throw new ProtocolException(sprintf('The JWT %s is not an object', $part));
        }

        return $value;
    }

    public static function base64UrlDecode(string $value): string
    {
        if ($value === '' || str_contains($value, '=') || !preg_match('/^[A-Za-z0-9_-]+$/D', $value)) {
            throw new ProtocolException('A JWT part is not canonical base64url');
        }
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if ($decoded === false) {
            throw new ProtocolException('A JWT part is not valid base64url');
        }

        return $decoded;
    }

    public static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /** Register the phpseclib runtime shipped by OPNsense for verification and signing. */
    public static function prepareRuntimeCryptography(): void
    {
        self::prepareAutoloader();
    }

    public static function prepareAutoloader(): void
    {
        if (self::$autoloaderReady) {
            return;
        }
        self::$autoloaderReady = true;
        foreach ([
            'phpseclib3' => '/usr/local/share/phpseclib',
            'ParagonIE\\ConstantTime' => '/usr/local/share/phpseclib/paragonie',
        ] as $namespace => $directory) {
            spl_autoload_register(static function (string $class) use ($namespace, $directory): void {
                $prefix = trim($namespace, '\\') . '\\';
                if (!str_starts_with($class, $prefix)) {
                    return;
                }
                $file = $directory . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
                if (is_file($file)) {
                    require_once $file;
                }
            });
        }
    }
}
