<?php

namespace OPNsense\OpenIDConnect;

use phpseclib3\Crypt\PublicKeyLoader;

/** One RFC 9449 proof key and the fresh, request-bound proofs it signs. */
final class DpopProof
{
    /** @param array<string,string> $publicJwk */
    private function __construct(
        private readonly string $keyId,
        private readonly array $publicJwk,
        private readonly mixed $signer
    ) {
    }

    /** @param array<string,mixed> $record */
    public static function fromStored(array $record): self
    {
        $keyId = $record['id'] ?? null;
        $privateKey = $record['private_key'] ?? null;
        $publicJwk = $record['public_jwk'] ?? null;
        if (!is_string($keyId) || !is_string($privateKey) || !is_array($publicJwk)
            || !hash_equals($keyId, self::thumbprint($publicJwk))) {
            throw new ProtocolException('The stored DPoP proof key is invalid');
        }
        JwtVerifier::prepareRuntime();
        try {
            $key = PublicKeyLoader::load($privateKey)->withHash('sha256')->withSignatureFormat('IEEE');
        } catch (\Throwable $e) {
            throw new ProtocolException('The stored DPoP proof key could not be loaded', 0, $e);
        }
        return new self($keyId, self::publicJwk($publicJwk), static fn(string $input): string => $key->sign($input));
    }

    /** @param array<string,string> $publicJwk */
    public static function forTesting(array $publicJwk, callable $signer): self
    {
        return new self(self::thumbprint($publicJwk), self::publicJwk($publicJwk), $signer);
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    /** @return array<string,string> */
    public function publicKey(): array
    {
        return $this->publicJwk;
    }

    public function proof(
        string $method,
        string $url,
        ?string $accessToken = null,
        ?string $nonce = null,
        ?int $now = null
    ): string {
        $method = strtoupper($method);
        if ($method === '' || !preg_match('/^[!#$%&\'*+.^_`|~0-9A-Z-]+$/D', $method)) {
            throw new ProtocolException('A DPoP proof requires a usable HTTP method');
        }
        $claims = [
            'jti' => JwtVerifier::base64UrlEncode(random_bytes(18)),
            'htm' => $method,
            'htu' => self::targetUri($url),
            'iat' => $now ?? time(),
        ];
        if ($accessToken !== null) {
            $claims['ath'] = JwtVerifier::base64UrlEncode(hash('sha256', $accessToken, true));
        }
        if ($nonce !== null) {
            self::assertNonce($nonce);
            $claims['nonce'] = $nonce;
        }
        $header = ['typ' => 'dpop+jwt', 'alg' => 'ES256', 'jwk' => $this->publicJwk];
        $input = self::jsonPart($header) . '.' . self::jsonPart($claims);
        try {
            $signature = ($this->signer)($input);
        } catch (\Throwable $e) {
            throw new ProtocolException('The DPoP proof could not be signed', 0, $e);
        }
        if (!is_string($signature) || strlen($signature) !== 64) {
            throw new ProtocolException('The DPoP signer returned an invalid ES256 signature');
        }
        return $input . '.' . JwtVerifier::base64UrlEncode($signature);
    }

    public static function targetUri(string $url): string
    {
        HttpClient::assertHttpsUrl($url);
        $parts = parse_url($url);
        $path = (string)($parts['path'] ?? '/');
        return 'https://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') . $path;
    }

    /** @param array<string,mixed> $jwk */
    public static function thumbprint(array $jwk): string
    {
        $public = self::publicJwk($jwk);
        $canonical = json_encode([
            'crv' => $public['crv'],
            'kty' => $public['kty'],
            'x' => $public['x'],
            'y' => $public['y'],
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        return JwtVerifier::base64UrlEncode(hash('sha256', $canonical, true));
    }

    public static function assertNonce(string $nonce): void
    {
        if ($nonce === '' || strlen($nonce) > 512 || !preg_match('/^[\x21\x23-\x5b\x5d-\x7e]+$/D', $nonce)) {
            throw new ProtocolException('The provider returned an invalid DPoP nonce');
        }
    }

    /** @param array<string,mixed> $jwk @return array<string,string> */
    private static function publicJwk(array $jwk): array
    {
        $public = [];
        foreach (['kty', 'crv', 'x', 'y'] as $name) {
            if (!is_string($jwk[$name] ?? null) || $jwk[$name] === '') {
                throw new ProtocolException('The DPoP public key is incomplete');
            }
            $public[$name] = $jwk[$name];
        }
        if ($public['kty'] !== 'EC' || $public['crv'] !== 'P-256') {
            throw new ProtocolException('The DPoP public key is not an ES256 key');
        }
        foreach (['x', 'y'] as $coordinate) {
            /* OPNsense's bundled phpseclib emits one optional base64url padding
             * character while newer releases omit it. Proof JWKs and thumbprints
             * always use the canonical unpadded representation. */
            if (!preg_match('/^[A-Za-z0-9_-]{43}=?$/D', $public[$coordinate])) {
                throw new ProtocolException('The DPoP public key is not an ES256 key');
            }
            $public[$coordinate] = rtrim($public[$coordinate], '=');
            $decoded = base64_decode(strtr($public[$coordinate], '-_', '+/') . '=', true);
            if (!is_string($decoded) || strlen($decoded) !== 32) {
                throw new ProtocolException('The DPoP public key is not an ES256 key');
            }
        }
        return $public;
    }

    /** @param array<string,mixed> $value */
    private static function jsonPart(array $value): string
    {
        return JwtVerifier::base64UrlEncode(json_encode(
            $value,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        ));
    }
}
