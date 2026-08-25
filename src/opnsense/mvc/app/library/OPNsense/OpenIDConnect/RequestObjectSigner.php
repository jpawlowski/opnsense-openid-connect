<?php

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\Trust\Store;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/** RFC 9101 signing with one administrator-selected OPNsense certificate. */
final class RequestObjectSigner
{
    public const ALGORITHMS = [
        'RS256', 'PS256', 'RS384', 'PS384', 'RS512', 'PS512',
        'ES256', 'ES384', 'ES512',
    ];
    public const LIFETIME = 60;

    private $keyLoader;
    private $signature;
    private $clock;

    /**
     * The optional callables keep host-independent tests away from OPNsense's certificate
     * store and phpseclib runtime. Production always uses the platform implementations.
     */
    public function __construct(?callable $keyLoader = null, ?callable $signature = null, ?callable $clock = null)
    {
        $this->keyLoader = $keyLoader;
        $this->signature = $signature;
        $this->clock = $clock;
    }

    /** @param array<string,string> $parameters */
    public function sign(OpenIDConnect $settings, ProviderMetadata $metadata, array $parameters): string
    {
        if (isset($parameters['request']) || isset($parameters['request_uri'])) {
            throw new ProtocolException('A Request Object may not contain request or request_uri');
        }
        $keyReference = $settings->requestObjectSigningKey();
        if ($keyReference === '') {
            throw new ProtocolException('JWT-secured authorization requests need a selected signing key');
        }
        $material = $this->keyMaterial($keyReference);
        $algorithm = $this->selectAlgorithm($metadata, $material);
        $now = $this->clock === null ? time() : (int)($this->clock)();

        $claims = $parameters;
        /* OAuth form values are strings, while RFC 9101 requires numeric parameters to
         * remain JSON numbers inside the Request Object. */
        if (isset($claims['max_age']) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $claims['max_age'])) {
            $claims['max_age'] = (int)$claims['max_age'];
        }
        if (isset($claims['claims'])) {
            if (!is_string($claims['claims'])) {
                throw new ProtocolException('The claims authorization parameter is not a JSON object');
            }
            try {
                $requestedClaims = json_decode($claims['claims'], false, 16, JSON_THROW_ON_ERROR);
            } catch (\JsonException $e) {
                throw new ProtocolException('The claims authorization parameter is not a JSON object', 0, $e);
            }
            if (!is_object($requestedClaims)) {
                throw new ProtocolException('The claims authorization parameter is not a JSON object');
            }
            /* The query parameter is form-encoded JSON, but RFC 9101 carries its value
             * as a native JSON object inside the signed JWT claims set. */
            $claims['claims'] = $requestedClaims;
        }
        $claims['iss'] = $settings->clientId();
        $claims['aud'] = $metadata->issuer();
        $claims['iat'] = $now;
        $claims['exp'] = $now + self::LIFETIME;
        $claims['jti'] = JwtVerifier::base64UrlEncode(random_bytes(24));

        $header = [
            'alg' => $algorithm,
            'kid' => $keyReference,
            'typ' => 'oauth-authz-req+jwt',
        ];
        try {
            $encodedHeader = JwtVerifier::base64UrlEncode((string)json_encode(
                $header,
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            ));
            $encodedClaims = JwtVerifier::base64UrlEncode((string)json_encode(
                $claims,
                JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
            ));
        } catch (\JsonException $e) {
            throw new ProtocolException('The authorization parameters cannot be encoded as a Request Object', 0, $e);
        }
        $signingInput = $encodedHeader . '.' . $encodedClaims;
        $signature = $this->signature === null
            ? $this->signPayload($algorithm, (string)$material['private_key'], $signingInput)
            : ($this->signature)($algorithm, (string)$material['private_key'], $signingInput);
        if (!is_string($signature) || $signature === '') {
            throw new ProtocolException('The Request Object could not be signed');
        }
        $jwt = $signingInput . '.' . JwtVerifier::base64UrlEncode($signature);
        if (strlen($jwt) > JwtVerifier::MAX_JWT_BYTES) {
            throw new ProtocolException('The Request Object exceeds its size limit');
        }
        return $jwt;
    }

    public function selectedAlgorithm(OpenIDConnect $settings, ProviderMetadata $metadata): string
    {
        $reference = $settings->requestObjectSigningKey();
        if ($reference === '') {
            throw new ProtocolException('JWT-secured authorization requests need a selected signing key');
        }
        return $this->selectAlgorithm($metadata, $this->keyMaterial($reference));
    }

    /** @return array{private_key:string,type:string,bits:int,curve:string} */
    private function keyMaterial(string $reference): array
    {
        if ($this->keyLoader !== null) {
            $material = ($this->keyLoader)($reference);
            if (!is_array($material)) {
                throw new ProtocolException('The selected Request Object signing key is unavailable');
            }
            return $material;
        }
        $certificate = Store::getCertificate($reference);
        if (!is_array($certificate) || !is_string($certificate['prv'] ?? null)
            || $certificate['prv'] === '') {
            throw new ProtocolException('The selected Request Object signing key is unavailable');
        }
        $privateKey = openssl_pkey_get_private($certificate['prv']);
        $details = $privateKey === false ? false : openssl_pkey_get_details($privateKey);
        if (!is_array($details)) {
            throw new ProtocolException('The selected Request Object signing key is invalid');
        }
        $type = match ($details['type'] ?? null) {
            OPENSSL_KEYTYPE_RSA => 'RSA',
            OPENSSL_KEYTYPE_EC => 'EC',
            default => '',
        };
        return [
            'private_key' => $certificate['prv'],
            'type' => $type,
            'bits' => (int)($details['bits'] ?? 0),
            'curve' => is_string($details['ec']['curve_name'] ?? null) ? $details['ec']['curve_name'] : '',
        ];
    }

    /** @param array{private_key:string,type:string,bits:int,curve:string} $material */
    private function selectAlgorithm(ProviderMetadata $metadata, array $material): string
    {
        $advertised = $metadata->get('request_object_signing_alg_values_supported', []);
        $advertised = is_array($advertised) ? $advertised : [];
        if ($material['type'] === 'RSA') {
            if ($material['bits'] < 2048) {
                throw new ProtocolException('The Request Object RSA signing key is shorter than 2048 bits');
            }
            foreach (array_slice(self::ALGORITHMS, 0, 6) as $candidate) {
                if (in_array($candidate, $advertised, true)) {
                    return $candidate;
                }
            }
        } elseif ($material['type'] === 'EC') {
            $candidate = match ($material['curve']) {
                'prime256v1', 'secp256r1' => 'ES256',
                'secp384r1' => 'ES384',
                'secp521r1' => 'ES512',
                default => null,
            };
            if ($candidate !== null && in_array($candidate, $advertised, true)) {
                return $candidate;
            }
        }
        throw new ProtocolException('The provider and selected key share no supported Request Object algorithm');
    }

    private function signPayload(string $algorithm, string $privateKey, string $payload): string
    {
        JwtVerifier::prepareRuntime();
        try {
            $key = PublicKeyLoader::loadPrivateKey($privateKey);
        } catch (\Throwable $e) {
            throw new ProtocolException('The selected Request Object signing key cannot be loaded', 0, $e);
        }
        $hash = 'sha' . substr($algorithm, 2);
        if (str_starts_with($algorithm, 'ES') && $key instanceof EC\PrivateKey) {
            return $key->withHash($hash)->withSignatureFormat('IEEE')->sign($payload);
        }
        if (($algorithm[0] ?? '') === 'R' && $key instanceof RSA\PrivateKey) {
            return $key->withHash($hash)->withPadding(RSA::SIGNATURE_PKCS1)->sign($payload);
        }
        if (str_starts_with($algorithm, 'PS') && $key instanceof RSA\PrivateKey) {
            return $key->withHash($hash)->withMGFHash($hash)->withSaltLength(intdiv((int)substr($algorithm, 2), 8))
                ->withPadding(RSA::SIGNATURE_PSS)->sign($payload);
        }
        throw new ProtocolException('The selected Request Object signing key does not match the negotiated algorithm');
    }
}
