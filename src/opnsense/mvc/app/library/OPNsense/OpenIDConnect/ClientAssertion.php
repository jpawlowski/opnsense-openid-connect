<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\Trust\Store;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/** One short-lived, single-use RFC 7523 private_key_jwt client assertion. */
class ClientAssertion
{
    public const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    public const LIFETIME = 60;
    public const ALGORITHMS = JwtVerifier::ALGORITHMS;

    public function __construct(private readonly OpenIDConnect $settings)
    {
        JwtVerifier::prepareRuntime();
    }

    /**
     * @param string[] $advertisedAlgorithms
     */
    public function create(string $audience, array $advertisedAlgorithms, ?int $now = null): string
    {
        HttpClient::assertHttpsUrl($audience);
        [$key, $algorithm, $thumbprint] = $this->signingMaterial($advertisedAlgorithms);
        $now ??= time();
        $clientId = $this->settings->clientId();
        $header = JwtVerifier::base64UrlEncode($this->json([
            'alg' => $algorithm,
            'typ' => 'JWT',
            'x5t#S256' => JwtVerifier::base64UrlEncode($thumbprint),
        ]));
        $claims = JwtVerifier::base64UrlEncode($this->json([
            'iss' => $clientId,
            'sub' => $clientId,
            'aud' => $audience,
            'jti' => JwtVerifier::base64UrlEncode(random_bytes(32)),
            'nbf' => $now,
            'iat' => $now,
            'exp' => $now + self::LIFETIME,
        ]));
        $input = $header . '.' . $claims;
        $signature = $this->sign($key, $algorithm, $input);

        return $input . '.' . JwtVerifier::base64UrlEncode($signature);
    }

    /** @param string[] $advertisedAlgorithms */
    public function assertUsable(array $advertisedAlgorithms): void
    {
        $this->signingMaterial($advertisedAlgorithms);
    }

    /**
     * The settings form has no provider metadata yet, but it must reject a key which
     * can never satisfy this client's asymmetric algorithm policy.
     *
     * @param string[] $allowedAlgorithms
     */
    public function assertCertificateUsable(string $reference, array $allowedAlgorithms): void
    {
        $certificate = $this->certificateMaterial($reference);
        $privateKey = openssl_pkey_get_private($certificate['prv']);
        $details = $privateKey === false ? false : openssl_pkey_get_details($privateKey);
        if (!is_array($details)) {
            throw new ProtocolException('The client signing private key could not be loaded');
        }
        if (!openssl_x509_check_private_key($certificate['crt'], $privateKey)) {
            throw new ProtocolException('The client signing certificate does not match its private key');
        }
        $this->selectAlgorithmDetails(
            $details['type'] ?? null,
            (int)($details['bits'] ?? 0),
            is_string($details['ec']['curve_name'] ?? null) ? $details['ec']['curve_name'] : '',
            $allowedAlgorithms
        );
        $this->certificateThumbprint($certificate['crt']);
    }

    /** @param string[] $advertisedAlgorithms @return array{object,string,string} */
    private function signingMaterial(array $advertisedAlgorithms): array
    {
        $reference = $this->settings->signingCertificate();
        if ($reference === '') {
            throw new ProtocolException('Private-key client authentication has no signing certificate');
        }
        $certificate = $this->certificateMaterial($reference);

        $key = $this->loadPrivateKey($certificate['prv']);
        $algorithm = $this->selectAlgorithm($key, $advertisedAlgorithms);
        $thumbprint = $this->certificateThumbprint($certificate['crt']);
        return [$key, $algorithm, $thumbprint];
    }

    /** @return array{crt:string,prv:string} */
    private function certificateMaterial(string $reference): array
    {
        $certificate = $this->certificate($reference);
        if (!is_array($certificate) || !is_string($certificate['crt'] ?? null)
            || !is_string($certificate['prv'] ?? null)
            || $certificate['crt'] === '' || $certificate['prv'] === '') {
            throw new ProtocolException('The client signing certificate or its private key is unavailable');
        }
        return ['crt' => $certificate['crt'], 'prv' => $certificate['prv']];
    }

    /** @return array<string,mixed>|false */
    protected function certificate(string $reference)
    {
        return Store::getCertificate($reference);
    }

    protected function loadPrivateKey(string $privateKey): object
    {
        try {
            return PublicKeyLoader::loadPrivateKey($privateKey);
        } catch (\Throwable $e) {
            throw new ProtocolException('The client signing private key could not be loaded', 0, $e);
        }
    }

    protected function certificateThumbprint(string $certificate): string
    {
        $thumbprint = openssl_x509_fingerprint($certificate, 'sha256', true);
        if (!is_string($thumbprint) || $thumbprint === '') {
            throw new ProtocolException('The client signing certificate could not be read');
        }
        return $thumbprint;
    }

    /** @param string[] $advertisedAlgorithms */
    protected function selectAlgorithm(object $key, array $advertisedAlgorithms): string
    {
        if ($key instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
            return $this->selectAlgorithmDetails(OPENSSL_KEYTYPE_RSA, $key->getLength(), '', $advertisedAlgorithms);
        } elseif ($key instanceof \phpseclib3\Crypt\EC\PrivateKey) {
            return $this->selectAlgorithmDetails(
                OPENSSL_KEYTYPE_EC,
                $key->getLength(),
                $key->getCurve(),
                $advertisedAlgorithms
            );
        }
        throw new ProtocolException('The client signing key type is unsupported');
    }

    /** @param string[] $advertisedAlgorithms */
    private function selectAlgorithmDetails($type, int $bits, string $curve, array $advertisedAlgorithms): string
    {
        $advertised = array_values(array_intersect(self::ALGORITHMS, $advertisedAlgorithms));
        if ($type === OPENSSL_KEYTYPE_RSA) {
            if ($bits < 2048) {
                throw new ProtocolException('The client RSA signing key is shorter than 2048 bits');
            }
            $usable = array_values(array_filter(
                $advertised,
                static fn(string $algorithm): bool => str_starts_with($algorithm, 'RS')
                    || str_starts_with($algorithm, 'PS')
            ));
        } elseif ($type === OPENSSL_KEYTYPE_EC) {
            $needed = [
                'secp256r1' => 'ES256',
                'prime256v1' => 'ES256',
                'secp384r1' => 'ES384',
                'secp521r1' => 'ES512',
            ][$curve] ?? null;
            $usable = $needed !== null && in_array($needed, $advertised, true) ? [$needed] : [];
        } else {
            throw new ProtocolException('The client signing key type is unsupported');
        }
        if ($usable === []) {
            throw new ProtocolException('The provider and client signing key share no supported algorithm');
        }
        return $usable[0];
    }

    protected function sign(object $key, string $algorithm, string $input): string
    {
        try {
            $hash = 'sha' . substr($algorithm, 2);
            $key = $key->withHash($hash);
            if (str_starts_with($algorithm, 'PS')) {
                $key = $key->withMGFHash($hash)
                    ->withSaltLength(strlen(hash($hash, '', true)))
                    ->withPadding(RSA::SIGNATURE_PSS);
            } elseif (str_starts_with($algorithm, 'RS')) {
                $key = $key->withPadding(RSA::SIGNATURE_PKCS1);
            } elseif (str_starts_with($algorithm, 'ES')) {
                $key = $key->withSignatureFormat('IEEE');
            } else {
                throw new ProtocolException('The client assertion signing algorithm is unsupported');
            }
            return $key->sign($input);
        } catch (ProtocolException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new ProtocolException('The client assertion could not be signed', 0, $e);
        }
    }

    /** @param array<string,mixed> $value */
    private function json(array $value): string
    {
        try {
            return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ProtocolException('The client assertion could not be encoded', 0, $e);
        }
    }
}
