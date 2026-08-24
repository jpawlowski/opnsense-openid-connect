<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Trust\Store;

/** One validated client certificate borrowed from OPNsense's existing trust store. */
final class ClientCertificate
{
    private function __construct(
        private readonly string $reference,
        private readonly string $certificateChain,
        private readonly string $privateKey,
        private readonly string $thumbprint
    ) {
    }

    public static function load(string $reference): self
    {
        if ($reference === '' || strlen($reference) > 128 || preg_match('/[\x00-\x20\x7f]/', $reference)) {
            throw new ProtocolException('The selected client certificate reference is invalid');
        }
        $stored = Store::getCertificate($reference);
        if (!is_array($stored) || !is_string($stored['crt'] ?? null) || !is_string($stored['prv'] ?? null)
            || $stored['crt'] === '' || $stored['prv'] === ''
            || strlen($stored['crt']) > 1048576 || strlen($stored['prv']) > 1048576) {
            throw new ProtocolException('The selected OPNsense certificate and private key are not available');
        }

        $certificate = @openssl_x509_read($stored['crt']);
        $privateKey = @openssl_pkey_get_private($stored['prv']);
        if ($certificate === false || $privateKey === false
            || !@openssl_x509_check_private_key($certificate, $privateKey)) {
            throw new ProtocolException('The selected client certificate and private key do not match');
        }
        $details = @openssl_x509_parse($certificate);
        $now = time();
        if (!is_array($details) || !is_int($details['validFrom_time_t'] ?? null)
            || !is_int($details['validTo_time_t'] ?? null)
            || $details['validFrom_time_t'] > $now || $details['validTo_time_t'] < $now) {
            throw new ProtocolException('The selected client certificate is not currently valid');
        }
        $digest = @openssl_x509_fingerprint($certificate, 'sha256', true);
        if (!is_string($digest) || strlen($digest) !== 32) {
            throw new ProtocolException('The selected client certificate cannot be fingerprinted');
        }

        $chain = $stored['crt'];
        if (is_array($stored['ca'] ?? null) && is_string($stored['ca']['crt'] ?? null)) {
            $chain .= $stored['ca']['crt'];
        }
        return new self($reference, $chain, $stored['prv'], JwtVerifier::base64UrlEncode($digest));
    }

    public function reference(): string
    {
        return $this->reference;
    }

    public function thumbprint(): string
    {
        return $this->thumbprint;
    }

    /** @return array<int,string> cURL options which keep the private key in memory. */
    public function curlOptions(): array
    {
        if (!defined('CURLOPT_SSLCERT_BLOB') || !defined('CURLOPT_SSLKEY_BLOB')) {
            throw new ProtocolException('This PHP cURL runtime cannot use in-memory client certificates');
        }
        return [
            CURLOPT_SSLCERTTYPE => 'PEM',
            CURLOPT_SSLKEYTYPE => 'PEM',
            constant('CURLOPT_SSLCERT_BLOB') => $this->certificateChain,
            constant('CURLOPT_SSLKEY_BLOB') => $this->privateKey,
        ];
    }
}
