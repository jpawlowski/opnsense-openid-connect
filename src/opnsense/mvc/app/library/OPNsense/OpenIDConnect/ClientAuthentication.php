<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** Frozen OAuth client authentication and certificate-bound-token policy for one login. */
final class ClientAuthentication
{
    private const TLS_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth'];

    private function __construct(
        private readonly string $method,
        private readonly ?ClientCertificate $certificate,
        private readonly bool $certificateBoundAccessTokens,
        private readonly ClientAuthenticator $authenticator
    ) {
    }

    public static function negotiate(
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        ?array $frozen = null,
        ?ClientAuthenticator $authenticator = null
    ): self {
        return self::fromState($settings, $metadata, $frozen, false, $authenticator);
    }

    /** @param array<string,mixed> $frozen trusted snapshot retained with an established session */
    public static function restore(
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        array $frozen,
        ?ClientAuthenticator $authenticator = null
    ): self
    {
        return self::fromState($settings, $metadata, $frozen, true, $authenticator);
    }

    /** @param array<string,mixed>|null $frozen */
    private static function fromState(
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        ?array $frozen,
        bool $restorePolicy,
        ?ClientAuthenticator $authenticator
    ): self {
        $frozenMethod = null;
        if ($frozen !== null) {
            if (!is_string($frozen['method'] ?? null)
                || !is_bool($frozen['certificate_bound_access_tokens'] ?? null)
                || !is_string($frozen['certificate_ref'] ?? null)
                || !is_string($frozen['certificate_thumbprint'] ?? null)) {
                throw new ProtocolException('The pending login carries invalid client authentication state');
            }
            /*
             * Discovery preferences may change during a login or a long-lived session.  The
             * previously selected method remains the only one known to match the issued grant,
             * so verify its continued support instead of silently negotiating a new preference.
             */
            $frozenMethod = $metadata->tokenEndpointAuthMethod($frozen['method']);
        }
        $method = $frozenMethod ?? self::selectedMethod($settings, $metadata, $authenticator);
        $bound = $restorePolicy && $frozen !== null
            ? $frozen['certificate_bound_access_tokens'] : $settings->certificateBoundAccessTokens();
        if (!$restorePolicy && $bound && !$metadata->supportsCertificateBoundAccessTokens()) {
            throw new ProtocolException('The provider does not advertise certificate-bound access tokens');
        }

        $reference = $settings->clientCertificateRef();
        $expectedThumbprint = null;
        if ($frozen !== null) {
            if (!$restorePolicy && $bound !== $frozen['certificate_bound_access_tokens']) {
                throw new ProtocolException('Client authentication changed while the login was pending');
            }
            $reference = $frozen['certificate_ref'];
            $expectedThumbprint = $frozen['certificate_thumbprint'];
            if ($reference !== '' && !$settings->acceptsClientCertificateRef($reference)) {
                throw new ProtocolException('The login client certificate is no longer active or retiring');
            }
        }

        $needsCertificate = in_array($method, self::TLS_METHODS, true) || $bound;
        if ($needsCertificate && $reference === '') {
            throw new ProtocolException('Mutual TLS requires an OPNsense client certificate');
        }
        $certificate = $needsCertificate ? ClientCertificate::load($reference) : null;
        if ($needsCertificate && $certificate === null) {
            throw new ProtocolException('Mutual TLS requires an OPNsense client certificate');
        }
        if ($expectedThumbprint !== null
            && !hash_equals($expectedThumbprint, $certificate?->thumbprint() ?? '')) {
            throw new ProtocolException('The login client certificate changed while the login was pending');
        }

        return new self(
            $method,
            $needsCertificate ? $certificate : null,
            $bound,
            $authenticator ?? new ClientAuthenticator($settings)
        );
    }

    private static function selectedMethod(
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        ?ClientAuthenticator $authenticator
    ): string
    {
        return ($authenticator ?? new ClientAuthenticator($settings))->selectMethod(
            $metadata,
            ClientAuthenticator::TOKEN
        );
    }

    /** @param array<string,string> $fields @param string[] $headers */
    public function authenticate(
        OpenIDConnect $settings,
        array &$fields,
        array &$headers,
        ?string $method = null
    ): void
    {
        $method ??= $this->method;
        if ($method === 'client_secret_basic') {
            $credentials = urlencode($settings->clientId()) . ':' . urlencode($settings->clientSecret());
            $headers[] = 'Authorization: Basic ' . base64_encode($credentials);
            return;
        }
        if ($method === 'client_secret_post') {
            $fields['client_id'] = $settings->clientId();
            $fields['client_secret'] = $settings->clientSecret();
            return;
        }
        if (in_array($method, self::TLS_METHODS, true) && $this->certificate !== null) {
            $fields['client_id'] = $settings->clientId();
            return;
        }
        throw new ProtocolException('No supported token endpoint authentication method is available');
    }

    public function revocationMethod(ProviderMetadata $metadata): string
    {
        $advertised = $metadata->get(
            'revocation_endpoint_auth_methods_supported',
            ['client_secret_basic']
        );
        $candidates = in_array($this->method, self::TLS_METHODS, true)
            ? [$this->method, ...array_values(array_diff(self::TLS_METHODS, [$this->method]))]
            : [
                $this->method,
                ...array_values(array_diff(
                    ['private_key_jwt', 'client_secret_basic', 'client_secret_post'],
                    [$this->method]
                )),
                ...($this->certificate === null ? [] : self::TLS_METHODS),
            ];
        foreach ($candidates as $candidate) {
            if (!is_array($advertised) || !in_array($candidate, $advertised, true)) {
                continue;
            }
            try {
                return $this->authenticator->selectMethod(
                    $metadata,
                    ClientAuthenticator::REVOCATION,
                    $candidate
                );
            } catch (ProtocolException $e) {
                continue;
            }
        }
        throw new ProtocolException('The provider offers no usable revocation endpoint authentication method');
    }

    public function method(): string
    {
        return $this->method;
    }

    public function endpoint(ProviderMetadata $metadata, string $name): ?string
    {
        return $metadata->endpoint($name, $this->usesMutualTls());
    }

    public function certificate(): ?ClientCertificate
    {
        return $this->certificate;
    }

    public function assertAccessTokenBinding(string $accessToken): void
    {
        if (!$this->certificateBoundAccessTokens || substr_count($accessToken, '.') !== 2) {
            return;
        }
        $parts = explode('.', $accessToken);
        $encoded = strtr($parts[1], '-_', '+/');
        $encoded .= str_repeat('=', (4 - strlen($encoded) % 4) % 4);
        $payload = base64_decode($encoded, true);
        if (!is_string($payload)) {
            return;
        }
        try {
            $claims = json_decode($payload, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return;
        }
        if (!is_array($claims) || !array_key_exists('cnf', $claims)) {
            return;
        }
        $reported = is_array($claims['cnf']) ? ($claims['cnf']['x5t#S256'] ?? null) : null;
        if (!is_string($reported) || $this->certificate === null
            || !hash_equals($this->certificate->thumbprint(), $reported)) {
            throw new ProtocolException('The access token is bound to a different client certificate');
        }
    }

    /**
     * @return array{
     *     method:string,
     *     certificate_bound_access_tokens:bool,
     *     certificate_ref:string,
     *     certificate_thumbprint:string
     * }
     */
    public function snapshot(): array
    {
        return [
            'method' => $this->method,
            'certificate_bound_access_tokens' => $this->certificateBoundAccessTokens,
            'certificate_ref' => $this->certificate?->reference() ?? '',
            'certificate_thumbprint' => $this->certificate?->thumbprint() ?? '',
        ];
    }

    private function usesMutualTls(): bool
    {
        return $this->certificate !== null;
    }
}
