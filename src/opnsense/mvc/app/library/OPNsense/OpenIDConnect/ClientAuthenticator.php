<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** Negotiated client authentication shared by every direct provider endpoint. */
final class ClientAuthenticator
{
    private const TLS_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth'];
    public const TOKEN = 'token';
    public const REVOCATION = 'revocation';
    public const INTROSPECTION = 'introspection';

    private ClientAssertion $assertion;

    public function __construct(private readonly OpenIDConnect $settings, ?ClientAssertion $assertion = null)
    {
        $this->assertion = $assertion ?? new ClientAssertion($settings);
    }

    /**
     * @param array<string,string> $fields
     * @param string[] $headers
     */
    public function authenticate(
        ProviderMetadata $metadata,
        string $endpoint,
        string $kind,
        array &$fields,
        array &$headers,
        ?string $audience = null,
        ?string $requiredMethod = null
    ): void {
        HttpClient::assertHttpsUrl($endpoint);
        $algorithmsField = $kind . '_endpoint_auth_signing_alg_values_supported';
        $method = $this->selectMethod($metadata, $kind, $requiredMethod);

        if ($method === 'client_secret_basic') {
            $secret = $this->settings->clientSecret();
            if ($secret === '') {
                throw new ProtocolException('Basic client authentication has no client secret');
            }
            $credentials = urlencode($this->settings->clientId()) . ':' . urlencode($secret);
            $headers[] = 'Authorization: Basic ' . base64_encode($credentials);
            return;
        }
        if ($method === 'client_secret_post') {
            $secret = $this->settings->clientSecret();
            if ($secret === '') {
                throw new ProtocolException('POST client authentication has no client secret');
            }
            $fields['client_id'] = $this->settings->clientId();
            $fields['client_secret'] = $secret;
            return;
        }
        if ($method === 'private_key_jwt') {
            $algorithms = $metadata->get($algorithmsField, []);
            $algorithms = $this->settings->clientAssertionAlgorithms(
                $algorithmsField,
                is_array($algorithms) ? $algorithms : []
            );
            $fields['client_id'] = $this->settings->clientId();
            $fields['client_assertion_type'] = ClientAssertion::TYPE;
            $fields['client_assertion'] = $this->assertion->create(
                $audience ?? $endpoint,
                $algorithms
            );
            return;
        }
        if (in_array($method, self::TLS_METHODS, true)) {
            $fields['client_id'] = $this->settings->clientId();
            return;
        }
        throw new ProtocolException('No supported client authentication method is available');
    }

    public function selectMethod(ProviderMetadata $metadata, string $kind, ?string $requiredMethod = null): string
    {
        if (!in_array($kind, [self::TOKEN, self::REVOCATION, self::INTROSPECTION], true)) {
            throw new \InvalidArgumentException('Unknown provider endpoint authentication kind');
        }
        $methodsField = $kind . '_endpoint_auth_methods_supported';
        $defaultMethods = $kind === self::INTROSPECTION ? [] : ['client_secret_basic'];
        $advertised = $metadata->get($methodsField, $defaultMethods);
        $advertised = is_array($advertised) ? $advertised : [];
        $selected = $requiredMethod ?? ($kind === self::TOKEN ? $this->settings->tokenAuthMethod() : null);
        if ($selected !== null) {
            if (!in_array($selected, OpenIDConnect::TOKEN_AUTH_METHODS, true)
                || !in_array($selected, $advertised, true)) {
                throw new ProtocolException('The selected client authentication method is not advertised for the endpoint');
            }
            $this->assertCredential($selected);
            if ($selected === 'private_key_jwt') {
                $this->assertPrivateKeyUsable($metadata, $kind);
            }
            return $selected;
        }

        if ($this->settings->clientCertificateRef() !== '') {
            foreach (self::TLS_METHODS as $candidate) {
                if (in_array($candidate, $advertised, true)) {
                    return $candidate;
                }
            }
            throw new ProtocolException(sprintf(
                'The provider offers no supported mutual-TLS authentication method for the %s endpoint',
                $kind
            ));
        }

        $privateKeyFailure = null;
        if (in_array('private_key_jwt', $advertised, true) && $this->hasCredential('private_key_jwt')) {
            try {
                $this->assertPrivateKeyUsable($metadata, $kind);
                return 'private_key_jwt';
            } catch (ProtocolException $e) {
                $privateKeyFailure = $e;
            }
        }
        foreach (['client_secret_basic', 'client_secret_post'] as $candidate) {
            if (in_array($candidate, $advertised, true) && $this->settings->clientSecret() !== '') {
                return $candidate;
            }
        }
        if ($privateKeyFailure !== null) {
            throw $privateKeyFailure;
        }
        throw new ProtocolException(sprintf(
            'The provider offers no supported client authentication method for the %s endpoint',
            $kind
        ));
    }

    private function assertPrivateKeyUsable(ProviderMetadata $metadata, string $kind): void
    {
        $algorithmsField = $kind . '_endpoint_auth_signing_alg_values_supported';
        $algorithms = $metadata->get($algorithmsField, []);
        $this->assertion->assertUsable($this->settings->clientAssertionAlgorithms(
            $algorithmsField,
            is_array($algorithms) ? $algorithms : []
        ));
    }

    private function hasCredential(string $method): bool
    {
        if ($method === 'private_key_jwt') {
            return $this->settings->signingCertificate() !== '';
        }
        return in_array($method, self::TLS_METHODS, true)
            ? $this->settings->clientCertificateRef() !== '' : $this->settings->clientSecret() !== '';
    }

    private function assertCredential(string $method): void
    {
        if ($this->hasCredential($method)) {
            return;
        }
        if ($method === 'private_key_jwt') {
            throw new ProtocolException('Private-key client authentication has no signing certificate');
        }
        throw new ProtocolException(in_array($method, self::TLS_METHODS, true)
            ? 'Mutual TLS has no client certificate'
            : 'The selected client authentication method has no client secret');
    }
}
