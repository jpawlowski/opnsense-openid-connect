<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** A validated OpenID Provider Configuration response. */
final class ProviderMetadata
{
    public const MAX_BYTES = 262144;
    public const DISCOVERY_SUFFIX = '/.well-known/openid-configuration';

    private const CLIENT_AUTH_METHODS = [
        'client_secret_basic', 'client_secret_post', 'tls_client_auth', 'self_signed_tls_client_auth',
    ];

    private function __construct(private readonly array $values)
    {
    }

    public static function discover(
        string $configured,
        HttpClient $http,
        ?string $issuerTemplate = null,
        bool $force = false,
        bool $allowStaleOnFailure = true
    ): self
    {
        [$issuer, $url] = self::locations($configured);
        $response = $http->getCached(
            $url,
            self::MAX_BYTES,
            'oidc-discovery',
            86400,
            $force,
            $allowStaleOnFailure,
            static function (HttpResponse $candidate) use ($issuer, $issuerTemplate): void {
                if ($candidate->contentType !== 'application/json') {
                    throw new ProtocolException('Discovery did not return application/json');
                }
                self::validated($issuer, $candidate->jsonObject(), $issuerTemplate);
            }
        );
        if ($response->status !== 200) {
            throw new ProtocolException(sprintf('Discovery returned HTTP %d', $response->status));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('Discovery did not return application/json');
        }
        $values = $response->jsonObject();
        return self::validated($issuer, $values, $issuerTemplate);
    }

    private static function validated(string $issuer, array $values, ?string $issuerTemplate = null): self
    {
        $expected = $issuerTemplate ?? $issuer;
        if (!isset($values['issuer']) || !is_string($values['issuer']) || !hash_equals($expected, $values['issuer'])) {
            throw new ProtocolException('The discovery issuer does not exactly match the configured issuer');
        }

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (!isset($values[$required]) || !is_string($values[$required])) {
                throw new ProtocolException(sprintf('Discovery is missing %s', $required));
            }
            HttpClient::assertHttpsUrl($values[$required]);
        }
        foreach ([
            'userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint',
            'pushed_authorization_request_endpoint',
        ] as $optional) {
            if (array_key_exists($optional, $values)) {
                if (!is_string($values[$optional])) {
                    throw new ProtocolException(sprintf('Discovery carries an invalid %s', $optional));
                }
                HttpClient::assertHttpsUrl($values[$optional]);
            }
        }
        $responseTypes = $values['response_types_supported'] ?? null;
        if (!is_array($responseTypes) || !array_is_list($responseTypes) || count($responseTypes) > 128
            || array_filter($responseTypes, 'is_string') !== $responseTypes
            || !in_array('code', $responseTypes, true)) {
            throw new ProtocolException('The provider does not advertise the authorization code flow');
        }
        $subjectTypes = $values['subject_types_supported'] ?? null;
        if (!is_array($subjectTypes) || !array_is_list($subjectTypes) || count($subjectTypes) > 16
            || array_filter($subjectTypes, 'is_string') !== $subjectTypes
            || array_intersect($subjectTypes, ['public', 'pairwise']) === []) {
            throw new ProtocolException('The provider advertises no supported subject identifier type');
        }
        foreach ([
            'id_token_signing_alg_values_supported', 'userinfo_signing_alg_values_supported',
            'request_object_signing_alg_values_supported',
            'authorization_signing_alg_values_supported',
            'authorization_encryption_alg_values_supported', 'authorization_encryption_enc_values_supported',
            'token_endpoint_auth_methods_supported', 'response_modes_supported',
            'code_challenge_methods_supported', 'grant_types_supported', 'scopes_supported',
            'revocation_endpoint_auth_methods_supported', 'dpop_signing_alg_values_supported',
        ] as $list) {
            if (array_key_exists($list, $values)
                && (!is_array($values[$list]) || !array_is_list($values[$list]) || $values[$list] === []
                    || count($values[$list]) > 128
                    || array_filter($values[$list], 'is_string') !== $values[$list])) {
                throw new ProtocolException(sprintf('Discovery carries an invalid %s', $list));
            }
        }
        if (array_key_exists('grant_types_supported', $values)
            && !in_array('authorization_code', $values['grant_types_supported'], true)) {
            throw new ProtocolException('The provider does not advertise the authorization code grant');
        }
        if (array_key_exists('scopes_supported', $values)
            && !in_array('openid', $values['scopes_supported'], true)) {
            throw new ProtocolException('The provider does not advertise the openid scope');
        }
        if (array_key_exists('authorization_response_iss_parameter_supported', $values)
            && !is_bool($values['authorization_response_iss_parameter_supported'])) {
            throw new ProtocolException('Discovery carries an invalid authorization response issuer flag');
        }
        if (array_key_exists('require_pushed_authorization_requests', $values)
            && !is_bool($values['require_pushed_authorization_requests'])) {
            throw new ProtocolException('Discovery carries an invalid pushed authorization request requirement');
        }
        if (array_key_exists('require_signed_request_object', $values)
            && !is_bool($values['require_signed_request_object'])) {
            throw new ProtocolException('Discovery carries an invalid signed Request Object requirement');
        }
        if (($values['require_pushed_authorization_requests'] ?? false) === true
            && !isset($values['pushed_authorization_request_endpoint'])) {
            throw new ProtocolException('Discovery requires pushed authorization requests but offers no endpoint');
        }
        if (isset($values['tls_client_certificate_bound_access_tokens'])
            && !is_bool($values['tls_client_certificate_bound_access_tokens'])) {
            throw new ProtocolException('Discovery carries an invalid certificate-bound access token flag');
        }
        if (isset($values['mtls_endpoint_aliases'])) {
            $aliases = $values['mtls_endpoint_aliases'];
            if (!is_array($aliases) || (array_is_list($aliases) && $aliases !== []) || count($aliases) > 32) {
                throw new ProtocolException('Discovery carries invalid mutual-TLS endpoint aliases');
            }
            foreach ([
                'token_endpoint', 'userinfo_endpoint', 'revocation_endpoint',
                'pushed_authorization_request_endpoint',
            ] as $endpoint) {
                if (!array_key_exists($endpoint, $aliases)) {
                    continue;
                }
                if (!is_string($aliases[$endpoint])) {
                    throw new ProtocolException(sprintf(
                        'Discovery carries an invalid mutual-TLS alias for %s',
                        $endpoint
                    ));
                }
                HttpClient::assertHttpsUrl($aliases[$endpoint]);
            }
        }
        $algorithms = $values['id_token_signing_alg_values_supported'] ?? null;
        if (!is_array($algorithms) || array_intersect($algorithms, JwtVerifier::ALGORITHMS) === []) {
            throw new ProtocolException('The provider advertises no supported asymmetric ID token algorithm');
        }
        $requestAlgorithms = $values['request_object_signing_alg_values_supported'] ?? [];
        if (($values['require_signed_request_object'] ?? false) === true
            && array_intersect($requestAlgorithms, RequestObjectSigner::ALGORITHMS) === []) {
            throw new ProtocolException('Discovery requires signed Request Objects but offers no supported algorithm');
        }

        return new self($values);
    }

    /** @return array{string,string} exact issuer and discovery URL */
    public static function locations(string $configured): array
    {
        $configured = self::normalizeIssuerInput($configured);
        HttpClient::assertHttpsUrl($configured);
        $parts = parse_url($configured);
        if (isset($parts['query'])) {
            throw new ProtocolException('An OpenID Connect issuer may not contain a query');
        }

        return [$configured, rtrim($configured, '/') . self::DISCOVERY_SUFFIX];
    }

    /** Accept a commonly pasted Discovery URL while keeping the stored value an issuer. */
    public static function normalizeIssuerInput($value, bool $preserveTrailingSlash = false): string
    {
        $value = trim((string)$value);
        if (!str_ends_with($value, self::DISCOVERY_SUFFIX)) {
            return $value;
        }
        $issuer = substr($value, 0, -strlen(self::DISCOVERY_SUFFIX));
        return $preserveTrailingSlash ? rtrim($issuer, '/') . '/' : $issuer;
    }

    public static function fromArray(array $values): self
    {
        if (!isset($values['issuer']) || !is_string($values['issuer'])) {
            throw new ProtocolException('The stored provider metadata is incomplete');
        }
        return self::validated($values['issuer'], $values);
    }

    public function get(string $name, $default = null)
    {
        return $this->values[$name] ?? $default;
    }

    public function issuer(): string
    {
        return (string)$this->values['issuer'];
    }

    public function authorizationEndpoint(): string
    {
        return (string)$this->values['authorization_endpoint'];
    }

    public function tokenEndpoint(): string
    {
        return (string)$this->values['token_endpoint'];
    }

    public function jwksUri(): string
    {
        return (string)$this->values['jwks_uri'];
    }

    public function userInfoEndpoint(): ?string
    {
        return isset($this->values['userinfo_endpoint']) ? (string)$this->values['userinfo_endpoint'] : null;
    }

    public function endSessionEndpoint(): ?string
    {
        return isset($this->values['end_session_endpoint']) ? (string)$this->values['end_session_endpoint'] : null;
    }

    public function revocationEndpoint(): ?string
    {
        return isset($this->values['revocation_endpoint']) ? (string)$this->values['revocation_endpoint'] : null;
    }

    public function pushedAuthorizationRequestEndpoint(): ?string
    {
        return isset($this->values['pushed_authorization_request_endpoint'])
            ? (string)$this->values['pushed_authorization_request_endpoint'] : null;
    }

    public function requiresPushedAuthorizationRequests(): bool
    {
        return ($this->values['require_pushed_authorization_requests'] ?? false) === true;
    }

    public function supportsCertificateBoundAccessTokens(): bool
    {
        return ($this->values['tls_client_certificate_bound_access_tokens'] ?? false) === true;
    }

    /** An mTLS client must prefer the matching alias while retaining the conventional fallback. */
    public function endpoint(string $name, bool $mutualTls): ?string
    {
        $known = [
            'token_endpoint', 'userinfo_endpoint', 'revocation_endpoint',
            'pushed_authorization_request_endpoint',
        ];
        if (!in_array($name, $known, true)) {
            throw new \InvalidArgumentException('Unknown provider endpoint');
        }
        if ($mutualTls) {
            $aliases = $this->values['mtls_endpoint_aliases'] ?? [];
            if (is_array($aliases) && isset($aliases[$name]) && is_string($aliases[$name])) {
                return $aliases[$name];
            }
        }
        return isset($this->values[$name]) && is_string($this->values[$name])
            ? $this->values[$name] : null;
    }

    public function requiresSignedRequestObject(): bool
    {
        return ($this->values['require_signed_request_object'] ?? false) === true;
    }

    public function authorizationResponseIssuerSupported(): bool
    {
        return ($this->values['authorization_response_iss_parameter_supported'] ?? false) === true;
    }

    /** Refuse a browser redirect before relying on an absent or contradictory capability. */
    public function assertAuthorizationCapabilities(string $responseMode): void
    {
        $pkceMethods = $this->values['code_challenge_methods_supported'] ?? [];
        if (!in_array('S256', $pkceMethods, true)) {
            throw new ProtocolException('The provider does not advertise PKCE S256 support');
        }

        /* RFC 8414 defaults an omitted response-mode list to query and fragment only. */
        $responseModes = $this->values['response_modes_supported'] ?? ['query', 'fragment'];
        if (!in_array($responseMode, $responseModes, true)) {
            throw new ProtocolException('The selected authorization response mode is not advertised');
        }
    }

    public function tokenEndpointAuthMethod(?string $configured = null): string
    {
        return $this->clientAuthMethod('token_endpoint_auth_methods_supported', $configured);
    }

    public function revocationEndpointAuthMethod(): string
    {
        return $this->clientAuthMethod('revocation_endpoint_auth_methods_supported');
    }

    private function clientAuthMethod(string $metadataName, ?string $configured = null): string
    {
        /* RFC 8414 defines client_secret_basic as the omission default for both endpoints. */
        $advertised = $this->values[$metadataName] ?? ['client_secret_basic'];
        $endpoint = $metadataName === 'token_endpoint_auth_methods_supported' ? 'token' : 'revocation';
        if ($configured !== null) {
            if (!in_array($configured, self::CLIENT_AUTH_METHODS, true)
                || !in_array($configured, $advertised, true)) {
                throw new ProtocolException(sprintf(
                    'The selected client authentication method is not advertised for the %s endpoint',
                    $endpoint
                ));
            }
            return $configured;
        }
        foreach (self::CLIENT_AUTH_METHODS as $method) {
            if (in_array($method, $advertised, true)) {
                return $method;
            }
        }

        throw new ProtocolException(sprintf(
            'The provider offers no supported client authentication method for the %s endpoint',
            $endpoint
        ));
    }

    /** @return string[] */
    public function dpopSigningAlgorithms(): array
    {
        $algorithms = $this->values['dpop_signing_alg_values_supported'] ?? [];
        return is_array($algorithms) ? $algorithms : [];
    }

    public function supportsDpop(): bool
    {
        return in_array('ES256', $this->dpopSigningAlgorithms(), true);
    }

    /** @return string[] advertised JARM algorithms, or the specification's RS256 default */
    public function authorizationResponseSigningAlgorithms(): array
    {
        return array_key_exists('authorization_signing_alg_values_supported', $this->values)
            ? $this->values['authorization_signing_alg_values_supported'] : ['RS256'];
    }

    public function toArray(): array
    {
        return $this->values;
    }
}
