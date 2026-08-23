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

    private function __construct(private readonly array $values)
    {
    }

    public static function discover(string $configured, HttpClient $http, ?string $issuerTemplate = null): self
    {
        [$issuer, $url] = self::locations($configured);
        $response = $http->get($url, self::MAX_BYTES);
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
        foreach (['userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint'] as $optional) {
            if (isset($values[$optional])) {
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
            'token_endpoint_auth_methods_supported', 'response_modes_supported',
            'code_challenge_methods_supported', 'grant_types_supported', 'scopes_supported',
        ] as $list) {
            if (isset($values[$list])
                && (!is_array($values[$list]) || !array_is_list($values[$list]) || count($values[$list]) > 128
                    || array_filter($values[$list], 'is_string') !== $values[$list])) {
                throw new ProtocolException(sprintf('Discovery carries an invalid %s', $list));
            }
        }
        if (isset($values['grant_types_supported'])
            && !in_array('authorization_code', $values['grant_types_supported'], true)) {
            throw new ProtocolException('The provider does not advertise the authorization code grant');
        }
        if (isset($values['scopes_supported']) && !in_array('openid', $values['scopes_supported'], true)) {
            throw new ProtocolException('The provider does not advertise the openid scope');
        }
        if (isset($values['authorization_response_iss_parameter_supported'])
            && !is_bool($values['authorization_response_iss_parameter_supported'])) {
            throw new ProtocolException('Discovery carries an invalid authorization response issuer flag');
        }
        $algorithms = $values['id_token_signing_alg_values_supported'] ?? null;
        if (!is_array($algorithms) || array_intersect($algorithms, JwtVerifier::ALGORITHMS) === []) {
            throw new ProtocolException('The provider advertises no supported asymmetric ID token algorithm');
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

    public function authorizationResponseIssuerSupported(): bool
    {
        return ($this->values['authorization_response_iss_parameter_supported'] ?? false) === true;
    }

    public function toArray(): array
    {
        return $this->values;
    }
}
