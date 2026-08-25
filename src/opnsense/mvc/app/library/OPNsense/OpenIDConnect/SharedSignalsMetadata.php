<?php

namespace OPNsense\OpenIDConnect;

/** Validated Shared Signals transmitter configuration metadata. */
final class SharedSignalsMetadata
{
    public const MAX_BYTES = 262144;
    public const PUSH_METHOD = 'urn:ietf:rfc:8935';
    public const POLL_METHOD = 'urn:ietf:rfc:8936';
    public const OAUTH_AUTHORIZATION = 'urn:ietf:rfc:6749';
    public const BASIC_AUTHORIZATION = 'urn:ietf:rfc:7617';

    private function __construct(private readonly array $values)
    {
    }

    public static function discover(
        string $issuer,
        HttpClient $http,
        bool $force = false,
        bool $allowStaleOnFailure = true
    ): self
    {
        $url = self::discoveryUrl($issuer);
        $response = $http->getCached(
            $url,
            self::MAX_BYTES,
            'ssf-discovery',
            86400,
            $force,
            $allowStaleOnFailure,
            static function (HttpResponse $candidate) use ($issuer): void {
                if ($candidate->contentType !== 'application/json') {
                    throw new ProtocolException('Shared Signals discovery did not return application/json');
                }
                self::validated($issuer, $candidate->jsonObject());
            }
        );
        if ($response->status !== 200) {
            throw new ProtocolException(sprintf('Shared Signals discovery returned HTTP %d', $response->status));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('Shared Signals discovery did not return application/json');
        }
        return self::validated($issuer, $response->jsonObject());
    }

    public static function fromArray(string $issuer, array $values): self
    {
        return self::validated($issuer, $values);
    }

    private static function validated(string $issuer, array $values): self
    {
        HttpClient::assertHttpsUrl($issuer);
        $parts = parse_url($issuer);
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new ProtocolException('A Shared Signals issuer may not contain a query or fragment');
        }
        if (!is_string($values['issuer'] ?? null) || !hash_equals($issuer, $values['issuer'])) {
            throw new ProtocolException('The Shared Signals discovery issuer does not exactly match');
        }
        if (!is_string($values['jwks_uri'] ?? null)) {
            throw new ProtocolException('Shared Signals discovery contains no signing key set');
        }
        HttpClient::assertHttpsUrl($values['jwks_uri']);
        foreach (['delivery_methods_supported', 'critical_subject_members'] as $field) {
            if (isset($values[$field]) && (!is_array($values[$field]) || !array_is_list($values[$field])
                || count($values[$field]) > 128 || array_filter($values[$field], 'is_string') !== $values[$field])) {
                throw new ProtocolException(sprintf('Shared Signals discovery carries an invalid %s', $field));
            }
        }
        foreach ([
            'configuration_endpoint', 'status_endpoint', 'add_subject_endpoint',
            'remove_subject_endpoint', 'verification_endpoint',
        ] as $endpoint) {
            if (isset($values[$endpoint])) {
                if (!is_string($values[$endpoint])) {
                    throw new ProtocolException(sprintf('Shared Signals discovery carries an invalid %s', $endpoint));
                }
                HttpClient::assertHttpsUrl($values[$endpoint]);
            }
        }
        if (isset($values['authorization_schemes'])) {
            if (!is_array($values['authorization_schemes']) || !array_is_list($values['authorization_schemes'])
                || count($values['authorization_schemes']) > 16) {
                throw new ProtocolException('Shared Signals discovery carries invalid authorization schemes');
            }
            foreach ($values['authorization_schemes'] as $scheme) {
                if (!is_array($scheme) || array_is_list($scheme)
                    || !is_string($scheme['spec_urn'] ?? null) || $scheme['spec_urn'] === ''
                    || strlen($scheme['spec_urn']) > 255 || preg_match('/[\x00-\x20\x7f]/', $scheme['spec_urn'])) {
                    throw new ProtocolException('Shared Signals discovery carries an invalid authorization scheme');
                }
            }
        }
        if (isset($values['default_subjects']) && !in_array($values['default_subjects'], ['ALL', 'NONE'], true)) {
            throw new ProtocolException('Shared Signals discovery carries invalid default subjects');
        }
        if (isset($values['spec_version'])
            && (!is_string($values['spec_version']) || strlen($values['spec_version']) > 32
                || preg_match('/[^A-Za-z0-9_.-]/', $values['spec_version']))) {
            throw new ProtocolException('Shared Signals discovery carries an invalid specification version');
        }

        return new self($values);
    }

    public static function discoveryUrl(string $issuer): string
    {
        HttpClient::assertHttpsUrl($issuer);
        $parts = parse_url($issuer);
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new ProtocolException('A Shared Signals issuer may not contain a query or fragment');
        }
        $authority = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $authority .= ':' . $parts['port'];
        }
        $path = rtrim((string)($parts['path'] ?? ''), '/');
        return $authority . '/.well-known/ssf-configuration' . $path;
    }

    public function issuer(): string
    {
        return (string)$this->values['issuer'];
    }

    public function jwksUri(): string
    {
        return (string)$this->values['jwks_uri'];
    }

    /** @return string[] */
    public function criticalSubjectMembers(): array
    {
        return $this->values['critical_subject_members'] ?? [];
    }

    /** @return string[] */
    public function deliveryMethods(): array
    {
        return $this->values['delivery_methods_supported'] ?? [];
    }

    public function supportsDelivery(string $method): bool
    {
        $methods = $this->deliveryMethods();
        return $methods === []
            ? hash_equals(self::PUSH_METHOD, $method)
            : in_array($method, $methods, true);
    }

    public function configurationEndpoint(): ?string
    {
        return $this->endpoint('configuration_endpoint');
    }

    public function statusEndpoint(): ?string
    {
        return $this->endpoint('status_endpoint');
    }

    /** @return string[] */
    public function authorizationSchemes(): array
    {
        return array_values(array_map(
            static fn(array $scheme): string => (string)$scheme['spec_urn'],
            $this->values['authorization_schemes'] ?? []
        ));
    }

    public function supportsAuthorization(string $specification): bool
    {
        $schemes = $this->authorizationSchemes();
        return $schemes === [] || in_array($specification, $schemes, true);
    }

    public function defaultSubjects(): ?string
    {
        return isset($this->values['default_subjects']) ? (string)$this->values['default_subjects'] : null;
    }

    private function endpoint(string $name): ?string
    {
        return isset($this->values[$name]) ? (string)$this->values[$name] : null;
    }
}
