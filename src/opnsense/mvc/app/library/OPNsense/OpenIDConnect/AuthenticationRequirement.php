<?php

namespace OPNsense\OpenIDConnect;

/** One exact authentication requirement frozen into an authorization transaction. */
final class AuthenticationRequirement
{
    public const MULTI_FACTOR = 'multi-factor';
    public const PHISHING_RESISTANT = 'phishing-resistant';
    public const TIERS = [self::MULTI_FACTOR, self::PHISHING_RESISTANT];

    public const ESSENTIAL_CLAIM = 'essential_claim';
    public const ACR_VALUES = 'acr_values';
    public const ENTRA_CONTEXT = 'entra_context';
    public const REQUEST_MODES = [self::ESSENTIAL_CLAIM, self::ACR_VALUES];

    private const MAX_CONTEXTS = 8;
    private const MAX_CONTEXT_BYTES = 256;
    private const MAX_METHODS = 16;
    private const MAX_METHOD_BYTES = 64;

    private const KNOWLEDGE_FACTOR = 'knowledge';
    private const POSSESSION_FACTOR = 'possession';
    private const INHERENCE_FACTOR = 'inherence';
    private const DIRECT_MULTI_FACTOR = 'multi-factor';

    /**
     * Every IANA-registered RFC 8176/EAP value is classified here. Null means that the value describes context,
     * channel or presence but does not unambiguously establish an authentication factor.
     *
     * @var array<string,string|null>
     */
    private const STANDARD_METHOD_EVIDENCE = [
        'face' => self::INHERENCE_FACTOR,
        'fpt' => self::INHERENCE_FACTOR,
        'geo' => null,
        'hwk' => self::POSSESSION_FACTOR,
        'iris' => self::INHERENCE_FACTOR,
        'kba' => self::KNOWLEDGE_FACTOR,
        'mca' => null,
        'mfa' => self::DIRECT_MULTI_FACTOR,
        'otp' => self::POSSESSION_FACTOR,
        'pin' => self::KNOWLEDGE_FACTOR,
        'pop' => self::POSSESSION_FACTOR,
        'pwd' => self::KNOWLEDGE_FACTOR,
        'rba' => null,
        'retina' => self::INHERENCE_FACTOR,
        'sc' => self::POSSESSION_FACTOR,
        'sms' => self::POSSESSION_FACTOR,
        'swk' => self::POSSESSION_FACTOR,
        'tel' => self::POSSESSION_FACTOR,
        'user' => null,
        'vbm' => self::INHERENCE_FACTOR,
        'wia' => null,
    ];

    /**
     * Microsoft documents these additional OIDC AMR values. The factor classifications distinguish concrete methods
     * from ambiguous signals; an Entra assurance result still has to carry its separate documented mfa value.
     *
     * @var array<string,string|null>
     */
    private const ENTRA_METHOD_EVIDENCE = [
        'emailotp' => null,
        'fido' => self::POSSESSION_FACTOR,
        'hotp' => self::POSSESSION_FACTOR,
        'ngcmfa' => null,
        'rsa' => null,
        'totp' => self::POSSESSION_FACTOR,
        'x509' => self::POSSESSION_FACTOR,
    ];

    private const EAP_KEY_METHODS = ['pop', 'hwk', 'swk'];
    private const ENTRA_PHISHING_RESISTANT_METHODS = ['fido', 'hwk', 'x509'];

    /**
     * @param string[] $contexts exact acceptable acr values, or one Entra acrs context
     * @param string[] $methods exact accepted amr values from which sufficient tier evidence must be present
     */
    public function __construct(
        private readonly string $tier,
        private readonly string $requestMode,
        private readonly array $contexts,
        private readonly array $methods
    ) {
        if (!in_array($tier, self::TIERS, true)) {
            throw new ProtocolException('The authentication requirement has an unknown tier');
        }
        if (!in_array($requestMode, array_merge(self::REQUEST_MODES, [self::ENTRA_CONTEXT]), true)) {
            throw new ProtocolException('The authentication requirement has an unknown request mode');
        }
        self::assertStringList($contexts, self::MAX_CONTEXTS, self::MAX_CONTEXT_BYTES, 'context');
        self::assertStringList($methods, self::MAX_METHODS, self::MAX_METHOD_BYTES, 'method');
        if ($requestMode === self::ENTRA_CONTEXT
            && (count($contexts) !== 1 || !preg_match('/^c(?:[1-9]|1[0-9]|2[0-5])$/D', $contexts[0]))) {
            throw new ProtocolException('The Microsoft authentication context is not usable');
        }
    }

    /** @return array{tier:string,request_mode:string,contexts:string[],methods:string[]} */
    public function toArray(): array
    {
        return [
            'tier' => $this->tier,
            'request_mode' => $this->requestMode,
            'contexts' => $this->contexts,
            'methods' => $this->methods,
        ];
    }

    /** @param array<string,mixed> $stored */
    public static function fromArray(array $stored): self
    {
        return new self(
            is_string($stored['tier'] ?? null) ? $stored['tier'] : '',
            is_string($stored['request_mode'] ?? null) ? $stored['request_mode'] : '',
            is_array($stored['contexts'] ?? null) ? $stored['contexts'] : [],
            is_array($stored['methods'] ?? null) ? $stored['methods'] : []
        );
    }

    public function equals(self $other): bool
    {
        return $this->toArray() === $other->toArray();
    }

    public function tier(): string
    {
        return $this->tier;
    }

    /** @return array<string,string> parameters added to an authorization request */
    public function authorizationParameters(): array
    {
        if ($this->requestMode === self::ACR_VALUES) {
            return ['acr_values' => implode(' ', $this->contexts)];
        }

        $claim = $this->requestMode === self::ENTRA_CONTEXT ? 'acrs' : 'acr';
        $contextRequest = $claim === 'acrs'
            ? ['essential' => true, 'value' => $this->contexts[0]]
            : ['essential' => true, 'values' => $this->contexts];
        return ['claims' => json_encode([
            'id_token' => [
                $claim => $contextRequest,
                'amr' => ['essential' => true],
            ],
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)];
    }

    /** @param array<string,mixed> $claims claims from an already verified ID token */
    public function assertSatisfied(array $claims): void
    {
        $matchedContext = null;
        if ($this->requestMode === self::ENTRA_CONTEXT) {
            $reported = $claims['acrs'] ?? null;
            self::assertReportedList($reported, self::MAX_CONTEXTS, self::MAX_CONTEXT_BYTES, 'authentication contexts');
            $matchedContext = self::matchingExactValue($reported, $this->contexts);
            if ($matchedContext === null) {
                throw new ProtocolException(
                    'The ID token does not satisfy the required Microsoft authentication context'
                );
            }
        } else {
            $reported = $claims['acr'] ?? null;
            if (!is_string($reported) || !self::usableValue($reported, self::MAX_CONTEXT_BYTES)) {
                throw new ProtocolException('The ID token does not satisfy the required authentication context');
            }
            $matchedContext = self::matchingExactValue([$reported], $this->contexts);
            if ($matchedContext === null) {
                throw new ProtocolException('The ID token does not satisfy the required authentication context');
            }
        }

        $methods = $claims['amr'] ?? null;
        self::assertReportedList($methods, self::MAX_METHODS, self::MAX_METHOD_BYTES, 'authentication methods');
        if (!$this->hasRequiredMethodEvidence($methods, $matchedContext)) {
            throw new ProtocolException('The ID token does not report a required authentication method');
        }
    }

    /** @param string[] $reported */
    private function hasRequiredMethodEvidence(array $reported, string $matchedContext): bool
    {
        if ($this->requestMode === self::ENTRA_CONTEXT) {
            if (!self::hasExactValue($reported, ['mfa'])) {
                return false;
            }
            return $this->tier === self::MULTI_FACTOR
                || $this->hasEntraPhishingResistantMethod($reported);
        }

        if ($this->tier === self::MULTI_FACTOR) {
            return $this->hasMultiFactorEvidence($reported);
        }

        if (in_array($matchedContext, ['phr', 'phrh'], true)) {
            return $this->hasEapPhishingResistantMethod($reported, $matchedContext);
        }

        return $this->hasEapPhishingResistantMethod($reported, 'phr');
    }

    /** @param string[] $reported */
    private function hasMultiFactorEvidence(array $reported): bool
    {
        $factors = [];
        foreach ($reported as $method) {
            if (!self::hasExactValue([$method], $this->methods)) {
                continue;
            }
            if (!array_key_exists($method, self::STANDARD_METHOD_EVIDENCE)) {
                // An exact administrator-supplied provider value is the local mapping for an otherwise unknown AMR.
                return true;
            }
            $evidence = self::STANDARD_METHOD_EVIDENCE[$method];
            if ($evidence === self::DIRECT_MULTI_FACTOR) {
                return true;
            }
            if ($evidence !== null) {
                $factors[$evidence] = true;
            }
        }
        return count($factors) >= 2;
    }

    /** @param string[] $reported */
    private function hasEapPhishingResistantMethod(array $reported, string $matchedContext): bool
    {
        foreach ($reported as $method) {
            if (!self::hasExactValue([$method], $this->methods)) {
                continue;
            }
            if ($matchedContext === 'phrh') {
                if ($method === 'hwk' || !self::knownMethod($method)) {
                    return true;
                }
                continue;
            }
            if (in_array($method, self::EAP_KEY_METHODS, true) || !self::knownMethod($method)) {
                return true;
            }
        }
        return false;
    }

    /** @param string[] $reported */
    private function hasEntraPhishingResistantMethod(array $reported): bool
    {
        foreach ($reported as $method) {
            if (!self::hasExactValue([$method], $this->methods)) {
                continue;
            }
            if (in_array($method, self::ENTRA_PHISHING_RESISTANT_METHODS, true)
                || !self::knownMethod($method, true)) {
                return true;
            }
        }
        return false;
    }

    private static function knownMethod(string $method, bool $includeEntra = false): bool
    {
        return array_key_exists($method, self::STANDARD_METHOD_EVIDENCE)
            || ($includeEntra && array_key_exists($method, self::ENTRA_METHOD_EVIDENCE));
    }

    /** @param mixed $reported */
    private static function assertReportedList($reported, int $maximum, int $maximumBytes, string $name): void
    {
        if (!is_array($reported) || !array_is_list($reported) || $reported === [] || count($reported) > $maximum) {
            throw new ProtocolException(sprintf('The ID token has no usable %s', $name));
        }
        foreach ($reported as $value) {
            if (!is_string($value) || !self::usableValue($value, $maximumBytes)) {
                throw new ProtocolException(sprintf('The ID token carries invalid %s', $name));
            }
        }
    }

    /** @param mixed[] $values */
    private static function assertStringList(array $values, int $maximum, int $maximumBytes, string $name): void
    {
        if (!array_is_list($values) || $values === [] || count($values) > $maximum) {
            throw new ProtocolException(sprintf('The authentication requirement has no usable %ss', $name));
        }
        foreach ($values as $value) {
            if (!is_string($value) || !self::usableValue($value, $maximumBytes)) {
                throw new ProtocolException(sprintf('The authentication requirement carries an invalid %s', $name));
            }
        }
    }

    private static function usableValue(string $value, int $maximumBytes): bool
    {
        return $value !== '' && strlen($value) <= $maximumBytes
            && !preg_match('/[\x00-\x20\x7f]/', $value);
    }

    /** @param string[] $reported @param string[] $accepted */
    private static function hasExactValue(array $reported, array $accepted): bool
    {
        return self::matchingExactValue($reported, $accepted) !== null;
    }

    /** @param string[] $reported @param string[] $accepted */
    private static function matchingExactValue(array $reported, array $accepted): ?string
    {
        foreach ($reported as $actual) {
            foreach ($accepted as $expected) {
                if (hash_equals($expected, $actual)) {
                    return $actual;
                }
            }
        }
        return null;
    }
}
