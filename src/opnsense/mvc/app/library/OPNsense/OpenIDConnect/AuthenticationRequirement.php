<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

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

    /**
     * @param string[] $contexts exact acceptable acr values, or one Entra acrs context
     * @param string[] $methods any one of these amr values has to be present
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
        if ($this->requestMode === self::ENTRA_CONTEXT) {
            $reported = $claims['acrs'] ?? null;
            self::assertReportedList($reported, self::MAX_CONTEXTS, self::MAX_CONTEXT_BYTES, 'authentication contexts');
            if (!self::hasExactValue($reported, $this->contexts)) {
                throw new ProtocolException('The ID token does not satisfy the required Microsoft authentication context');
            }
        } else {
            $reported = $claims['acr'] ?? null;
            if (!is_string($reported) || !self::usableValue($reported, self::MAX_CONTEXT_BYTES)
                || !self::hasExactValue([$reported], $this->contexts)) {
                throw new ProtocolException('The ID token does not satisfy the required authentication context');
            }
        }

        $methods = $claims['amr'] ?? null;
        self::assertReportedList($methods, self::MAX_METHODS, self::MAX_METHOD_BYTES, 'authentication methods');
        if (!self::hasExactValue($methods, $this->methods)) {
            throw new ProtocolException('The ID token does not report a required authentication method');
        }
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
        foreach ($reported as $actual) {
            foreach ($accepted as $expected) {
                if (hash_equals($expected, $actual)) {
                    return true;
                }
            }
        }
        return false;
    }
}
