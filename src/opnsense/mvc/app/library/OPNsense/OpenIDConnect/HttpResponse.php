<?php

namespace OPNsense\OpenIDConnect;

/** Immutable result of one bounded HTTPS exchange. */
final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $contentType,
        public readonly string $body,
        public readonly string $url,
        /** @var array<string,mixed> lower-case response header names; duplicates remain detectable */
        public readonly array $headers = [],
        public readonly string $source = 'live'
    ) {
    }

    public function retryAfterSeconds(?int $now = null): ?int
    {
        $value = trim((string)($this->headers['retry-after'] ?? ''));
        if ($value === '') {
            return null;
        }
        if (ctype_digit($value)) {
            return min(3600, (int)$value);
        }
        $timestamp = strtotime($value);
        if ($timestamp === false) {
            return null;
        }
        return min(3600, max(0, $timestamp - ($now ?? time())));
    }

    /** A bounded, body-free description suitable for an administrator-facing diagnostic. */
    public function diagnosticSummary(): string
    {
        $summary = sprintf(
            'HTTP %d; Content-Type: %s',
            $this->status,
            $this->contentType !== '' ? $this->contentType : 'missing'
        );
        $retryAfter = $this->retryAfterSeconds();
        if ($retryAfter !== null) {
            $summary .= sprintf('; Retry-After: %d seconds', $retryAfter);
        }
        return $summary;
    }

    /** @return array<mixed> */
    public function jsonObject(): array
    {
        if ($this->contentType !== 'application/json' && !str_ends_with($this->contentType, '+json')) {
            throw new ProtocolException('The provider did not return a JSON media type');
        }
        try {
            $decoded = json_decode($this->body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ProtocolException('The provider returned invalid JSON', 0, $e);
        }
        if (!is_array($decoded) || array_is_list($decoded)) {
            throw new ProtocolException('The provider returned a JSON value instead of an object');
        }

        return $decoded;
    }
}
