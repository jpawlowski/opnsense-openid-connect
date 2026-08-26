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
