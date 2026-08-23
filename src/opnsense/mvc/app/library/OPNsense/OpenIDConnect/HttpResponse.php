<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** Immutable result of one bounded HTTPS exchange. */
final class HttpResponse
{
    public function __construct(
        public readonly int $status,
        public readonly string $contentType,
        public readonly string $body,
        public readonly string $url
    ) {
    }

    /** @return array<mixed> */
    public function jsonObject(): array
    {
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
