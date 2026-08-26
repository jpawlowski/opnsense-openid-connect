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

use OPNsense\Auth\OpenIDConnect;

/** Small, secret-free persistent health, PAR and SSF poll state shared by PHP workers and cron. */
final class ProviderRuntimeState
{
    private const RETRY_DELAYS = [60, 120, 300, 600, 900];
    private const SSF_POLL_FRESH_SECONDS = 180;

    public static function parKey(OpenIDConnect $settings, ProviderMetadata $metadata): string
    {
        return hash('sha256', json_encode([
            $settings->issuerUrl(),
            $metadata->issuer(),
            $metadata->pushedAuthorizationRequestEndpoint(),
            $settings->clientId(),
            $settings->applicationCode(),
            $settings->tokenAuthMethod(),
            $settings->parMode(),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function parIsBypassed(string $key): bool
    {
        return (self::read('par-' . $key)['status'] ?? '') === 'bypassed';
    }

    public static function parMayProbe(string $key, ?int $now = null): bool
    {
        $now ??= time();
        $state = self::read('par-' . $key);
        return ($state['status'] ?? '') === 'bypassed'
            && is_int($state['next_probe'] ?? null) && $state['next_probe'] <= $now;
    }

    public static function parUnavailable(string $key, ?int $retryAfter = null, ?int $now = null): void
    {
        $now ??= time();
        $state = self::read('par-' . $key);
        $failures = min(1000, max(0, (int)($state['failures'] ?? 0)) + 1);
        $delay = self::RETRY_DELAYS[min($failures - 1, count(self::RETRY_DELAYS) - 1)];
        if ($retryAfter !== null) {
            $delay = max($delay, min(3600, max(0, $retryAfter)));
        }
        self::write('par-' . $key, [
            'status' => 'bypassed',
            'failures' => $failures,
            'updated' => $now,
            'next_probe' => $now + $delay,
            'reason' => 'temporarily_unavailable',
        ]);
    }

    public static function parAvailable(string $key, ?int $now = null): void
    {
        $now ??= time();
        self::write('par-' . $key, [
            'status' => 'fresh',
            'failures' => 0,
            'updated' => $now,
            'last_success' => $now,
            'next_probe' => 0,
        ]);
    }

    public static function parHardFailure(string $key, ?int $now = null): void
    {
        $now ??= time();
        self::write('par-' . $key, [
            'status' => 'error',
            'failures' => 0,
            'updated' => $now,
            'next_probe' => 0,
            'reason' => 'configuration_or_protocol',
        ]);
    }

    /** @return array<string,mixed> */
    public static function parStatus(string $key): array
    {
        return self::read('par-' . $key);
    }

    public static function ssfKey(OpenIDConnect $settings, SharedSignalsMetadata $metadata): string
    {
        return hash('sha256', json_encode([
            $settings->sharedSignalsIssuer(),
            $metadata->issuer(),
            $settings->sharedSignalsStreamId(),
            $settings->sharedSignalsAudience(),
            $settings->sharedSignalsDeliveryMethod(),
            $settings->applicationCode(),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function ssfPollSuccess(string $key, int $events, ?int $now = null): void
    {
        $now ??= time();
        $previous = self::read('ssf-' . $key);
        self::write('ssf-' . $key, [
            'status' => 'fresh',
            'updated' => $now,
            'fresh_until' => $now + self::SSF_POLL_FRESH_SECONDS,
            'last_success' => $now,
            'last_event' => $events > 0 ? $now : ($previous['last_event'] ?? null),
            'events' => $events,
            'reason' => '',
        ]);
    }

    public static function ssfPollFailure(string $key, string $reason, ?int $now = null): void
    {
        $now ??= time();
        $previous = self::read('ssf-' . $key);
        self::write('ssf-' . $key, [
            'status' => 'error',
            'updated' => $now,
            'fresh_until' => null,
            'last_success' => $previous['last_success'] ?? null,
            'last_event' => $previous['last_event'] ?? null,
            'events' => 0,
            'reason' => $reason,
        ]);
    }

    /** @return array<string,mixed> */
    public static function ssfStatus(string $key, ?int $now = null): array
    {
        $now ??= time();
        $state = self::read('ssf-' . $key);
        if (($state['status'] ?? '') === 'fresh'
            && is_int($state['fresh_until'] ?? null) && $state['fresh_until'] < $now) {
            $state['status'] = 'stale';
        }
        return $state;
    }

    private static function directory(): string
    {
        return defined('OPENIDCONNECT_TEST_RUNTIME_DIRECTORY')
            ? (string)constant('OPENIDCONNECT_TEST_RUNTIME_DIRECTORY')
            : '/var/db/openid-connect/runtime';
    }

    /** @return array<string,mixed> */
    private static function read(string $name): array
    {
        $body = @file_get_contents(self::directory() . '/' . $name . '.json');
        if (!is_string($body) || $body === '') {
            return [];
        }
        try {
            $decoded = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return [];
        }
        return is_array($decoded) && !array_is_list($decoded) ? $decoded : [];
    }

    /** @param array<string,mixed> $state */
    private static function write(string $name, array $state): void
    {
        $directory = self::directory();
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            syslog(LOG_NOTICE, 'OIDC: the provider runtime directory could not be created');
            return;
        }
        @chmod($directory, 0700);
        $path = $directory . '/' . $name . '.json';
        $temporary = $path . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
        $body = json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (@file_put_contents($temporary, $body, LOCK_EX) !== strlen($body)
            || !@chmod($temporary, 0600) || !@rename($temporary, $path)) {
            @unlink($temporary);
            syslog(LOG_NOTICE, 'OIDC: provider runtime state could not be written');
        }
    }
}
