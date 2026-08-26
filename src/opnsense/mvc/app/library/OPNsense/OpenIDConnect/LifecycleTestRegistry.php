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

/**
 * Short-lived grants and observations for the optional browser lifecycle test.
 *
 * A test never becomes a PHP login session and is never placed in SessionRegistry. The
 * ID Token is retained only long enough to supply the provider's end-session endpoint;
 * logout receivers record channel arrival against digests of issuer/session identity.
 */
final class LifecycleTestRegistry
{
    private const INDEX = '/var/lib/php/sessions/.openidconnect-lifecycle-tests';
    private const MAX_BYTES = 4194304;
    private const MAX_RECORD_BYTES = 131072;
    private const MAX_RECORDS = 64;
    private const LIFETIME = 600;

    /** @param string[] $expectedChannels */
    public static function create(
        string $applicationCode,
        string $provider,
        string $issuer,
        string $subject,
        string $sid,
        string $idToken,
        string $returnUri,
        string $target,
        array $expectedChannels
    ): string {
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $applicationCode)
            || $provider === '' || strlen($provider) > 255 || self::hasControls($provider)
            || $issuer === '' || $subject === '' || $idToken === '' || strlen($idToken) > JwtVerifier::MAX_JWT_BYTES
            || !self::validTarget($target)) {
            throw new ProtocolException('The lifecycle test cannot be stored safely');
        }
        HttpClient::assertHttpsUrl($returnUri);
        $expectedChannels = array_values(array_intersect(['frontchannel', 'backchannel'], $expectedChannels));
        $id = JwtVerifier::base64UrlEncode(random_bytes(32));
        $created = time();
        $record = [
            'created' => $created,
            'expires' => $created + self::LIFETIME,
            'app_code' => $applicationCode,
            'provider' => $provider,
            'issuer' => $issuer,
            'subject_digest' => self::identityDigest($issuer, 'sub', $subject),
            'sid_digest' => $sid === '' ? '' : self::identityDigest($issuer, 'sid', $sid),
            'id_token' => $idToken,
            'return_uri' => $returnUri,
            'target' => $target,
            'expected' => $expectedChannels,
            'testable' => [
                'frontchannel' => $sid !== '',
                'backchannel' => true,
            ],
            'started' => null,
            'returned' => null,
            'observed' => [],
        ];
        $encoded = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($encoded) > self::MAX_RECORD_BYTES) {
            throw new ProtocolException('The lifecycle test exceeds its size limit');
        }
        self::change(static function (array &$records) use ($id, $record): void {
            $records[$id] = $record;
            while (count($records) > self::MAX_RECORDS) {
                array_shift($records);
            }
        });
        return $id;
    }

    /** @return array<string,mixed> secret-bearing start material for the authenticated controller only */
    public static function start(string $id): array
    {
        self::assertId($id);
        $found = null;
        self::change(static function (array &$records) use ($id, &$found): void {
            if (!isset($records[$id]) || !is_array($records[$id]) || $records[$id]['started'] !== null) {
                return;
            }
            $records[$id]['started'] = time();
            $found = $records[$id];
            unset($records[$id]['id_token']);
        });
        if (!is_array($found)) {
            throw new ProtocolException('The lifecycle test is missing, expired, or already started');
        }
        return $found;
    }

    /** Note only a notification which already passed its channel's complete protocol validation. */
    public static function observe(
        string $applicationCode,
        string $channel,
        string $issuer,
        ?string $sid,
        ?string $subject
    ): void {
        if (!in_array($channel, ['frontchannel', 'backchannel'], true) || $issuer === '') {
            return;
        }
        $sidDigest = is_string($sid) && $sid !== '' ? self::identityDigest($issuer, 'sid', $sid) : '';
        $subjectDigest = is_string($subject) && $subject !== ''
            ? self::identityDigest($issuer, 'sub', $subject) : '';
        self::change(static function (array &$records) use (
            $applicationCode,
            $channel,
            $issuer,
            $sidDigest,
            $subjectDigest
        ): void {
            foreach ($records as &$record) {
                if (!is_array($record) || !is_int($record['started'] ?? null)
                    || !is_string($record['app_code'] ?? null)
                    || !hash_equals($applicationCode, $record['app_code'])
                    || !is_string($record['issuer'] ?? null) || !hash_equals($issuer, $record['issuer'])) {
                    continue;
                }
                $sidMatches = $sidDigest !== '' && is_string($record['sid_digest'] ?? null)
                    && $record['sid_digest'] !== '' && hash_equals($sidDigest, $record['sid_digest']);
                $subjectMatches = $subjectDigest !== '' && is_string($record['subject_digest'] ?? null)
                    && hash_equals($subjectDigest, $record['subject_digest']);
                /* Logout Token and session invalidation semantics give sid precedence.
                 * A subject-wide match is valid only when the notification has no sid. */
                if ($sidDigest !== '' ? $sidMatches : $subjectMatches) {
                    $record['observed'][$channel] = time();
                }
            }
            unset($record);
        });
    }

    public static function returned(string $id, string $applicationCode): string
    {
        self::assertId($id);
        $target = '';
        self::change(static function (array &$records) use ($id, $applicationCode, &$target): void {
            $record = $records[$id] ?? null;
            if (!is_array($record) || !is_int($record['started'] ?? null)
                || !is_string($record['app_code'] ?? null)
                || !hash_equals($applicationCode, $record['app_code'])) {
                return;
            }
            $records[$id]['returned'] = time();
            $target = is_string($record['target'] ?? null) && self::validTarget($record['target'])
                ? $record['target'] : '/system_authservers.php';
        });
        if ($target === '') {
            throw new ProtocolException('The logout return does not match a pending lifecycle test');
        }
        return $target;
    }

    /** @return array<string,mixed> a secret-free result for the authenticated settings page */
    public static function status(string $id): array
    {
        self::assertId($id);
        $found = null;
        self::change(static function (array &$records) use ($id, &$found): void {
            $found = isset($records[$id]) && is_array($records[$id]) ? $records[$id] : null;
        });
        if (!is_array($found)) {
            throw new ProtocolException('The lifecycle test result is missing or expired');
        }
        return [
            'provider' => (string)($found['provider'] ?? ''),
            'expected' => is_array($found['expected'] ?? null) ? array_values($found['expected']) : [],
            'testable' => is_array($found['testable'] ?? null) ? $found['testable'] : [],
            'observed' => is_array($found['observed'] ?? null) ? $found['observed'] : [],
            'started' => $found['started'] ?? null,
            'returned' => $found['returned'] ?? null,
        ];
    }

    /** @param callable(array<string,array<string,mixed>>&):void $callback */
    private static function change(callable $callback): void
    {
        $index = defined('OPENIDCONNECT_TEST_LIFECYCLE_REGISTRY')
            ? (string)constant('OPENIDCONNECT_TEST_LIFECYCLE_REGISTRY') : self::INDEX;
        $handle = @fopen($index, 'c+');
        if ($handle === false) {
            throw new ProtocolException('The lifecycle test index cannot be opened');
        }
        @chmod($index, 0600);
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new ProtocolException('The lifecycle test index cannot be locked');
            }
            $size = fstat($handle)['size'] ?? 0;
            if (!is_int($size) || $size < 0 || $size > self::MAX_BYTES) {
                throw new ProtocolException('The lifecycle test index is oversized');
            }
            rewind($handle);
            $raw = $size === 0 ? '' : stream_get_contents($handle, self::MAX_BYTES + 1);
            $records = $raw === '' ? [] : json_decode($raw, true);
            if (!is_array($records)) {
                throw new ProtocolException('The lifecycle test index is invalid');
            }
            $now = time();
            foreach ($records as $id => $record) {
                if (!is_string($id) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $id)
                    || !is_array($record) || !is_int($record['expires'] ?? null) || $record['expires'] < $now) {
                    unset($records[$id]);
                }
            }
            $callback($records);
            $encoded = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            if (strlen($encoded) > self::MAX_BYTES) {
                throw new ProtocolException('The lifecycle test index would exceed its size limit');
            }
            rewind($handle);
            ftruncate($handle, 0);
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new ProtocolException('The lifecycle test index cannot be saved');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function identityDigest(string $issuer, string $kind, string $value): string
    {
        return hash('sha256', $issuer . "\0" . $kind . "\0" . $value);
    }

    private static function assertId(string $id): void
    {
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $id)) {
            throw new ProtocolException('The lifecycle test identifier is invalid');
        }
    }

    private static function validTarget(string $target): bool
    {
        return (bool)preg_match('#^/system_authservers\.php(?:\?act=edit&id=(?:0|[1-9][0-9]*))?$#D', $target);
    }

    private static function hasControls(string $value): bool
    {
        return (bool)preg_match('/[\x00-\x1f\x7f]/', $value);
    }
}
