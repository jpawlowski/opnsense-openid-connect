<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/**
 * Bounded, local holding area for unknown identities awaiting an administrator.
 *
 * An unauthenticated login attempt must not write provider-controlled values into
 * config.xml. This 0600 file therefore holds only short, display-safe hints and the
 * stable issuer/subject pair. Approval moves that exact pair into the auth-server
 * configuration; denial merely removes it. Records expire after seven days.
 */
final class PendingIdentityRegistry
{
    private const INDEX = '/var/lib/php/sessions/.openidconnect-pending-identities';
    private const MAX_BYTES = 1048576;
    private const MAX_RECORDS = 100;
    private const LIFETIME = 604800;

    /** @param array<string,mixed> $hints */
    public static function record(string $applicationCode, string $issuer, string $subject, array $hints): string
    {
        self::assertIdentity($applicationCode, $issuer, $subject);
        $id = substr(hash('sha256', $applicationCode . "\0" . $issuer . "\0" . $subject), 0, 20);
        $now = time();
        $safe = [];
        foreach (['username', 'email', 'name'] as $name) {
            $value = $hints[$name] ?? null;
            if (is_string($value)) {
                $value = trim(preg_replace('/[\x00-\x1f\x7f]/', '', $value) ?? '');
                if ($value !== '') {
                    $safe[$name] = self::limit($value, 255);
                }
            }
        }
        if (($hints['email_verified'] ?? null) === true || ($hints['email_verified'] ?? null) === 'true') {
            $safe['email_verified'] = true;
        }
        self::change(static function (array &$records) use ($id, $applicationCode, $issuer, $subject, $safe, $now): void {
            $firstSeen = is_int($records[$id]['first_seen'] ?? null) ? $records[$id]['first_seen'] : $now;
            $attempts = is_int($records[$id]['attempts'] ?? null) ? $records[$id]['attempts'] + 1 : 1;
            $records[$id] = [
                'id' => $id,
                'app_code' => $applicationCode,
                'issuer' => $issuer,
                'subject' => $subject,
                'hints' => $safe,
                'first_seen' => $firstSeen,
                'last_seen' => $now,
                'attempts' => min($attempts, 2147483647),
            ];
            while (count($records) > self::MAX_RECORDS) {
                array_shift($records);
            }
        });
        return $id;
    }

    /** @return array<int,array<string,mixed>> */
    public static function listing(string $applicationCode): array
    {
        $found = [];
        self::change(static function (array &$records) use ($applicationCode, &$found): void {
            foreach ($records as $record) {
                if (is_array($record) && is_string($record['app_code'] ?? null)
                    && hash_equals($applicationCode, $record['app_code'])) {
                    $found[] = $record;
                }
            }
        });
        usort($found, static fn(array $a, array $b): int => ($b['last_seen'] ?? 0) <=> ($a['last_seen'] ?? 0));
        return $found;
    }

    /** @return array<string,mixed>|null */
    public static function find(string $id, string $applicationCode): ?array
    {
        $found = null;
        self::change(static function (array &$records) use ($id, $applicationCode, &$found): void {
            $record = $records[$id] ?? null;
            if (is_array($record) && is_string($record['app_code'] ?? null)
                && hash_equals($applicationCode, $record['app_code'])) {
                $found = $record;
            }
        });
        return $found;
    }

    public static function remove(string $id, string $applicationCode): bool
    {
        $removed = false;
        self::change(static function (array &$records) use ($id, $applicationCode, &$removed): void {
            $record = $records[$id] ?? null;
            if (is_array($record) && is_string($record['app_code'] ?? null)
                && hash_equals($applicationCode, $record['app_code'])) {
                unset($records[$id]);
                $removed = true;
            }
        });
        return $removed;
    }

    /** @param callable(array<string,array<string,mixed>>&):void $callback */
    private static function change(callable $callback): void
    {
        $path = defined('OPENIDCONNECT_TEST_PENDING_REGISTRY')
            ? (string)constant('OPENIDCONNECT_TEST_PENDING_REGISTRY') : self::INDEX;
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            throw new ProtocolException('The pending identity index cannot be opened');
        }
        @chmod($path, 0600);
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new ProtocolException('The pending identity index cannot be locked');
            }
            $size = fstat($handle)['size'] ?? 0;
            if (!is_int($size) || $size < 0 || $size > self::MAX_BYTES) {
                throw new ProtocolException('The pending identity index is oversized');
            }
            rewind($handle);
            $raw = $size === 0 ? '' : stream_get_contents($handle, self::MAX_BYTES + 1);
            $records = $raw === '' ? [] : json_decode($raw, true);
            if (!is_array($records)) {
                throw new ProtocolException('The pending identity index is invalid');
            }
            $cutoff = time() - self::LIFETIME;
            foreach ($records as $id => $record) {
                if (!is_string($id) || !preg_match('/^[a-f0-9]{20}$/D', $id) || !is_array($record)
                    || !is_int($record['last_seen'] ?? null) || $record['last_seen'] < $cutoff) {
                    unset($records[$id]);
                }
            }
            $callback($records);
            $encoded = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            if (strlen($encoded) > self::MAX_BYTES) {
                throw new ProtocolException('The pending identity index would exceed its size limit');
            }
            rewind($handle);
            ftruncate($handle, 0);
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new ProtocolException('The pending identity index cannot be saved');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function assertIdentity(string $applicationCode, string $issuer, string $subject): void
    {
        if (!preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $applicationCode)
            || $issuer === '' || strlen($issuer) > 2048 || preg_match('/[\x00-\x1f\x7f]/', $issuer)
            || $subject === '' || strlen($subject) > 255 || preg_match('/[\x00-\x1f\x7f]/', $subject)) {
            throw new ProtocolException('The unknown identity cannot be queued safely');
        }
    }

    private static function limit(string $value, int $length): string
    {
        return function_exists('mb_substr') ? mb_substr($value, 0, $length, 'UTF-8') : substr($value, 0, $length);
    }
}
