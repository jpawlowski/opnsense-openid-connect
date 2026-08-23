<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/**
 * A small, local index used only to find OIDC-created PHP sessions for front- and
 * back-channel logout.  It contains no token or client secret and is readable only by
 * the WebGUI account that owns the PHP session directory.
 */
final class SessionRegistry
{
    private const INDEX = '/var/lib/php/sessions/.openidconnect-sessions';
    private const LOGOUT_REPLAYS = '/var/lib/php/sessions/.openidconnect-logout-tokens';
    private const MAX_BYTES = 1048576;
    private const MAX_RECORDS = 2048;

    public static function record(
        string $sessionId,
        string $provider,
        string $issuer,
        string $subject,
        string $sid,
        int $expires
    ): void {
        if (!self::validSessionId($sessionId) || $issuer === '' || $subject === '') {
            throw new ProtocolException('The authenticated session cannot be indexed safely');
        }
        self::change(function (array &$records) use ($sessionId, $provider, $issuer, $subject, $sid, $expires): void {
            $records[$sessionId] = [
                'provider' => substr($provider, 0, 255),
                'issuer' => $issuer,
                'sub' => $subject,
                'sid' => $sid,
                'expires' => $expires,
            ];
            while (count($records) > self::MAX_RECORDS) {
                array_shift($records);
            }
        });
    }

    public static function remove(string $sessionId): void
    {
        if (!self::validSessionId($sessionId)) {
            return;
        }
        self::change(static function (array &$records) use ($sessionId): void {
            unset($records[$sessionId]);
        });
    }

    /** @return int number of session files invalidated */
    public static function terminate(string $issuer, ?string $sid, ?string $subject): int
    {
        if ($issuer === '' || (($sid === null || $sid === '') && ($subject === null || $subject === ''))) {
            return 0;
        }
        $terminated = 0;
        self::change(function (array &$records) use ($issuer, $sid, $subject, &$terminated): void {
            foreach ($records as $sessionId => $record) {
                if (!is_array($record) || !is_string($record['issuer'] ?? null)
                    || !hash_equals($issuer, $record['issuer'])) {
                    continue;
                }
                $matches = $sid !== null && $sid !== ''
                    ? is_string($record['sid'] ?? null) && hash_equals($sid, $record['sid'])
                    : is_string($record['sub'] ?? null) && hash_equals((string)$subject, $record['sub']);
                if ($matches && self::destroySessionFile((string)$sessionId)) {
                    unset($records[$sessionId]);
                    $terminated++;
                }
            }
        });
        return $terminated;
    }

    /**
     * Atomically remember a Back-Channel Logout jti. False means it was already seen.
     * Only a digest is stored, and entries live for at most ten minutes.
     */
    public static function acceptLogoutToken(string $issuer, string $jti, int $expires): bool
    {
        if ($issuer === '' || $jti === '' || strlen($jti) > 255 || preg_match('/[\x00-\x1f\x7f]/', $jti)) {
            throw new ProtocolException('The logout token cannot be indexed safely');
        }
        $now = time();
        $expires = min(max($expires, $now + 1), $now + 600);
        $key = JwtVerifier::base64UrlEncode(hash('sha256', $issuer . "\0" . $jti, true));
        $accepted = false;
        self::changeFile(
            self::LOGOUT_REPLAYS,
            static function (array &$records) use ($key, $expires, &$accepted): void {
                if (isset($records[$key])) {
                    return;
                }
                $records[$key] = $expires;
                while (count($records) > self::MAX_RECORDS) {
                    array_shift($records);
                }
                $accepted = true;
            },
            static function (string $id, $record, int $now): bool {
                return !preg_match('/^[A-Za-z0-9_-]{43}$/D', $id)
                    || !is_int($record) || $record < $now;
            }
        );
        return $accepted;
    }

    /** @param callable(array<string,array<string,mixed>>&):void $callback */
    private static function change(callable $callback): void
    {
        self::changeFile(
            self::INDEX,
            $callback,
            static function (string $id, $record, int $now): bool {
                return !self::validSessionId($id) || !is_array($record)
                    || !is_int($record['expires'] ?? null) || $record['expires'] < $now;
            }
        );
    }

    /** @param callable(array&):void $callback @param callable(string,mixed,int):bool $expired */
    private static function changeFile(string $path, callable $callback, callable $expired): void
    {
        $handle = @fopen($path, 'c+');
        if ($handle === false) {
            throw new ProtocolException('The OIDC session index cannot be opened');
        }
        @chmod($path, 0600);
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new ProtocolException('The OIDC session index cannot be locked');
            }
            $size = fstat($handle)['size'] ?? 0;
            if (!is_int($size) || $size < 0 || $size > self::MAX_BYTES) {
                throw new ProtocolException('The OIDC session index is oversized');
            }
            rewind($handle);
            $raw = $size === 0 ? '' : stream_get_contents($handle, self::MAX_BYTES + 1);
            $records = $raw === '' ? [] : json_decode($raw, true);
            if (!is_array($records)) {
                throw new ProtocolException('The OIDC session index is invalid');
            }
            $now = time();
            foreach ($records as $id => $record) {
                if ($expired((string)$id, $record, $now)) {
                    unset($records[$id]);
                }
            }
            $callback($records);
            $encoded = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            if (strlen($encoded) > self::MAX_BYTES) {
                throw new ProtocolException('The OIDC session index would exceed its size limit');
            }
            rewind($handle);
            ftruncate($handle, 0);
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new ProtocolException('The OIDC session index cannot be saved');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function destroySessionFile(string $sessionId): bool
    {
        if (!self::validSessionId($sessionId) || session_module_name() !== 'files') {
            return false;
        }
        $directory = (string)ini_get('session.save_path');
        if (str_contains($directory, ';')) {
            $directory = (string)substr($directory, strrpos($directory, ';') + 1);
        }
        if ($directory === '' || !is_dir($directory)) {
            return false;
        }
        $path = rtrim($directory, '/') . '/sess_' . $sessionId;
        $handle = @fopen($path, 'r+');
        if ($handle === false) {
            /* A session that has already expired is already logged out. */
            return !file_exists($path);
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return false;
        }
        ftruncate($handle, 0);
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
        return @unlink($path) || !file_exists($path);
    }

    private static function validSessionId(string $sessionId): bool
    {
        return (bool)preg_match('/^[A-Za-z0-9,-]{16,128}$/D', $sessionId);
    }
}
