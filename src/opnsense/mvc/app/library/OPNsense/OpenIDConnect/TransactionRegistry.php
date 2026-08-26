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
 * Short-lived, one-time login transactions for Form POST response modes.
 *
 * OPNsense deliberately marks its PHP session cookie SameSite=Lax, so a cross-site
 * authorization response POST carries no original session cookie. Keeping only these
 * random-state-bound transactions server-side preserves that protection and still lets
 * standards-compliant form_post providers return. No tokens or client secrets are stored.
 */
final class TransactionRegistry
{
    private const INDEX = '/var/lib/php/sessions/.openidconnect-transactions';
    private const MAX_BYTES = 8388608;
    private const MAX_RECORD_BYTES = 65536;
    private const MAX_RECORDS = 512;
    private const LIFETIME = 600;

    /** @param array<string,mixed> $transaction */
    public static function store(string $state, array $transaction): void
    {
        self::assertState($state);
        $encoded = json_encode($transaction, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($encoded) > self::MAX_RECORD_BYTES || !is_int($transaction['created'] ?? null)) {
            throw new ProtocolException('The login transaction cannot be stored safely');
        }
        self::change(static function (array &$records) use ($state, $transaction): void {
            $records[$state] = $transaction;
            while (count($records) > self::MAX_RECORDS) {
                array_shift($records);
            }
        });
    }

    /** @return array<string,mixed> */
    public static function consume(string $state, string $applicationCode): array
    {
        self::assertState($state);
        $found = null;
        self::change(static function (array &$records) use ($state, &$found): void {
            if (isset($records[$state]) && is_array($records[$state])) {
                $found = $records[$state];
                unset($records[$state]);
            }
        });
        if (!is_array($found) || !is_string($found['app_code'] ?? null)
            || !hash_equals($applicationCode, $found['app_code'])) {
            throw new ProtocolException('The authorization response does not match a pending login');
        }
        return $found;
    }

    /** @param callable(array<string,array<string,mixed>>&):void $callback */
    private static function change(callable $callback): void
    {
        $handle = @fopen(self::INDEX, 'c+');
        if ($handle === false) {
            throw new ProtocolException('The form-post transaction index cannot be opened');
        }
        @chmod(self::INDEX, 0600);
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new ProtocolException('The form-post transaction index cannot be locked');
            }
            $size = fstat($handle)['size'] ?? 0;
            if (!is_int($size) || $size < 0 || $size > self::MAX_BYTES) {
                throw new ProtocolException('The form-post transaction index is oversized');
            }
            rewind($handle);
            $raw = $size === 0 ? '' : stream_get_contents($handle, self::MAX_BYTES + 1);
            $records = $raw === '' ? [] : json_decode($raw, true);
            if (!is_array($records)) {
                throw new ProtocolException('The form-post transaction index is invalid');
            }
            $cutoff = time() - self::LIFETIME;
            foreach ($records as $state => $record) {
                if (!is_string($state) || !is_array($record)
                    || !is_int($record['created'] ?? null) || $record['created'] < $cutoff) {
                    unset($records[$state]);
                }
            }
            $callback($records);
            $encoded = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            if (strlen($encoded) > self::MAX_BYTES) {
                throw new ProtocolException('The form-post transaction index would exceed its size limit');
            }
            rewind($handle);
            ftruncate($handle, 0);
            if (fwrite($handle, $encoded) !== strlen($encoded) || !fflush($handle)) {
                throw new ProtocolException('The form-post transaction index cannot be saved');
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function assertState(string $state): void
    {
        if (!preg_match('/^p\.[A-Za-z0-9_-]{43}$/D', $state)) {
            throw new ProtocolException('The authorization response carries no usable state');
        }
    }
}
