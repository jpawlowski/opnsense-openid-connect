<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** HTTP-aware, bounded persistence for public Discovery and signing-key responses. */
final class ProviderCache
{
    public const DEFAULT_FRESHNESS = 3600;
    public const MIN_FRESHNESS = 60;
    public const MAX_FRESHNESS = 86400;

    public static function get(
        HttpClient $http,
        string $url,
        int $maxBytes,
        string $namespace,
        int $maximumStale,
        bool $force = false,
        bool $allowStaleOnFailure = true,
        ?callable $validator = null
    ): HttpResponse {
        $now = time();
        $entry = self::read($namespace, $url);
        if (!$force && self::usable($entry, 'fresh_until', $now)) {
            return self::response($entry, $url, 'cache-fresh');
        }

        $headers = [];
        if (is_string($entry['etag'] ?? null) && self::validEtag($entry['etag'])) {
            $headers[] = 'If-None-Match: ' . $entry['etag'];
        }
        self::markRefreshing($namespace, $url);
        try {
            $response = $http->get($url, $maxBytes, $headers);
        } catch (ProviderUnavailableException $e) {
            self::clearRefreshing($namespace, $url);
            if ($allowStaleOnFailure && self::staleUsable($entry, $now)) {
                return self::response($entry, $url, 'cache-stale');
            }
            throw $e;
        } catch (\Throwable $e) {
            self::clearRefreshing($namespace, $url);
            throw $e;
        }
        self::clearRefreshing($namespace, $url);

        if ($response->status === 304 && $entry !== []) {
            $policy = self::policy($response->headers + (array)($entry['headers'] ?? []), $now, $maximumStale);
            if ($policy['no_store']) {
                self::remove($namespace, $url);
                return self::response($entry, $url, 'revalidated');
            }
            $entry = array_replace($entry, $policy, [
                'stored' => $now,
                'headers' => $response->headers + (array)($entry['headers'] ?? []),
            ]);
            self::write($namespace, $url, $entry);
            return self::response($entry, $url, 'revalidated');
        }
        if (($response->status === 429 || $response->status >= 500)
            && $allowStaleOnFailure && self::staleUsable($entry, $now)) {
            return self::response($entry, $url, 'cache-stale');
        }
        if ($response->status !== 200) {
            return $response;
        }

        /* Persist only public material which its protocol owner has already accepted. */
        if ($validator !== null) {
            $validator($response);
        }

        $policy = self::policy($response->headers, $now, $maximumStale);
        if ($policy['no_store']) {
            self::remove($namespace, $url);
            return $response;
        }
        $entry = array_replace($policy, [
            'stored' => $now,
            'status' => $response->status,
            'content_type' => $response->contentType,
            'body' => $response->body,
            'headers' => $response->headers,
            'etag' => self::validEtag((string)($response->headers['etag'] ?? ''))
                ? (string)$response->headers['etag'] : '',
        ]);
        self::write($namespace, $url, $entry);
        return new HttpResponse(
            $response->status,
            $response->contentType,
            $response->body,
            $response->url,
            $response->headers,
            'live'
        );
    }

    /** @return array{status:string,stored:?int,fresh_until:?int,stale_until:?int} */
    public static function status(string $namespace, string $url, ?int $now = null): array
    {
        $now ??= time();
        $entry = self::read($namespace, $url);
        $status = self::isRefreshing($namespace, $url, $now) ? 'refreshing'
            : ($entry === [] ? 'missing'
                : (self::usable($entry, 'fresh_until', $now) ? 'fresh'
                    : (self::staleUsable($entry, $now) ? 'stale' : 'error')));
        return [
            'status' => $status,
            'stored' => is_int($entry['stored'] ?? null) ? $entry['stored'] : null,
            'fresh_until' => is_int($entry['fresh_until'] ?? null) ? $entry['fresh_until'] : null,
            'stale_until' => is_int($entry['stale_until'] ?? null) ? $entry['stale_until'] : null,
        ];
    }

    public static function cachedResponse(string $namespace, string $url): ?HttpResponse
    {
        $entry = self::read($namespace, $url);
        return $entry === [] ? null : self::response($entry, $url, 'cache');
    }

    /** At most one worker per minute may turn an unknown signing key into a live refresh. */
    public static function claimRefresh(string $namespace, string $url, ?int $now = null): bool
    {
        $now ??= time();
        $directory = self::directory();
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return false;
        }
        $path = self::path($namespace . '-refresh', $url);
        $handle = @fopen($path, 'c+');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) {
                fclose($handle);
            }
            return false;
        }
        $previous = trim((string)stream_get_contents($handle));
        if (ctype_digit($previous) && (int)$previous > $now - 60) {
            flock($handle, LOCK_UN);
            fclose($handle);
            return false;
        }
        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, (string)$now);
        fflush($handle);
        @chmod($path, 0600);
        flock($handle, LOCK_UN);
        fclose($handle);
        return true;
    }

    /** @return array<string,mixed> */
    private static function policy(array $headers, int $now, int $maximumStale): array
    {
        $control = strtolower((string)($headers['cache-control'] ?? ''));
        $noStore = preg_match('/(?:^|,)\s*no-store\s*(?:,|$)/', $control) === 1;
        $noCache = preg_match('/(?:^|,)\s*no-cache(?:\s*=\s*"[^"]*")?\s*(?:,|$)/', $control) === 1;
        $mustRevalidate = $noCache
            || preg_match('/(?:^|,)\s*must-revalidate\s*(?:,|$)/', $control) === 1;
        $freshness = self::DEFAULT_FRESHNESS;
        if (preg_match('/(?:^|,)\s*s-maxage\s*=\s*"?(\d+)"?/i', $control, $match)) {
            $freshness = (int)$match[1];
        } elseif (preg_match('/(?:^|,)\s*max-age\s*=\s*"?(\d+)"?/i', $control, $match)) {
            $freshness = (int)$match[1];
        } elseif (is_string($headers['expires'] ?? null) && ($expires = strtotime($headers['expires'])) !== false) {
            $freshness = max(0, $expires - $now);
        }
        if ($noCache) {
            $freshness = 0;
        }
        $freshness = $freshness === 0 ? 0 : max(self::MIN_FRESHNESS, min(self::MAX_FRESHNESS, $freshness));
        $age = ctype_digit((string)($headers['age'] ?? '')) ? (int)$headers['age'] : 0;
        if (is_string($headers['date'] ?? null) && ($date = strtotime($headers['date'])) !== false) {
            $age = max($age, max(0, $now - $date));
        }
        $freshUntil = $now + max(0, $freshness - $age);
        return [
            'no_store' => $noStore,
            'must_revalidate' => $mustRevalidate,
            'fresh_until' => $freshUntil,
            'stale_until' => $freshUntil + ($mustRevalidate ? 0 : max(0, $maximumStale)),
        ];
    }

    /** @param array<string,mixed> $entry */
    private static function staleUsable(array $entry, int $now): bool
    {
        return ($entry['must_revalidate'] ?? true) === false && self::usable($entry, 'stale_until', $now);
    }

    /** @param array<string,mixed> $entry */
    private static function usable(array $entry, string $field, int $now): bool
    {
        return is_int($entry[$field] ?? null) && $entry[$field] > $now
            && is_int($entry['status'] ?? null) && $entry['status'] === 200
            && is_string($entry['content_type'] ?? null) && is_string($entry['body'] ?? null);
    }

    /** @param array<string,mixed> $entry */
    private static function response(array $entry, string $url, string $source): HttpResponse
    {
        return new HttpResponse(
            (int)$entry['status'],
            (string)$entry['content_type'],
            (string)$entry['body'],
            $url,
            is_array($entry['headers'] ?? null) ? $entry['headers'] : [],
            $source
        );
    }

    private static function directory(): string
    {
        return defined('OPENIDCONNECT_TEST_CACHE_DIRECTORY')
            ? (string)constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY')
            : '/var/db/openid-connect/cache';
    }

    private static function path(string $namespace, string $url): string
    {
        return self::directory() . '/' . preg_replace('/[^A-Za-z0-9_.-]/', '_', $namespace)
            . '-' . hash('sha256', $url) . '.json';
    }

    /** @return array<string,mixed> */
    private static function read(string $namespace, string $url): array
    {
        $body = @file_get_contents(self::path($namespace, $url));
        if (!is_string($body) || $body === '') {
            return [];
        }
        try {
            $entry = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return [];
        }
        return is_array($entry) && !array_is_list($entry) ? $entry : [];
    }

    /** @param array<string,mixed> $entry */
    private static function write(string $namespace, string $url, array $entry): void
    {
        $directory = self::directory();
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            syslog(LOG_NOTICE, 'OIDC: the provider cache directory could not be created');
            return;
        }
        @chmod($directory, 0700);
        $path = self::path($namespace, $url);
        $temporary = $path . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
        $body = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (@file_put_contents($temporary, $body, LOCK_EX) !== strlen($body)
            || !@chmod($temporary, 0600) || !@rename($temporary, $path)) {
            @unlink($temporary);
            syslog(LOG_NOTICE, 'OIDC: provider cache state could not be written');
        }
    }

    private static function remove(string $namespace, string $url): void
    {
        @unlink(self::path($namespace, $url));
    }

    private static function validEtag(string $value): bool
    {
        return $value !== '' && strlen($value) <= 1024
            && preg_match('/^(?:W\/)?"[^"\x00-\x1f\x7f]*"$/D', $value) === 1;
    }

    private static function markRefreshing(string $namespace, string $url): void
    {
        $directory = self::directory();
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            return;
        }
        $path = self::path($namespace . '-inflight', $url);
        if (@file_put_contents($path, (string)time(), LOCK_EX) !== false) {
            @chmod($path, 0600);
        }
    }

    private static function clearRefreshing(string $namespace, string $url): void
    {
        @unlink(self::path($namespace . '-inflight', $url));
    }

    private static function isRefreshing(string $namespace, string $url, int $now): bool
    {
        $value = trim((string)@file_get_contents(self::path($namespace . '-inflight', $url)));
        return ctype_digit($value) && (int)$value >= $now - HttpClient::TOTAL_TIMEOUT - 5;
    }
}
