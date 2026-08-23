<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/**
 * The only way the protocol reaches the network.
 *
 * Redirects are followed one at a time so every target is subjected to the same HTTPS
 * and URL checks. Bodies are stopped while they arrive; Content-Length is not trusted.
 */
class HttpClient
{
    public const CONNECT_TIMEOUT = 5;
    public const TOTAL_TIMEOUT = 15;
    public const MAX_REDIRECTS = 3;

    /** @var callable|null test transport */
    private $transport;

    public function __construct(?callable $transport = null)
    {
        $this->transport = $transport;
    }

    public function get(string $url, int $maxBytes, array $headers = []): HttpResponse
    {
        return $this->request('GET', $url, null, $headers, $maxBytes);
    }

    public function postForm(string $url, array $fields, int $maxBytes, array $headers = []): HttpResponse
    {
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';

        return $this->request(
            'POST',
            $url,
            http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
            $headers,
            $maxBytes
        );
    }

    public function request(
        string $method,
        string $url,
        ?string $body,
        array $headers,
        int $maxBytes
    ): HttpResponse {
        if ($maxBytes < 1) {
            throw new \InvalidArgumentException('A positive response limit is required');
        }

        $current = $url;
        for ($redirects = 0; ; $redirects++) {
            static::assertHttpsUrl($current);
            $response = $this->requestOnce($method, $current, $body, $headers, $maxBytes);
            if (!is_int($response['status']) || $response['status'] < 0 || $response['status'] > 599
                || !is_string($response['body']) || strlen($response['body']) > $maxBytes
                || !is_string($response['content_type']) || !is_string($response['location'])) {
                throw new ProtocolException('The provider returned an invalid or oversized HTTP response');
            }

            if (!in_array($response['status'], [301, 302, 303, 307, 308], true)) {
                return new HttpResponse(
                    $response['status'],
                    $response['content_type'],
                    $response['body'],
                    $current
                );
            }
            if ($redirects >= self::MAX_REDIRECTS) {
                throw new ProtocolException('The provider redirected too many times');
            }
            $location = $response['location'];
            if ($location === '') {
                throw new ProtocolException('The provider sent a redirect without a Location');
            }
            /*
             * An authorization header, bearer token, client assertion or secret belongs
             * to exactly the endpoint discovery named.  Following a redirect with any
             * of them would let that endpoint hand the credential to another host.  POST
             * redirects are also not part of the token/UserInfo protocols, so fail closed
             * instead of changing their method behind the caller's back.
             */
            if ($method !== 'GET' || self::hasSensitiveHeader($headers)) {
                throw new ProtocolException('A credential-bearing provider request may not be redirected');
            }
            $current = static::resolve($current, $location);

            /* RFC 7231 changes these redirects to GET; 307/308 preserve the request. */
            if (in_array($response['status'], [301, 302, 303], true)) {
                $method = 'GET';
                $body = null;
                $headers = array_values(array_filter(
                    $headers,
                    fn(string $header): bool => stripos($header, 'Content-Type:') !== 0
                ));
            }
        }
    }

    /** @return array{status:int,content_type:string,body:string,location:string} */
    protected function requestOnce(
        string $method,
        string $url,
        ?string $postBody,
        array $headers,
        int $maxBytes
    ): array {
        if ($this->transport !== null) {
            $answer = ($this->transport)($method, $url, $postBody, $headers, $maxBytes);
            if (!is_array($answer)) {
                throw new ProtocolException('The test transport returned no response');
            }

            return $answer + ['status' => 0, 'content_type' => '', 'body' => '', 'location' => ''];
        }

        $received = '';
        $location = '';
        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => self::TOTAL_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'OPNsense-OpenID-Connect/1.0',
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/json'], $headers),
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$location): int {
                if (stripos($line, 'Location:') === 0) {
                    $location = trim(substr($line, strlen('Location:')));
                }

                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$received, $maxBytes): int {
                if (strlen($received) + strlen($chunk) > $maxBytes) {
                    return 0;
                }
                $received .= $chunk;

                return strlen($chunk);
            },
        ]);
        if ($postBody !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $postBody);
        }

        $ok = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_HTTP_CODE);
        $contentType = strtolower(trim(explode(';', (string)curl_getinfo($handle, CURLINFO_CONTENT_TYPE))[0]));
        $problem = curl_error($handle);
        unset($handle);

        if ($ok === false) {
            $reason = strlen($received) >= $maxBytes ? 'response exceeded its size limit' : $problem;
            throw new ProtocolException('The provider request failed: ' . ($reason ?: 'network error'));
        }

        return ['status' => $status, 'content_type' => $contentType, 'body' => $received, 'location' => $location];
    }

    public static function assertHttpsUrl(string $url): void
    {
        if ($url === '' || preg_match('/[\x00-\x20\x7f]/', $url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            throw new ProtocolException('The provider names an invalid URL');
        }
        $parts = parse_url($url);
        if (strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) {
            throw new ProtocolException('The provider URL must use HTTPS');
        }
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new ProtocolException('The provider URL may not contain credentials or a fragment');
        }
    }

    private static function hasSensitiveHeader(array $headers): bool
    {
        foreach ($headers as $header) {
            if (is_string($header) && preg_match('/^(Authorization|Cookie|Proxy-Authorization):/i', $header)) {
                return true;
            }
        }
        return false;
    }

    private static function resolve(string $base, string $location): string
    {
        if (parse_url($location, PHP_URL_SCHEME) !== null) {
            return $location;
        }
        $parts = parse_url($base);
        $origin = $parts['scheme'] . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . $parts['port'] : '');
        if (str_starts_with($location, '//')) {
            return $parts['scheme'] . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }
        $path = (string)($parts['path'] ?? '/');

        return $origin . substr($path, 0, (int)strrpos($path, '/') + 1) . $location;
    }
}
