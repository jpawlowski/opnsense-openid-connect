<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** Bounded, metadata-bound SSF stream management and poll delivery client. */
final class SharedSignalsClient
{
    public const MAX_BYTES = 1048576;
    public const MAX_POLL_EVENTS = 20;

    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @return array<string,mixed> */
    public function createStream(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $method,
        ?string $pushEndpoint = null,
        ?string $pushAuthorization = null,
        string $description = ''
    ): array {
        $this->requireDelivery($metadata, $method);
        $delivery = ['method' => $method];
        if ($method === SharedSignalsMetadata::PUSH_METHOD) {
            if ($pushEndpoint === null || $pushAuthorization === null) {
                throw new ProtocolException('Push stream creation requires its receiver endpoint and authorization');
            }
            HttpClient::assertHttpsUrl($pushEndpoint);
            $delivery['endpoint_url'] = $pushEndpoint;
            $delivery['authorization_header'] = self::validatedAuthorization($pushAuthorization);
        }
        $request = [
            'delivery' => $delivery,
            'events_requested' => SecurityEventVerifier::ACTIONABLE_EVENTS,
        ];
        if ($description !== '') {
            $request['description'] = self::boundedText($description, 255, 'stream description');
        }
        $response = $this->jsonRequest(
            'POST',
            $this->endpoint($metadata->configurationEndpoint(), 'configuration'),
            $request,
            $metadata,
            $authorization
        );
        if ($response->status !== 201) {
            $this->unexpected($response, 'create stream', [409]);
        }
        return $this->streamConfiguration(
            $metadata,
            $response->jsonObject(),
            null,
            $method,
            $method === SharedSignalsMetadata::PUSH_METHOD ? $pushEndpoint : null
        );
    }

    /** @return array<string,mixed> */
    public function readStream(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $streamId,
        string $method,
        ?string $expectedDeliveryEndpoint = null,
        ?string $audience = null
    ): array {
        $streamId = self::streamId($streamId);
        $response = $this->authorizedRequest(
            'GET',
            self::withQuery($this->endpoint($metadata->configurationEndpoint(), 'configuration'), [
                'stream_id' => $streamId,
            ]),
            null,
            $metadata,
            $authorization
        );
        if ($response->status !== 200) {
            $this->unexpected($response, 'read stream', [404]);
        }
        return $this->streamConfiguration(
            $metadata,
            $response->jsonObject(),
            $streamId,
            $method,
            $expectedDeliveryEndpoint,
            $audience
        );
    }

    /** @return array<string,mixed> */
    public function updateStream(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $streamId,
        string $method,
        ?string $pushEndpoint = null,
        ?string $pushAuthorization = null,
        ?string $audience = null,
        string $description = ''
    ): array {
        $this->requireDelivery($metadata, $method);
        $request = [
            'stream_id' => self::streamId($streamId),
            'events_requested' => SecurityEventVerifier::ACTIONABLE_EVENTS,
            'delivery' => ['method' => $method],
        ];
        if ($method === SharedSignalsMetadata::PUSH_METHOD) {
            if ($pushEndpoint === null || $pushAuthorization === null) {
                throw new ProtocolException('Push stream updates require its receiver endpoint and authorization');
            }
            HttpClient::assertHttpsUrl($pushEndpoint);
            $request['delivery']['endpoint_url'] = $pushEndpoint;
            $request['delivery']['authorization_header'] = self::validatedAuthorization($pushAuthorization);
        }
        if ($description !== '') {
            $request['description'] = self::boundedText($description, 255, 'stream description');
        }
        $response = $this->jsonRequest(
            'PATCH',
            $this->endpoint($metadata->configurationEndpoint(), 'configuration'),
            $request,
            $metadata,
            $authorization
        );
        if ($response->status !== 200) {
            $this->unexpected($response, 'update stream', [202, 404]);
        }
        return $this->streamConfiguration(
            $metadata,
            $response->jsonObject(),
            $request['stream_id'],
            $method,
            $method === SharedSignalsMetadata::PUSH_METHOD ? $pushEndpoint : null,
            $audience
        );
    }

    public function deleteStream(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $streamId
    ): void {
        $response = $this->authorizedRequest(
            'DELETE',
            self::withQuery($this->endpoint($metadata->configurationEndpoint(), 'configuration'), [
                'stream_id' => self::streamId($streamId),
            ]),
            null,
            $metadata,
            $authorization
        );
        if ($response->status !== 204) {
            $this->unexpected($response, 'delete stream', [404]);
        }
    }

    /** @return array{stream_id:string,status:string,reason?:string} */
    public function readStatus(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $streamId
    ): array {
        $streamId = self::streamId($streamId);
        $response = $this->authorizedRequest(
            'GET',
            self::withQuery($this->endpoint($metadata->statusEndpoint(), 'status'), ['stream_id' => $streamId]),
            null,
            $metadata,
            $authorization
        );
        if ($response->status !== 200) {
            $this->unexpected($response, 'read stream status', [404]);
        }
        return $this->streamStatus($response->jsonObject(), $streamId);
    }

    /** @return array{stream_id:string,status:string,reason?:string} */
    public function updateStatus(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $streamId,
        string $status,
        string $reason = ''
    ): array {
        $request = ['stream_id' => self::streamId($streamId), 'status' => self::status($status)];
        if ($reason !== '') {
            $request['reason'] = self::boundedText($reason, 255, 'stream status reason');
        }
        $response = $this->jsonRequest(
            'POST',
            $this->endpoint($metadata->statusEndpoint(), 'status'),
            $request,
            $metadata,
            $authorization
        );
        if ($response->status !== 200) {
            $this->unexpected($response, 'update stream status', [404]);
        }
        return $this->streamStatus($response->jsonObject(), $request['stream_id']);
    }

    /**
     * @param string[] $acknowledged
     * @param array<string,array{err:string,description:string}> $errors
     * @return array{sets:array<string,string>,more_available:bool}
     */
    public function poll(
        SharedSignalsMetadata $metadata,
        string $authorization,
        string $endpoint,
        array $acknowledged = [],
        array $errors = [],
        int $maximumEvents = self::MAX_POLL_EVENTS
    ): array {
        if (!$metadata->supportsDelivery(SharedSignalsMetadata::POLL_METHOD)) {
            throw new ProtocolException('The transmitter does not advertise poll delivery');
        }
        HttpClient::assertHttpsUrl($endpoint);
        if ($maximumEvents < 0 || $maximumEvents > self::MAX_POLL_EVENTS) {
            throw new ProtocolException('The poll event limit is invalid');
        }
        $request = ['maxEvents' => $maximumEvents, 'returnImmediately' => true];
        if ($acknowledged !== []) {
            $request['ack'] = array_values(array_map([self::class, 'streamId'], $acknowledged));
        }
        if ($errors !== []) {
            if (count($errors) > self::MAX_POLL_EVENTS) {
                throw new ProtocolException('Too many poll delivery errors were supplied');
            }
            $request['setErrs'] = $errors;
        }
        $response = $this->jsonRequest('POST', $endpoint, $request, $metadata, $authorization, $errors !== []);
        if ($response->status !== 200) {
            $this->unexpected($response, 'poll stream', []);
        }
        $body = $response->jsonObject();
        $sets = $body['sets'] ?? null;
        if (!is_array($sets) || array_is_list($sets) || count($sets) > self::MAX_POLL_EVENTS) {
            throw new ProtocolException('The poll endpoint returned an invalid SET collection');
        }
        foreach ($sets as $jti => $set) {
            if (!is_string($jti) || self::streamId($jti) !== $jti
                || !is_string($set) || $set === '' || strlen($set) > JwtVerifier::MAX_JWT_BYTES) {
                throw new ProtocolException('The poll endpoint returned an invalid Security Event Token');
            }
        }
        if (isset($body['moreAvailable']) && !is_bool($body['moreAvailable'])) {
            throw new ProtocolException('The poll endpoint returned an invalid availability flag');
        }
        return ['sets' => $sets, 'more_available' => (bool)($body['moreAvailable'] ?? false)];
    }

    public static function validatedAuthorization(string $value): string
    {
        $value = trim($value);
        if (strlen($value) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $value)
            || !preg_match('#^(?:Bearer [A-Za-z0-9._~+/-]+=*|Basic [A-Za-z0-9+/]+=*)$#D', $value)) {
            throw new ProtocolException('The Shared Signals authorization value is invalid');
        }
        return $value;
    }

    /** @return array<string,mixed> */
    private function streamConfiguration(
        SharedSignalsMetadata $metadata,
        array $configuration,
        ?string $expectedStreamId,
        string $expectedMethod,
        ?string $expectedDeliveryEndpoint = null,
        ?string $expectedAudience = null
    ): array {
        $streamId = self::streamId((string)($configuration['stream_id'] ?? ''));
        if ($expectedStreamId !== null && !hash_equals($expectedStreamId, $streamId)) {
            throw new ProtocolException('The transmitter returned another Shared Signals stream');
        }
        if (!is_string($configuration['iss'] ?? null)
            || !hash_equals($metadata->issuer(), $configuration['iss'])) {
            throw new ProtocolException('The stream issuer does not exactly match Shared Signals discovery');
        }
        $audiences = is_string($configuration['aud'] ?? null)
            ? [$configuration['aud']] : ($configuration['aud'] ?? null);
        if (!is_array($audiences) || !array_is_list($audiences) || $audiences === [] || count($audiences) > 16
            || array_filter($audiences, static fn($value): bool => is_string($value) && $value !== ''
                && strlen($value) <= 255 && !preg_match('/[\x00-\x1f\x7f]/', $value)) !== $audiences) {
            throw new ProtocolException('The transmitter returned an invalid Shared Signals audience');
        }
        if ($expectedAudience !== null && !in_array($expectedAudience, $audiences, true)) {
            throw new ProtocolException('The stream audience does not include this receiver');
        }
        if ($expectedAudience === null && count($audiences) !== 1) {
            throw new ProtocolException('A new stream must identify one unambiguous receiver audience');
        }
        $delivery = $configuration['delivery'] ?? null;
        if (!is_array($delivery) || array_is_list($delivery)
            || !is_string($delivery['method'] ?? null) || !hash_equals($expectedMethod, $delivery['method'])
            || !is_string($delivery['endpoint_url'] ?? null)) {
            throw new ProtocolException('The transmitter returned another Shared Signals delivery method');
        }
        HttpClient::assertHttpsUrl($delivery['endpoint_url']);
        if ($expectedDeliveryEndpoint !== null
            && !hash_equals($expectedDeliveryEndpoint, $delivery['endpoint_url'])) {
            throw new ProtocolException('The transmitter returned another Shared Signals delivery endpoint');
        }
        foreach (['events_supported', 'events_requested', 'events_delivered'] as $field) {
            if (isset($configuration[$field]) && (!is_array($configuration[$field])
                || !array_is_list($configuration[$field]) || count($configuration[$field]) > 128
                || array_filter($configuration[$field], static fn($value): bool => is_string($value)
                    && $value !== '' && strlen($value) <= 512 && !preg_match('/[\x00-\x20\x7f]/', $value))
                    !== $configuration[$field])) {
                throw new ProtocolException(sprintf('The transmitter returned invalid %s', $field));
            }
        }
        if (!isset($configuration['events_delivered'])) {
            throw new ProtocolException('The transmitter did not identify delivered Shared Signals events');
        }
        $requested = $configuration['events_requested'] ?? null;
        if (!is_array($requested)) {
            throw new ProtocolException('The transmitter did not retain the requested Shared Signals events');
        }
        $expectedEvents = SecurityEventVerifier::ACTIONABLE_EVENTS;
        sort($requested);
        sort($expectedEvents);
        if ($requested !== $expectedEvents
            || array_diff($configuration['events_delivered'], SecurityEventVerifier::ACTIONABLE_EVENTS) !== []) {
            throw new ProtocolException('The transmitter returned another Shared Signals event selection');
        }
        return $configuration + [
            'audience' => $expectedAudience ?? $audiences[0],
            'poll_endpoint' => $expectedMethod === SharedSignalsMetadata::POLL_METHOD
                ? $delivery['endpoint_url'] : '',
        ];
    }

    /** @return array{stream_id:string,status:string,reason?:string} */
    private function streamStatus(array $value, string $streamId): array
    {
        if (!is_string($value['stream_id'] ?? null) || !hash_equals($streamId, $value['stream_id'])) {
            throw new ProtocolException('The transmitter returned another Shared Signals stream status');
        }
        $result = ['stream_id' => $streamId, 'status' => self::status((string)($value['status'] ?? ''))];
        if (isset($value['reason'])) {
            if (!is_string($value['reason'])) {
                throw new ProtocolException('The transmitter returned an invalid stream status reason');
            }
            $result['reason'] = self::boundedText($value['reason'], 255, 'stream status reason');
        }
        return $result;
    }

    private function jsonRequest(
        string $method,
        string $url,
        array $body,
        SharedSignalsMetadata $metadata,
        string $authorization,
        bool $withLanguage = false
    ): HttpResponse {
        $headers = ['Content-Type: application/json'];
        if ($withLanguage) {
            $headers[] = 'Content-Language: en';
        }
        return $this->authorizedRequest(
            $method,
            $url,
            json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            $metadata,
            $authorization,
            $headers
        );
    }

    private function authorizedRequest(
        string $method,
        string $url,
        ?string $body,
        SharedSignalsMetadata $metadata,
        string $authorization,
        array $headers = []
    ): HttpResponse {
        $authorization = self::validatedAuthorization($authorization);
        $specification = str_starts_with($authorization, 'Bearer ')
            ? SharedSignalsMetadata::OAUTH_AUTHORIZATION : SharedSignalsMetadata::BASIC_AUTHORIZATION;
        if (!$metadata->supportsAuthorization($specification)) {
            throw new ProtocolException(
                'Shared Signals discovery does not advertise the configured authorization scheme'
            );
        }
        $headers[] = 'Authorization: ' . $authorization;
        return $this->http->request($method, $url, $body, $headers, self::MAX_BYTES);
    }

    private function endpoint(?string $endpoint, string $name): string
    {
        if ($endpoint === null) {
            throw new ProtocolException(sprintf('Shared Signals discovery has no %s endpoint', $name));
        }
        return $endpoint;
    }

    private function requireDelivery(SharedSignalsMetadata $metadata, string $method): void
    {
        if (!in_array($method, [SharedSignalsMetadata::PUSH_METHOD, SharedSignalsMetadata::POLL_METHOD], true)
            || !$metadata->supportsDelivery($method)) {
            throw new ProtocolException(
                'The transmitter does not advertise the selected Shared Signals delivery method'
            );
        }
    }

    private function unexpected(HttpResponse $response, string $operation, array $known): never
    {
        $detail = in_array($response->status, $known, true) ? ' with a defined non-success result' : '';
        throw new ProtocolException(sprintf(
            'The transmitter could not %s%s (HTTP %d)',
            $operation,
            $detail,
            $response->status
        ));
    }

    private static function streamId(string $value): string
    {
        if ($value === '' || strlen($value) > 255 || !preg_match('/^[A-Za-z0-9._~-]+$/D', $value)) {
            throw new ProtocolException('The Shared Signals stream identifier is invalid');
        }
        return $value;
    }

    private static function status(string $value): string
    {
        if (!in_array($value, ['enabled', 'paused', 'disabled'], true)) {
            throw new ProtocolException('The Shared Signals stream status is invalid');
        }
        return $value;
    }

    private static function boundedText(string $value, int $maximum, string $label): string
    {
        if (strlen($value) > $maximum || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            throw new ProtocolException(sprintf('The Shared Signals %s is invalid', $label));
        }
        return $value;
    }

    private static function withQuery(string $url, array $values): string
    {
        return $url . (str_contains($url, '?') ? '&' : '?')
            . http_build_query($values, '', '&', PHP_QUERY_RFC3986);
    }
}
