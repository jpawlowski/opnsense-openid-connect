<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** Authenticated PAR exchange shared by interactive logins, diagnostics and recovery probes. */
final class ParClient
{
    public const MAX_BYTES = 262144;
    private bool $credentialsExercised = false;

    public function __construct(private readonly OpenIDConnect $settings, private readonly HttpClient $http)
    {
    }

    /** @param array<string,string> $parameters */
    public function push(ProviderMetadata $metadata, string $endpoint, array $parameters): string
    {
        $this->credentialsExercised = false;
        $headers = ['Accept: application/json'];
        $this->authenticate($metadata, $parameters, $headers);
        // A metadata refusal above never exposed the credentials to transport; from this point the authenticated
        // request is attempted even when the provider or network rejects it.
        $this->credentialsExercised = true;
        $response = $this->http->postForm($endpoint, $parameters, self::MAX_BYTES, $headers);
        if ($response->status === 429 || $response->status >= 500) {
            throw new ProviderUnavailableException(
                sprintf('The pushed authorization request endpoint returned HTTP %d', $response->status),
                $response->retryAfterSeconds()
            );
        }
        if ($response->status !== 201) {
            if ($response->contentType === 'application/json') {
                $error = $response->jsonObject()['error'] ?? null;
                if (in_array($error, ['temporarily_unavailable', 'server_error'], true)) {
                    throw new ProviderUnavailableException(
                        'The pushed authorization request endpoint is temporarily unavailable',
                        $response->retryAfterSeconds()
                    );
                }
            }
            throw new ProtocolException(sprintf(
                'The pushed authorization request endpoint returned HTTP %d',
                $response->status
            ));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException('The pushed authorization request endpoint did not return application/json');
        }
        $answer = $response->jsonObject();
        $requestUri = $answer['request_uri'] ?? null;
        if (!is_string($requestUri) || $requestUri === '' || strlen($requestUri) > 4096
            || preg_match('/[\x00-\x1f\x7f]/', $requestUri)) {
            throw new ProtocolException('The pushed authorization request endpoint returned no usable request URI');
        }
        if (!is_int($answer['expires_in'] ?? null) || $answer['expires_in'] <= 0) {
            throw new ProtocolException('The pushed authorization request endpoint returned no valid expiry');
        }
        return $requestUri;
    }

    public function credentialsExercised(): bool
    {
        return $this->credentialsExercised;
    }

    public function probe(ProviderMetadata $metadata, string $redirectUri): void
    {
        $endpoint = $metadata->pushedAuthorizationRequestEndpoint();
        if ($endpoint === null) {
            throw new ProtocolException('Discovery offers no pushed authorization request endpoint');
        }
        $verifier = JwtVerifier::base64UrlEncode(random_bytes(64));
        $parameters = [
            'response_type' => 'code',
            'client_id' => $this->settings->clientId(),
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $this->settings->scopes()),
            'state' => JwtVerifier::base64UrlEncode(random_bytes(32)),
            'nonce' => JwtVerifier::base64UrlEncode(random_bytes(32)),
            'code_challenge' => JwtVerifier::base64UrlEncode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            'max_age' => (string)$this->settings->maximumAuthenticationAge(),
        ];
        if ($this->settings->responseMode() !== 'query') {
            $parameters['response_mode'] = $this->settings->responseMode();
        }
        $requirement = $this->settings->authenticationRequirement();
        if ($requirement !== null) {
            $parameters = array_replace($parameters, $requirement->authorizationParameters());
        }
        if ($this->settings->selectAccount()) {
            $parameters['prompt'] = 'select_account';
        }
        $this->push($metadata, $endpoint, $parameters);
    }

    /** @param array<string,string> $fields @param string[] $headers */
    private function authenticate(ProviderMetadata $metadata, array &$fields, array &$headers): void
    {
        $method = $metadata->tokenEndpointAuthMethod($this->settings->tokenAuthMethod());
        if ($method === 'client_secret_basic') {
            $credentials = urlencode($this->settings->clientId()) . ':' . urlencode($this->settings->clientSecret());
            $headers[] = 'Authorization: Basic ' . base64_encode($credentials);
            return;
        }
        if ($method === 'client_secret_post') {
            $fields['client_secret'] = $this->settings->clientSecret();
            return;
        }
        throw new ProtocolException('No supported token endpoint authentication method is available');
    }
}
