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

/** Authenticated PAR exchange shared by interactive logins, diagnostics and recovery probes. */
final class ParClient
{
    public const MAX_BYTES = 262144;
    private ClientAuthenticator $clientAuthenticator;
    private bool $credentialsExercised = false;
    private ?HttpResponse $lastResponse = null;
    private RequestObjectSigner $requestObjectSigner;

    public function __construct(
        private readonly OpenIDConnect $settings,
        private readonly HttpClient $http,
        private ?ClientAuthentication $clientAuthentication = null,
        ?RequestObjectSigner $requestObjectSigner = null,
        ?ClientAuthenticator $clientAuthenticator = null
    ) {
        $this->requestObjectSigner = $requestObjectSigner ?? new RequestObjectSigner();
        $this->clientAuthenticator = $clientAuthenticator ?? new ClientAuthenticator($settings);
    }

    /** @param array<string,string> $parameters */
    public function push(ProviderMetadata $metadata, string $endpoint, array $parameters): string
    {
        $this->credentialsExercised = false;
        $this->lastResponse = null;
        $headers = ['Accept: application/json'];
        $authentication = $this->authentication($metadata);
        $endpoint = $authentication->endpoint($metadata, 'pushed_authorization_request_endpoint') ?? $endpoint;
        $this->clientAuthenticator->authenticate(
            $metadata,
            $endpoint,
            ClientAuthenticator::TOKEN,
            $parameters,
            $headers,
            $metadata->issuer(),
            $authentication->method()
        );
        // A metadata refusal above never exposed the credentials to transport; from this point the authenticated
        // request is attempted even when the provider or network rejects it.
        $this->credentialsExercised = true;
        $response = $this->http->postForm(
            $endpoint,
            $parameters,
            self::MAX_BYTES,
            $headers,
            $authentication->certificate()
        );
        $this->lastResponse = $response;
        if ($response->status === 429 || $response->status >= 500) {
            throw new ProviderUnavailableException(
                sprintf(
                    'The pushed authorization request endpoint returned %s',
                    $response->diagnosticSummary()
                ),
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
                'The pushed authorization request endpoint returned %s; expected HTTP 201',
                $response->diagnosticSummary()
            ));
        }
        if ($response->contentType !== 'application/json') {
            throw new ProtocolException(sprintf(
                'The pushed authorization request endpoint returned %s; expected application/json',
                $response->diagnosticSummary()
            ));
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

    public function lastResponse(): ?HttpResponse
    {
        return $this->lastResponse;
    }

    public function probe(ProviderMetadata $metadata, string $redirectUri): void
    {
        $endpoint = $this->authentication($metadata)->endpoint(
            $metadata,
            'pushed_authorization_request_endpoint'
        );
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
        $key = $this->settings->requestObjectSigningKey();
        if ($metadata->requiresSignedRequestObject() && $key === '') {
            throw new ProtocolException('Discovery requires signed Request Objects but no signing key is selected');
        }
        if ($key !== '') {
            $parameters = [
                'client_id' => $this->settings->clientId(),
                'request' => $this->requestObjectSigner->sign($this->settings, $metadata, $parameters),
            ];
        }
        $this->push($metadata, $endpoint, $parameters);
    }

    private function authentication(ProviderMetadata $metadata): ClientAuthentication
    {
        return $this->clientAuthentication ??= ClientAuthentication::negotiate(
            $this->settings,
            $metadata,
            null,
            $this->clientAuthenticator
        );
    }
}
