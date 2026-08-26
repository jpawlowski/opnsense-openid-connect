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

/** Check a public client registration without authenticating a user or consuming an authorization code. */
final class AuthorizationPreflight
{
    private const MAX_BYTES = 65536;
    private const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
    private const SILENT_INTERACTION_ERRORS = [
        'login_required', 'interaction_required', 'account_selection_required', 'consent_required',
    ];

    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @return array{status:string,value:string,note:string,verification:string} */
    public function check(
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        ?string $redirectUri,
        bool $parCoversRegistration = true
    ): array {
        if ($settings->clientId() === '' || $redirectUri === null) {
            return $this->result(
                'warning',
                gettext('Not tested'),
                gettext('Enter a Client ID and use an accepted HTTPS WebGUI origin to test the registration.'),
                'not-tested'
            );
        }
        if ($metadata->requiresPushedAuthorizationRequests()
            || ($parCoversRegistration && $metadata->pushedAuthorizationRequestEndpoint() !== null
                && $settings->parMode() !== 'disabled')) {
            return $this->result(
                'success',
                gettext('Covered by PAR'),
                gettext('The authenticated PAR check validates the client and callback before browser sign-in.'),
                'skipped'
            );
        }
        if ($metadata->requiresSignedRequestObject() || $settings->requestObjectSigningKey() !== '') {
            return $this->result(
                'info',
                gettext('Covered by Test sign-in'),
                gettext('A signed Request Object is in use, so a reduced unsigned probe is not sent.'),
                'skipped'
            );
        }
        if ($settings->responseMode() !== 'query') {
            return $this->result(
                'info',
                gettext('Covered by Test sign-in'),
                gettext('The selected response mode cannot be verified by a reduced query-response probe.'),
                'skipped'
            );
        }

        $state = self::randomValue();
        $verifier = self::randomValue();
        $url = HttpClient::appendQueryParameters($metadata->authorizationEndpoint(), [
            'response_type' => 'code',
            'client_id' => $settings->clientId(),
            'redirect_uri' => $redirectUri,
            'scope' => 'openid',
            'state' => $state,
            'nonce' => self::randomValue(),
            'code_challenge' => self::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            'response_mode' => 'query',
            'prompt' => 'none',
        ]);
        $response = $this->http->getFirstResponse($url, self::MAX_BYTES, [
            'Accept: text/html, application/xhtml+xml, application/json',
        ]);
        $responseNote = sprintf(gettext(' Provider response: %s.'), $response->diagnosticSummary());

        if (in_array($response->status, self::REDIRECT_STATUSES, true)) {
            $location = $response->headers['location'] ?? null;
            $callback = is_string($location)
                ? $this->callbackOutcome($location, $redirectUri, $state)
                : null;
            if ($callback === 'accepted') {
                return $this->result(
                    'success',
                    gettext('Client ID and callback accepted'),
                    gettext(
                        'A silent authorization request returned to the exact callback without authenticating a user.'
                    ) . $responseNote,
                    'live'
                );
            }
            if ($callback === 'rejected') {
                return $this->result(
                    'error',
                    gettext('Client registration rejected'),
                    gettext(
                        'The authorization endpoint rejected the Client ID, callback, or preliminary request before sign-in.'
                    ) . $responseNote,
                    'live'
                );
            }
            return $this->result(
                'warning',
                gettext('Provider response was inconclusive'),
                gettext('The provider redirected the silent request somewhere other than the exact OPNsense callback.')
                    . $responseNote,
                'live'
            );
        }

        if ($response->status >= 400) {
            return $this->result(
                'error',
                gettext('Client registration rejected'),
                gettext(
                    'The authorization endpoint rejected the Client ID, callback, or preliminary request before sign-in.'
                ) . $responseNote,
                'live'
            );
        }

        return $this->result(
            'warning',
            gettext('Provider response was inconclusive'),
            gettext('The provider did not return the silent request to OPNsense; the full browser test is still required.')
                . $responseNote,
            'live'
        );
    }

    /** @return array{status:string,value:string,note:string,verification:string} */
    private function result(string $status, string $value, string $note, string $verification): array
    {
        return compact('status', 'value', 'note', 'verification');
    }

    private function callbackOutcome(string $location, string $redirectUri, string $state): ?string
    {
        if (str_contains($location, '#') || !str_starts_with($location, $redirectUri . '?')) {
            return null;
        }
        if (!hash_equals($redirectUri, substr($location, 0, strlen($redirectUri)))) {
            return null;
        }
        parse_str((string)parse_url($location, PHP_URL_QUERY), $parameters);
        if (!is_string($parameters['state'] ?? null) || !hash_equals($state, $parameters['state'])) {
            return null;
        }
        $error = $parameters['error'] ?? null;
        if (!is_string($error) || $error === '') {
            return 'inconclusive';
        }
        if (array_key_exists('code', $parameters)
            || array_key_exists('id_token', $parameters)
            || array_key_exists('access_token', $parameters)) {
            return 'rejected';
        }
        return in_array($error, self::SILENT_INTERACTION_ERRORS, true) ? 'accepted' : 'rejected';
    }

    private static function randomValue(): string
    {
        return self::base64Url(random_bytes(32));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
