<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** Check a public client registration without authenticating a user or consuming an authorization code. */
final class AuthorizationPreflight
{
    private const MAX_BYTES = 65536;
    private const REDIRECT_STATUSES = [301, 302, 303, 307, 308];

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
                'info',
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

        if (in_array($response->status, self::REDIRECT_STATUSES, true)) {
            $location = $response->headers['location'] ?? null;
            if (is_string($location) && $this->isAcceptedCallback($location, $redirectUri, $state)) {
                return $this->result(
                    'success',
                    gettext('Client ID and callback accepted'),
                    gettext(
                        'A silent authorization request returned to the exact callback without authenticating a user.'
                    ),
                    'live'
                );
            }
            return $this->result(
                'warning',
                gettext('Provider response was inconclusive'),
                gettext('The provider redirected the silent request somewhere other than the exact OPNsense callback.'),
                'live'
            );
        }

        if ($response->status >= 400) {
            return $this->result(
                'error',
                gettext('Client registration rejected'),
                gettext(
                    'The authorization endpoint rejected the Client ID, callback, or preliminary request before sign-in.'
                ),
                'live'
            );
        }

        return $this->result(
            'warning',
            gettext('Provider response was inconclusive'),
            gettext('The provider did not return the silent request to OPNsense; the full browser test is still required.'),
            'live'
        );
    }

    /** @return array{status:string,value:string,note:string,verification:string} */
    private function result(string $status, string $value, string $note, string $verification): array
    {
        return compact('status', 'value', 'note', 'verification');
    }

    private function isAcceptedCallback(string $location, string $redirectUri, string $state): bool
    {
        if (str_contains($location, '#') || !str_starts_with($location, $redirectUri . '?')) {
            return false;
        }
        if (!hash_equals($redirectUri, substr($location, 0, strlen($redirectUri)))) {
            return false;
        }
        parse_str((string)parse_url($location, PHP_URL_QUERY), $parameters);
        return is_string($parameters['state'] ?? null) && hash_equals($state, $parameters['state']);
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
