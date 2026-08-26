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

/** One live, side-effect-bounded provider preflight shared by setup diagnostics. */
final class ProviderProbe
{
    public const FORM_FIELDS = [
        'openidconnect_provider_url', 'openidconnect_app_code', 'openidconnect_provider_profile',
        'openidconnect_microsoft_audience', 'openidconnect_client_id', 'openidconnect_client_secret',
        'openidconnect_signing_certificate', 'openidconnect_token_auth', 'openidconnect_client_certificate',
        'openidconnect_retiring_client_certificate', 'openidconnect_certificate_bound_access_tokens',
        'openidconnect_par_mode', 'openidconnect_request_object_key',
        'openidconnect_scopes',
        'openidconnect_response_mode', 'openidconnect_claims_source', 'openidconnect_max_age',
        'openidconnect_select_account', 'openidconnect_required_authentication', 'openidconnect_acr_request',
        'openidconnect_acr_values', 'openidconnect_amr_values', 'openidconnect_entra_auth_context',
        'openidconnect_origin_policy', 'openidconnect_standard_https_port',
        'openidconnect_redirect_urls', 'openidconnect_tls_offloading',
    ];

    private $clientAssertionFactory;

    public function __construct(private readonly HttpClient $http, ?callable $clientAssertionFactory = null)
    {
        $this->clientAssertionFactory = $clientAssertionFactory;
    }

    /** @param array<string,string> $values */
    public static function settings(array $values): OpenIDConnect
    {
        $allowed = ['type' => OpenIDConnect::TYPE];
        foreach (self::FORM_FIELDS as $field) {
            $allowed[$field] = (string)($values[$field] ?? '');
        }
        $settings = new OpenIDConnect();
        $settings->setProperties($allowed);
        return $settings;
    }

    /** @return array<int,array<string,mixed>> */
    public function checks(OpenIDConnect $settings, ?string $redirectUri): array
    {
        $metadata = ProviderMetadata::discover(
            $settings->issuerUrl(),
            $this->http,
            $settings->discoveryIssuerTemplate(),
            true,
            false
        );
        $checks = $this->metadataChecks($settings, $metadata);
        try {
            $keySet = (new JwtVerifier($this->http))->probeKeySetDetails($metadata->jwksUri());
            $checks[] = self::check(
                gettext('Signing keys'),
                sprintf(gettext('%d usable key(s)'), $keySet['count']),
                'success',
                gettext('The JWKS endpoint contains supported signing material. Provider response: ')
                    . $keySet['response']->diagnosticSummary() . '.',
                ['opnsense', 'idp'],
                'live',
                'signing-keys'
            );
        } catch (\Throwable $error) {
            $checks[] = self::check(
                gettext('Signing keys'),
                gettext('Live check failed'),
                'error',
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live',
                'signing-keys'
            );
        }
        $checks[] = $this->requestObjectCheck($settings, $metadata);
        try {
            $authorization = (new AuthorizationPreflight($this->http))->check($settings, $metadata, $redirectUri);
            $checks[] = self::check(
                gettext('Authorization registration'),
                $authorization['value'],
                $authorization['status'],
                $authorization['note'],
                ['opnsense', 'idp'],
                $authorization['verification'],
                'authorization-registration'
            );
        } catch (\Throwable $error) {
            $checks[] = self::failureCheck(
                gettext('Authorization registration'),
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live',
                'authorization-registration'
            );
        }
        $checks[] = $this->parCheck($settings, $metadata, $redirectUri);
        return $checks;
    }

    /** @param array<int,array<string,mixed>> $checks */
    public static function answer(array $checks, string $accepted, string $warning, string $failed): array
    {
        $warnings = count(array_filter(
            $checks,
            static fn(array $check): bool => ($check['status'] ?? '') === 'warning'
        ));
        $errors = count(array_filter(
            $checks,
            static fn(array $check): bool => ($check['status'] ?? '') === 'error'
        ));
        $overall = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'success');
        return [
            'status' => 'ok',
            'overall' => $overall,
            'headline' => $errors > 0 ? sprintf($failed, $errors)
                : ($warnings === 0 ? $accepted : sprintf($warning, $warnings)),
            'checks' => $checks,
            'summary' => implode("\n", array_map(
                static fn(array $check): string => sprintf(
                    '%s: %s',
                    (string)($check['label'] ?? ''),
                    (string)($check['value'] ?? '')
                ),
                $checks
            )),
        ];
    }

    /** @return array<int,array<string,mixed>> */
    public static function healthReadiness(OpenIDConnect $settings, ?string $redirectUri): array
    {
        $complete = self::clientConfigurationReady($settings);
        $transportReady = $settings->isWebGuiTransportReady();
        $transport = $transportReady && $redirectUri !== null;
        return [
            self::check(
                gettext('Client configuration'),
                $complete ? gettext('Complete confidential client') : gettext('Incomplete'),
                $complete ? 'success' : 'error',
                $complete
                    ? gettext('Exact issuer URL, Client ID and the selected client credential are present.')
                    : gettext('Enter Exact issuer URL, Client ID and the selected client credential.'),
                ['opnsense'],
                'configuration',
                'client-configuration'
            ),
            self::check(
                gettext('WebGUI transport'),
                $transport ? gettext('Accepted') : gettext('Blocked'),
                $transport ? 'success' : 'error',
                $transport
                    ? gettext('The current form provides an accepted HTTPS WebGUI origin.')
                    : ($transportReady
                        ? gettext('The current WebGUI origin is not accepted by these form values.')
                        : $settings->webGuiTransportProblem()),
                ['browser', 'opnsense'],
                'configuration',
                'webgui-transport'
            ),
            self::webGuiOriginsCheck($settings),
        ];
    }

    /** @return array<string,mixed> */
    public static function webGuiOriginsCheck(OpenIDConnect $settings): array
    {
        $origins = $settings->effectiveWebGuiOrigins();
        return self::check(
            gettext('Effective WebGUI origins'),
            $origins === [] ? gettext('None') : implode(', ', $origins),
            $origins === [] ? 'error' : 'success',
            $origins === []
                ? gettext('No browser origin is accepted for OpenID Connect sign-in.')
                : gettext('OpenID Connect sign-in can start from exactly these browser origins.'),
            ['browser', 'opnsense'],
            'configuration',
            'webgui-origins'
        );
    }

    /** @return array<string,mixed> */
    private function requestObjectCheck(OpenIDConnect $settings, ProviderMetadata $metadata): array
    {
        $key = $settings->requestObjectSigningKey();
        if ($key === '') {
            return self::check(
                gettext('JWT-secured authorization request'),
                $metadata->requiresSignedRequestObject() ? gettext('Required by provider') : gettext('Disabled'),
                $metadata->requiresSignedRequestObject() ? 'error' : 'success',
                $metadata->requiresSignedRequestObject()
                    ? gettext('Select and register a Request Object signing key before sign-in.')
                    : gettext('Select a registered OPNsense certificate to sign RFC 9101 Request Objects.'),
                ['opnsense'],
                'configuration',
                'request-object'
            );
        }
        try {
            $algorithm = (new RequestObjectSigner())->selectedAlgorithm($settings, $metadata);
            return self::check(
                gettext('JWT-secured authorization request'),
                $algorithm,
                'success',
                sprintf(gettext('Request Objects use the selected certificate with kid %s.'), $key),
                ['opnsense'],
                'configuration',
                'request-object'
            );
        } catch (\Throwable $error) {
            return self::check(
                gettext('JWT-secured authorization request'),
                gettext('No compatible signing key'),
                'error',
                $error->getMessage(),
                ['opnsense'],
                'configuration',
                'request-object'
            );
        }
    }

    /** @return array<string,mixed> */
    public static function credentialsCheck(array $par): array
    {
        if (($par['credentials_exercised'] ?? false) === true) {
            return self::check(
                gettext('Client credentials'),
                gettext('Exercised by PAR'),
                ($par['status'] ?? '') === 'success' ? 'success' : 'info',
                gettext('The live PAR request used the selected client authentication method.'),
                ['opnsense', 'idp'],
                'live',
                'client-credentials'
            );
        }
        return self::check(
            gettext('Client credentials'),
            gettext('Not exercised'),
            'info',
            gettext('This provider path did not use the credentials; Test sign-in exercises them with a code.'),
            ['opnsense', 'idp'],
            'not-tested',
            'client-credentials'
        );
    }

    /** @param string[] $actors @return array<string,mixed> */
    public static function failureCheck(
        string $label,
        string $note,
        array $actors,
        string $verification,
        string $guidance = 'provider-preflight'
    ): array {
        return self::check(
            $label,
            gettext('Live check failed'),
            'error',
            $note,
            $actors,
            $verification,
            $guidance
        );
    }

    /** @return array<int,array<string,mixed>> */
    private function metadataChecks(OpenIDConnect $settings, ProviderMetadata $metadata): array
    {
        $list = static function ($value): array {
            return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
        };
        $algorithms = array_values(array_intersect(
            $list($metadata->get('id_token_signing_alg_values_supported', [])),
            JwtVerifier::ALGORITHMS
        ));
        $authProblem = null;
        try {
            if ($settings->clientId() === '') {
                throw new \RuntimeException(gettext('Enter the client ID before testing client authentication.'));
            }
            $authenticator = new ClientAuthenticator($settings, $this->clientAssertion($settings));
            $authentication = ClientAuthentication::negotiate($settings, $metadata, null, $authenticator);
            if (in_array($authentication->method(), ['client_secret_basic', 'client_secret_post'], true)
                && $settings->clientSecret() === '') {
                throw new \RuntimeException(
                    gettext('Enter the client secret required by the selected authentication method.')
                );
            }
            $authMethods = [$authentication->method()];
        } catch (\Throwable $error) {
            $authMethods = [];
            $authProblem = $error->getMessage();
        }
        $advertisedAssertionAlgorithms = $metadata->get(
            'token_endpoint_auth_signing_alg_values_supported',
            []
        );
        $assertionAlgorithms = $settings->clientAssertionAlgorithms(
            'token_endpoint_auth_signing_alg_values_supported',
            is_array($advertisedAssertionAlgorithms) ? $advertisedAssertionAlgorithms : []
        );
        $advertisedResponseModes = $metadata->get('response_modes_supported', null);
        $responseModes = $list($advertisedResponseModes ?? ['query', 'fragment']);
        $pkceAdvertised = in_array(
            'S256',
            $list($metadata->get('code_challenge_methods_supported', [])),
            true
        );
        $dpopAlgorithms = $metadata->dpopSigningAlgorithms();
        $dpopAdvertised = $metadata->supportsDpop();
        $dpopUsable = $dpopAdvertised && $settings->supportsDpopAccessTokens();
        $userInfo = $metadata->userInfoEndpoint();
        $profile = $settings->providerProfile();
        $profileLabels = OpenIDConnect::providerProfileOptions();
        $checks = [
            self::check(
                gettext('Discovery'),
                $metadata->issuer(),
                'success',
                gettext(
                    'The document was fetched live and its issuer matches exactly. Provider response: HTTP 200; '
                    . 'Content-Type: application/json.'
                ),
                ['opnsense', 'idp'],
                'live',
                'discovery'
            ),
            self::check(
                gettext('Provider profile'),
                $profileLabels[$profile] ?? $profile,
                'success',
                gettext('Provider-specific defaults never relax protocol validation.'),
                ['opnsense'],
                'configuration',
                'provider-profile'
            ),
            self::check(
                gettext('Authorization endpoint'),
                $metadata->authorizationEndpoint(),
                'success',
                gettext('Discovery advertises this browser path; Test sign-in exercises it.'),
                ['browser', 'idp'],
                'not-tested',
                'authorization-endpoint'
            ),
            self::check(
                gettext('Token endpoint'),
                $metadata->tokenEndpoint(),
                'success',
                gettext('Discovery advertises this mandatory server path; Test sign-in exercises it with a code.'),
                ['opnsense', 'idp'],
                'not-tested',
                'token-endpoint'
            ),
            self::check(
                gettext('UserInfo endpoint'),
                $userInfo ?? gettext('Not offered'),
                $userInfo !== null || $settings->claimsSource() !== 'userinfo' ? 'success' : 'error',
                $userInfo !== null
                    ? gettext('UserInfo can supply identity claims when configured or needed.')
                    : ($settings->claimsSource() === 'userinfo'
                        ? gettext('The selected claims source requires UserInfo, but the provider does not offer it.')
                        : gettext('UserInfo is optional for the selected claims source.')),
                ['opnsense', 'idp'],
                'not-tested',
                'userinfo'
            ),
            self::check(
                gettext('ID Token signatures'),
                implode(', ', $algorithms) ?: gettext('None supported'),
                $algorithms === [] ? 'error' : 'success',
                $algorithms === []
                    ? gettext('No supported asymmetric ID Token signature is advertised.')
                    : gettext('At least one supported asymmetric signature is advertised.'),
                ['opnsense'],
                'metadata',
                'id-token-signatures'
            ),
            self::check(
                gettext('Client authentication'),
                implode(', ', $authMethods) ?: gettext('None supported'),
                $authMethods === [] ? 'error' : 'success',
                $authMethods === []
                    ? ($authProblem ?? gettext('No usable token endpoint authentication method is available.'))
                    : gettext('At least one confidential-client authentication method is usable.'),
                ['opnsense'],
                'metadata',
                'client-authentication'
            ),
            self::check(
                gettext('Client assertion signatures'),
                implode(', ', array_intersect($assertionAlgorithms, ClientAssertion::ALGORITHMS))
                    ?: gettext('Not offered'),
                in_array('private_key_jwt', $authMethods, true)
                    ? ($assertionAlgorithms === [] ? 'warning' : 'success') : 'info',
                in_array('private_key_jwt', $authMethods, true)
                    ? ($assertionAlgorithms === []
                        ? gettext('No supported private-key JWT signing algorithm is advertised.')
                        : gettext('Private-key JWT can negotiate one of these asymmetric signatures.'))
                    : gettext('Private-key JWT client authentication is not selected.'),
                ['opnsense'],
                'metadata',
                'client-assertion-signatures'
            ),
            self::check(
                gettext('Certificate-bound access tokens'),
                $metadata->supportsCertificateBoundAccessTokens()
                    ? gettext('Advertised') : gettext('Not advertised'),
                $metadata->supportsCertificateBoundAccessTokens() ? 'success' : 'info',
                $metadata->supportsCertificateBoundAccessTokens()
                    ? gettext('The provider can bind access tokens to the mutual-TLS client certificate.')
                    : gettext('Certificate-bound access tokens cannot be required for this provider.'),
                ['opnsense'],
                'metadata',
                'certificate-bound-tokens'
            ),
            self::check(
                gettext('PKCE'),
                $pkceAdvertised ? 'S256' : gettext('S256 not advertised'),
                $pkceAdvertised ? 'success' : 'error',
                $pkceAdvertised
                    ? gettext('The provider explicitly advertises the required S256 method.')
                    : gettext(
                        'This client requires the provider to advertise PKCE S256; sign-in is refused without it.'
                    ),
                ['opnsense'],
                'metadata',
                'pkce'
            ),
            self::check(
                gettext('DPoP sender constraint'),
                $dpopAlgorithms === [] ? gettext('Not advertised') : implode(', ', $dpopAlgorithms),
                'success',
                $dpopUsable
                    ? gettext('ES256 is advertised; Test sign-in uses a proof-key-bound token flow.')
                    : ($dpopAdvertised
                        ? gettext(
                            'This profile documents a different key-bound ID Token extension; its access ' .
                            'token remains Bearer rather than being treated as RFC 9449 DPoP.'
                        )
                        : gettext('Bearer access tokens remain in use unless the provider advertises ES256 DPoP.')),
                ['opnsense'],
                'metadata',
                'dpop'
            ),
        ];
        if ($userInfo === null && $settings->claimsSource() !== 'userinfo') {
            $checks[4]['section'] = 'unsupported';
        }
        if ($dpopAlgorithms === []) {
            $checks[8]['section'] = 'unsupported';
        }
        $this->appendSelectedMetadataChecks(
            $checks,
            $settings,
            $metadata,
            $responseModes,
            $authMethods,
            $authProblem
        );
        return $checks;
    }

    /** @param array<int,array<string,mixed>> $checks @param string[] $responseModes
     *  @param string[] $authMethods */
    private function appendSelectedMetadataChecks(
        array &$checks,
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        array $responseModes,
        array $authMethods,
        ?string $authProblem
    ): void {
        $responseMode = $settings->responseMode();
        $modeSupported = in_array($responseMode, $responseModes, true);
        $modesAdvertised = is_array($metadata->get('response_modes_supported', null));
        $checks[] = self::check(
            gettext('Authorization response mode'),
            $responseMode,
            $modeSupported ? 'success' : 'error',
            !$modesAdvertised
                ? ($modeSupported
                    ? gettext('The selected mode is covered by the provider metadata omission default.')
                    : gettext('The selected mode is not covered by the provider metadata omission default.'))
                : ($modeSupported
                    ? gettext('The selected response mode is advertised.')
                    : gettext('The selected response mode is not advertised.')),
            ['idp', 'browser', 'opnsense'],
            'metadata',
            'response-mode'
        );
        if (str_ends_with($responseMode, '.jwt')) {
            $jarmAlgorithms = array_values(array_intersect(
                $metadata->authorizationResponseSigningAlgorithms(),
                JwtVerifier::ALGORITHMS
            ));
            $checks[] = self::check(
                gettext('JARM signatures'),
                implode(', ', $jarmAlgorithms) ?: gettext('None supported'),
                $jarmAlgorithms === [] ? 'error' : 'success',
                $jarmAlgorithms === []
                    ? gettext('The provider advertises no supported asymmetric JARM signature.')
                    : gettext('The signed authorization response can use a supported asymmetric signature.'),
                ['opnsense'],
                'metadata',
                'jarm'
            );
        }
        $tokenAuth = $settings->tokenAuthMethod();
        $selectedAuth = $tokenAuth === null ? gettext('Follow the provider') : $tokenAuth;
        $selectedAuthUsable = $authMethods !== [];
        $checks[] = self::check(
            gettext('Selected authentication method'),
            $selectedAuth,
            $selectedAuthUsable ? 'success' : 'error',
            $selectedAuthUsable
                ? gettext('The configured choice can use the provider metadata.')
                : ($authProblem ?? gettext('The selected client authentication method is not usable.')),
            ['opnsense'],
            'metadata',
            'selected-authentication'
        );
        $issuerAdvertised = $metadata->authorizationResponseIssuerSupported();
        $issuerCheck = self::check(
            gettext('Authorization response issuer'),
            $issuerAdvertised ? gettext('Advertised') : gettext('Not advertised'),
            'success',
            $issuerAdvertised
                ? gettext('The provider advertises RFC 9207 issuer identification.')
                : gettext('The distinct callback and frozen metadata still protect this provider from mix-up.'),
            ['idp', 'browser', 'opnsense'],
            'metadata',
            'authorization-response-issuer'
        );
        if (!$issuerAdvertised) {
            $issuerCheck['section'] = 'unsupported';
        }
        $checks[] = $issuerCheck;
        $signOutCheck = self::check(
            gettext('Provider sign-out'),
            $metadata->endSessionEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            $metadata->endSessionEndpoint() !== null || !$settings->redirectsLogoutMenu() ? 'success' : 'warning',
            $metadata->endSessionEndpoint() === null
                ? ($settings->redirectsLogoutMenu()
                    ? gettext('Redirecting the Log Out menu is selected, but Discovery offers no sign-out endpoint.')
                    : gettext('Provider sign-out is optional; local logout still works.'))
                : gettext('RP-initiated provider sign-out is available.'),
            ['browser', 'idp'],
            $metadata->endSessionEndpoint() === null ? 'metadata' : 'not-tested',
            'provider-signout'
        );
        if ($metadata->endSessionEndpoint() === null && !$settings->redirectsLogoutMenu()) {
            $signOutCheck['section'] = 'unsupported';
        }
        $checks[] = $signOutCheck;
        $revocationCheck = self::check(
            gettext('Token revocation'),
            $metadata->revocationEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'success',
            $metadata->revocationEndpoint() === null
                ? gettext('Token revocation is optional and will be skipped.')
                : gettext('Tokens can be revoked during provider-aware logout.'),
            ['opnsense', 'idp'],
            $metadata->revocationEndpoint() === null ? 'metadata' : 'not-tested',
            'token-revocation'
        );
        if ($metadata->revocationEndpoint() === null) {
            $revocationCheck['section'] = 'unsupported';
        }
        $checks[] = $revocationCheck;
        if ($settings->providerProfile() === 'entra' && !str_contains($metadata->issuer(), '/v2.0')) {
            $checks[] = self::check(
                gettext('Microsoft Entra issuer profile'),
                gettext('Tenant-specific v2.0 issuer expected'),
                'error',
                gettext('Do not use common, organizations, consumers or v1 metadata with this profile.'),
                ['opnsense'],
                'configuration',
                'entra-profile'
            );
        }
    }

    /** @return array<string,mixed> */
    private function parCheck(OpenIDConnect $settings, ProviderMetadata $metadata, ?string $redirectUri): array
    {
        $mode = $settings->parMode();
        $endpoint = $metadata->pushedAuthorizationRequestEndpoint();
        $required = $metadata->requiresPushedAuthorizationRequests();
        if ($mode === 'disabled') {
            return self::check(
                gettext('PAR endpoint'),
                $required ? gettext('Required by provider') : gettext('Skipped by setting'),
                $required ? 'error' : 'success',
                $required
                    ? gettext('The provider requires PAR, so it cannot be disabled.')
                    : gettext('No PAR request was sent because PAR is disabled.'),
                ['opnsense', 'idp'],
                'skipped',
                'par'
            );
        }
        if ($endpoint === null) {
            $check = self::check(
                gettext('PAR endpoint'),
                gettext('Not offered'),
                $mode === 'required' ? 'error' : 'success',
                $mode === 'required'
                    ? gettext('PAR is required locally but Discovery offers no endpoint.')
                    : gettext('Automatic mode uses a normal browser authorization request.'),
                ['opnsense', 'idp'],
                'metadata',
                'par'
            );
            if ($mode !== 'required') {
                $check['section'] = 'unsupported';
            }
            return $check;
        }
        if (!self::clientConfigurationReady($settings)) {
            return self::check(
                gettext('PAR endpoint'),
                gettext('Not tested'),
                'warning',
                gettext('Enter Client ID and the selected client credential to run the live PAR check.'),
                ['opnsense', 'idp'],
                'not-tested',
                'par'
            );
        }
        if ($redirectUri === null) {
            return self::check(
                gettext('PAR endpoint'),
                gettext('Not tested'),
                'error',
                gettext('The current WebGUI origin is not accepted by these form values.'),
                ['opnsense'],
                'configuration',
                'par'
            );
        }
        $key = ProviderRuntimeState::parKey($settings, $metadata);
        $client = new ParClient(
            $settings,
            $this->http,
            null,
            null,
            new ClientAuthenticator($settings, $this->clientAssertion($settings))
        );
        try {
            $client->probe($metadata, $redirectUri);
            ProviderRuntimeState::parAvailable($key);
            $response = $client->lastResponse();
            $check = self::check(
                gettext('PAR endpoint'),
                gettext('Live authenticated request accepted'),
                'success',
                gettext(
                    'PAR will be used automatically. The returned request URI was deliberately discarded; ' .
                    'no browser transaction was created.'
                ) . ($response === null ? '' : sprintf(
                    gettext(' Provider response: %s.'),
                    $response->diagnosticSummary()
                )),
                ['opnsense', 'idp'],
                'live',
                'par'
            );
            $check['credentials_exercised'] = $client->credentialsExercised();
            return $check;
        } catch (ProviderUnavailableException $error) {
            if ($mode === 'auto' && !$required) {
                ProviderRuntimeState::parUnavailable($key, $error->retryAfter());
                $check = self::check(
                    gettext('PAR endpoint'),
                    gettext('Temporarily unavailable; bypass active'),
                    'warning',
                    gettext('New logins use the browser authorization request while recovery runs in the background.'),
                    ['opnsense', 'idp'],
                    'live',
                    'par'
                );
                $check['credentials_exercised'] = $client->credentialsExercised();
                return $check;
            }
            $check = self::check(
                gettext('PAR endpoint'),
                gettext('Live check failed'),
                'error',
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live',
                'par'
            );
            $check['credentials_exercised'] = $client->credentialsExercised();
            return $check;
        } catch (\Throwable $error) {
            ProviderRuntimeState::parHardFailure($key);
            $check = self::check(
                gettext('PAR endpoint'),
                gettext('Live check failed'),
                'error',
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live',
                'par'
            );
            $check['credentials_exercised'] = $client->credentialsExercised();
            return $check;
        }
    }

    private function clientAssertion(OpenIDConnect $settings): ClientAssertion
    {
        $assertion = $this->clientAssertionFactory === null
            ? new ClientAssertion($settings) : ($this->clientAssertionFactory)($settings);
        if (!$assertion instanceof ClientAssertion) {
            throw new \LogicException('The provider probe client-assertion factory returned an invalid value');
        }
        return $assertion;
    }

    /** @param string[] $actors @return array<string,mixed> */
    private static function check(
        string $label,
        string $value,
        string $status,
        string $note,
        array $actors,
        string $verification,
        string $guidance
    ): array {
        return compact('label', 'value', 'status', 'note', 'actors', 'verification')
            + self::guidance($guidance);
    }

    /** @return array{purpose:string,standards:array<int,array{title:string,url:string}>} */
    private static function guidance(string $topic): array
    {
        $standards = [
            'oidc-discovery' => self::standard(
                gettext('OpenID Connect Discovery 1.0, section 4.3'),
                'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation'
            ),
            'oidc-authorization' => self::standard(
                gettext('OpenID Connect Core 1.0, section 3.1.2'),
                'https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint'
            ),
            'oidc-auth-request' => self::standard(
                gettext('OpenID Connect Core 1.0 — Authentication Request'),
                'https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest'
            ),
            'oidc-token' => self::standard(
                gettext('OpenID Connect Core 1.0, section 3.1.3'),
                'https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint'
            ),
            'oidc-id-token' => self::standard(
                gettext('OpenID Connect Core 1.0 — ID Token Validation'),
                'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation'
            ),
            'oidc-userinfo' => self::standard(
                gettext('OpenID Connect Core 1.0, section 5.3'),
                'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo'
            ),
            'oidc-client-auth' => self::standard(
                gettext('OpenID Connect Core 1.0, section 9'),
                'https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication'
            ),
            'oidc-logout' => self::standard(
                gettext('OpenID Connect RP-Initiated Logout 1.0, section 2'),
                'https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout'
            ),
            'rfc6749-client-auth' => self::standard(
                gettext('RFC 6749, section 2.3 — Client Authentication'),
                'https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3'
            ),
            'rfc6749-tls' => self::standard(
                gettext('RFC 6749 — Endpoint Request Confidentiality'),
                'https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1.2.' . '1'
            ),
            'rfc7009' => self::standard(
                gettext('RFC 7009, section 2.1 — Revocation Request'),
                'https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1'
            ),
            'rfc7515' => self::standard(
                gettext('RFC 7515, section 5.2 — JWS Validation'),
                'https://www.rfc-editor.org/rfc/rfc7515.html#section-5.2'
            ),
            'rfc7517' => self::standard(
                gettext('RFC 7517, section 5 — JWK Set Format'),
                'https://www.rfc-editor.org/rfc/rfc7517.html#section-5'
            ),
            'rfc7523' => self::standard(
                gettext('RFC 7523, section 2.2 — JWT Client Authentication'),
                'https://www.rfc-editor.org/rfc/rfc7523.html#section-2.2'
            ),
            'rfc7636' => self::standard(
                gettext('RFC 7636, section 4 — Protocol'),
                'https://www.rfc-editor.org/rfc/rfc7636.html#section-4'
            ),
            'rfc8414' => self::standard(
                gettext('RFC 8414, section 2 — Authorization Server Metadata'),
                'https://www.rfc-editor.org/rfc/rfc8414.html#section-2'
            ),
            'rfc8705' => self::standard(
                gettext('RFC 8705, section 3 — Certificate-Bound Access Tokens'),
                'https://www.rfc-editor.org/rfc/rfc8705.html#section-3'
            ),
            'rfc9101' => self::standard(
                gettext('RFC 9101, section 5 — JWT-Secured Authorization Requests'),
                'https://www.rfc-editor.org/rfc/rfc9101.html#section-5'
            ),
            'rfc9126' => self::standard(
                gettext('RFC 9126, section 2 — Pushed Authorization Request Endpoint'),
                'https://www.rfc-editor.org/rfc/rfc9126.html#section-2'
            ),
            'rfc9207' => self::standard(
                gettext('RFC 9207, section 2 — Authorization Response Issuer'),
                'https://www.rfc-editor.org/rfc/rfc9207.html#section-2'
            ),
            'rfc9449' => self::standard(
                gettext('RFC 9449, section 4 — DPoP Proof JWT Syntax'),
                'https://www.rfc-editor.org/rfc/rfc9449.html#section-4'
            ),
            'rfc9700' => self::standard(
                gettext('RFC 9700, section 2.1 — Protecting Redirect-Based Flows'),
                'https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1'
            ),
            'jarm' => self::standard(
                gettext('JWT Secured Authorization Response Mode, section 2'),
                'https://openid.net/specs/oauth-v2-jarm.html#section-2'
            ),
        ];
        $guidance = [
            'signing-keys' => [
                gettext('These keys let OPNsense confirm that signed messages really came from this provider.'),
                [$standards['rfc7517']],
            ],
            'authorization-registration' => [
                gettext('This catches a wrong Client ID or return address before a user tries to sign in.'),
                [$standards['oidc-auth-request']],
            ],
            'client-configuration' => [
                gettext('These values identify OPNsense to the provider for protected server requests.'),
                [$standards['rfc6749-client-auth']],
            ],
            'webgui-transport' => [
                gettext('A trusted HTTPS address keeps sign-in responses on the intended firewall connection.'),
                [$standards['rfc6749-tls']],
            ],
            'webgui-origins' => [
                gettext('This limits which browser addresses are allowed to start a sign-in for this firewall.'),
                [$standards['oidc-auth-request'], $standards['rfc9700']],
            ],
            'request-object' => [
                gettext('A signed request lets the provider detect changed sign-in instructions.'),
                [$standards['rfc9101']],
            ],
            'client-credentials' => [
                gettext('Client credentials prove that a protected request comes from this OPNsense installation.'),
                [$standards['rfc6749-client-auth']],
            ],
            'provider-preflight' => [
                gettext('This confirms that OPNsense can securely reach and recognize the configured provider.'),
                [$standards['oidc-discovery']],
            ],
            'discovery' => [
                gettext('Discovery tells OPNsense which endpoints and security features belong to this provider.'),
                [$standards['oidc-discovery'], $standards['rfc8414']],
            ],
            'provider-profile' => [
                gettext('The profile supplies safe provider-specific defaults without weakening login checks.'),
                [$standards['oidc-discovery']],
            ],
            'authorization-endpoint' => [
                gettext('This is where the browser sends the user to sign in with the identity provider.'),
                [$standards['oidc-authorization']],
            ],
            'token-endpoint' => [
                gettext('This is where OPNsense exchanges the one-time sign-in code for tokens.'),
                [$standards['oidc-token']],
            ],
            'userinfo' => [
                gettext('UserInfo can provide the account details OPNsense needs after authentication.'),
                [$standards['oidc-userinfo']],
            ],
            'id-token-signatures' => [
                gettext('A supported signature lets OPNsense detect forged or changed identity tokens.'),
                [$standards['oidc-id-token'], $standards['rfc7515']],
            ],
            'client-authentication' => [
                gettext('This finds a method the provider accepts for recognizing OPNsense.'),
                [$standards['oidc-client-auth'], $standards['rfc8414']],
            ],
            'client-assertion-signatures' => [
                gettext('This lets OPNsense use a certificate instead of a shared secret to identify itself.'),
                [$standards['rfc7523']],
            ],
            'certificate-bound-tokens' => [
                gettext('Certificate binding makes a stolen access token unusable without the matching private key.'),
                [$standards['rfc8705']],
            ],
            'pkce' => [
                gettext('PKCE keeps an intercepted sign-in code from being redeemed by someone else.'),
                [$standards['rfc7636']],
            ],
            'dpop' => [
                gettext('DPoP makes a stolen access token unusable without the matching proof key.'),
                [$standards['rfc9449']],
            ],
            'response-mode' => [
                gettext('The response mode determines how the provider returns the sign-in result to OPNsense.'),
                [$standards['oidc-auth-request']],
            ],
            'jarm' => [
                gettext('JARM signs the browser response so OPNsense can detect changes before using it.'),
                [$standards['jarm']],
            ],
            'selected-authentication' => [
                gettext('This confirms that the configured way of identifying OPNsense is supported.'),
                [$standards['oidc-client-auth'], $standards['rfc8414']],
            ],
            'authorization-response-issuer' => [
                gettext('The issuer value helps reject a sign-in response that came from the wrong provider.'),
                [$standards['rfc9207']],
            ],
            'provider-signout' => [
                gettext('Provider sign-out can also end the provider session when a user leaves OPNsense.'),
                [$standards['oidc-logout']],
            ],
            'token-revocation' => [
                gettext('Revocation asks the provider to invalidate tokens that are no longer needed after logout.'),
                [$standards['rfc7009']],
            ],
            'entra-profile' => [
                gettext('A tenant-specific issuer keeps sign-ins tied to the intended Microsoft Entra directory.'),
                [$standards['oidc-discovery']],
            ],
            'par' => [
                gettext('PAR sends sign-in instructions directly to the provider so the browser cannot alter them.'),
                [$standards['rfc9126']],
            ],
        ];
        if (!array_key_exists($topic, $guidance)) {
            throw new \LogicException('The provider probe check has no diagnostic guidance');
        }
        return [
            'purpose' => $guidance[$topic][0],
            'standards' => $guidance[$topic][1],
        ];
    }

    /** @return array{title:string,url:string} */
    private static function standard(string $title, string $url): array
    {
        return compact('title', 'url');
    }

    private static function clientConfigurationReady(OpenIDConnect $settings): bool
    {
        if ($settings->issuerUrl() === '' || $settings->clientId() === '') {
            return false;
        }
        $method = $settings->tokenAuthMethod();
        $certificate = $settings->clientCertificateRef();
        $needsCertificate = $settings->certificateBoundAccessTokens()
            || in_array($method, ['tls_client_auth', 'self_signed_tls_client_auth'], true)
            || ($method === null && $certificate !== '');
        if ($needsCertificate) {
            try {
                return ClientCertificate::load($certificate) !== null;
            } catch (\Throwable $error) {
                return false;
            }
        }
        if ($method === 'private_key_jwt'
            || ($method === null && $settings->signingCertificate() !== '')) {
            return $settings->signingCertificate() !== '';
        }
        return $settings->clientSecret() !== '';
    }
}
