<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;

/** One live, side-effect-bounded provider preflight shared by setup diagnostics. */
final class ProviderProbe
{
    public const FORM_FIELDS = [
        'openidconnect_provider_url', 'openidconnect_app_code', 'openidconnect_provider_profile',
        'openidconnect_microsoft_audience', 'openidconnect_client_id', 'openidconnect_client_secret',
        'openidconnect_token_auth', 'openidconnect_par_mode', 'openidconnect_request_object_key',
        'openidconnect_scopes',
        'openidconnect_response_mode', 'openidconnect_claims_source', 'openidconnect_max_age',
        'openidconnect_select_account', 'openidconnect_required_authentication', 'openidconnect_acr_request',
        'openidconnect_acr_values', 'openidconnect_amr_values', 'openidconnect_entra_auth_context',
        'openidconnect_origin_policy', 'openidconnect_redirect_urls', 'openidconnect_tls_offloading',
    ];

    public function __construct(private readonly HttpClient $http)
    {
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
            $keyCount = (new JwtVerifier($this->http))->probeKeySet($metadata->jwksUri());
            $checks[] = self::check(
                gettext('Signing keys'),
                sprintf(gettext('%d usable key(s)'), $keyCount),
                'success',
                gettext('The JWKS endpoint was fetched live and contains supported signing material.'),
                ['opnsense', 'idp'],
                'live'
            );
        } catch (\Throwable $error) {
            $checks[] = self::check(
                gettext('Signing keys'),
                gettext('Live check failed'),
                'error',
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live'
            );
        }
        $checks[] = $this->requestObjectCheck($settings, $metadata);
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
        $complete = $settings->issuerUrl() !== '' && $settings->clientId() !== '' && $settings->clientSecret() !== '';
        $transportReady = $settings->isWebGuiTransportReady();
        $transport = $transportReady && $redirectUri !== null;
        return [
            self::check(
                gettext('Client configuration'),
                $complete ? gettext('Complete confidential client') : gettext('Incomplete'),
                $complete ? 'success' : 'error',
                $complete
                    ? gettext('Exact issuer URL, Client ID and Client Secret are present in the current form.')
                    : gettext('Enter Exact issuer URL, Client ID and Client Secret before checking connection health.'),
                ['opnsense'],
                'configuration'
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
                'configuration'
            ),
        ];
    }

    /** @return array<string,mixed> */
    private function requestObjectCheck(OpenIDConnect $settings, ProviderMetadata $metadata): array
    {
        $key = $settings->requestObjectSigningKey();
        if ($key === '') {
            return self::check(
                gettext('JWT-secured authorization request'),
                $metadata->requiresSignedRequestObject() ? gettext('Required by provider') : gettext('Disabled'),
                $metadata->requiresSignedRequestObject() ? 'error' : 'info',
                $metadata->requiresSignedRequestObject()
                    ? gettext('Select and register a Request Object signing key before sign-in.')
                    : gettext('Select a registered OPNsense certificate to sign RFC 9101 Request Objects.'),
                ['opnsense'],
                'configuration'
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
                'configuration'
            );
        } catch (\Throwable $error) {
            return self::check(
                gettext('JWT-secured authorization request'),
                gettext('No compatible signing key'),
                'error',
                $error->getMessage(),
                ['opnsense'],
                'configuration'
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
                'live'
            );
        }
        return self::check(
            gettext('Client credentials'),
            gettext('Not exercised'),
            'info',
            gettext('This provider path did not use the credentials; Test sign-in exercises them with a code.'),
            ['opnsense', 'idp'],
            'not-tested'
        );
    }

    /** @param string[] $actors @return array<string,mixed> */
    public static function failureCheck(
        string $label,
        string $note,
        array $actors,
        string $verification
    ): array {
        return self::check(
            $label,
            gettext('Live check failed'),
            'error',
            $note,
            $actors,
            $verification
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
        $authMethods = array_values(array_intersect(
            $list($metadata->get('token_endpoint_auth_methods_supported', ['client_secret_basic'])),
            ['client_secret_basic', 'client_secret_post']
        ));
        $advertisedAuth = $list($metadata->get(
            'token_endpoint_auth_methods_supported',
            ['client_secret_basic']
        ));
        $advertisedResponseModes = $metadata->get('response_modes_supported', null);
        $responseModes = $list($advertisedResponseModes ?? ['query', 'fragment']);
        $pkceAdvertised = in_array(
            'S256',
            $list($metadata->get('code_challenge_methods_supported', [])),
            true
        );
        $dpopAlgorithms = $metadata->dpopSigningAlgorithms();
        $dpopUsable = $metadata->supportsDpop();
        $userInfo = $metadata->userInfoEndpoint();
        $parEndpoint = $metadata->pushedAuthorizationRequestEndpoint();
        $profile = $settings->providerProfile();
        $profileLabels = OpenIDConnect::providerProfileOptions();
        $checks = [
            self::check(
                gettext('Discovery'),
                $metadata->issuer(),
                'success',
                gettext('The document was fetched live and its issuer matches exactly.'),
                ['opnsense', 'idp'],
                'live'
            ),
            self::check(
                gettext('Provider profile'),
                $profileLabels[$profile] ?? $profile,
                'info',
                gettext('Provider-specific defaults never relax protocol validation.'),
                ['opnsense'],
                'configuration'
            ),
            self::check(
                gettext('Authorization endpoint'),
                $metadata->authorizationEndpoint(),
                'info',
                gettext('Discovery advertises this browser path; Test sign-in exercises it.'),
                ['browser', 'idp'],
                'not-tested'
            ),
            self::check(
                gettext('Token endpoint'),
                $metadata->tokenEndpoint(),
                'info',
                gettext('Discovery advertises this mandatory server path; Test sign-in exercises it with a code.'),
                ['opnsense', 'idp'],
                'not-tested'
            ),
            self::check(
                gettext('UserInfo endpoint'),
                $userInfo ?? gettext('Not offered'),
                $userInfo !== null ? 'success' : ($settings->claimsSource() === 'userinfo' ? 'warning' : 'info'),
                $userInfo !== null
                    ? gettext('UserInfo can supply identity claims when configured or needed.')
                    : ($settings->claimsSource() === 'userinfo'
                        ? gettext('The selected claims source requires UserInfo, but the provider does not offer it.')
                        : gettext('UserInfo is optional for the selected claims source.')),
                ['opnsense', 'idp'],
                'not-tested'
            ),
            self::check(
                gettext('ID Token signatures'),
                implode(', ', $algorithms) ?: gettext('None supported'),
                $algorithms === [] ? 'warning' : 'success',
                $algorithms === []
                    ? gettext('No supported asymmetric ID Token signature is advertised.')
                    : gettext('At least one supported asymmetric signature is advertised.'),
                ['opnsense'],
                'metadata'
            ),
            self::check(
                gettext('Client authentication'),
                implode(', ', $authMethods) ?: gettext('None supported'),
                $authMethods === [] ? 'warning' : 'success',
                $authMethods === []
                    ? gettext('No supported token endpoint authentication method is advertised.')
                    : gettext('At least one confidential-client authentication method is usable.'),
                ['opnsense'],
                'metadata'
            ),
            self::check(
                gettext('PKCE'),
                $pkceAdvertised ? 'S256' : gettext('S256 not advertised'),
                $pkceAdvertised ? 'success' : 'warning',
                $pkceAdvertised
                    ? gettext('The provider explicitly advertises the required S256 method.')
                    : gettext(
                        'This client still sends PKCE S256; the provider must accept it despite omitting metadata.'
                    ),
                ['opnsense'],
                'metadata'
            ),
            self::check(
                gettext('DPoP sender constraint'),
                $dpopAlgorithms === [] ? gettext('Not advertised') : implode(', ', $dpopAlgorithms),
                $dpopUsable ? 'success' : 'info',
                $dpopUsable
                    ? gettext('ES256 is advertised; Test sign-in uses a proof-key-bound token flow.')
                    : gettext('Bearer access tokens remain in use unless the provider advertises ES256 DPoP.'),
                ['opnsense'],
                'metadata'
            ),
            self::check(
                gettext('PAR metadata'),
                $parEndpoint ?? gettext('Not offered'),
                'info',
                $parEndpoint === null
                    ? gettext('Discovery offers no PAR endpoint.')
                    : gettext('The separate PAR row below performs an authenticated live request.'),
                ['opnsense', 'idp'],
                'metadata'
            ),
        ];
        $this->appendSelectedMetadataChecks(
            $checks,
            $settings,
            $metadata,
            $responseModes,
            $authMethods,
            $advertisedAuth
        );
        return $checks;
    }

    /** @param array<int,array<string,mixed>> $checks @param string[] $responseModes
     *  @param string[] $authMethods @param string[] $advertisedAuth */
    private function appendSelectedMetadataChecks(
        array &$checks,
        OpenIDConnect $settings,
        ProviderMetadata $metadata,
        array $responseModes,
        array $authMethods,
        array $advertisedAuth
    ): void {
        $responseMode = $settings->responseMode();
        $modeSupported = in_array($responseMode, $responseModes, true);
        $modesAdvertised = is_array($metadata->get('response_modes_supported', null));
        $checks[] = self::check(
            gettext('Authorization response mode'),
            $responseMode,
            $modesAdvertised ? ($modeSupported ? 'success' : 'warning') : ($modeSupported ? 'info' : 'warning'),
            !$modesAdvertised
                ? ($modeSupported
                    ? gettext('The selected mode is covered by the provider metadata omission default.')
                    : gettext('The selected mode is not covered by the provider metadata omission default.'))
                : ($modeSupported
                    ? gettext('The selected response mode is advertised.')
                    : gettext('The selected response mode is not advertised.')),
            ['idp', 'browser', 'opnsense'],
            'metadata'
        );
        if (str_ends_with($responseMode, '.jwt')) {
            $jarmAlgorithms = array_values(array_intersect(
                $metadata->authorizationResponseSigningAlgorithms(),
                JwtVerifier::ALGORITHMS
            ));
            $checks[] = self::check(
                gettext('JARM signatures'),
                implode(', ', $jarmAlgorithms) ?: gettext('None supported'),
                $jarmAlgorithms === [] ? 'warning' : 'success',
                $jarmAlgorithms === []
                    ? gettext('The provider advertises no supported asymmetric JARM signature.')
                    : gettext('The signed authorization response can use a supported asymmetric signature.'),
                ['opnsense'],
                'metadata'
            );
        }
        $tokenAuth = $settings->tokenAuthMethod();
        $selectedAuth = $tokenAuth === null ? gettext('Follow the provider') : $tokenAuth;
        $selectedAuthUsable = $tokenAuth === null ? $authMethods !== [] : in_array($tokenAuth, $advertisedAuth, true);
        $checks[] = self::check(
            gettext('Selected authentication method'),
            $selectedAuth,
            $selectedAuthUsable ? 'success' : 'warning',
            $selectedAuthUsable
                ? gettext('The configured choice can use the provider metadata.')
                : gettext('The selected client authentication method is not advertised.'),
            ['opnsense'],
            'metadata'
        );
        $issuerAdvertised = $metadata->authorizationResponseIssuerSupported();
        $checks[] = self::check(
            gettext('Authorization response issuer'),
            $issuerAdvertised ? gettext('Advertised') : gettext('Not advertised'),
            $issuerAdvertised ? 'success' : 'info',
            $issuerAdvertised
                ? gettext('The provider advertises RFC 9207 issuer identification.')
                : gettext('The distinct callback and frozen metadata still protect this provider from mix-up.'),
            ['idp', 'browser', 'opnsense'],
            'metadata'
        );
        $checks[] = self::check(
            gettext('Provider sign-out'),
            $metadata->endSessionEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'info',
            $metadata->endSessionEndpoint() === null
                ? gettext('Provider sign-out is optional; local logout still works.')
                : gettext('RP-initiated provider sign-out is available.'),
            ['browser', 'idp'],
            $metadata->endSessionEndpoint() === null ? 'metadata' : 'not-tested'
        );
        $checks[] = self::check(
            gettext('Token revocation'),
            $metadata->revocationEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'info',
            $metadata->revocationEndpoint() === null
                ? gettext('Token revocation is optional and will be skipped.')
                : gettext('Tokens can be revoked during provider-aware logout.'),
            ['opnsense', 'idp'],
            $metadata->revocationEndpoint() === null ? 'metadata' : 'not-tested'
        );
        if ($settings->providerProfile() === 'entra' && !str_contains($metadata->issuer(), '/v2.0')) {
            $checks[] = self::check(
                gettext('Microsoft Entra issuer profile'),
                gettext('Tenant-specific v2.0 issuer expected'),
                'warning',
                gettext('Do not use common, organizations, consumers or v1 metadata with this profile.'),
                ['opnsense'],
                'configuration'
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
                $required ? 'error' : 'info',
                $required
                    ? gettext('The provider requires PAR, so it cannot be disabled.')
                    : gettext('No PAR request was sent because PAR is disabled.'),
                ['opnsense', 'idp'],
                'skipped'
            );
        }
        if ($endpoint === null) {
            return self::check(
                gettext('PAR endpoint'),
                gettext('Not offered'),
                $mode === 'required' ? 'error' : 'info',
                $mode === 'required'
                    ? gettext('PAR is required locally but Discovery offers no endpoint.')
                    : gettext('Automatic mode uses a normal browser authorization request.'),
                ['opnsense', 'idp'],
                'metadata'
            );
        }
        if ($settings->clientId() === '' || $settings->clientSecret() === '') {
            return self::check(
                gettext('PAR endpoint'),
                gettext('Not tested'),
                'warning',
                gettext('Enter Client ID and Client Secret to run the authenticated live PAR check.'),
                ['opnsense', 'idp'],
                'not-tested'
            );
        }
        if ($redirectUri === null) {
            return self::check(
                gettext('PAR endpoint'),
                gettext('Not tested'),
                'error',
                gettext('The current WebGUI origin is not accepted by these form values.'),
                ['opnsense'],
                'configuration'
            );
        }
        $key = ProviderRuntimeState::parKey($settings, $metadata);
        $client = new ParClient($settings, $this->http);
        try {
            $client->probe($metadata, $redirectUri);
            ProviderRuntimeState::parAvailable($key);
            $check = self::check(
                gettext('PAR endpoint'),
                gettext('Live authenticated request accepted'),
                'success',
                gettext(
                    'PAR will be used automatically. The returned request URI was deliberately discarded; ' .
                    'no browser transaction was created.'
                ),
                ['opnsense', 'idp'],
                'live'
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
                    'live'
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
                'live'
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
                'live'
            );
            $check['credentials_exercised'] = $client->credentialsExercised();
            return $check;
        }
    }

    /** @param string[] $actors @return array<string,mixed> */
    private static function check(
        string $label,
        string $value,
        string $status,
        string $note,
        array $actors,
        string $verification
    ): array {
        return compact('label', 'value', 'status', 'note', 'actors', 'verification');
    }
}
