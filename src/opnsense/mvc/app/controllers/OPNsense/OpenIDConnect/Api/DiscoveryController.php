<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ParClient;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\ProviderRuntimeState;
use OPNsense\OpenIDConnect\ProviderUnavailableException;
use OPNsense\OpenIDConnect\RequestObjectSigner;
use OPNsense\OpenIDConnect\RelyingParty;

/** Authenticated, CSRF-protected preflight of an issuer's discovery metadata. */
class DiscoveryController extends PrivateApiControllerBase
{
    public function probeAction()
    {
        $this->response->setContentType('application/json', 'UTF-8');
        $given = trim((string)$this->request->getPost('url', null, ''));
        try {
            $profile = (string)$this->request->getPost('profile', null, 'general');
            $microsoftAudience = (string)$this->request->getPost('microsoft_audience', null, 'tenant');
            $profile = in_array($profile, OpenIDConnect::PROVIDER_PROFILES, true) ? $profile : 'general';
            $microsoftAudience = in_array($microsoftAudience, OpenIDConnect::MICROSOFT_AUDIENCES, true)
                ? $microsoftAudience : 'tenant';
            $template = $profile === 'entra' && $microsoftAudience !== 'tenant'
                ? ($microsoftAudience === 'consumers'
                    ? 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0'
                    : 'https://login.microsoftonline.com/{tenantid}/v2.0')
                : null;
            $http = new HttpClient();
            /* This explicit diagnostic must not let an old cache hide a broken live path. */
            $metadata = ProviderMetadata::discover($given, $http, $template, true, false);
            $responseMode = (string)$this->request->getPost('response_mode', null, 'query');
            $tokenAuth = (string)$this->request->getPost('token_auth', null, '');
            $claimsSource = (string)$this->request->getPost('claims_source', null, 'auto');
            $responseMode = in_array($responseMode, OpenIDConnect::RESPONSE_MODES, true) ? $responseMode : 'query';
            $tokenAuth = in_array($tokenAuth, array_merge(OpenIDConnect::TOKEN_AUTH_METHODS, ['']), true)
                ? $tokenAuth : '';
            $claimsSource = in_array($claimsSource, OpenIDConnect::CLAIMS_SOURCES, true)
                ? $claimsSource : 'auto';
            $checks = $this->checks(
                $metadata,
                $profile,
                $responseMode,
                $tokenAuth,
                $claimsSource
            );
            try {
                $keyCount = (new JwtVerifier($http))->probeKeySet($metadata->jwksUri());
                $checks[] = $this->check(
                    gettext('Signing keys (OPNsense → IdP)'),
                    sprintf(gettext('%d usable key(s)'), $keyCount),
                    'success',
                    gettext('The JWKS endpoint was fetched live and contains supported signing material.')
                );
            } catch (\Throwable $e) {
                $checks[] = $this->check(
                    gettext('Signing keys (OPNsense → IdP)'),
                    gettext('Live check failed'),
                    'error',
                    $e->getMessage()
                );
            }

            $settings = $this->currentSettings($given);
            $checks[] = $this->requestObjectCheck($settings, $metadata);
            $checks[] = $this->parCheck($settings, $metadata, $http);
            $warnings = count(array_filter(
                $checks,
                static fn(array $check): bool => $check['status'] === 'warning'
            ));
            $errors = count(array_filter(
                $checks,
                static fn(array $check): bool => $check['status'] === 'error'
            ));
            $overall = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'success');
            return [
                'status' => 'ok',
                'overall' => $overall,
                'headline' => $errors > 0
                    ? sprintf(gettext('Server connectivity has %d failure(s)'), $errors)
                    : ($warnings === 0
                        ? gettext('Server connectivity accepted')
                        : sprintf(gettext('Server connectivity accepted with %d warning(s)'), $warnings)),
                'checks' => $checks,
                /* Keep a plain-text representation for API clients predating the status table. */
                'summary' => implode("\n", array_map(
                    static fn(array $check): string => sprintf('%s: %s', $check['label'], $check['value']),
                    $checks
                )),
            ];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => gettext('Discovery was not accepted: ') . $e->getMessage()];
        }
    }

    /** @return array<int,array{label:string,value:string,status:string,note:string}> */
    private function checks(
        ProviderMetadata $metadata,
        string $profile,
        string $responseMode,
        string $tokenAuth,
        string $claimsSource
    ): array
    {
        $list = static function ($value): array {
            return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
        };
        $algorithms = array_values(array_intersect(
            $list($metadata->get('id_token_signing_alg_values_supported', [])),
            JwtVerifier::ALGORITHMS
        ));
        $jarmAlgorithms = array_values(array_intersect(
            $metadata->authorizationResponseSigningAlgorithms(),
            JwtVerifier::ALGORITHMS
        ));
        $authMethods = array_values(array_intersect(
            $list($metadata->get('token_endpoint_auth_methods_supported', ['client_secret_basic'])),
            ['client_secret_basic', 'client_secret_post']
        ));
        $responseModes = $list($metadata->get('response_modes_supported', []));
        $advertisedAuth = $list($metadata->get(
            'token_endpoint_auth_methods_supported',
            ['client_secret_basic']
        ));
        $pkceAdvertised = in_array(
            'S256',
            $list($metadata->get('code_challenge_methods_supported', [])),
            true
        );
        $userInfo = $metadata->userInfoEndpoint();
        $parEndpoint = $metadata->pushedAuthorizationRequestEndpoint();
        $profileLabels = OpenIDConnect::providerProfileOptions();

        $checks = [
            $this->check(
                gettext('Discovery (OPNsense → IdP)'),
                $metadata->issuer(),
                'success',
                gettext('The document was fetched live and its issuer matches exactly.')
            ),
            $this->check(
                gettext('Provider profile'),
                $profileLabels[$profile] ?? $profile,
                'info',
                gettext('Provider-specific defaults never relax protocol validation.')
            ),
            $this->check(
                gettext('Authorization endpoint (Browser → IdP)'),
                $metadata->authorizationEndpoint(),
                'info',
                gettext('Discovery advertises this browser path; Test sign-in exercises it.')
            ),
            $this->check(
                gettext('Token endpoint (OPNsense → IdP)'),
                $metadata->tokenEndpoint(),
                'info',
                gettext('Discovery advertises this mandatory server path; Test sign-in exercises it with a code.')
            ),
            $this->check(
                gettext('UserInfo endpoint (OPNsense → IdP)'),
                $userInfo ?? gettext('Not offered'),
                $userInfo !== null ? 'success' : ($claimsSource === 'userinfo' ? 'warning' : 'info'),
                $userInfo !== null
                    ? gettext('UserInfo can supply identity claims when configured or needed.')
                    : ($claimsSource === 'userinfo'
                        ? gettext('The selected claims source requires UserInfo, but the provider does not offer it.')
                        : gettext('UserInfo is optional for the selected claims source.'))
            ),
            $this->check(
                gettext('ID Token signatures'),
                implode(', ', $algorithms) ?: gettext('None supported'),
                $algorithms === [] ? 'warning' : 'success',
                $algorithms === []
                    ? gettext('No supported asymmetric ID Token signature is advertised.')
                    : gettext('At least one supported asymmetric signature is advertised.')
            ),
            $this->check(
                gettext('Client authentication'),
                implode(', ', $authMethods) ?: gettext('None supported'),
                $authMethods === [] ? 'warning' : 'success',
                $authMethods === []
                    ? gettext('No supported token endpoint authentication method is advertised.')
                    : gettext('At least one confidential-client authentication method is usable.')
            ),
            $this->check(
                gettext('PKCE'),
                $pkceAdvertised ? 'S256' : gettext('S256 not advertised'),
                $pkceAdvertised ? 'success' : 'warning',
                $pkceAdvertised
                    ? gettext('The provider explicitly advertises the required S256 method.')
                    : gettext(
                        'This client still sends PKCE S256; the provider must accept it despite omitting metadata.'
                    )
            ),
            $this->check(
                gettext('PAR metadata'),
                $parEndpoint ?? gettext('Not offered'),
                'info',
                $parEndpoint === null
                    ? gettext('Discovery offers no PAR endpoint.')
                    : gettext('The separate PAR row below performs an authenticated live request.')
            ),
        ];

        if ($responseModes === []) {
            $checks[] = $this->check(
                gettext('Authorization response mode'),
                $responseMode,
                'info',
                gettext('The provider does not advertise response modes; the selected mode is tested during sign-in.')
            );
        } else {
            $modeSupported = in_array($responseMode, $responseModes, true);
            $checks[] = $this->check(
                gettext('Authorization response mode'),
                $responseMode,
                $modeSupported ? 'success' : 'warning',
                $modeSupported
                    ? gettext('The selected response mode is advertised.')
                    : gettext('The selected response mode is not advertised.')
            );
        }

        if (str_ends_with($responseMode, '.jwt')) {
            $checks[] = $this->check(
                gettext('JARM signatures'),
                implode(', ', $jarmAlgorithms) ?: gettext('None supported'),
                $jarmAlgorithms === [] ? 'warning' : 'success',
                $jarmAlgorithms === []
                    ? gettext('The provider advertises no supported asymmetric JARM signature.')
                    : gettext('The signed authorization response can use a supported asymmetric signature.')
            );
        }

        $selectedAuth = $tokenAuth === '' ? gettext('Follow the provider') : $tokenAuth;
        $selectedAuthUsable = $tokenAuth === '' ? $authMethods !== [] : in_array($tokenAuth, $advertisedAuth, true);
        $checks[] = $this->check(
            gettext('Selected authentication method'),
            $selectedAuth,
            $selectedAuthUsable ? 'success' : 'warning',
            $selectedAuthUsable
                ? gettext('The configured choice can use the provider metadata.')
                : gettext('The selected client authentication method is not advertised.')
        );

        $checks[] = $this->check(
            gettext('Authorization response issuer'),
            $metadata->authorizationResponseIssuerSupported()
                ? gettext('Advertised') : gettext('Not advertised'),
            $metadata->authorizationResponseIssuerSupported() ? 'success' : 'info',
            $metadata->authorizationResponseIssuerSupported()
                ? gettext('The provider advertises RFC 9207 issuer identification.')
                : gettext('The distinct callback and frozen metadata still protect this provider from mix-up.')
        );
        $checks[] = $this->check(
            gettext('Provider sign-out (Browser → IdP)'),
            $metadata->endSessionEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'info',
            $metadata->endSessionEndpoint() === null
                ? gettext('Provider sign-out is optional; local logout still works.')
                : gettext('RP-initiated provider sign-out is available.')
        );
        $checks[] = $this->check(
            gettext('Token revocation (OPNsense → IdP)'),
            $metadata->revocationEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'info',
            $metadata->revocationEndpoint() === null
                ? gettext('Token revocation is optional and will be skipped.')
                : gettext('Tokens can be revoked during provider-aware logout.')
        );

        if ($profile === 'entra' && !str_contains($metadata->issuer(), '/v2.0')) {
            $checks[] = $this->check(
                gettext('Microsoft Entra issuer profile'),
                gettext('Tenant-specific v2.0 issuer expected'),
                'warning',
                gettext('Do not use common, organizations, consumers or v1 metadata with this profile.')
            );
        }

        return $checks;
    }

    private function currentSettings(string $issuer): OpenIDConnect
    {
        $fields = [
            'openidconnect_app_code', 'openidconnect_provider_profile', 'openidconnect_microsoft_audience',
            'openidconnect_client_id', 'openidconnect_client_secret', 'openidconnect_token_auth',
            'openidconnect_par_mode', 'openidconnect_request_object_key', 'openidconnect_scopes',
            'openidconnect_response_mode',
            'openidconnect_max_age', 'openidconnect_select_account', 'openidconnect_required_authentication',
            'openidconnect_acr_request', 'openidconnect_acr_values', 'openidconnect_amr_values',
            'openidconnect_entra_auth_context', 'openidconnect_origin_policy', 'openidconnect_redirect_urls',
            'openidconnect_tls_offloading',
        ];
        $values = ['type' => OpenIDConnect::TYPE, 'openidconnect_provider_url' => $issuer];
        foreach ($fields as $field) {
            $values[$field] = (string)$this->request->getPost($field, null, '');
        }
        $settings = new OpenIDConnect();
        $settings->setProperties($values);
        return $settings;
    }

    /** @return array{label:string,value:string,status:string,note:string} */
    private function requestObjectCheck(OpenIDConnect $settings, ProviderMetadata $metadata): array
    {
        $key = $settings->requestObjectSigningKey();
        if ($key === '') {
            return $this->check(
                gettext('JWT-secured authorization request'),
                $metadata->requiresSignedRequestObject() ? gettext('Required by provider') : gettext('Disabled'),
                $metadata->requiresSignedRequestObject() ? 'error' : 'info',
                $metadata->requiresSignedRequestObject()
                    ? gettext('Select and register a Request Object signing key before sign-in.')
                    : gettext('Select a registered OPNsense certificate to sign RFC 9101 Request Objects.')
            );
        }
        try {
            $algorithm = (new RequestObjectSigner())->selectedAlgorithm($settings, $metadata);
            return $this->check(
                gettext('JWT-secured authorization request'),
                $algorithm,
                'success',
                sprintf(gettext('Request Objects use the selected certificate with kid %s.'), $key)
            );
        } catch (\Throwable $e) {
            return $this->check(
                gettext('JWT-secured authorization request'),
                gettext('No compatible signing key'),
                'error',
                $e->getMessage()
            );
        }
    }

    /** @return array{label:string,value:string,status:string,note:string} */
    private function parCheck(OpenIDConnect $settings, ProviderMetadata $metadata, HttpClient $http): array
    {
        $mode = $settings->parMode();
        $endpoint = $metadata->pushedAuthorizationRequestEndpoint();
        $required = $metadata->requiresPushedAuthorizationRequests();
        if ($mode === 'disabled') {
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                $required ? gettext('Required by provider') : gettext('Skipped by setting'),
                $required ? 'error' : 'info',
                $required
                    ? gettext('The provider requires PAR, so it cannot be disabled.')
                    : gettext('No PAR request was sent because PAR is disabled.')
            );
        }
        if ($endpoint === null) {
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Not offered'),
                $mode === 'required' ? 'error' : 'info',
                $mode === 'required'
                    ? gettext('PAR is required locally but Discovery offers no endpoint.')
                    : gettext('Automatic mode uses a normal browser authorization request.')
            );
        }
        if ($settings->clientId() === '' || $settings->clientSecret() === '') {
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Not tested'),
                'warning',
                gettext('Enter Client ID and Client Secret to run the authenticated live PAR check.')
            );
        }
        $redirectUri = RelyingParty::acceptedRedirectUri($settings, $this->request);
        if ($redirectUri === null) {
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Not tested'),
                'error',
                gettext('The current WebGUI origin is not accepted by these form values.')
            );
        }
        $key = ProviderRuntimeState::parKey($settings, $metadata);
        try {
            (new ParClient($settings, $http))->probe($metadata, $redirectUri);
            ProviderRuntimeState::parAvailable($key);
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Live authenticated request accepted'),
                'success',
                gettext('The returned request URI was deliberately discarded; no browser transaction was created.')
            );
        } catch (ProviderUnavailableException $e) {
            if ($mode === 'auto' && !$required) {
                ProviderRuntimeState::parUnavailable($key, $e->retryAfter());
                return $this->check(
                    gettext('PAR endpoint (OPNsense → IdP)'),
                    gettext('Temporarily unavailable; bypass active'),
                    'warning',
                    gettext('New logins use the browser authorization request while recovery runs in the background.')
                );
            }
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Live check failed'),
                'error',
                $e->getMessage()
            );
        } catch (\Throwable $e) {
            ProviderRuntimeState::parHardFailure($key);
            return $this->check(
                gettext('PAR endpoint (OPNsense → IdP)'),
                gettext('Live check failed'),
                'error',
                $e->getMessage()
            );
        }
    }

    /** @return array{label:string,value:string,status:string,note:string} */
    private function check(string $label, string $value, string $status, string $note): array
    {
        return compact('label', 'value', 'status', 'note');
    }
}
