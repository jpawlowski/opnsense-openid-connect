<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;

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
            $metadata = ProviderMetadata::discover($given, new HttpClient(), $template);
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
            $warnings = count(array_filter(
                $checks,
                static fn(array $check): bool => $check['status'] === 'warning'
            ));
            return [
                'status' => 'ok',
                'overall' => $warnings === 0 ? 'success' : 'warning',
                'headline' => $warnings === 0
                    ? gettext('Discovery document accepted')
                    : sprintf(gettext('Discovery document accepted with %d warning(s)'), $warnings),
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
        $profileLabels = OpenIDConnect::providerProfileOptions();

        $checks = [
            $this->check(
                gettext('Exact issuer'),
                $metadata->issuer(),
                'success',
                gettext('The issuer and Discovery document match exactly.')
            ),
            $this->check(
                gettext('Provider profile'),
                $profileLabels[$profile] ?? $profile,
                'info',
                gettext('Provider-specific defaults never relax protocol validation.')
            ),
            $this->check(
                gettext('Authorization endpoint'),
                $metadata->authorizationEndpoint(),
                'success',
                gettext('A valid HTTPS authorization endpoint is available.')
            ),
            $this->check(
                gettext('Token endpoint'),
                $metadata->tokenEndpoint(),
                'success',
                gettext('A valid HTTPS token endpoint is available.')
            ),
            $this->check(
                gettext('UserInfo endpoint'),
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
                    : gettext('This client still sends PKCE S256; the provider must accept it despite omitting metadata.')
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
            gettext('Provider sign-out'),
            $metadata->endSessionEndpoint() === null ? gettext('Not offered') : gettext('Offered'),
            'info',
            $metadata->endSessionEndpoint() === null
                ? gettext('Provider sign-out is optional; local logout still works.')
                : gettext('RP-initiated provider sign-out is available.')
        );
        $checks[] = $this->check(
            gettext('Token revocation'),
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

    /** @return array{label:string,value:string,status:string,note:string} */
    private function check(string $label, string $value, string $status, string $note): array
    {
        return compact('label', 'value', 'status', 'note');
    }
}
