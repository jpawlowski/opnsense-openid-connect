<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\ProviderCache;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\ProviderProbe;
use OPNsense\OpenIDConnect\ProviderRuntimeState;
use OPNsense\OpenIDConnect\RelyingParty;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;

/** Secret-free cached status and CSRF-protected live diagnostics for the current form. */
class HealthController extends PrivateApiControllerBase
{
    public function probeAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => gettext('A protected POST request is required.')];
        }
        $checks = [];
        try {
            $settings = ProviderProbe::settings($this->formValues());
            $redirectUri = RelyingParty::acceptedRedirectUri($settings, $this->request);
            $checks = ProviderProbe::healthReadiness($settings, $redirectUri);
            if ($settings->issuerUrl() === '' || $settings->clientId() === '' || $settings->clientSecret() === '') {
                return ProviderProbe::answer(
                    $checks,
                    gettext('Connection health accepted'),
                    gettext('Connection health accepted with %d warning(s)'),
                    gettext('Connection health has %d failure(s)')
                );
            }
            $providerChecks = (new ProviderProbe(new HttpClient()))->checks($settings, $redirectUri);
            $checks = array_merge($checks, $providerChecks);
            $par = end($providerChecks);
            if (is_array($par)) {
                $checks[] = ProviderProbe::credentialsCheck($par);
            }
            return ProviderProbe::answer(
                $checks,
                gettext('Connection health accepted'),
                gettext('Connection health accepted with %d warning(s)'),
                gettext('Connection health has %d failure(s)')
            );
        } catch (\Throwable $error) {
            $checks[] = ProviderProbe::failureCheck(
                gettext('Live provider preflight'),
                $error->getMessage(),
                ['opnsense', 'idp'],
                'live'
            );
            return ProviderProbe::answer(
                $checks,
                gettext('Connection health accepted'),
                gettext('Connection health accepted with %d warning(s)'),
                gettext('Connection health has %d failure(s)')
            );
        }
    }

    public function statusAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        $name = trim((string)$this->request->get('provider', null, ''));
        try {
            $settings = (new AuthenticationFactory())->get($name);
            if (!$settings instanceof OpenIDConnect) {
                throw new \RuntimeException('The selected server is not an OpenID Connect server');
            }
            [, $discoveryUrl] = ProviderMetadata::locations($settings->issuerUrl());
            $items = [[
                'label' => gettext('Discovery'),
                'direction' => gettext('OPNsense → IdP'),
            ] + ProviderCache::status('oidc-discovery', $discoveryUrl)];

            $cached = ProviderCache::cachedResponse('oidc-discovery', $discoveryUrl);
            if ($cached !== null) {
                $metadata = ProviderMetadata::fromArray($cached->jsonObject());
                $items[] = [
                    'label' => gettext('Signing keys'),
                    'direction' => gettext('OPNsense → IdP'),
                ] + ProviderCache::status('oidc-jwks', $metadata->jwksUri());
                $endpoint = $metadata->pushedAuthorizationRequestEndpoint();
                if ($endpoint !== null && $settings->parMode() !== 'disabled') {
                    $par = ProviderRuntimeState::parStatus(ProviderRuntimeState::parKey($settings, $metadata));
                    $items[] = [
                        'label' => gettext('Pushed authorization requests'),
                        'direction' => gettext('OPNsense → IdP'),
                        'status' => (string)($par['status'] ?? 'missing'),
                        'stored' => is_int($par['updated'] ?? null) ? $par['updated'] : null,
                        'fresh_until' => null,
                        'stale_until' => is_int($par['next_probe'] ?? null) ? $par['next_probe'] : null,
                    ];
                }
            }

            if ($settings->receivesSharedSignals() && $settings->sharedSignalsIssuer() !== '') {
                $ssfUrl = SharedSignalsMetadata::discoveryUrl($settings->sharedSignalsIssuer());
                $items[] = [
                    'label' => gettext('Shared Signals discovery'),
                    'direction' => gettext('OPNsense → transmitter'),
                ] + ProviderCache::status('ssf-discovery', $ssfUrl);
                $ssfCached = ProviderCache::cachedResponse('ssf-discovery', $ssfUrl);
                if ($ssfCached !== null) {
                    $ssf = SharedSignalsMetadata::fromArray(
                        $settings->sharedSignalsIssuer(),
                        $ssfCached->jsonObject()
                    );
                    $items[] = [
                        'label' => gettext('Shared Signals signing keys'),
                        'direction' => gettext('OPNsense → transmitter'),
                    ] + ProviderCache::status('ssf-jwks', $ssf->jwksUri());
                    if ($settings->sharedSignalsDeliveryMethod() === SharedSignalsMetadata::POLL_METHOD) {
                        $poll = ProviderRuntimeState::ssfStatus(ProviderRuntimeState::ssfKey($settings, $ssf));
                        $items[] = [
                            'label' => gettext('Shared Signals polling'),
                            'direction' => gettext('OPNsense → transmitter'),
                            'status' => (string)($poll['status'] ?? 'missing'),
                            'stored' => is_int($poll['updated'] ?? null) ? $poll['updated'] : null,
                            'fresh_until' => is_int($poll['fresh_until'] ?? null) ? $poll['fresh_until'] : null,
                            'stale_until' => null,
                        ];
                    }
                }
            }
            return ['status' => 'ok', 'items' => $items];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => gettext('Connectivity status is unavailable.')];
        }
    }

    /** @return array<string,string> */
    private function formValues(): array
    {
        $values = [];
        foreach (ProviderProbe::FORM_FIELDS as $field) {
            $values[$field] = (string)$this->request->getPost($field, null, '');
        }
        return $values;
    }
}
