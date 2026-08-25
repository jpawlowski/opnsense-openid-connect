<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\ProviderProbe;
use OPNsense\OpenIDConnect\RelyingParty;

/** Authenticated, CSRF-protected preflight of an issuer's discovery metadata. */
class DiscoveryController extends PrivateApiControllerBase
{
    public function probeAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => gettext('A protected POST request is required.')];
        }
        try {
            $settings = ProviderProbe::settings($this->formValues());
            $redirectUri = RelyingParty::acceptedRedirectUri($settings, $this->request);
            $checks = [ProviderProbe::webGuiOriginsCheck($settings)];
            $checks = array_merge($checks, $this->providerProbe()->checks($settings, $redirectUri));
            return ProviderProbe::answer(
                $checks,
                gettext('Server connectivity accepted'),
                gettext('Server connectivity accepted with %d warning(s)'),
                gettext('Server connectivity has %d failure(s)')
            );
        } catch (\Throwable $error) {
            return [
                'status' => 'error',
                'message' => gettext('Discovery was not accepted: ') . $error->getMessage(),
            ];
        }
    }

    protected function providerProbe(): ProviderProbe
    {
        return new ProviderProbe(new HttpClient());
    }

    /** @return array<string,string> */
    private function formValues(): array
    {
        $values = [];
        foreach (ProviderProbe::FORM_FIELDS as $field) {
            $values[$field] = (string)$this->request->getPost($field, null, '');
        }
        if ($values['openidconnect_provider_url'] === '') {
            $values['openidconnect_provider_url'] = (string)$this->request->getPost('url', null, '');
        }
        return $values;
    }
}
