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
