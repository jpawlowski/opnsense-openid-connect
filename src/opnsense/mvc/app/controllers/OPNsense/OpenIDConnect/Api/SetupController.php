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

use OPNsense\Auth\OpenIDConnect;
use OPNsense\OpenIDConnect\ProviderSetup;

/** Authenticated, CSRF-protected generation of provider-side onboarding files. */
class SetupController extends PrivateApiControllerBase
{
    public function generateAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');

        try {
            $origins = OpenIDConnect::splitList((string)$this->request->getPost('origins', null, ''));
            $artifact = ProviderSetup::generate(
                (string)$this->request->getPost('profile', null, ''),
                (string)$this->request->getPost('application_code', null, ''),
                (string)$this->request->getPost('display_name', null, ''),
                $origins,
                $this->postedFlag('post_logout_redirect'),
                (string)$this->request->getPost('logout_channel', null, 'backchannel'),
                (string)$this->request->getPost('sector_origin', null, ''),
                [
                    'openidconnect_scopes' =>
                        (string)$this->request->getPost('openidconnect_scopes', null, ''),
                    'openidconnect_username_claim' =>
                        (string)$this->request->getPost('openidconnect_username_claim', null, ''),
                    'openidconnect_group_claim' =>
                        (string)$this->request->getPost('openidconnect_group_claim', null, ''),
                    'openidconnect_required_authentication' =>
                        (string)$this->request->getPost('openidconnect_required_authentication', null, ''),
                    'openidconnect_acr_request' =>
                        (string)$this->request->getPost('openidconnect_acr_request', null, ''),
                    'openidconnect_acr_values' =>
                        (string)$this->request->getPost('openidconnect_acr_values', null, ''),
                    'openidconnect_amr_values' =>
                        (string)$this->request->getPost('openidconnect_amr_values', null, ''),
                ],
                (string)$this->request->getPost('preferred_origin', null, '')
            );
            return ['status' => 'ok'] + $artifact;
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => gettext('Setup file was not generated: ') . $e->getMessage()];
        }
    }

    private function postedFlag(string $name): bool
    {
        return in_array(strtolower((string)$this->request->getPost($name, null, '')), [
            '1', 'yes', 'true', 'on',
        ], true);
    }
}
