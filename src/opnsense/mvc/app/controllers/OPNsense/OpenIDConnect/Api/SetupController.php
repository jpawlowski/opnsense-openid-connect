<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
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
