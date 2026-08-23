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
                (string)$this->request->getPost('logout_channel', null, 'backchannel')
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
