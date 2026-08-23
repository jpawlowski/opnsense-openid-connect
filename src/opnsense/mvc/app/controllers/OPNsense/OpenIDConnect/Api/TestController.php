<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\OpenIDConnect\RelyingParty;

/** Start an authenticated, CSRF-protected browser sign-in test for a saved server. */
class TestController extends PrivateApiControllerBase
{
    public function startAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        $name = trim((string)$this->request->getPost('provider', null, ''));
        if ($name === '' || strlen($name) > 255 || preg_match('/[\x00-\x1f\x7f]/', $name)) {
            return ['status' => 'error', 'message' => gettext('Select a saved OpenID Connect server.')];
        }

        try {
            $settings = (new AuthenticationFactory())->get($name);
            if (!$settings instanceof OpenIDConnect) {
                throw new \RuntimeException(gettext('The selected server is not an OpenID Connect server.'));
            }
            if (!$settings->isWebGuiTransportReady()) {
                throw new \RuntimeException($settings->webGuiTransportProblem());
            }
            if (!$settings->isSignInTestReady()) {
                throw new \RuntimeException(gettext(
                    'Complete and save Exact issuer URL, Client ID and Client Secret before testing sign-in.'
                ));
            }

            /*
             * A disabled draft may deliberately be tested before it is offered on the
             * public login page. Reaching this controller already requires an
             * authenticated WebGUI session and its explicit ACL privilege.
             */
            $authorizationUrl = (new RelyingParty($settings, $this))->authorizationUrl(
                $name,
                '/system_authservers.php',
                true
            );
            $this->session->close();

            /* Core HTML-escapes string values in legacy-page API responses; Base64 keeps query separators exact. */
            return ['status' => 'ok', 'authorization_url_b64' => base64_encode($authorizationUrl)];
        } catch (\Throwable $e) {
            syslog(LOG_NOTICE, sprintf('OIDC: sign-in test for %s could not be started (%s)', $name, $e->getMessage()));
            return [
                'status' => 'error',
                'message' => gettext('The sign-in test could not be started: ') . $e->getMessage(),
            ];
        }
    }
}
