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

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\AuthorizationPreflight;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\LifecycleTestRegistry;
use OPNsense\OpenIDConnect\ProviderMetadata;
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
            $http = new HttpClient();
            $metadata = ProviderMetadata::discover(
                $settings->issuerUrl(),
                $http,
                $settings->discoveryIssuerTemplate(),
                true,
                false
            );
            $preflight = (new AuthorizationPreflight($http))->check(
                $settings,
                $metadata,
                RelyingParty::acceptedRedirectUri($settings, $this->request)
            );
            if ($preflight['status'] === 'error') {
                throw new \RuntimeException($preflight['note']);
            }
            $authorizationUrl = (new RelyingParty($settings, $this))->authorizationUrl(
                $name,
                $this->editTarget($name),
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

    /** Start the optional provider logout half from the still-authenticated settings page. */
    public function logoutAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        $id = trim((string)$this->request->getPost('test_id', null, ''));
        try {
            $test = LifecycleTestRegistry::start($id);
            $name = (string)($test['provider'] ?? '');
            $settings = (new AuthenticationFactory())->get($name);
            if (!$settings instanceof OpenIDConnect
                || !hash_equals($settings->applicationCode(), (string)($test['app_code'] ?? ''))) {
                throw new \RuntimeException(gettext('The saved authentication server no longer matches this test.'));
            }
            $exchange = new RelyingParty($settings, $this);
            $exchange->requireIssuer((string)($test['issuer'] ?? ''));
            if (!$exchange->supportsRpInitiatedLogout()) {
                throw new \RuntimeException(gettext('Discovery no longer offers an RP-initiated logout endpoint.'));
            }
            $logoutUrl = $exchange->signOutUrl(
                (string)($test['id_token'] ?? ''),
                (string)($test['return_uri'] ?? ''),
                $id
            );
            $this->session->close();
            return ['status' => 'ok', 'logout_url_b64' => base64_encode($logoutUrl)];
        } catch (\Throwable $e) {
            syslog(LOG_NOTICE, sprintf('OIDC: lifecycle sign-out test could not be started (%s)', $e->getMessage()));
            return [
                'status' => 'error',
                'message' => gettext('The sign-out test could not be started: ') . $e->getMessage(),
            ];
        }
    }

    /** Return only secret-free observations to the authenticated result modal. */
    public function resultAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        $id = trim((string)$this->request->getPost('test_id', null, ''));
        try {
            return ['status' => 'ok', 'result' => LifecycleTestRegistry::status($id)];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => gettext('The lifecycle test result is unavailable.')];
        }
    }

    /** Return to the exact core row that supplied the saved connector under test. */
    private function editTarget(string $name): string
    {
        $matches = [];
        $position = 0;
        foreach (Config::getInstance()->object()->system->authserver ?? [] as $server) {
            if ((string)($server->type ?? '') === OpenIDConnect::TYPE
                && hash_equals($name, (string)($server->name ?? ''))) {
                $matches[] = $position;
            }
            $position++;
        }

        return count($matches) === 1
            ? '/system_authservers.php?act=edit&id=' . $matches[0]
            : '/system_authservers.php';
    }
}
