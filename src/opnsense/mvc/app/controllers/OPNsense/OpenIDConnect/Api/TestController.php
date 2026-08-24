<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\AuthorizationPreflight;
use OPNsense\OpenIDConnect\HttpClient;
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
