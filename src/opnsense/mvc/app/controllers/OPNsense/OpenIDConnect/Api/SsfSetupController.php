<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;

/** Authenticated setup helpers; no stream-management credential is retained. */
class SsfSetupController extends PrivateApiControllerBase
{
    public function secretAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        return [
            'status' => 'ok',
            'secret' => JwtVerifier::base64UrlEncode(random_bytes(32)),
        ];
    }

    public function probeAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $metadata = SharedSignalsMetadata::discover(
                trim((string)$this->request->getPost('issuer', null, '')),
                new HttpClient()
            );
            return [
                'status' => 'ok',
                'issuer' => $metadata->issuer(),
                'push_method' => SharedSignalsMetadata::PUSH_METHOD,
                'events' => SecurityEventVerifier::ACTIONABLE_EVENTS,
            ];
        } catch (\Throwable $e) {
            return [
                'status' => 'error',
                'message' => gettext('Shared Signals discovery was not accepted: ') . $e->getMessage(),
            ];
        }
    }
}
