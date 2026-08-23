<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Base\ApiControllerBase;

/** Apply private-response policy before core can answer authentication or CSRF failures. */
abstract class PrivateApiControllerBase extends ApiControllerBase
{
    public function beforeExecuteRoute($dispatcher)
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->setHeader('Pragma', 'no-cache');
        $this->response->setHeader('Referrer-Policy', 'no-referrer');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');

        return parent::beforeExecuteRoute($dispatcher);
    }
}
