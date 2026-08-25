<?php

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
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );

        return parent::beforeExecuteRoute($dispatcher);
    }
}
