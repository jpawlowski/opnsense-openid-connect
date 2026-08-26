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
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\SecurityEventException;
use OPNsense\OpenIDConnect\SharedSignalsEventProcessor;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;

/** Public RFC 8935 push receiver for signed Shared Signals events. */
class SsfController extends ApiControllerBase
{
    public function doAuth()
    {
        return true;
    }

    public function beforeExecuteRoute($dispatcher)
    {
        $this->response->setContentType('text/plain', 'UTF-8');
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->setHeader('Pragma', 'no-cache');
        $this->response->setHeader('Referrer-Policy', 'no-referrer');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );
        $contentType = strtolower(trim(explode(';', $this->request->getHeader('CONTENT_TYPE'))[0]));
        if ($dispatcher->getActionName() === 'push' && $this->request->isPost()
            && $contentType === 'application/secevent+jwt') {
            /* The delivery secret and signed SET replace a WebGUI session and CSRF token for this endpoint. */
            return true;
        }
        return parent::beforeExecuteRoute($dispatcher);
    }

    public function pushAction(string $applicationCode = ''): string
    {
        if (!$this->request->isPost()) {
            return $this->error('invalid_request', 'A Security Event Token POST is required.');
        }
        $contentType = strtolower(trim(explode(';', $this->request->getHeader('CONTENT_TYPE'))[0]));
        if ($contentType !== 'application/secevent+jwt') {
            return $this->error('invalid_request', 'The request does not contain a Security Event Token.');
        }
        $resolved = $this->settingsForApplicationCode($applicationCode);
        if ($resolved === null || !$resolved['settings']->receivesSharedSignals()
            || $resolved['settings']->sharedSignalsDeliveryMethod() !== SharedSignalsMetadata::PUSH_METHOD) {
            return $this->error('access_denied', 'This receiver does not accept the transmission.');
        }
        $settings = $resolved['settings'];
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $settings->sharedSignalsPushSecret())
            || $settings->sharedSignalsAudience() === '' || $settings->sharedSignalsIssuer() === '') {
            return $this->error('access_denied', 'This receiver does not accept the transmission.');
        }
        $authorization = trim($this->request->getHeader('AUTHORIZATION'));
        $acceptedAuthorization = array_map(
            static fn(string $secret): string => 'Bearer ' . $secret,
            array_filter([
                $settings->sharedSignalsPushSecret(),
                $settings->sharedSignalsPreviousPushSecret(),
            ], static fn(string $secret): bool => preg_match('/^[A-Za-z0-9_-]{43}$/D', $secret) === 1)
        );
        if ($authorization === '' || !array_reduce(
            $acceptedAuthorization,
            static fn(bool $accepted, string $expected): bool => (bool)(
                $accepted | hash_equals($expected, $authorization)
            ),
            false
        )) {
            return $this->error('authentication_failed', 'The transmitter could not be authenticated.');
        }
        $set = $this->request->getRawBody();
        if (!is_string($set) || $set === '' || strlen($set) > JwtVerifier::MAX_JWT_BYTES) {
            return $this->error('invalid_request', 'The Security Event Token is empty or oversized.');
        }

        try {
            $metadata = SharedSignalsMetadata::discover($settings->sharedSignalsIssuer(), new HttpClient());
            if (!$metadata->supportsDelivery(SharedSignalsMetadata::PUSH_METHOD)) {
                throw new \RuntimeException('The transmitter does not advertise push delivery');
            }
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf(
                'OIDC: Shared Signals metadata for %s could not be used (%s)',
                $resolved['name'],
                $e->getMessage()
            ));
            $this->response->setStatusCode(503, 'Service Unavailable');
            return '';
        }

        try {
            $event = (new SharedSignalsEventProcessor(new HttpClient()))->process(
                $set,
                $resolved['name'],
                $settings,
                $metadata
            );
        } catch (SecurityEventException $e) {
            syslog(LOG_NOTICE, sprintf(
                'OIDC: Shared Signals delivery for %s was refused (%s)',
                $resolved['name'],
                $e->getMessage()
            ));
            return $this->error($e->errorCategory(), 'The Security Event Token was not accepted.');
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf(
                'OIDC: Shared Signals verification for %s failed unexpectedly (%s)',
                $resolved['name'],
                $e->getMessage()
            ));
            $this->response->setStatusCode(503, 'Service Unavailable');
            return '';
        }

        try {
            syslog(LOG_NOTICE, sprintf(
                'OIDC: accepted Shared Signals event %s for %s; ended %d session(s)',
                $event['event'],
                $resolved['name'],
                $event['count']
            ));
            return $this->accepted();
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf(
                'OIDC: Shared Signals action for %s could not be completed (%s)',
                $resolved['name'],
                $e->getMessage()
            ));
            $this->response->setStatusCode(503, 'Service Unavailable');
            return '';
        }
    }

    private function accepted(): string
    {
        $this->response->setStatusCode(202, 'Accepted');
        return '';
    }

    private function error(string $code, string $description): string
    {
        $this->response->setStatusCode(400, 'Bad Request');
        $this->response->setContentType('application/json', 'UTF-8');
        $this->response->setHeader('Content-Language', 'en');
        return (string)json_encode(['err' => $code, 'description' => $description]);
    }

    /** @return array{name:string,settings:OpenIDConnect}|null */
    private function settingsForApplicationCode(string $applicationCode): ?array
    {
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $applicationCode)
            || in_array($applicationCode, ['.', '..'], true)) {
            return null;
        }
        $names = [];
        foreach (Config::getInstance()->object()->system->authserver ?? [] as $server) {
            if ((string)($server->type ?? '') === OpenIDConnect::TYPE
                && hash_equals($applicationCode, trim((string)($server->openidconnect_app_code ?? 'main')))
                && (string)($server->name ?? '') !== '') {
                $names[] = (string)$server->name;
            }
        }
        if (count($names) !== 1) {
            return null;
        }
        try {
            $settings = (new AuthenticationFactory())->get($names[0]);
        } catch (\Throwable $e) {
            return null;
        }
        return $settings instanceof OpenIDConnect ? ['name' => $names[0], 'settings' => $settings] : null;
    }
}
