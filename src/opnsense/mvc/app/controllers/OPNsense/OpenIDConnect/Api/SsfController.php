<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SecurityEventException;
use OPNsense\OpenIDConnect\SessionRegistry;
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
            && !$this->isExternalClient() && $contentType === 'application/secevent+jwt') {
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
        if ($resolved === null || !$resolved['settings']->receivesSharedSignals()) {
            return $this->error('access_denied', 'This receiver does not accept the transmission.');
        }
        $settings = $resolved['settings'];
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $settings->sharedSignalsPushSecret())
            || $settings->sharedSignalsAudience() === '' || $settings->sharedSignalsIssuer() === '') {
            return $this->error('access_denied', 'This receiver does not accept the transmission.');
        }
        $expectedAuthorization = 'Bearer ' . $settings->sharedSignalsPushSecret();
        $authorization = trim($this->request->getHeader('AUTHORIZATION'));
        if ($authorization === '' || !hash_equals($expectedAuthorization, $authorization)) {
            return $this->error('authentication_failed', 'The transmitter could not be authenticated.');
        }
        $set = $this->request->getRawBody();
        if (!is_string($set) || $set === '' || strlen($set) > JwtVerifier::MAX_JWT_BYTES) {
            return $this->error('invalid_request', 'The Security Event Token is empty or oversized.');
        }

        try {
            $metadata = SharedSignalsMetadata::discover($settings->sharedSignalsIssuer(), new HttpClient());
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
            $event = (new SecurityEventVerifier(new JwtVerifier(new HttpClient(), 'ssf-jwks')))->verify(
                $set,
                $metadata,
                $settings->sharedSignalsAudience(),
                $settings->issuerUrl(),
                $settings->providerProfile() === 'okta'
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
            if (!SessionRegistry::acceptSecurityEvent(
                $resolved['name'],
                $metadata->issuer(),
                $settings->sharedSignalsAudience(),
                $event['jti']
            )) {
                return $this->accepted();
            }
            try {
                $count = $event['actionable'] && $event['subject_issuer'] !== null && $event['subject'] !== null
                    ? SessionRegistry::terminateForSecurityEvent(
                        $resolved['name'],
                        $event['subject_issuer'],
                        $event['subject'],
                        $event['cutoff']
                    ) : 0;
            } catch (\Throwable $e) {
                try {
                    SessionRegistry::releaseSecurityEvent(
                        $resolved['name'],
                        $metadata->issuer(),
                        $settings->sharedSignalsAudience(),
                        $event['jti']
                    );
                } catch (\Throwable $releaseError) {
                    syslog(LOG_ERR, 'OIDC: a Shared Signals replay marker could not be released');
                }
                throw $e;
            }
            syslog(LOG_NOTICE, sprintf(
                'OIDC: accepted Shared Signals event %s for %s; ended %d session(s)',
                $event['event'],
                $resolved['name'],
                $count
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
