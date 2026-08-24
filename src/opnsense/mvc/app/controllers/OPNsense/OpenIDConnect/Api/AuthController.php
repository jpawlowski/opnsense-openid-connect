<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\Core\SanitizeFilter;
use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\RelyingParty;
use OPNsense\OpenIDConnect\ProtocolException;
use OPNsense\OpenIDConnect\SessionRegistry;
use OPNsense\OpenIDConnect\SessionGrant;
use OPNsense\OpenIDConnect\WebGuiAccess;

/**
 * The browser's side of an OpenID Connect login to the web interface.
 *
 *   /api/openidconnect/auth/login     start the exchange, or go where the browser belongs
 *   /api/openidconnect/auth/callback  finish it and turn the answer into a session
 *   /api/openidconnect/auth/logout    end here and at the provider
 *   /api/openidconnect/auth/icon      hand on a provider's logo for the login button
 *   /api/openidconnect/auth/builtinicon hand out a package-owned provider mark
 *   /api/openidconnect/auth/sector    publish callback URIs for pairwise subjects
 *
 * These endpoints answer before anyone is logged in, so doAuth() declines the usual
 * session check. What protects them is the protocol: the provider's answer has to carry
 * the state and the nonce this firewall issued, and a session is only established once
 * RelyingParty has accepted it.
 */
class AuthController extends ApiControllerBase
{
    /** clock tolerance when judging how old an authentication is */
    private const CLOCK_TOLERANCE = 60;

    /** what a login page has any use for; anything else is not an icon */
    private const ICON_TYPES = [
        'image/png', 'image/jpeg', 'image/gif', 'image/webp',
        'image/svg+xml', 'image/x-icon', 'image/vnd.microsoft.icon',
    ];

    /** an icon that does not fit in here is not one either */
    private const ICON_MAX_BYTES = 262144;

    public function doAuth()
    {
        return true;
    }

    /**
     * OIDC form_post is protected by the transaction state and nonce, not by the WebGUI
     * CSRF header an external provider cannot know. Every other POST keeps core's normal
     * authentication and CSRF processing.
     */
    public function beforeExecuteRoute($dispatcher)
    {
        if (in_array($dispatcher->getActionName(), ['icon', 'builtinicon'], true)) {
            /* Safe failure defaults; a validated image deliberately overrides type, policy and caching. */
            $this->response->setContentType('text/plain', 'UTF-8');
            $this->response->setHeader('Cache-Control', 'no-store');
            $this->response->setHeader('Referrer-Policy', 'no-referrer');
            $this->response->setHeader('X-Content-Type-Options', 'nosniff');
            $this->response->setHeader(
                'Content-Security-Policy',
                "default-src 'none'; frame-ancestors 'none'; sandbox"
            );
        } else {
            /* Authorization codes, tokens and failure references must never be cached or leaked as referrers. */
            $this->response->setContentType('text/plain', 'UTF-8');
            $this->response->setHeader('Cache-Control', 'no-store');
            $this->response->setHeader('Pragma', 'no-cache');
            $this->response->setHeader('Referrer-Policy', 'no-referrer');
            $this->response->setHeader('X-Content-Type-Options', 'nosniff');
            $this->response->setHeader(
                'Content-Security-Policy',
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            );
        }
        if (in_array($dispatcher->getActionName(), ['callback', 'backchannel'], true)
            && $this->request->isPost()
            && !$this->isExternalClient()
            && str_starts_with(strtolower($this->request->getHeader('CONTENT_TYPE')), 'application/x-www-form-urlencoded')) {
            return true;
        }

        return parent::beforeExecuteRoute($dispatcher);
    }

    /** Publish the saved redirect URIs only through this server's exact configured sector origin. */
    public function sectorAction(string $applicationCode = '')
    {
        $settings = $this->settingsForApplicationCode($applicationCode);
        $sectorOrigin = $settings?->sectorOrigin() ?? '';
        if ($settings === null || $sectorOrigin === '') {
            return $this->refuse(404, 'Not Found', 'Not Found.');
        }
        try {
            $requestOrigin = OpenIDConnect::normalizeHttpsOrigin(RelyingParty::intendedOrigin(
                $this->request,
                $settings->usesTrustedTlsOffloading()
            ));
        } catch (\Throwable $e) {
            return $this->refuse(404, 'Not Found', 'Not Found.');
        }
        if ($requestOrigin === null || !hash_equals($sectorOrigin, $requestOrigin)) {
            return $this->refuse(404, 'Not Found', 'Not Found.');
        }

        $this->response->setContentType('application/json', 'UTF-8');
        return array_map(
            static fn(string $origin): string => $origin . RelyingParty::callbackPath($applicationCode),
            $settings->effectiveWebGuiOrigins()
        );
    }

    /* ------------------------------------------------------ federated session logout */

    /** Receive a signed OIDC Back-Channel Logout token from a configured provider. */
    public function backchannelAction(string $applicationCode = '')
    {
        $settings = $this->settingsForApplicationCode($applicationCode);
        $logoutToken = $this->request->getPost('logout_token', null, null);
        if ($settings === null || !$settings->acceptsBackchannelLogout()
            || !is_string($logoutToken) || $logoutToken === ''
            || strlen($logoutToken) > JwtVerifier::MAX_JWT_BYTES) {
            return $this->refuse(400, 'Bad Request', 'The logout request was not accepted.');
        }

        $acceptedReplay = null;
        try {
            $http = new HttpClient();
            $metadata = ProviderMetadata::discover(
                $settings->issuerUrl(),
                $http,
                $settings->discoveryIssuerTemplate()
            );
            $issuerValidator = $settings->discoveryIssuerTemplate() === null ? null
                : fn(array $claims, array $key) => $settings->validateMicrosoftIssuer($claims, $key);
            $claims = (new JwtVerifier($http))->verifyLogoutToken(
                $logoutToken,
                $metadata,
                $settings->clientId(),
                null,
                $issuerValidator
            );
            $logoutIssuer = (string)$claims['iss'];
            $replayExpires = $claims['exp'] + JwtVerifier::CLOCK_TOLERANCE;
            if (!SessionRegistry::acceptLogoutToken($logoutIssuer, $claims['jti'], $replayExpires)) {
                throw new ProtocolException('The back-channel logout token was already processed');
            }
            $acceptedReplay = [$logoutIssuer, (string)$claims['jti']];
            $count = SessionRegistry::terminate(
                $logoutIssuer,
                is_string($claims['sid'] ?? null) ? $claims['sid'] : null,
                is_string($claims['sub'] ?? null) ? $claims['sub'] : null
            );
            syslog(LOG_NOTICE, sprintf('OIDC: back-channel logout invalidated %d local session(s)', $count));
        } catch (\Throwable $e) {
            if ($acceptedReplay !== null) {
                try {
                    SessionRegistry::releaseLogoutToken($acceptedReplay[0], $acceptedReplay[1]);
                } catch (\Throwable $releaseError) {
                    syslog(LOG_ERR, 'OIDC: a failed back-channel logout replay marker could not be released');
                }
            }
            return $this->protocolFailure('', 'the back-channel logout was not accepted', $e, 400);
        }

        $this->response->setHeader('Cache-Control', 'no-store');
        return '';
    }

    /** Receive an iframe-based OIDC Front-Channel Logout notification. */
    public function frontchannelAction(string $applicationCode = '')
    {
        $settings = $this->settingsForApplicationCode($applicationCode);
        $issuer = $this->request->get('iss', null);
        $sid = $this->request->get('sid', null);
        if ($settings === null || !$settings->acceptsFrontchannelLogout()
            || !is_string($issuer) || !is_string($sid)
            || $issuer === '' || $sid === '' || strlen($sid) > 255
            || ($settings->discoveryIssuerTemplate() === null
                ? !hash_equals($settings->issuerUrl(), $issuer)
                : !$settings->acceptsMicrosoftIssuerValue($issuer))) {
            return $this->refuse(400, 'Bad Request', 'The logout request was not accepted.');
        }
        try {
            $count = SessionRegistry::terminate($issuer, $sid, null);
            syslog(LOG_NOTICE, sprintf('OIDC: front-channel logout invalidated %d local session(s)', $count));
        } catch (\Throwable $e) {
            return $this->protocolFailure('', 'the front-channel logout was not accepted', $e, 400);
        }
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors *");
        return '';
    }

    /* -------------------------------------------------------------------- login */

    public function loginAction()
    {
        $target = $this->requestedTarget();

        if ($this->alreadySignedIn()) {
            /**
             * A provider-initiated launch - someone clicking this firewall's tile in the
             * identity provider - arrives with a session already in place. Nothing is
             * wrong; the browser simply belongs somewhere else.
             */
            return $this->sendTo($target);
        }

        $name = (string)$this->request->get('provider');
        $settings = $this->settingsFor($name);
        if ($settings === null) {
            $this->auditRefusal($name, 'no authentication server of that name');
            return $this->refuse(404, 'Not Found', 'No such authentication server.');
        }

        if (!$settings->isEnabled() || RelyingParty::acceptedRedirectUri($settings, $this->request) === null) {
            syslog(LOG_NOTICE, 'OIDC: refusing a login begun under an unavailable provider or WebGUI origin');
            $this->auditRefusal($name, 'begun under an address this server does not accept');
            return $this->refuse(400, 'Bad Request', 'Single sign-on is not available under this address.');
        }

        $settings->trace(sprintf('starting an exchange for %s, target %s', $name, $target));

        try {
            (new RelyingParty($settings, $this))->begin($name, $target);
        } catch (\Exception $e) {
            return $this->protocolFailure($name, 'the exchange could not be begun', $e);
        }

        $this->session->close();

        return 'Redirecting to the identity provider...';
    }

    /* ----------------------------------------------------------------- callback */

    public function callbackAction(string $applicationCode = '')
    {
        $parameters = $this->authorizationResponse();
        $name = '';
        $purpose = 'login';
        try {
            $transaction = RelyingParty::consumeTransaction($this->session, $parameters, $applicationCode);
            $name = (string)$transaction['provider'];
            $target = (string)($transaction['target'] ?? '/');
            $purpose = (string)($transaction['purpose'] ?? 'login');
            if (!in_array($purpose, ['login', 'test'], true)) {
                throw new ProtocolException('The pending transaction has an unknown purpose');
            }
            if ($purpose === 'login' && $this->alreadySignedIn()) {
                return $this->sendTo('/');
            }
            $settings = $this->settingsFor($name);
            if ($settings === null || ($purpose === 'login' && !$settings->isEnabled())
                || !hash_equals($applicationCode, $settings->applicationCode())) {
                throw new ProtocolException('The pending provider configuration no longer exists');
            }
            $exchange = new RelyingParty($settings, $this);
            $claims = $exchange->complete($transaction, $parameters);
        } catch (\Exception $e) {
            return $this->protocolFailure($name, 'the authorization response was not accepted', $e, 403);
        }

        $settings->trace('the provider answered and the answer was accepted');

        if (!$this->authenticationIsRecentEnough($settings, $exchange)) {
            $this->auditRefusal($name, 'the authentication is older than accepted');
            return $this->refuse(403, 'Forbidden', 'The provider reported an authentication older than accepted.');
        }

        if ($purpose === 'test') {
            $settings->trace('the accepted answer completed a sign-in test without changing the local session');
            return $this->signInTestResult($name, $settings, $exchange, $claims);
        }

        $account = $settings->localAccountFor($claims, $exchange->issuer(), $exchange->subject());
        if ($account === null) {
            /* localAccountFor() has already said in the log which of its reasons it was */
            $this->auditRefusal($name, 'no local account this login may use');
            return $this->refuse(403, 'Forbidden', 'There is no local account for this user, or it may not be used.');
        }

        try {
            $authorizedTarget = (new WebGuiAccess(new ACL()))->authorizedTarget($account, $target);
        } catch (\Throwable $e) {
            return $this->protocolFailure($name, 'local WebGUI authorization could not be checked', $e);
        }
        if ($authorizedTarget === null) {
            $settings->trace(sprintf('resolved to local account %s, but no usable WebGUI page is authorized', $account));
            $this->auditAuthorizationRefusal($name, $account);
            return $this->authorizationDeniedResult();
        }
        if ($authorizedTarget !== $target) {
            $settings->trace(sprintf(
                'local account %s may not open requested target %s; using authorized landing page %s',
                $account,
                $target,
                $authorizedTarget
            ));
        } else {
            $settings->trace(sprintf('resolved to local account %s, sending to %s', $account, $authorizedTarget));
        }
        try {
            $this->establishSession($account, $name, $exchange);
        } catch (\Throwable $e) {
            return $this->protocolFailure($name, 'the local session could not be established', $e);
        }

        return $this->sendTo($authorizedTarget);
    }

    /* ------------------------------------------------------------------- logout */

    /**
     * Core's own logout drops the local session and nothing else, and the link in the page
     * header is written into authgui.inc where a plugin cannot reach it. This is the
     * deliberate alternative; the Log Out menu entry can be pointed here.
     */
    public function logoutAction()
    {
        /**
         * Somebody leaving arrives from this firewall or by typing the address; a
         * cross-site request is a foreign page ending the session for them, and with it
         * the tokens the provider issued. The session cookie is SameSite=Lax, so a
         * navigation from anywhere carries it - the browser's own account of where the
         * request came from is what tells the two apart.
         */
        if (!$this->sameOriginNavigation()) {
            return $this->sendTo('/');
        }

        $name = (string)$this->session->get(SessionGrant::PROVIDER);
        $issuer = (string)$this->session->get(SessionGrant::ISSUER);
        $idToken = (string)$this->session->get(SessionGrant::ID_TOKEN);
        $tokens = json_decode((string)$this->session->get(SessionGrant::TOKENS), true) ?: [];
        $clientAuthentication = json_decode(
            (string)$this->session->get(SessionGrant::CLIENT_AUTHENTICATION),
            true
        );
        $clientAuthentication = is_array($clientAuthentication) ? $clientAuthentication : null;

        $settings = $name === '' || $issuer === '' || $idToken === '' ? null : $this->settingsFor($name);
        $settings?->trace(sprintf('signing out of %s, %d token(s) to hand back', $name, count(array_filter($tokens))));

        /**
         * Drop the local session the way core does. Nothing may be written through the
         * session wrapper from here on: the dispatcher would open a fresh session on the
         * way out and hand the browser a new cookie.
         */
        try {
            SessionRegistry::remove(session_id());
        } catch (\Throwable $e) {
            syslog(LOG_NOTICE, sprintf('OIDC: could not remove the session logout index (%s)', $e->getMessage()));
        }
        $this->discardSession();

        if ($settings === null) {
            return $this->sendTo('/');
        }

        try {
            $exchange = new RelyingParty($settings, $this, null, null, $clientAuthentication);
            /*
             * A server name can be reused for another issuer after this session was
             * created. Never hand grants from the former issuer to endpoints discovered
             * from the replacement configuration.
             */
            $exchange->requireIssuer($issuer);

            /* ending the session at the provider does not invalidate what it already issued */
            foreach ($tokens as $hint => $token) {
                if (empty($token)) {
                    continue;
                }
                try {
                    $exchange->revokeToken($token, (string)$hint);
                } catch (\Exception $e) {
                    syslog(LOG_NOTICE, sprintf('OIDC: could not revoke the %s (%s)', $hint, $e->getMessage()));
                }
            }

            $exchange->signOut($idToken, $settings->returnsAfterLogout() ? $exchange->ownOrigin() . '/' : null);
        } catch (\Exception $e) {
            /* the local session is gone already; never strand anyone on an error page */
            syslog(LOG_ERR, sprintf('OIDC: signing out at the provider failed (%s)', $e->getMessage()));
            return $this->sendTo('/');
        }

        return 'Signing out at the identity provider...';
    }

    private function sameOriginNavigation(): bool
    {
        $fetchSite = strtolower(trim($this->request->getHeader('Sec-Fetch-Site')));
        if (in_array($fetchSite, ['same-origin', 'none'], true)) {
            return true;
        }
        $referer = trim($this->request->getHeader('REFERER'));
        if ($referer === '') {
            return false;
        }
        $parts = parse_url($referer);
        $origin = strtolower((string)($parts['scheme'] ?? '')) . '://' . strtolower((string)($parts['host'] ?? ''))
            . (isset($parts['port']) ? ':' . $parts['port'] : '');
        try {
            $provider = (string)$this->session->get(SessionGrant::PROVIDER);
            $settings = $provider !== '' ? $this->settingsFor($provider) : null;
            return hash_equals(strtolower(RelyingParty::intendedOrigin(
                $this->request,
                $settings instanceof OpenIDConnect && $settings->usesTrustedTlsOffloading()
            )), $origin);
        } catch (ProtocolException $e) {
            return false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /* --------------------------------------------------------------------- icon */

    /**
     * Hands on a provider's logo, so that the login page needs no third-party request.
     *
     * This answers before anyone has signed in, and what it answers with comes from a
     * machine that is not this one. So the far end gets to choose the picture and nothing
     * else: the scheme is ours, the content type has to be one of ours, the size is
     * bounded, and the answer is served under headers that keep it a picture even when
     * somebody opens the address directly. An SVG handed on as the far end labelled it
     * would otherwise be a script running in this firewall's origin, on a page reachable
     * without a login.
     */
    public function iconAction()
    {
        $settings = $this->settingsFor((string)$this->request->get('provider'));
        if ($settings === null || !$settings->isEnabled()) {
            return $this->refuse(404, 'Not Found', 'No such authentication server.');
        }

        $source = $settings->iconUrl();
        if (!OpenIDConnect::isFetchableUrl($source)) {
            return $this->refuse(404, 'Not Found', 'This server has no icon to hand on.');
        }

        $answer = RelyingParty::fetchOverWeb($source, self::ICON_MAX_BYTES);

        /* an answer over the size is a transfer curl gave up on, and says so in plain words */
        if (!$answer['ok'] || $answer['status'] !== 200) {
            syslog(LOG_NOTICE, sprintf(
                'OIDC: could not fetch the configured login icon (%s)',
                $answer['problem'] ?: 'HTTP ' . $answer['status']
            ));
            return $this->refuse(404, 'Not Found', 'The configured icon is not available.');
        }
        if (!in_array($answer['type'], self::ICON_TYPES, true)) {
            syslog(LOG_NOTICE, sprintf(
                'OIDC: refusing to hand on an icon answered as %s',
                $answer['type'] ?: 'nothing'
            ));
            return $this->refuse(404, 'Not Found', 'What that address answers with is not an image.');
        }

        $this->response->setHeader('Content-Type', $answer['type']);
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');

        return $answer['body'];
    }

    /** Serve the reviewed SVG which a provider profile selects by default. */
    public function builtiniconAction(string $profile = '')
    {
        $path = OpenIDConnect::providerIconPath($profile);
        if ($path === null) {
            return $this->refuse(404, 'Not Found', 'No such built-in provider icon.');
        }
        $body = file_get_contents($path);
        if (!is_string($body) || $body === '' || strlen($body) > self::ICON_MAX_BYTES) {
            syslog(LOG_ERR, sprintf('OIDC: built-in provider icon %s could not be read safely', $profile));
            return $this->refuse(404, 'Not Found', 'The built-in provider icon is not available.');
        }

        $this->response->setHeader('Content-Type', 'image/svg+xml');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
        return $body;
    }

    /* ------------------------------------------------------------------ helpers */

    /**
     * @return OpenIDConnect|null the named server, when it speaks this protocol
     */
    private function settingsFor(string $name): ?OpenIDConnect
    {
        if ($name === '') {
            return null;
        }
        try {
            $settings = (new AuthenticationFactory())->get($name);
        } catch (\Throwable $e) {
            syslog(LOG_NOTICE, sprintf('OIDC: could not read authentication server %s (%s)', $name, $e->getMessage()));
            return null;
        }

        return $settings instanceof OpenIDConnect ? $settings : null;
    }

    /** Resolve a callback code uniquely, so two configurations can never share a logout URI. */
    private function settingsForApplicationCode(string $applicationCode): ?OpenIDConnect
    {
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $applicationCode)
            || in_array($applicationCode, ['.', '..'], true)) {
            return null;
        }
        $matches = [];
        foreach (Config::getInstance()->object()->system->authserver ?? [] as $server) {
            $code = trim((string)($server->openidconnect_app_code ?? 'main'));
            if ((string)($server->type ?? '') === OpenIDConnect::TYPE
                && hash_equals($applicationCode, $code)
                && !empty((string)($server->name ?? ''))) {
                $matches[] = (string)$server->name;
            }
        }
        if (count($matches) !== 1) {
            return null;
        }
        return $this->settingsFor($matches[0]);
    }

    private function alreadySignedIn(): bool
    {
        return $this->session->get('Username') != null;
    }

    /**
     * @return string where the browser asked to go, '/' when that was absent or not local
     */
    private function requestedTarget(): string
    {
        $asked = (new SanitizeFilter())->sanitize($this->request->get('redir') ?? '', 'local_uri');

        return empty($asked) ? '/' : $asked;
    }

    /** @return array<string,mixed> only parameters defined for an authorization response */
    private function authorizationResponse(): array
    {
        $parameters = [];
        foreach ([
            'response', 'state', 'code', 'iss', 'error', 'error_description', 'error_uri', 'session_state',
            'access_token', 'id_token', 'token_type', 'expires_in',
        ] as $name) {
            $value = $this->request->isPost()
                ? $this->request->getPost($name, null, null)
                : $this->request->get($name, null);
            if ($value !== null) {
                $parameters[$name] = $value;
            }
        }
        return $parameters;
    }

    /**
     * A provider may ignore max_age, so its answer is checked rather than trusted.
     */
    private function authenticationIsRecentEnough(OpenIDConnect $settings, RelyingParty $exchange): bool
    {
        $limit = $settings->maximumAuthenticationAge();
        $authenticatedAt = $exchange->authenticationTime();
        if ($authenticatedAt === null) {
            /* required in the id_token once max_age was asked for, OIDC Core 3.1.2.1 */
            syslog(LOG_ERR, 'OIDC: refusing a login, no auth_time came back although max_age was requested');
            return false;
        }

        $age = time() - $authenticatedAt;
        $settings->trace(sprintf('authentication is %d seconds old, at most %d accepted', $age, $limit));
        if ($age > $limit + self::CLOCK_TOLERANCE) {
            syslog(LOG_NOTICE, sprintf(
                'OIDC: refusing a login, the authentication is %d seconds old and at most %d are accepted',
                $age,
                $limit
            ));
            return false;
        }

        return true;
    }

    /**
     * Turn an accepted exchange into a web interface session, and note what a later logout
     * will need to undo it.
     */
    private function establishSession(string $account, string $provider, RelyingParty $exchange): void
    {
        $webgui = Config::getInstance()->object()->system->webgui;

        $this->session->set('Username', $account);
        $this->session->set('last_access', time());
        $this->session->set('protocol', (string)$webgui->protocol);

        $idToken = (string)$exchange->getIdToken();
        if ($idToken !== '') {
            $this->session->set(SessionGrant::PROVIDER, $provider);
            $this->session->set(SessionGrant::ISSUER, $exchange->issuer());
            $this->session->set(SessionGrant::ID_TOKEN, $idToken);
            $this->session->set(SessionGrant::TOKENS, (string)json_encode(array_filter([
                'access_token' => (string)$exchange->getAccessToken(),
                'refresh_token' => (string)$exchange->getRefreshToken(),
            ])));
            $this->session->set(
                SessionGrant::CLIENT_AUTHENTICATION,
                (string)json_encode($exchange->getClientAuthenticationSnapshot())
            );
        }

        syslog(LOG_NOTICE, sprintf('OIDC: %s signed in through %s', $account, $provider));
        $this->audit(LOG_NOTICE, sprintf(
            "Successful login for user '%s' from: %s [using OpenID Connect + %s]",
            $account,
            $this->request->getClientAddress(),
            $provider
        ));

        $this->session->close();
        $sessionId = $this->renewSessionId();
        if ($sessionId !== '') {
            try {
                $minutes = max(1, (int)($webgui->session_timeout ?? 240));
                SessionRegistry::record(
                    $sessionId,
                    $provider,
                    $exchange->issuer(),
                    $exchange->subject(),
                    $exchange->sessionIdentifier(),
                    time() + $minutes * 60
                );
            } catch (\Throwable $e) {
                syslog(LOG_ERR, sprintf(
                    'OIDC: could not index the session for federated logout (%s)',
                    $e->getMessage()
                ));
            }
        }
    }

    /**
     * Hand the browser a new session id now that the session has gained privileges, so
     * that an id planted beforehand is worth nothing afterwards.
     *
     * Deliberately after the wrapper has written its payload: rotating an id that already
     * carries the login means it cannot be left behind in the old session, because
     * session_regenerate_id(true) copies the data across and removes the old file.
     */
    private function renewSessionId(): string
    {
        try {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            if (!session_regenerate_id(true)) {
                throw new ProtocolException('The session identifier could not be renewed');
            }
            $sessionId = session_id();
            session_write_close();
            return $sessionId;
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf('OIDC: could not renew the session id after a login (%s)', $e->getMessage()));
            /* A privileged session under its pre-login identifier is session fixation. */
            try {
                $this->discardSession();
            } catch (\Throwable $discardError) {
                syslog(LOG_ERR, sprintf(
                    'OIDC: could not discard a session after identifier rotation failed (%s)',
                    $discardError->getMessage()
                ));
            }
            throw new ProtocolException('The local session could not be secured', 0, $e);
        }
    }

    /**
     * Clear the php session, the way the logout branch of core's session_auth() does.
     */
    private function discardSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $_SESSION = [];
        if (isset($_COOKIE[session_name()])) {
            $secure = (string)Config::getInstance()->object()->system->webgui->protocol === 'https';
            setcookie(session_name(), '', time() - 42000, '/', '', $secure, true);
        }

        session_destroy();
    }

    private function sendTo(string $location): string
    {
        $this->response->redirect($location);

        return 'Redirecting...';
    }

    /**
     * Report a complete browser-flow test without granting access or applying identity policy.
     *
     * form_post deliberately arrives without the SameSite=Lax administrator cookie. The
     * session wrapper briefly starts an otherwise empty PHP session while constructing the
     * controller; suppress its cookie so it cannot replace the administrator's still-stored
     * browser cookie. No transaction data was written to that temporary session.
     */
    private function signInTestResult(
        string $name,
        OpenIDConnect $settings,
        RelyingParty $exchange,
        object $claims
    ): string {
        if ($this->request->isPost()) {
            header_remove('Set-Cookie');
        }
        $this->response->setContentType('text/html', 'UTF-8');
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );

        $claimName = $settings->usernameClaim();
        $claimValue = $this->displayClaim($claims, $claimName);
        $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $rows = [
            [gettext('Authentication server'), $name, 'info'],
            [gettext('Exact issuer'), $exchange->issuer(), 'success'],
            [gettext('PKCE binding'), 'S256', 'success'],
            [gettext('Subject'), $exchange->subject(), 'success'],
            [
                sprintf(gettext('Username claim (%s)'), $claimName),
                $claimValue,
                property_exists($claims, $claimName) ? 'success' : 'warning',
            ],
            [gettext('Claims source'), $settings->claimsSource(), 'info'],
        ];
        $status = [
            'success' => ['symbol' => '✓', 'label' => gettext('Passed')],
            'warning' => ['symbol' => '!', 'label' => gettext('Warning')],
            'info' => ['symbol' => 'i', 'label' => gettext('Information')],
        ];
        $table = '';
        foreach ($rows as [$label, $value, $rowStatus]) {
            $table .= '<tr data-status="' . $rowStatus . '"><th>' . $escape((string)$label)
                . '</th><td><code>' . $escape((string)$value) . '</code></td><td><span class="badge '
                . $rowStatus . '"><span aria-hidden="true">' . $status[$rowStatus]['symbol']
                . '</span> ' . $escape($status[$rowStatus]['label']) . '</span></td></tr>';
        }

        return '<!doctype html><html><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $escape(gettext('OpenID Connect sign-in test')) . '</title>'
            . '<style>:root{color-scheme:light dark;--bg:#f3f5f7;--panel:#fff;--text:#263238;--muted:#5d6b73;'
            . '--line:#d8dee2;--success:#197343;--success-bg:#e9f7ef;--warning:#805400;--warning-bg:#fff4d6;'
            . '--info:#215f87;--info-bg:#e8f4fb}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);'
            . 'font:16px/1.5 system-ui,-apple-system,sans-serif}main{max-width:64rem;margin:3rem auto;padding:0 1rem}.panel{'
            . 'background:var(--panel);border:1px solid var(--line);border-radius:.7rem;box-shadow:0 .25rem 1.25rem #00000012;'
            . 'overflow:hidden}.hero{display:flex;gap:1rem;align-items:center;padding:1.5rem 1.75rem;background:var(--success-bg);'
            . 'border-bottom:1px solid var(--line)}.hero-icon{display:grid;place-items:center;flex:0 0 3rem;height:3rem;border-radius:50%;'
            . 'background:var(--success);color:#fff;font-size:1.7rem;font-weight:700}.hero h1{margin:0;color:var(--success);font-size:1.65rem}'
            . '.hero p{margin:.2rem 0 0;color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));'
            . 'gap:1rem;padding:1.5rem}.card{display:grid;grid-template-columns:2rem 1fr;gap:.7rem;padding:1rem;border:1px solid var(--line);'
            . 'border-radius:.45rem}.card.success{background:var(--success-bg);color:var(--success)}.card.info{background:var(--info-bg);'
            . 'color:var(--info)}.card.warning{background:var(--warning-bg);color:var(--warning)}.card .mark{font-size:1.3rem;'
            . 'font-weight:800}.card strong{display:block}.card span:last-child{display:block;margin-top:.2rem;color:var(--text);font-size:.92rem}'
            . '.details{padding:0 1.5rem 1.5rem}.details h2{font-size:1.15rem;margin:.25rem 0 .75rem}table{border-collapse:collapse;'
            . 'width:100%}th,td{text-align:left;vertical-align:top;border-top:1px solid var(--line);padding:.7rem}th{width:30%}'
            . 'td:last-child{text-align:right;width:8rem}code{overflow-wrap:anywhere;color:inherit}.badge{display:inline-block;white-space:nowrap;'
            . 'padding:.25rem .45rem;border-radius:1rem;font-size:.78rem;font-weight:700}.badge.success{background:var(--success-bg);'
            . 'color:var(--success)}.badge.warning{background:var(--warning-bg);color:var(--warning)}.badge.info{background:var(--info-bg);'
            . 'color:var(--info)}.actions{padding:0 1.5rem 1.5rem}a{display:inline-block;padding:.6rem .85rem;background:#337ab7;'
            . 'color:#fff;text-decoration:none;border-radius:.3rem;font-weight:600}@media(max-width:600px){main{margin:1rem auto}.hero{'
            . 'align-items:flex-start}.cards{grid-template-columns:1fr}.details{overflow-x:auto}th{min-width:10rem}}@media(prefers-color-scheme:dark){'
            . ':root{--bg:#172126;--panel:#202c32;--text:#edf2f4;--muted:#bdc9ce;--line:#405159;--success:#76d39e;'
            . '--success-bg:#183c2a;--warning:#ffd166;--warning-bg:#493a13;--info:#8dccf2;--info-bg:#17384c}}'
            . '</style></head><body><main><section class="panel oidc-signin-result" aria-labelledby="result-title">'
            . '<header class="hero"><span class="hero-icon" aria-hidden="true">✓</span><div><h1 id="result-title">'
            . $escape(gettext('Sign-in test succeeded')) . '</h1><p>'
            . $escape(gettext('The identity provider answered and every required protocol check passed.'))
            . '</p></div></header><div class="cards"><div class="card success"><span class="mark" aria-hidden="true">✓</span><div><strong>'
            . $escape(gettext('Protocol validation passed')) . '</strong><span>'
            . $escape(gettext('Authorization response, PKCE, code exchange, ID Token and claims source were accepted.'))
            . '</span></div></div><div class="card info"><span class="mark" aria-hidden="true">i</span><div><strong>'
            . $escape(gettext('OPNsense remained unchanged')) . '</strong><span>'
            . $escape(gettext('No login session, local account, subject binding or group membership was changed.'))
            . '</span></div></div><div class="card warning"><span class="mark" aria-hidden="true">!</span><div><strong>'
            . $escape(gettext('Provider session may remain')) . '</strong><span>'
            . $escape(gettext('Use a private window when a later test must begin without the provider SSO session.'))
            . '</span></div></div></div><section class="details"><h2>' . $escape(gettext('Verified details'))
            . '</h2><table class="oidc-signin-results"><tbody>' . $table . '</tbody></table></section><div class="actions">'
            . '<a href="/system_authservers.php">' . $escape(gettext('Return to authentication servers'))
            . '</a></div></section></main></body></html>';
    }

    private function displayClaim(object $claims, string $name): string
    {
        if (!property_exists($claims, $name)) {
            return gettext('not present');
        }
        $value = $claims->{$name};
        if (is_array($value)) {
            $scalars = array_filter($value, static fn($item): bool => is_scalar($item) || $item === null);
            $value = count($scalars) === count($value)
                ? implode(', ', array_map(static fn($item): string => (string)$item, $value))
                : gettext('present as structured data');
        } elseif (is_object($value)) {
            $value = gettext('present as structured data');
        } elseif (is_bool($value)) {
            $value = $value ? 'true' : 'false';
        } elseif ($value === null) {
            $value = 'null';
        } else {
            $value = (string)$value;
        }
        $value = preg_replace('/[\x00-\x1f\x7f]/', ' ', (string)$value);

        return strlen($value) > 512 ? substr($value, 0, 509) . '...' : $value;
    }

    /** Explain a successful provider authentication that local OPNsense ACLs do not admit. */
    private function authorizationDeniedResult(): string
    {
        $this->response->setStatusCode(403, 'Forbidden');
        $this->response->setContentType('text/html', 'UTF-8');
        $this->response->setHeader(
            'Content-Security-Policy',
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        );
        if ($this->request->isPost()) {
            header_remove('Set-Cookie');
        }
        $escape = static fn(string $value): string => htmlspecialchars(
            $value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        return '<!doctype html><html><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . $escape(gettext('WebGUI access denied')) . '</title>'
            . '<style>:root{color-scheme:light dark;--bg:#f3f5f7;--panel:#fff;--text:#263238;--muted:#5d6b73;'
            . '--line:#d8dee2;--accent:#9c2f2f;--accent-bg:#fbeaea}*{box-sizing:border-box}body{margin:0;background:var(--bg);'
            . 'color:var(--text);font:16px/1.55 system-ui,-apple-system,sans-serif}main{max-width:44rem;margin:4rem auto;padding:0 1rem}'
            . '.panel{background:var(--panel);border:1px solid var(--line);border-radius:.7rem;box-shadow:0 .25rem 1.25rem #00000012;'
            . 'overflow:hidden}.hero{display:flex;gap:1rem;align-items:center;padding:1.6rem;background:var(--accent-bg);border-bottom:1px solid var(--line)}'
            . '.mark{display:grid;place-items:center;flex:0 0 3rem;height:3rem;border-radius:50%;background:var(--accent);color:#fff;'
            . 'font-size:1.5rem;font-weight:800}.hero h1{margin:0;color:var(--accent);font-size:1.55rem}.hero p{margin:.2rem 0 0;color:var(--muted)}'
            . '.content{padding:1.6rem}.notice{margin:1rem 0;padding:1rem;border:1px solid var(--line);border-radius:.4rem;background:var(--accent-bg)}'
            . 'ol{padding-left:1.3rem}li+li{margin-top:.45rem}a{display:inline-block;margin-top:.5rem;padding:.6rem .85rem;background:#337ab7;'
            . 'color:#fff;text-decoration:none;border-radius:.3rem;font-weight:600}@media(max-width:600px){main{margin:1rem auto}.hero{align-items:flex-start}}'
            . '@media(prefers-color-scheme:dark){:root{--bg:#172126;--panel:#202c32;--text:#edf2f4;--muted:#bdc9ce;'
            . '--line:#405159;--accent:#ff8d8d;--accent-bg:#472525}}</style></head><body><main><section class="panel oidc-access-denied">'
            . '<header class="hero"><span class="mark" aria-hidden="true">!</span><div><h1>'
            . $escape(gettext('WebGUI access denied')) . '</h1><p>'
            . $escape(gettext('The identity provider authenticated you successfully, but OPNsense did not authorize this account.'))
            . '</p></div></header><div class="content"><div class="notice">'
            . $escape(gettext('No WebGUI session was created. The mapped local account has no usable WebGUI privilege from this network.'))
            . '</div><p>' . $escape(gettext('Ask a firewall administrator to check the local OPNsense account:')) . '</p><ol><li>'
            . $escape(gettext('Assign at least one WebGUI privilege directly to the user or through a local group.'))
            . '</li><li>' . $escape(gettext('If the group restricts source networks, allow the address from which this sign-in was made.'))
            . '</li><li>' . $escape(gettext('Then start a new sign-in from the login page.'))
            . '</li></ol><a href="/">' . $escape(gettext('Return to login'))
            . '</a></div></section></main></body></html>';
    }

    private function refuse(int $code, string $status, string $message): string
    {
        $this->response->setStatusCode($code, $status);

        return $message;
    }

    private function protocolFailure(string $provider, string $context, \Throwable $error, int $status = 500): string
    {
        $reference = bin2hex(random_bytes(6));
        $this->auditRefusal($provider, sprintf('%s [%s]: %s', $context, $reference, $error->getMessage()));
        syslog(LOG_ERR, sprintf('OIDC: %s [%s] (%s)', $context, $reference, $error->getMessage()));
        return $this->refuse(
            $status,
            $status === 403 ? 'Forbidden' : 'Server Error',
            sprintf('OpenID Connect could not complete this request. Reference: %s', $reference)
        );
    }

    /**
     * Say in the log OPNsense keeps its logins in that somebody was not let in.
     *
     * Beside the refusal rather than folded into it: every refusal in this controller
     * then reads the same, and the reason - which is deliberately not in the answer the
     * browser gets, see docs/setup/troubleshooting.md - is written where it happens.
     */
    private function auditRefusal(string $provider, string $reason): void
    {
        $this->audit(LOG_WARNING, sprintf(
            'Web GUI authentication error for OpenID Connect server %s from %s: %s',
            $provider === '' ? '-' : $provider,
            $this->request->getClientAddress(),
            $reason
        ));
    }

    /** Record authentication success followed by a distinct local authorization denial. */
    private function auditAuthorizationRefusal(string $provider, string $account): void
    {
        $this->audit(LOG_WARNING, sprintf(
            "Web GUI authorization error for local user '%s' through OpenID Connect server %s from %s: no usable WebGUI privilege",
            $account,
            $provider === '' ? '-' : $provider,
            $this->request->getClientAddress()
        ));
        syslog(LOG_NOTICE, sprintf(
            'OIDC: refusing a session for %s through %s because no usable WebGUI page is authorized',
            $account,
            $provider === '' ? '-' : $provider
        ));
    }

    /**
     * Write to the log OPNsense keeps its logins in.
     *
     * A login that only appears in the plugin's own lines is a login nobody sees: the
     * interface, the alerting and everything else that watches who gets in reads the
     * audit facility, which is where core writes from authgui.inc. closelog() puts the
     * next syslog() call back where it was.
     */
    private function audit(int $priority, string $message): void
    {
        openlog('audit', LOG_ODELAY, LOG_AUTH);
        syslog($priority, $message);
        closelog();
    }
}
