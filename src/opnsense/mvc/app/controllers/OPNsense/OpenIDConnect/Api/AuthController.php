<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use Jumbojett\OpenIDConnectClientException;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\Core\SanitizeFilter;
use OPNsense\OpenIDConnect\RelyingParty;

/**
 * The browser's side of an OpenID Connect login to the web interface.
 *
 *   /api/openidconnect/auth/login     start the exchange, or go where the browser belongs
 *   /api/openidconnect/auth/callback  finish it and turn the answer into a session
 *   /api/openidconnect/auth/logout    end here and at the provider
 *   /api/openidconnect/auth/icon      hand on a provider's logo for the login button
 *
 * These endpoints answer before anyone is logged in, so doAuth() declines the usual
 * session check. What protects them is the protocol: the provider's answer has to carry
 * the state and the nonce this firewall issued, and a session is only established once
 * RelyingParty has accepted it.
 */
class AuthController extends ApiControllerBase
{
    /** which server this exchange belongs to, needed again at the callback */
    private const EXCHANGE_PROVIDER = 'openidconnect_exchange_provider';
    /** where the browser was heading before it was sent away */
    private const EXCHANGE_TARGET = 'openidconnect_exchange_target';

    /** kept for the lifetime of the session so that logging out can undo the login */
    private const GRANT_PROVIDER = 'openidconnect_grant_provider';
    private const GRANT_ID_TOKEN = 'openidconnect_grant_id_token';
    private const GRANT_TOKENS = 'openidconnect_grant_tokens';

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

        if (RelyingParty::acceptedRedirectUri($settings, $this->request) === null) {
            $intended = RelyingParty::intendedRedirectUri($this->request);
            syslog(LOG_NOTICE, sprintf('OIDC: refusing a login begun at %s, which is not accepted', $intended));
            $this->auditRefusal($name, 'begun under an address this server does not accept');

            $accepted = $settings->acceptedRedirectUrls();

            return $this->refuse(400, 'Bad Request', $accepted === []
                ? 'Single sign-on is not set up: this server accepts no redirect URLs yet. '
                    . 'Add the addresses this web interface is reached under to Accepted redirect URLs.'
                : sprintf(
                    'Single sign-on is not offered under this address. Accepted: %s',
                    implode(', ', $accepted)
                ));
        }

        $settings->trace(sprintf('starting an exchange for %s, target %s', $name, $target));
        $this->session->set(self::EXCHANGE_PROVIDER, $name);
        $this->session->set(self::EXCHANGE_TARGET, $target);

        try {
            /* authenticate() sets the Location header and returns false on the way out */
            (new RelyingParty($settings, $this))->authenticate();
        } catch (\Exception $e) {
            $this->auditRefusal($name, 'the exchange could not be begun: ' . $e->getMessage());
            return $this->refuse(500, 'Server Error', 'Cannot begin the exchange: ' . $e->getMessage());
        }

        $this->session->close();

        return 'Redirecting to the identity provider...';
    }

    /* ----------------------------------------------------------------- callback */

    public function callbackAction()
    {
        $name = (string)$this->session->get(self::EXCHANGE_PROVIDER);
        $target = (string)($this->session->get(self::EXCHANGE_TARGET) ?: '/');

        if ($this->alreadySignedIn()) {
            /* an earlier round trip already saw this through */
            $this->forgetExchange();
            return $this->sendTo($target);
        }

        if ($name === '') {
            $this->auditRefusal($name, 'an answer arrived for an exchange that was never begun here');
            return $this->refuse(400, 'Bad Request', 'No exchange is in progress. Please start again.');
        }
        $this->forgetExchange();

        $settings = $this->settingsFor($name);
        if ($settings === null) {
            $this->auditRefusal($name, 'no authentication server of that name');
            return $this->refuse(404, 'Not Found', 'No such authentication server.');
        }

        try {
            $exchange = new RelyingParty($settings, $this);
            if (!$exchange->authenticate()) {
                $this->auditRefusal($name, 'the exchange was not completed');
                return $this->refuse(400, 'Bad Request', 'The identity provider did not complete the exchange.');
            }
            $claims = $exchange->requestUserInfo();
        } catch (\Exception $e) {
            $this->auditRefusal($name, $e->getMessage());
            return $this->refuse(403, 'Forbidden', 'The answer was not accepted: ' . $e->getMessage());
        }

        $settings->trace('the provider answered and the answer was accepted');

        if (!$this->authenticationIsRecentEnough($settings, $exchange)) {
            $this->auditRefusal($name, 'the authentication is older than accepted');
            return $this->refuse(403, 'Forbidden', 'The provider reported an authentication older than accepted.');
        }

        $account = $settings->localAccountFor($claims);
        if ($account === null) {
            /* localAccountFor() has already said in the log which of its reasons it was */
            $this->auditRefusal($name, 'no local account this login may use');
            return $this->refuse(403, 'Forbidden', 'There is no local account for this user, or it may not be used.');
        }

        $settings->trace(sprintf('resolved to local account %s, sending to %s', $account, $target));
        $this->establishSession($account, $name, $exchange);

        return $this->sendTo($target);
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
        if (strcasecmp($this->request->getHeader('Sec-Fetch-Site'), 'cross-site') === 0) {
            return $this->sendTo('/');
        }

        $name = (string)$this->session->get(self::GRANT_PROVIDER);
        $idToken = (string)$this->session->get(self::GRANT_ID_TOKEN);
        $tokens = json_decode((string)$this->session->get(self::GRANT_TOKENS), true) ?: [];

        $settings = $name === '' || $idToken === '' ? null : $this->settingsFor($name);
        $settings?->trace(sprintf('signing out of %s, %d token(s) to hand back', $name, count(array_filter($tokens))));

        /**
         * Drop the local session the way core does. Nothing may be written through the
         * session wrapper from here on: the dispatcher would open a fresh session on the
         * way out and hand the browser a new cookie.
         */
        $this->discardSession();

        if ($settings === null) {
            return $this->sendTo('/');
        }

        try {
            $exchange = new RelyingParty($settings, $this);
            /* the session is gone; nothing may write a new one into being behind us */
            $exchange->sealSession();

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
        if ($settings === null) {
            return $this->refuse(404, 'Not Found', 'No such authentication server.');
        }

        $source = $settings->iconUrl();
        if (!OpenIDConnect::isFetchableUrl($source)) {
            return $this->refuse(404, 'Not Found', 'This server has no icon to hand on.');
        }

        $answer = RelyingParty::fetchOverWeb($source, self::ICON_MAX_BYTES);

        /* an answer over the size is a transfer curl gave up on, and says so in plain words */
        if (!$answer['ok'] || $answer['status'] !== 200) {
            return $this->refuse(404, 'Not Found', 'Could not fetch the icon: '
                . ($answer['problem'] ?: 'HTTP ' . $answer['status']));
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

    /* ------------------------------------------------------------------ helpers */

    /**
     * @return OpenIDConnect|null the named server, when it speaks this protocol
     */
    private function settingsFor(string $name): ?OpenIDConnect
    {
        if ($name === '') {
            return null;
        }
        $settings = (new AuthenticationFactory())->get($name);

        return $settings instanceof OpenIDConnect ? $settings : null;
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

    private function forgetExchange(): void
    {
        $this->session->remove(self::EXCHANGE_PROVIDER);
        $this->session->remove(self::EXCHANGE_TARGET);
    }

    /**
     * A provider may ignore max_age, so its answer is checked rather than trusted.
     */
    private function authenticationIsRecentEnough(OpenIDConnect $settings, RelyingParty $exchange): bool
    {
        $limit = $settings->maximumAuthenticationAge();
        if ($limit === 0) {
            return true;
        }

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
            $this->session->set(self::GRANT_PROVIDER, $provider);
            $this->session->set(self::GRANT_ID_TOKEN, $idToken);
            $this->session->set(self::GRANT_TOKENS, (string)json_encode(array_filter([
                'access_token' => (string)$exchange->getAccessToken(),
                'refresh_token' => (string)$exchange->getRefreshToken(),
            ])));
        }

        syslog(LOG_NOTICE, sprintf('OIDC: %s signed in through %s', $account, $provider));
        $this->audit(LOG_NOTICE, sprintf(
            "Successful login for user '%s' from: %s [using OpenID Connect + %s]",
            $account,
            $this->request->getClientAddress(),
            $provider
        ));

        $this->session->close();
        $this->renewSessionId();
    }

    /**
     * Hand the browser a new session id now that the session has gained privileges, so
     * that an id planted beforehand is worth nothing afterwards.
     *
     * Deliberately after the wrapper has written its payload: rotating an id that already
     * carries the login means it cannot be left behind in the old session, because
     * session_regenerate_id(true) copies the data across and removes the old file.
     */
    private function renewSessionId(): void
    {
        try {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            if (!session_regenerate_id(true)) {
                syslog(LOG_ERR, 'OIDC: could not renew the session id after a login');
            }
            session_write_close();
        } catch (\Throwable $e) {
            /* losing the rotation is bad; losing the login would be worse */
            syslog(LOG_ERR, sprintf('OIDC: could not renew the session id after a login (%s)', $e->getMessage()));
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

    private function refuse(int $code, string $status, string $message): string
    {
        $this->response->setStatusCode($code, $status);

        return $message;
    }

    /**
     * Say in the log OPNsense keeps its logins in that somebody was not let in.
     *
     * Beside the refusal rather than folded into it: every refusal in this controller
     * then reads the same, and the reason - which is deliberately not in the answer the
     * browser gets, see docs/README.md - is written where it happens.
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
