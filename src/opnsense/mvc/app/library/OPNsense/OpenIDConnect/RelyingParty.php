<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

require_once __DIR__ . '/OpenIDConnectClient.php';

use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Response;
use OPNsense\Mvc\Session;

/**
 * This firewall in its role as the relying party of an OpenID Connect exchange.
 *
 * The protocol itself is handled by the bundled Jumbojett client (Apache-2.0, see
 * VENDOR.md); this class is the seam between that client and OPNsense - its session, its
 * request and its response - and the place where the checks the library leaves to its
 * caller are made.
 *
 * Those checks are not settings. They are what the protocol asks for, and an installation
 * does not get to differ on them:
 *
 *  - the signature algorithm is decided here and not by the token's own header
 *  - an id_token without a usable exp, or with the wrong nonce, is refused
 *  - a token made out to several audiences has to name this firewall as the party it was
 *    issued for
 *  - the answer has to carry the state this firewall issued before any of it is acted on,
 *    the code included
 *  - the UserInfo response is bound to the id_token by its subject
 *  - every address the provider names is fetched over http or https and nothing else
 *  - PKCE is requested, and no call to the provider may hang the web interface
 */
class RelyingParty extends OpenIDConnectClient
{
    /**
     * Asymmetric only. HS* keys the signature with the client secret, which is a different
     * trust model - and since the algorithm is named in the attacker-supplied token
     * header, the acceptable set has to be decided on this side.
     */
    public const SIGNING_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS512'];

    /**
     * Claims that carry the protocol rather than the person. They are verified where they
     * belong and are of no use in deciding which local account someone is, so they are
     * kept out of the claim set handed on.
     */
    private const PROTOCOL_CLAIMS = [
        'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce',
        'at_hash', 'c_hash', 'azp', 'sid', 'typ', 'auth_time', 'acr', 'amr',
    ];

    /** seconds; nothing the provider does should be able to hold the interface open */
    public const REQUEST_TIMEOUT = 15;

    /**
     * A name, an address or a bracketed IPv6 address, with an optional port - what a Host
     * header is allowed to look like. Anything else is somebody making one value out of
     * two, and the callback address is built from this.
     */
    private const HOST_HEADER = '/^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?'
        . '(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.?'
        . '|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/';

    private static bool $autoloaderReady = false;

    private OpenIDConnect $settings;
    private Session $session;
    private Request $request;
    private Response $response;

    /** set once the local session is gone, so that nothing writes a new one into being */
    private bool $sessionSealed = false;

    public function __construct(OpenIDConnect $settings, Controller $controller)
    {
        self::prepareAutoloader();

        parent::__construct($settings->issuerUrl(), $settings->clientId(), $settings->clientSecret());

        $this->settings = $settings;
        $this->session = $controller->session;
        $this->request = $controller->request;
        $this->response = $controller->response;

        $redirectUri = static::acceptedRedirectUri($settings, $controller->request);
        if ($redirectUri === null) {
            throw new OpenIDConnectClientException(sprintf(
                'This firewall does not accept %s as a redirect URI',
                static::intendedRedirectUri($controller->request)
            ));
        }
        $this->setRedirectURL($redirectUri);

        $this->addScope($settings->scopes());
        $this->setTimeout(self::REQUEST_TIMEOUT);

        /* applied only when the provider advertises it, so asking is always safe */
        $this->setCodeChallengeMethod('S256');

        $maximumAge = $settings->maximumAuthenticationAge();
        if ($maximumAge > 0) {
            $this->addAuthParam(['max_age' => $maximumAge]);
        }

        $settings->trace(sprintf(
            'exchange prepared for %s, returning to %s, scopes %s, max_age %s, token auth %s',
            $settings->issuerUrl(),
            $redirectUri,
            implode('+', $settings->scopes()),
            $maximumAge > 0 ? (string)$maximumAge : 'unset',
            $settings->tokenAuthMethod() ?? 'as advertised'
        ));
    }

    /**
     * Decide how this firewall authenticates at the token endpoint.
     *
     * The library asks whether a method is acceptable to both sides, which is the right
     * default. An installation may insist instead, for the one case that default cannot
     * handle: a provider that advertises a method it does not actually accept.
     */
    public function supportsAuthMethod(string $auth_method, array $advertised): bool
    {
        $insisted = $this->settings->tokenAuthMethod();
        if ($insisted !== null) {
            return $auth_method === $insisted;
        }

        return parent::supportsAuthMethod($auth_method, $advertised);
    }

    /* ------------------------------------------------------------ redirect target */

    /**
     * @return string the callback address implied by the name the browser used
     */
    public static function intendedRedirectUri(Request $request): string
    {
        return $request->getScheme() . '://' . $request->getHeader('HOST') . OpenIDConnect::CALLBACK_PATH;
    }

    /**
     * Pick this request's callback address out of the configured list.
     *
     * An allow list rather than a single pinned address: a firewall reachable under
     * several names keeps working, while a name that is not listed is refused instead of
     * being sent off to finish somewhere it has no session.
     *
     * An empty list accepts nothing. Building the address from the Host header instead
     * would hand whoever asked the address this firewall then names to the provider as
     * its redirect_uri - leaving nothing but the provider's own strictness between a
     * browser and finishing somewhere else with a code in hand. Refusing costs an
     * installation that has not filled the field in one error page saying what to enter,
     * and signing in with a username and password is not affected either way.
     *
     * @return string|null null when the browser arrived under a name that is not accepted
     */
    public static function acceptedRedirectUri(OpenIDConnect $settings, Request $request): ?string
    {
        /* whatever else happens, the name the browser used has to be a name */
        if (!preg_match(self::HOST_HEADER, $request->getHeader('HOST'))) {
            syslog(LOG_NOTICE, 'OIDC: refusing a login begun under a Host header that is not a host name');
            return null;
        }

        $accepted = $settings->acceptedRedirectUrls();
        if ($accepted === []) {
            syslog(LOG_ERR, 'OIDC: refusing a login, this server has no accepted redirect URLs configured');
            return null;
        }

        $intended = static::intendedRedirectUri($request);

        foreach ($accepted as $candidate) {
            if (strcasecmp(rtrim($candidate, '/'), rtrim($intended, '/')) === 0) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @return string scheme://host[:port] of this firewall, as the provider knows it
     */
    public function ownOrigin(): string
    {
        $parts = parse_url((string)$this->getRedirectURL());
        if (!empty($parts['scheme']) && !empty($parts['host'])) {
            return $parts['scheme'] . '://' . $parts['host']
                . (empty($parts['port']) ? '' : ':' . $parts['port']);
        }

        return $this->request->getScheme() . '://' . $this->request->getHeader('HOST');
    }

    /* ----------------------------------------------------------------- the checks */

    /**
     * Check the state before the answer is acted on at all.
     *
     * The library checks it too, but only after it has handed the code to the token
     * endpoint - so an answer that was never asked for here gets a code redeemed for it
     * first. Nothing is granted by that, but a firewall should not spend a round trip on
     * a request it can already tell is not one of its own.
     */
    public function authenticate(): bool
    {
        if (isset($_REQUEST['code']) || isset($_REQUEST['id_token'])) {
            $issued = $this->getState();
            $returned = $_REQUEST['state'] ?? null;

            if (!is_string($issued) || $issued === '' || !is_string($returned) || !hash_equals($issued, $returned)) {
                throw new OpenIDConnectClientException('The answer does not carry the state this firewall issued');
            }
        }

        return parent::authenticate();
    }

    /**
     * Decide on the algorithm before the library acts on what the token claims to be.
     */
    public function verifyJWTSignature(string $jwt): bool
    {
        $header = $this->decodeJWT($jwt, 0);
        $algorithm = is_object($header) ? ($header->alg ?? null) : null;

        if ($algorithm === null || !in_array($algorithm, $this->permittedAlgorithms(), true)) {
            throw new OpenIDConnectClientException(sprintf(
                'Refusing a token signed with %s',
                $algorithm === null ? 'no stated algorithm' : $algorithm
            ));
        }

        return parent::verifyJWTSignature($jwt);
    }

    /**
     * @return string[] what the provider advertises, minus anything symmetric
     */
    private function permittedAlgorithms(): array
    {
        $advertised = $this->getProviderConfigValue('id_token_signing_alg_values_supported', []);
        $permitted = is_array($advertised)
            ? array_values(array_intersect($advertised, self::SIGNING_ALGORITHMS))
            : [];

        $this->settings->trace('accepting signatures: ' . implode(', ', $permitted ?: self::SIGNING_ALGORITHMS));

        return $permitted ?: self::SIGNING_ALGORITHMS;
    }

    /**
     * The library checks exp and nonce only where the claim happens to be present, so a
     * token that simply leaves one out passes. Require both on the id_token.
     *
     * $accessToken is given exactly on the id_token path; a signed UserInfo response is
     * verified with null, where neither claim belongs and the library already ties the
     * subject to the id_token itself.
     */
    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool
    {
        if (!parent::verifyJWTClaims($claims, $accessToken)) {
            return false;
        }

        if ($accessToken === null) {
            return true;
        }

        if (!isset($claims->exp) || !is_int($claims->exp)) {
            syslog(LOG_ERR, 'OIDC: refusing an id_token that carries no usable expiry');
            return false;
        }

        $nonce = $this->getNonce();
        if (!empty($nonce)) {
            if (!isset($claims->nonce) || !hash_equals((string)$nonce, (string)$claims->nonce)) {
                syslog(LOG_ERR, 'OIDC: refusing an id_token whose nonce does not match the request');
                return false;
            }
        }

        if (!static::issuedForThisFirewall($claims, $this->getClientID())) {
            syslog(LOG_ERR, 'OIDC: refusing an id_token issued for several audiences without naming this one');
            return false;
        }

        return true;
    }

    /**
     * Whether a token made out to several audiences names this firewall as the one it was
     * issued for.
     *
     * The library is satisfied when this firewall is among the audiences at all. Where
     * there is more than one, OIDC Core 3.1.3.7 asks for azp as well and asks that it name
     * the client - otherwise a token minted for another client at the same provider, with
     * this one merely listed alongside it, would do.
     *
     * @param object $claims the id_token payload
     */
    public static function issuedForThisFirewall(object $claims, string $clientId): bool
    {
        $audiences = is_array($claims->aud ?? null) ? $claims->aud : [$claims->aud ?? null];
        if (count($audiences) < 2) {
            return true;
        }

        $party = $claims->azp ?? null;

        return is_string($party) && hash_equals($clientId, $party);
    }

    /**
     * OpenID Connect Core 5.3.2 asks that the subject of the UserInfo response match the
     * subject of the id_token. The library enforces that for a signed response but not for
     * the plain JSON one, which is the usual case - and the JSON response is what the
     * local account is identified from, so the binding matters most exactly there.
     */
    public function requestUserInfo(?string $attribute = null)
    {
        $reported = parent::requestUserInfo(null);
        $this->assertSubjectBinding($reported);
        $claims = $this->withIdTokenClaims($reported);

        if ($attribute === null) {
            return $claims;
        }

        return property_exists($claims, $attribute) ? $claims->$attribute : null;
    }

    /**
     * Hand on what the id_token says as well as what UserInfo says.
     *
     * Providers disagree about where a claim belongs. Microsoft Entra ID is the clearest
     * case: its UserInfo response can only ever carry sub, name, family_name, given_name,
     * picture and email - preferred_username is in the id_token and nowhere else, and
     * Microsoft's own advice is to read the id_token rather than call UserInfo. Others go
     * the other way: Zitadel leaves the profile claims out of the id_token unless asked,
     * and Keycloak returns custom claims from UserInfo only.
     *
     * Taking both is safe here because both have been verified: the id_token by signature,
     * issuer, audience, nonce and expiry, and the UserInfo response by its subject matching
     * that id_token. Where they overlap UserInfo wins - it is the endpoint made for this,
     * and it answers with what is true now rather than what was true when the token was
     * signed.
     */
    private function withIdTokenClaims(object $reported): object
    {
        $merged = new \stdClass();

        foreach ((array)($this->getIdTokenPayload() ?? new \stdClass()) as $name => $value) {
            if (!in_array($name, self::PROTOCOL_CLAIMS, true)) {
                $merged->{$name} = $value;
            }
        }

        $fromUserInfo = [];
        foreach ((array)$reported as $name => $value) {
            $merged->{$name} = $value;
            $fromUserInfo[] = $name;
        }

        $this->settings->trace(sprintf(
            'claims: %s from UserInfo, %d in total after adding the id_token',
            implode(', ', $fromUserInfo) ?: 'none',
            count((array)$merged)
        ));

        return $merged;
    }

    /**
     * @throws OpenIDConnectClientException when the two subjects disagree
     */
    private function assertSubjectBinding($claims): void
    {
        $signed = $this->getIdTokenPayload()->sub ?? null;
        $reported = is_object($claims) ? ($claims->sub ?? null) : null;

        if ($signed !== null && $reported !== null && hash_equals((string)$signed, (string)$reported)) {
            $this->settings->trace('UserInfo response is bound to the id_token');
            return;
        }

        /* says present or missing rather than the values, which identify a person */
        $detail = sprintf(
            'id_token subject %s, UserInfo subject %s',
            $signed === null ? 'missing' : 'present',
            $reported === null ? 'missing' : 'present'
        );
        syslog(LOG_ERR, "OIDC: refusing a login, the UserInfo response is not bound to the id_token ($detail)");

        throw new OpenIDConnectClientException('The UserInfo subject does not match the id_token subject');
    }

    /**
     * @return int|null when the provider says it last authenticated this person
     */
    public function authenticationTime(): ?int
    {
        $authTime = $this->getIdTokenPayload()->auth_time ?? null;

        return is_int($authTime) ? $authTime : null;
    }

    /**
     * Fetch something over the web, and nothing but the web.
     *
     * Both endpoints that reach out from this plugin want the same thing: http or https,
     * a bounded time, a bounded size and a handful of redirects. Written once, because
     * the protocol allow list is the point of it and a second copy is a second place to
     * remember when the next option is added.
     *
     * The size is judged while the body arrives rather than afterwards. CURLOPT_MAXFILESIZE
     * only bites when a length is announced, so an answer that announces none would be
     * entirely in memory by the time anyone measured it - on an endpoint that answers
     * before anyone has signed in.
     *
     * @return array{ok: bool, body: string, status: int, type: string, problem: string}
     */
    public static function fetchOverWeb(string $url, int $maxBytes): array
    {
        $body = '';
        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            /* curl speaks file://, ftp:// and more; this is for what the web serves */
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => self::REQUEST_TIMEOUT,
            CURLOPT_TIMEOUT => self::REQUEST_TIMEOUT,
            CURLOPT_MAXFILESIZE => $maxBytes,
            CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body, $maxBytes): int {
                $body .= $chunk;

                /* a short count is how libcurl is told to give up on a transfer */
                return strlen($body) > $maxBytes ? 0 : strlen($chunk);
            },
        ]);

        $answer = [
            'ok' => curl_exec($handle) !== false,
            'body' => $body,
            'status' => (int)curl_getinfo($handle, CURLINFO_HTTP_CODE),
            /* "image/svg+xml; charset=utf-8" is the same thing as "image/svg+xml" */
            'type' => strtolower(trim(explode(';', (string)curl_getinfo($handle, CURLINFO_CONTENT_TYPE))[0])),
            'problem' => curl_error($handle),
        ];
        /* no curl_close(): it has done nothing since PHP 8.0 and says so since 8.5 */
        unset($handle);

        return $answer;
    }

    /**
     * Everything the provider names is fetched over the web and nothing else.
     *
     * The token, UserInfo, jwks and revocation addresses all come out of the discovery
     * document, which is the provider's to write. curl speaks file://, ftp:// and more,
     * so the scheme is decided on this side rather than over there.
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        if (!OpenIDConnect::isFetchableUrl($url)) {
            throw new OpenIDConnectClientException('The provider names an address this firewall will not fetch');
        }

        return parent::fetchURL($url, $post_body, $headers);
    }

    /* --------------------------------------------------------- OPNsense plumbing */

    /**
     * The authorization and end_session addresses come from the provider as well, and
     * this one ends up in a Location header rather than in a request of ours.
     */
    public function redirect(string $url)
    {
        if (!OpenIDConnect::isFetchableUrl($url)) {
            throw new OpenIDConnectClientException(
                'The provider names an address this firewall will not send anyone to'
            );
        }

        $this->response->redirect($url);
    }

    /**
     * Stop writing to the session, for good.
     *
     * Called once the local session has been destroyed: the framework flushes what was
     * written to the session on the way out, and would start a fresh one to do it - which
     * would hand the browser a new cookie moments after it was told to drop the old one.
     * Nothing in the sign-out path writes today; sealing it means nothing has to keep
     * checking that this is still true after the next library update.
     */
    public function sealSession(): void
    {
        $this->sessionSealed = true;
    }

    /**
     * The framework owns the php session: it copies the payload, closes the session so
     * that concurrent requests are not locked out, and writes changes back on close. So
     * there is nothing to start or commit here, and values pass through serialize()
     * because the wrapper hands back strings and arrays only.
     */
    protected function startSession()
    {
    }

    protected function commitSession()
    {
    }

    protected function getSessionKey(string $key)
    {
        $stored = $this->session->get($key, null);

        /* strings and arrays are all that is ever put in, so nothing else comes back out */
        return $stored === null ? false : unserialize($stored, ['allowed_classes' => false]);
    }

    protected function setSessionKey(string $key, $value)
    {
        if ($this->sessionSealed) {
            return;
        }

        $this->session->set($key, serialize($value));
    }

    protected function unsetSessionKey(string $key)
    {
        if ($this->sessionSealed) {
            return;
        }

        $this->session->remove($key);
    }

    /**
     * phpseclib ships with OPNsense but without an autoloader, so one is registered for
     * the two namespaces the bundled client reaches for. Once per request; registering
     * per instance would pile up handlers for no gain.
     */
    private static function prepareAutoloader(): void
    {
        if (self::$autoloaderReady) {
            return;
        }
        self::$autoloaderReady = true;

        foreach ([
            'phpseclib3' => '/usr/local/share/phpseclib',
            'ParagonIE\\ConstantTime' => '/usr/local/share/phpseclib/paragonie',
        ] as $namespace => $directory) {
            spl_autoload_register(static function (string $class) use ($namespace, $directory): void {
                $prefix = trim($namespace, '\\') . '\\';
                if (!str_starts_with($class, $prefix)) {
                    return;
                }
                $file = $directory . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
                if (is_file($file)) {
                    require_once $file;
                }
            });
        }
    }
}
