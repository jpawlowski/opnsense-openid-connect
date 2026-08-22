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

namespace OPNsense\Auth;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * An authentication server of type "oidc": everything the browser flow needs to know,
 * read from one <authserver> entry.
 *
 * This connector never verifies a credential itself. OpenID Connect happens in the
 * browser, so authenticate() and preauth() decline by design; the work is done by
 * OPNsense\OpenIDConnect\Api\AuthController and the flow ends by putting a username into the
 * session. What lives here is the configuration surface and the reading of it.
 *
 * Settings are exposed through named accessors rather than public properties so that
 * every default sits in exactly one place and callers cannot see half-parsed values.
 */
class OpenIDConnect extends Base implements IAuthConnector
{
    /** value of <type> in config.xml, and the name of the api module */
    public const TYPE = 'openidconnect';

    /** where the provider is told to send the browser back to */
    public const CALLBACK_PATH = '/api/openidconnect/auth/callback';

    /** signature algorithms an id_token may be signed with, see RelyingParty */
    public const BUTTON_STYLES = ['button', 'link'];
    public const ICON_MODES = ['monochrome', 'original'];

    /** how this firewall authenticates itself at the token endpoint */
    public const TOKEN_AUTH_METHODS = ['client_secret_basic', 'client_secret_post'];

    /** when an e-mail address may stand in for the username claim */
    public const EMAIL_MATCHING = ['verified', 'always', 'off'];

    /** schemes this firewall will fetch something over */
    public const FETCHABLE_SCHEMES = ['http', 'https'];

    /** @var array raw settings of this authentication server */
    private array $settings = [];

    public static function getType()
    {
        return self::TYPE;
    }

    public function getDescription()
    {
        /* fa-brands carries the openid mark in the FontAwesome 6 core ships */
        return '<i class="fa-brands fa-openid fa-fw"></i> ' . gettext('OpenID Connect');
    }

    /**
     * @param array $config the <authserver> entry as an array
     */
    public function setProperties($config)
    {
        $this->settings = is_array($config) ? $config : [];
    }

    public function getLastAuthProperties()
    {
        return [];
    }

    /**
     * Declining is the point: there is no password to check here. Anything that reaches
     * this connector with a credential in hand is not doing OpenID Connect.
     */
    public function authenticate($username, $password)
    {
        return false;
    }

    public function preauth($config)
    {
        return false;
    }

    /**
     * Fields for System > Access > Servers. The form understands text, dropdown and
     * checkbox; anything richer is upgraded in the browser by assets/settings-form.js,
     * which is delivered through the last, contentless entry.
     *
     * Every key carries the openidconnect_ prefix because core stores these flat, as siblings of
     * the refid, type and name it writes itself, in one <authserver> entry shared with
     * every other kind of authentication server.
     *
     * @return array
     */
    public function getConfigurationOptions()
    {
        $callback = sprintf(
            gettext('The provider must accept %s as a redirect URI.'),
            '<code>https://{firewall}' . self::CALLBACK_PATH . '</code>'
        );

        return [
            'openidconnect_provider_url' => [
                'name' => gettext('Provider URL'),
                'help' => gettext(
                    'The issuer, or the address of its discovery document. Everything else is read from ' .
                    'there, so the provider needs <code>/.well-known/openid-configuration</code> to be ' .
                    'reachable from this firewall.'
                ) . ' ' . $callback,
                'type' => 'text',
                'validate' => fn($value) => static::isFetchableUrl($value)
                    ? [] : [gettext('The provider URL is not an http or https address.')],
            ],
            'openidconnect_client_id' => [
                'name' => gettext('Client ID'),
                'type' => 'text',
                'validate' => fn($value) => !empty(trim((string)$value))
                    ? [] : [gettext('A client ID is required.')],
            ],
            'openidconnect_client_secret' => [
                'name' => gettext('Client Secret'),
                'help' => gettext(
                    'This firewall authenticates as a confidential client. Public clients, which have no ' .
                    'secret, are not supported.'
                ),
                'type' => 'text',
                'validate' => fn($value) => !empty(trim((string)$value))
                    ? [] : [gettext('A client secret is required.')],
            ],
            'openidconnect_token_auth' => [
                'name' => gettext('Authentication method'),
                'help' => gettext(
                    'How this firewall proves who it is at the token endpoint. Following the provider is ' .
                    'right unless it advertises something it does not actually accept, which is the one ' .
                    'case where insisting helps.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => [
                    '' => gettext('Follow the provider'),
                    'client_secret_basic' => gettext('Insist on Basic (secret in the header)'),
                    'client_secret_post' => gettext('Insist on POST (secret in the body)'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::TOKEN_AUTH_METHODS, ['']), true)
                    ? [] : [gettext('Unknown authentication method.')],
            ],
            'openidconnect_username_claim' => [
                'name' => gettext('Username claim'),
                'help' => gettext(
                    'Which claim names the local account. Usually <code>preferred_username</code> or ' .
                    '<code>email</code>. A user is matched against the local account of that name, and ' .
                    'against local e-mail addresses.'
                ),
                'type' => 'text',
                'validate' => fn($value) => !empty(trim((string)$value))
                    ? [] : [gettext('A username claim is required.')],
            ],
            'openidconnect_email_match' => [
                'name' => gettext('Match by e-mail address'),
                'help' => gettext(
                    'When the username claim names no local account, the <code>email</code> claim may be ' .
                    'matched against the addresses of local accounts. <b>Only accept a verified address</b> ' .
                    'unless the provider is known not to report one: wherever a person can set their own ' .
                    'address, an unverified match is a way onto somebody else\'s account. Microsoft Entra ID ' .
                    'sends no <code>email_verified</code> at all, so matching by address there means ' .
                    'accepting whatever it says.'
                ),
                'type' => 'dropdown',
                'default' => 'verified',
                'options' => [
                    'verified' => gettext('Only a verified address'),
                    'always' => gettext('Any address the provider reports'),
                    'off' => gettext('Never, the username claim decides alone'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::EMAIL_MATCHING, ['']), true)
                    ? [] : [gettext('Unknown e-mail matching mode.')],
            ],
            'openidconnect_scopes' => [
                'name' => gettext('Scopes'),
                'help' => gettext('Requested alongside <code>openid</code>, which is always sent.'),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'openidconnect_redirect_urls' => [
                'name' => gettext('Accepted redirect URLs'),
                'help' => gettext(
                    'The address the provider is sent back to is picked from this list by matching the ' .
                    'name the browser used, so a firewall reachable under several names keeps working ' .
                    'while anything else is refused outright. Every address this web interface is reached ' .
                    'under belongs here, one per entry. An empty list accepts nothing: the address handed ' .
                    'to the provider would otherwise be whatever name a browser asked under.'
                ) . ' ' . $callback,
                'type' => 'text',
                'validate' => function ($value) {
                    $urls = static::splitList($value);
                    if ($urls === []) {
                        return [gettext('At least one accepted redirect URL is required.')];
                    }
                    foreach ($urls as $url) {
                        if (!static::isFetchableUrl($url)) {
                            return [sprintf(gettext('%s is not an http or https address.'), $url)];
                        }
                    }
                    return [];
                },
            ],
            'openidconnect_max_age' => [
                'name' => gettext('Maximum authentication age'),
                'help' => gettext(
                    'Seconds. When set, the provider is asked to authenticate the user afresh if their ' .
                    'last authentication is older, and an answer reporting an older one is refused. Leave ' .
                    'empty to accept any session the provider already has.'
                ),
                'type' => 'text',
                /* not empty(): empty('0') is true in PHP, so a typed zero would have
                   slipped through and then quietly meant "off" */
                'validate' => fn($value) => trim((string)$value) === ''
                    || (ctype_digit(trim((string)$value)) && (int)$value > 0)
                    ? [] : [gettext('Maximum authentication age must be a positive number of seconds, or empty.')],
            ],
            'openidconnect_create_users' => [
                'name' => gettext('Create an account on first login'),
                'help' => gettext(
                    'Create a local account on first login. Off is the safer default: a firewall is not a ' .
                    'service that should take on new users because an identity provider says so.'
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'openidconnect_default_groups' => [
                'name' => gettext('Groups for a new account'),
                'help' => gettext(
                    'Groups an automatically created account is placed in, on the login that creates it. ' .
                    'An account that already exists is left alone, so this is not a way to grant something ' .
                    'to everyone who signs in.'
                ),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'openidconnect_allow_root' => [
                'name' => gettext('Allow the built-in root account'),
                'help' => gettext(
                    'Off by default, and worth leaving off: <code>root</code> is the account the web ' .
                    'interface hands every privilege to without asking the privilege system, and it is the ' .
                    'way back in when single sign-on is what broke. Leaving it out keeps one door that the ' .
                    'identity provider cannot open.'
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'openidconnect_group_claim' => [
                'name' => gettext('Group claim'),
                'help' => gettext(
                    'Claim in the UserInfo response holding the group names, commonly <code>groups</code>. ' .
                    'Leave empty and group membership is decided here and nowhere else. ' .
                    '<b>Filling it in hands part of this firewall\'s privilege assignment to the identity ' .
                    'provider</b>: whoever can change a group there can change what someone may do here. ' .
                    'On a firewall that is worth a deliberate decision, so it is off unless asked for.'
                ),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'openidconnect_assignable_groups' => [
                'name' => gettext('Assignable groups'),
                'help' => gettext(
                    'Only these local groups may be granted or withdrawn by the provider; everything else ' .
                    'stays as it is set here. Empty means every local group is on the table, which is ' .
                    'rarely what anyone wants. Ignored while Group claim is empty.'
                ),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'openidconnect_debug' => [
                'name' => gettext('Trace the exchange'),
                'help' => gettext(
                    'Write what happens during a login to the system log: provider, addresses, which ' .
                    'claims arrived and who they resolved to. Never tokens, secrets or claim values that ' .
                    'are not needed to follow the flow. Meant for working out why a login is refused, ' .
                    'not for leaving on.'
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'openidconnect_logout_menu' => [
                'name' => gettext('Redirect the Log Out menu entry'),
                'help' => gettext(
                    'Point Lobby &gt; Log Out at <code>/api/openidconnect/auth/logout</code>, so that leaving the ' .
                    'web interface ends the session at the provider as well and not only here. The link ' .
                    'in the page header belongs to OPNsense itself and always ends locally.'
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'openidconnect_logout_redirect' => [
                'name' => gettext('Return here after logout'),
                'help' => gettext(
                    'Ask the provider to send the browser back to this firewall once it has ended its own ' .
                    'session. The provider has to accept this firewall as a post logout redirect URI, ' .
                    'otherwise it refuses. Leave off to end on the provider\'s own page.'
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'openidconnect_button_style' => [
                'name' => gettext('Login button style'),
                'help' => gettext('A custom button markup below overrides this.'),
                'type' => 'dropdown',
                'default' => 'button',
                'options' => [
                    'button' => gettext('Button, full width'),
                    'link' => gettext('Link (OPNsense default)'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::BUTTON_STYLES, ['']), true)
                    ? [] : [gettext('Unknown button style.')],
            ],
            'openidconnect_icon_url' => [
                'name' => gettext('Icon URL'),
                'help' => gettext(
                    'PNG or SVG. An absolute URL is fetched by the firewall and handed on; a path ' .
                    'starting with a slash is served from this firewall directly, which is how a theme ' .
                    'asset becomes the logo, for example ' .
                    '<code>/ui/themes/&lt;theme&gt;/build/images/icon-logo.svg</code>. A ' .
                    '<code>data:</code> URI is passed through. Ignored when Icon markup is filled in.'
                ),
                'type' => 'text',
                'validate' => function ($value) {
                    $value = trim((string)$value);
                    if ($value === '') {
                        return [];
                    }
                    /* it ends up inside a css url() on the login page */
                    if (static::hasControlCharacters($value)) {
                        return [gettext('Icon URL may not contain control characters.')];
                    }
                    if (static::isLocalPath($value) || str_starts_with($value, 'data:')
                        || static::isFetchableUrl($value)) {
                        return [];
                    }
                    return [gettext(
                        'Icon URL needs an http or https address, a data: URI, or a path starting ' .
                        'with a slash.'
                    )];
                },
            ],
            'openidconnect_icon_svg' => [
                'name' => gettext('Icon markup'),
                'help' => gettext(
                    'The icon as SVG source, for when there is nowhere to host a file. Handed to the ' .
                    'browser as a data: URI and never inlined into the page, so it is only ever treated ' .
                    'as an image. Keep it small: it travels with every rendering of the login page.'
                ),
                'type' => 'text',
                'validate' => function ($value) {
                    $value = trim((string)$value);
                    if ($value === '') {
                        return [];
                    }
                    if (strlen($value) > 65536) {
                        return [gettext('Icon markup is larger than 64 kB, please use Icon URL instead.')];
                    }
                    if (!preg_match('/<svg[\s>]/i', $value)) {
                        return [gettext('Icon markup does not contain an <svg> element.')];
                    }
                    if (preg_match('/<script[\s>]|\son[a-z]+\s*=/i', $value)) {
                        return [gettext('Remove scripts and event handlers from the icon markup.')];
                    }
                    return [];
                },
            ],
            'openidconnect_icon_mode' => [
                'name' => gettext('Icon rendering'),
                'help' => gettext(
                    'A single colour icon is redrawn in the button\'s text colour, which is what makes a ' .
                    'dark provider logo readable on a coloured button in a light and a dark theme alike. ' .
                    'It works for line art only: a logo with a filled background becomes a solid block.'
                ),
                'type' => 'dropdown',
                'default' => 'monochrome',
                'options' => [
                    'monochrome' => gettext('Single colour (redraw to match the text)'),
                    'original' => gettext('Original colours'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::ICON_MODES, ['']), true)
                    ? [] : [gettext('Unknown icon rendering.')],
            ],
            'openidconnect_custom_button' => [
                'name' => gettext('Custom button markup'),
                'help' => gettext(
                    'Full control over the login page entry. <code>%name%</code>, <code>%url%</code> and ' .
                    '<code>%icon%</code> are filled in. Overrides the button style and rendering above.'
                ),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            /**
             * Not a setting: the form has no hook for scripts or styles, so they ride
             * along in the help text of an entry that renders nothing. An empty type is
             * a type all the same - core reads $field['type'] before it decides what to
             * draw, and an entry without one costs a warning on every render.
             *
             * Core stores every field it was given, so this one reaches config.xml as an
             * empty element. It has no accessor and nothing reads it back.
             */
            '__openidconnect_form' => [
                'name' => '',
                'type' => '',
                'help' => $this->browserAssets(),
            ],
        ];
    }

    /**
     * The settings form has no hook for scripts or styles, so they ride along in the help
     * text of a field that renders nothing. Hidden by the stylesheet.
     */
    private function browserAssets(): string
    {
        $assets = __DIR__ . '/../OpenIDConnect/assets/';
        $groups = [];
        foreach (config_read_array('system', 'group') as $group) {
            if (!empty($group['name'])) {
                $groups[] = (string)$group['name'];
            }
        }

        $options = json_encode([
            'groups' => $groups,
            'testLabel' => gettext('Test discovery'),
            'redirectHint' => 'https://firewall.example.net' . self::CALLBACK_PATH,
            'tokenizerCss' => function_exists('get_themed_filename')
                ? get_themed_filename('/css/tokenize2.css') : '/ui/css/tokenize2.css',
        ], JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        return '<style>.auth_openidconnect:has(#help_for_field_openidconnect___openidconnect_form){display:none !important}</style>'
            . '<script>window.__oidcForm = ' . $options . ';</script>'
            . '<script>' . @file_get_contents($assets . 'settings-form.js') . '</script>';
    }

    /* ------------------------------------------------------------ local accounts */

    /**
     * Work out which local account a set of claims belongs to.
     *
     * Matching is by the configured claim against the account name, and by e-mail against
     * the account's address. Creation, when it is switched on at all, goes through the
     * same configd action the rest of OPNsense uses, so an account made here is
     * indistinguishable from one made anywhere else.
     *
     * Finding an account is not the same as being allowed to use it: what the provider
     * answers decides who someone is, and the local account decides whether that person
     * may sign in at all. See accountMayBeUsed().
     *
     * @param object $claims the UserInfo response
     * @return string|null the local account name, null when there is none and none was made
     */
    public function localAccountFor(object $claims): ?string
    {
        $claimed = trim((string)($claims->{$this->usernameClaim()} ?? ''));
        $this->trace(sprintf(
            'claims carry %s; username claim %s',
            implode(', ', array_keys(get_object_vars($claims))),
            $claimed === '' ? 'empty' : 'set'
        ));

        $created = false;
        $user = $claimed === '' ? null : $this->getUser($claimed);

        if ($user === null) {
            /* only now, so that a login the username claim settles says nothing about
               addresses it never needed */
            $email = $this->matchableEmail($claims);
            $user = $this->userByEmail($email);

            if ($user === null) {
                $user = $this->createAccount($claimed !== '' ? $claimed : $email);
                if ($user === null) {
                    return null;
                }
                $created = true;
            }
        }

        if (!$this->accountMayBeUsed($user)) {
            return null;
        }

        /* the spelling the configuration uses, which is the one the privilege system
           looks up - core normalises the same way through getUserName() after a local
           login, and a session name that differs in case resolves to no privileges */
        $account = (string)$user->name;

        $this->syncGroups($account, $claims, $created);

        return $account;
    }

    /**
     * Whether this local account may be signed in to at all.
     *
     * OpenID Connect answers who someone is at the provider. Whether that person may have
     * this firewall is decided here, and the same three questions core's own Local
     * connector asks before it accepts a password have to be asked on this way in too -
     * otherwise disabling an account locally, the usual way to end someone's access,
     * quietly stops meaning anything for whoever still has an account at the provider.
     * Nothing re-checks it afterwards either: session_auth() only watches the clock.
     *
     * @param object $user the <user> entry, as core hands it back
     */
    private function accountMayBeUsed(object $user): bool
    {
        $name = (string)$user->name;

        if (!empty((string)($user->disabled ?? ''))) {
            syslog(LOG_NOTICE, sprintf('OIDC: refusing a login, the local account %s is disabled', $name));
            return false;
        }

        /* judged by the day, the way core does it, so that a login on the expiry date works */
        $expires = trim((string)($user->expires ?? ''));
        if ($expires !== '' && strtotime('-1 day') > strtotime(date('m/d/Y', (int)strtotime($expires)))) {
            syslog(LOG_NOTICE, sprintf('OIDC: refusing a login, the local account %s has expired', $name));
            return false;
        }

        if (!$this->allowsRoot() && ($name === 'root' || (string)($user->uid ?? '') === '0')) {
            syslog(LOG_NOTICE, 'OIDC: refusing a login as root, which this server is not allowed to reach');
            return false;
        }

        return true;
    }

    /**
     * The e-mail address this login may be matched against, empty when it may not be.
     *
     * An address only says something about who someone is where the provider has checked
     * that it is theirs. Where a person can type their own, an unverified address is a
     * way onto somebody else's local account - so the default takes email_verified
     * seriously, and an installation whose provider sends none has to say so.
     */
    private function matchableEmail(object $claims): string
    {
        $mode = $this->emailMatching();
        if ($mode === 'off') {
            return '';
        }

        $email = trim((string)($claims->email ?? ''));
        if ($email === '' || $mode === 'always') {
            return $email;
        }

        /* a bool from most providers, the string "true" from a few */
        $verified = $claims->email_verified ?? null;
        if ($verified === true || $verified === 1 || $verified === 'true' || $verified === '1') {
            return $email;
        }

        $this->trace('not matching by e-mail address, the provider reports none as verified');
        syslog(LOG_NOTICE, 'OIDC: not matching by e-mail address, the provider does not report it as verified');

        return '';
    }

    /**
     * Hand group membership to core, which is what LDAP and RADIUS do here as well.
     *
     * Nothing happens unless a group claim is configured or default groups are set, so an
     * installation that decides membership locally keeps deciding it locally.
     */
    private function syncGroups(string $account, object $claims, bool $created): void
    {
        /* what a new account starts with, not something re-applied to everyone who signs in */
        $defaults = $created ? $this->defaultGroups() : [];
        $claim = $this->groupClaim();
        if ($claim === '' && $defaults === []) {
            return;
        }

        /* core reads an LDAP shaped list: one entry per line, group name after "cn=" */
        $granted = [];
        if ($claim !== '') {
            foreach (static::namesIn($claims->{$claim} ?? []) as $group) {
                $granted[] = 'cn=' . $group;
            }
            $this->trace(sprintf('provider offers %d group(s) for %s', count($granted), $account));
        }

        /**
         * Which local groups core may change. With a group claim that is the assignable
         * list, where empty means every local group - the documented "the provider
         * decides everything". Without one there is nothing for the provider to decide,
         * so the scope is the default groups alone: handing core an empty scope there
         * would read as every group there is, and a first login would strip memberships
         * nobody asked it to touch.
         */
        $scope = $claim === '' ? $defaults : $this->assignableGroups();

        $this->setGroupMembership($account, implode("\n", $granted), $scope, false, $defaults);
    }

    /**
     * Read group names out of whatever shape a provider chose for the claim.
     *
     * A plain list of names is the common case. Some providers hand back an object keyed
     * by name instead - Zitadel's role claim is one - so its keys are the names. Anything
     * that is not a string is skipped rather than allowed to turn a login into a fatal.
     *
     * @param mixed $value the raw claim
     * @return string[]
     */
    public static function namesIn($value): array
    {
        $entries = is_object($value) ? (array)$value : $value;
        if (!is_array($entries)) {
            $entries = is_scalar($entries) ? [$entries] : [];
        }

        /* a list carries the names as values, a map carries them as keys */
        $names = array_is_list($entries) ? $entries : array_keys($entries);

        $found = [];
        foreach ($names as $name) {
            if (is_scalar($name) && trim((string)$name) !== '') {
                $found[] = trim((string)$name);
            }
        }

        return $found;
    }

    /**
     * @return object|null the local account carrying this address
     */
    private function userByEmail(string $email): ?object
    {
        if ($email === '') {
            return null;
        }

        $config = Config::getInstance()->object();
        if (!isset($config->system->user)) {
            return null;
        }

        foreach ($config->system->user as $user) {
            if (isset($user->email) && strcasecmp(trim((string)$user->email), $email) === 0) {
                return $user;
            }
        }

        return null;
    }

    /**
     * @return object|null the new account, null when creation is off or failed
     */
    private function createAccount(string $username): ?object
    {
        if ($username === '' || !$this->createsUsers()) {
            return null;
        }

        $answer = json_decode((new Backend())->configdpRun('auth add user', [$username]), true);
        if (($answer['status'] ?? '') !== 'ok') {
            syslog(LOG_ERR, sprintf('OIDC: could not create a local account for %s', $username));
            return null;
        }

        Config::getInstance()->forceReload();
        syslog(LOG_NOTICE, sprintf('OIDC: created local account %s after a first login', $username));
        $this->trace(sprintf('account %s did not exist and was created', $username));

        return $this->getUser($username);
    }

    /* ---------------------------------------------------------------- settings */

    private function text(string $key, string $default = ''): string
    {
        $value = trim((string)($this->settings[$key] ?? ''));

        return $value === '' ? $default : $value;
    }

    private function flag(string $key): bool
    {
        return !empty($this->settings[$key]);
    }

    private function choice(string $key, array $allowed, string $default): string
    {
        $value = $this->text($key);

        return in_array($value, $allowed, true) ? $value : $default;
    }

    /**
     * Split a list field. One entry per line or comma separated, blanks dropped.
     *
     * @return string[]
     */
    public static function splitList($value): array
    {
        $parts = preg_split('/[\r\n,]+/', (string)$value) ?: [];

        return array_values(array_filter(array_map('trim', $parts), fn($v) => $v !== ''));
    }

    /** @return bool whether $value addresses this firewall rather than somewhere else */
    public static function isLocalPath($value): bool
    {
        return str_starts_with(trim((string)$value), '/');
    }

    /**
     * Whether $value carries anything that is not a printable character.
     *
     * Stated once, because an address written by a person ends up in more than one place
     * that a newline would change the meaning of - a css url() on the login page, a
     * header, a log line - and three literals that have to agree are three that can
     * quietly stop agreeing.
     */
    public static function hasControlCharacters($value): bool
    {
        return (bool)preg_match('/[\x00-\x1f\x7f]/', (string)$value);
    }

    /**
     * Whether $value is an address this firewall may go and fetch.
     *
     * FILTER_VALIDATE_URL says nothing about the scheme: file://, ftp:// and gopher://
     * all pass it, and curl speaks every one of them. So the scheme is named here. Spaces
     * are refused along with the control characters - deliberately stricter than the rule
     * above, because an address does not contain one and two addresses separated by one
     * is exactly the shape being kept out.
     */
    public static function isFetchableUrl($value): bool
    {
        $value = trim((string)$value);
        if ($value === '' || static::hasControlCharacters($value) || str_contains($value, ' ')) {
            return false;
        }
        if (!filter_var($value, FILTER_VALIDATE_URL)) {
            return false;
        }

        return in_array(strtolower((string)parse_url($value, PHP_URL_SCHEME)), self::FETCHABLE_SCHEMES, true);
    }

    /**
     * @param string[] $names
     * @return string[] the same names in lower case
     */
    private static function lowercased(array $names): array
    {
        return array_map('strtolower', $names);
    }

    public function issuerUrl(): string
    {
        /* the discovery document may be given by its own address or by the issuer's */
        $url = $this->text('openidconnect_provider_url');
        $marker = strpos($url, '.well-known/');

        return $marker === false ? $url : substr($url, 0, $marker);
    }

    public function clientId(): string
    {
        return $this->text('openidconnect_client_id');
    }

    public function clientSecret(): string
    {
        return $this->text('openidconnect_client_secret');
    }

    /** @return string[] */
    public function scopes(): array
    {
        $scopes = static::splitList($this->text('openidconnect_scopes'));

        return $scopes ?: ['openid', 'email', 'profile'];
    }

    public function usernameClaim(): string
    {
        return $this->text('openidconnect_username_claim', 'preferred_username');
    }

    /** @return string[] addresses the provider may send the browser back to */
    public function acceptedRedirectUrls(): array
    {
        return static::splitList($this->text('openidconnect_redirect_urls'));
    }

    /** @return int seconds, 0 when any age is acceptable */
    public function maximumAuthenticationAge(): int
    {
        return max(0, (int)$this->text('openidconnect_max_age', '0'));
    }

    public function createsUsers(): bool
    {
        return $this->flag('openidconnect_create_users');
    }

    /** @return string when an e-mail address may stand in for the username claim */
    public function emailMatching(): string
    {
        return $this->choice('openidconnect_email_match', self::EMAIL_MATCHING, 'verified');
    }

    /** @return bool whether this server may resolve to the built-in root account */
    public function allowsRoot(): bool
    {
        return $this->flag('openidconnect_allow_root');
    }

    /**
     * @return string[] groups a newly created account is placed in
     *
     * Lower case, because that is the only spelling core will act on:
     * setGroupMembership() compares against strtolower() of the local group name, so a
     * name typed with a capital matches nothing and the sync silently does nothing at
     * all - while the form goes on looking as though it were switched on. Core's own LDAP
     * connector lowercases these for the same reason.
     */
    public function defaultGroups(): array
    {
        return static::lowercased(static::splitList($this->text('openidconnect_default_groups')));
    }

    public function buttonStyle(): string
    {
        return $this->choice('openidconnect_button_style', self::BUTTON_STYLES, 'button');
    }

    public function iconMode(): string
    {
        return $this->choice('openidconnect_icon_mode', self::ICON_MODES, 'monochrome');
    }

    public function iconMarkup(): string
    {
        return $this->text('openidconnect_icon_svg');
    }

    public function iconUrl(): string
    {
        return $this->text('openidconnect_icon_url');
    }

    public function customButton(): string
    {
        return $this->text('openidconnect_custom_button');
    }

    public function redirectsLogoutMenu(): bool
    {
        return $this->flag('openidconnect_logout_menu');
    }

    public function returnsAfterLogout(): bool
    {
        return $this->flag('openidconnect_logout_redirect');
    }

    /**
     * @return string|null the method to insist on, null to follow the provider
     */
    public function tokenAuthMethod(): ?string
    {
        $chosen = $this->text('openidconnect_token_auth');

        return in_array($chosen, self::TOKEN_AUTH_METHODS, true) ? $chosen : null;
    }

    /** @return string claim carrying the group names, empty when groups are ignored */
    public function groupClaim(): string
    {
        return $this->text('openidconnect_group_claim');
    }

    /**
     * @return string[] group names the provider may assign, empty for every local group
     *
     * Lower case, for the reason given at defaultGroups().
     */
    public function assignableGroups(): array
    {
        return static::lowercased(static::splitList($this->text('openidconnect_assignable_groups')));
    }

    public function isTracing(): bool
    {
        return $this->flag('openidconnect_debug');
    }

    /**
     * Write a line about the exchange to syslog, when tracing is switched on.
     *
     * Deliberately never given a token, a secret or a raw claim set: tracing is there to
     * show the shape of a flow - which provider, which address, which claims arrived, who
     * it resolved to - and a trace that lands in a support mail should not carry material
     * that grants access.
     */
    public function trace(string $message): void
    {
        if (!$this->isTracing()) {
            return;
        }

        /**
         * LOG_NOTICE rather than LOG_INFO: OPNsense's syslog-ng keeps notice and above
         * and drops the rest, so a trace written at info level would be invisible - which
         * looks exactly like a switch that does not work. Measured on 26.7.
         */
        syslog(LOG_NOTICE, 'OIDC trace: ' . $message);
    }
}
