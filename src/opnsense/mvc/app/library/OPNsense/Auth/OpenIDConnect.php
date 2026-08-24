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
use OPNsense\OpenIDConnect\AuthenticationRequirement;
use OPNsense\OpenIDConnect\PendingIdentityRegistry;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\SharedSignalsClient;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;

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
    public const BUTTON_TEXT_MODES = ['localized', 'label_only', 'custom'];
    public const ICON_MODES = ['monochrome', 'original'];

    /** how this firewall authenticates itself at the token endpoint */
    public const TOKEN_AUTH_METHODS = ['client_secret_basic', 'client_secret_post'];
    public const PAR_MODES = ['auto', 'required', 'disabled'];
    public const LOGOUT_NOTIFICATION_MODES = ['both', 'backchannel', 'frontchannel', 'off'];
    public const SSF_DELIVERY_METHODS = ['push', 'poll'];

    /** when an e-mail address may stand in for the username claim */
    public const EMAIL_MATCHING = ['verified', 'always', 'off'];

    public const PROVIDER_PROFILES = [
        'general', 'auth0', 'authelia', 'authentik', 'cognito', 'duo', 'dex',
        'fusionauth', 'gitlab', 'google', 'ibm_verify', 'jumpcloud', 'keycloak',
        'entra', 'okta', 'onelogin', 'oracle_idcs', 'ping', 'pocketid', 'apple',
        'wso2', 'zitadel', 'linkedin', 'slack', 'yahoo', 'orcid',
    ];
    public const CLAIMS_SOURCES = ['auto', 'id_token', 'userinfo'];
    public const RESPONSE_MODES = ['query', 'form_post', 'query.jwt', 'form_post.jwt'];
    public const BOOTSTRAP_MODES = ['strict', 'approval', 'username', 'verified_email', 'either'];
    public const MICROSOFT_AUDIENCES = ['tenant', 'organizations', 'consumers', 'common'];
    public const ORIGIN_POLICIES = ['opnsense', 'custom'];
    public const REQUIRED_AUTHENTICATION = AuthenticationRequirement::TIERS;
    public const ACR_REQUEST_MODES = AuthenticationRequirement::REQUEST_MODES;

    /** Global services whose familiar public login name has no installation-specific variant. */
    private const FIXED_PROVIDER_BUTTON_LABELS = [
        'apple' => 'Apple',
        'entra' => 'Microsoft',
        'google' => 'Google',
        'linkedin' => 'LinkedIn',
        'orcid' => 'ORCID',
        'slack' => 'Slack',
        'yahoo' => 'Yahoo',
    ];

    /** Require a fresh provider authentication after four hours by default. */
    public const DEFAULT_MAX_AUTHENTICATION_AGE = 14400;

    /** schemes this firewall will fetch something over */
    public const FETCHABLE_SCHEMES = ['https'];

    /** @var array raw settings of this authentication server */
    private array $settings = [];
    private bool $bindingConflict = false;
    private string $pendingApprovalId = '';

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
        if (array_key_exists('openidconnect_provider_url', $this->settings)) {
            $this->settings['openidconnect_provider_url'] = ProviderMetadata::normalizeIssuerInput(
                $this->settings['openidconnect_provider_url'],
                $this->providerRequiresTrailingIssuerSlash()
            );
        }
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
        return [
            'openidconnect_enabled' => [
                'name' => gettext('Offer on the login page'),
                'help' => gettext('Keep this disabled while a provider is being prepared or diagnosed.'),
                'type' => 'checkbox',
                'default' => '0',
                'validate' => fn($value) => [],
            ],
            'openidconnect_app_code' => [
                'name' => gettext('Application code'),
                'help' => gettext(
                    'A stable, URL-safe name used in this provider\'s distinct callback URI. ' .
                    'Use a different value for every OpenID Connect server, for example ' .
                    '<code>authentik</code>. This is only a short identifier, not a URL. ' .
                    'The endpoint reference below shows the resulting addresses and what each one is for.'
                ),
                'type' => 'text',
                'default' => 'main',
                'validate' => fn($value) => $this->validateApplicationCode($value),
            ],
            'openidconnect_provider_profile' => [
                'name' => gettext('Provider profile'),
                'help' => gettext(
                    'Generic follows the standards without provider-specific assumptions. A named profile ' .
                    'fills every provider-dependent starting value, locks documented provider invariants and ' .
                    'adds diagnostics; it never weakens token checks. Tenant and realm values remain editable.'
                ),
                'type' => 'dropdown',
                'default' => 'general',
                'options' => static::providerProfileOptions(),
                'validate' => fn($value) => in_array($value ?: 'general', self::PROVIDER_PROFILES, true)
                    ? [] : [gettext('Unknown provider profile.')],
            ],
            'openidconnect_provider_url' => [
                'name' => gettext('Exact issuer URL'),
                'help' => gettext(
                    'Enter the issuer exactly as the provider publishes it, including its path and any ' .
                    'trailing slash. You may also paste its complete ' .
                    '<code>/.well-known/openid-configuration</code> address; the suffix is removed before ' .
                    'the issuer is saved. Saving checks only the URL ' .
                    'syntax; the separate Discovery test checks the provider and may fail without preventing a save. ' .
                    'It may be left empty while this server is disabled and the provider is being prepared.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = ProviderMetadata::normalizeIssuerInput(
                        $value,
                        $this->providerRequiresTrailingIssuerSlash()
                    );
                    return $this->usesManagedMicrosoftIssuer()
                        || ($value === '' && $this->allowsIncompleteDraft())
                        ? [] : (static::isIssuerUrl($value)
                            ? [] : [gettext('The provider URL must be a valid HTTPS address.')]);
                },
            ],
            'openidconnect_microsoft_audience' => [
                'name' => gettext('Microsoft account audience'),
                'help' => gettext(
                    'A single saved server produces one login button. Choose a specific tenant, Entra ' .
                    'organizations, personal Microsoft accounts, or both. Configure separate servers when ' .
                    'personal and work accounts should have separate buttons or different admission policies.'
                ),
                'type' => 'dropdown',
                'default' => 'tenant',
                'options' => [
                    'tenant' => gettext('One specific Entra tenant'),
                    'organizations' => gettext('Any Entra organization (work or school accounts)'),
                    'consumers' => gettext('Personal Microsoft accounts only'),
                    'common' => gettext('Entra organizations and personal Microsoft accounts'),
                ],
                'validate' => fn($value) => in_array($value ?: 'tenant', self::MICROSOFT_AUDIENCES, true)
                    ? [] : [gettext('Unknown Microsoft account audience.')],
            ],
            'openidconnect_client_id' => [
                'name' => gettext('Client ID'),
                'type' => 'text',
                'help' => gettext('May be left empty while the server is disabled and the provider creates the client.'),
                'validate' => fn($value) => !empty(trim((string)$value)) || $this->allowsIncompleteDraft()
                    ? [] : [gettext('A client ID is required.')],
            ],
            'openidconnect_client_secret' => [
                'name' => gettext('Client Secret'),
                'help' => gettext(
                    'This firewall authenticates as a confidential client. Public clients, which have no ' .
                    'secret, are not supported.'
                ),
                'type' => 'text',
                'validate' => fn($value) => !empty(trim((string)$value)) || $this->allowsIncompleteDraft()
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
            'openidconnect_par_mode' => [
                'name' => gettext('Pushed authorization requests'),
                'help' => gettext(
                    'Automatic uses PAR when Discovery offers it and temporarily bypasses an unavailable optional ' .
                    'endpoint while a background check recovers it. Required fails the login instead. Disabled ' .
                    'sends the authorization parameters through the browser and cannot override a provider which ' .
                    'requires PAR.'
                ),
                'type' => 'dropdown',
                'default' => 'auto',
                'options' => [
                    'auto' => gettext('Automatic with availability fallback'),
                    'required' => gettext('Required'),
                    'disabled' => gettext('Disabled'),
                ],
                'validate' => fn($value) => in_array($value ?: 'auto', self::PAR_MODES, true)
                    ? [] : [gettext('Unknown pushed authorization request mode.')],
            ],
            'openidconnect_request_object_key' => [
                'name' => gettext('Request Object signing key'),
                'help' => gettext(
                    'Advanced. Select a dedicated OPNsense certificate whose public key and displayed kid are ' .
                    'registered for this client at the provider. Authorization parameters are then sent in a ' .
                    'short-lived signed RFC 9101 Request Object, including through PAR. For rotation, register ' .
                    'the replacement certificate first, select it here, test sign-in, and only then remove the old key.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => $this->requestObjectSigningKeyOptions(),
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return $value === '' || array_key_exists($value, $this->requestObjectSigningKeyOptions())
                        ? [] : [gettext('Select an OPNsense certificate with a private key.')];
                },
            ],
            'openidconnect_username_claim' => [
                'name' => gettext('Username claim'),
                'help' => gettext(
                    'Which claim names the local account. Usually <code>preferred_username</code> or ' .
                    '<code>email</code>. A user is matched against the local account of that name, and ' .
                    'against local e-mail addresses.'
                ),
                'type' => 'text',
                'default' => 'preferred_username',
                'validate' => fn($value) => !empty(trim((string)$value))
                    ? [] : [gettext('A username claim is required.')],
            ],
            'openidconnect_claims_source' => [
                'name' => gettext('Claims source'),
                'help' => gettext(
                    'Automatic uses verified ID Token claims and calls UserInfo only when a configured ' .
                    'identity or group claim is missing. UserInfo, when used, is always bound by sub.'
                ),
                'type' => 'dropdown',
                'default' => 'auto',
                'options' => [
                    'auto' => gettext('Automatic'),
                    'id_token' => gettext('ID Token only'),
                    'userinfo' => gettext('Require UserInfo'),
                ],
                'validate' => fn($value) => in_array($value ?: 'auto', self::CLAIMS_SOURCES, true)
                    ? [] : [gettext('Unknown claims source.')],
            ],
            'openidconnect_response_mode' => [
                'name' => gettext('Authorization response mode'),
                'help' => gettext(
                    'Query is the interoperable default. Apple uses Form POST when scopes are requested. ' .
                    'The JARM choices require a provider that returns signed authorization responses.'
                ),
                'type' => 'dropdown',
                'default' => 'query',
                'options' => [
                    'query' => gettext('Query'),
                    'form_post' => gettext('Form POST'),
                    'query.jwt' => gettext('Signed query (JARM)'),
                    'form_post.jwt' => gettext('Signed Form POST (JARM)'),
                ],
                'validate' => fn($value) => in_array($value ?: 'query', self::RESPONSE_MODES, true)
                    ? [] : [gettext('Unknown response mode.')],
            ],
            'openidconnect_required_authentication' => [
                'name' => gettext('Required authentication'),
                'help' => gettext(
                    'Require the verified ID Token to report both an accepted authentication context and an ' .
                    'accepted authentication method before OPNsense resolves an account or creates a WebGUI ' .
                    'session. Provider policy only preserves the provider\'s normal sign-in decision. ' .
                    'Multi-factor accepts ordinary MFA; phishing-resistant is intended for Passkeys, FIDO2, ' .
                    'WebAuthn or an equivalent provider policy.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => [
                    '' => gettext('Provider policy only'),
                    AuthenticationRequirement::MULTI_FACTOR => gettext('Multi-factor authentication'),
                    AuthenticationRequirement::PHISHING_RESISTANT => gettext('Phishing-resistant authentication'),
                ],
                'validate' => fn($value) => $this->validateRequiredAuthentication($value),
            ],
            'openidconnect_acr_request' => [
                'name' => gettext('Authentication context request'),
                'help' => gettext(
                    'Advanced. Following the provider uses an essential ID Token claim for Generic OpenID ' .
                    'Connect and acr_values for Okta. Change this only when the provider documents another ' .
                    'request form. Microsoft Entra uses its separate authentication context below.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => [
                    '' => gettext('Follow the provider preset'),
                    AuthenticationRequirement::ESSENTIAL_CLAIM => gettext('Essential ID Token acr claim'),
                    AuthenticationRequirement::ACR_VALUES => gettext('acr_values authorization parameter'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::ACR_REQUEST_MODES, ['']), true)
                    ? [] : [gettext('Unknown authentication context request.')],
            ],
            'openidconnect_acr_values' => [
                'name' => gettext('Accepted authentication contexts'),
                'help' => gettext(
                    'Advanced. Exact, case-sensitive acr values, separated by commas or lines. Empty restores ' .
                    'the documented preset. A provider may use installation-specific values only when their ' .
                    'meaning is agreed and enforced there.'
                ),
                'type' => 'text',
                'validate' => fn($value) => static::validateRequirementList(
                    $value,
                    8,
                    256,
                    gettext('authentication context')
                ),
            ],
            'openidconnect_amr_values' => [
                'name' => gettext('Accepted authentication methods'),
                'help' => gettext(
                    'Advanced. Exact, case-sensitive amr values from which the selected policy must have sufficient ' .
                    'evidence. Empty restores the documented preset. Standard MFA needs mfa or methods from two ' .
                    'different factor types. user means presence only; the hardware-key value is hwk, not hw.'
                ),
                'type' => 'text',
                'validate' => fn($value) => static::validateRequirementList(
                    $value,
                    16,
                    64,
                    gettext('authentication method')
                ),
            ],
            'openidconnect_entra_auth_context' => [
                'name' => gettext('Microsoft authentication context'),
                'help' => gettext(
                    'Microsoft Entra Conditional Access authentication context assigned to this application ' .
                    'requirement. Configure the selected c1-c25 context in the tenant with the corresponding ' .
                    'authentication strength. It is required because these identifiers have tenant-local meaning.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => ['' => gettext('Select the tenant context')] + array_combine(
                    array_map(static fn($number) => 'c' . $number, range(1, 25)),
                    array_map(static fn($number) => 'c' . $number, range(1, 25))
                ),
                'validate' => fn($value) => $this->validateMicrosoftAuthenticationContext($value),
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
            'openidconnect_select_account' => [
                'name' => gettext('Always show account selection'),
                'help' => gettext(
                    'Send <code>prompt=select_account</code> when a login begins. This is useful when ' .
                    'administrators commonly have more than one account at the identity provider. Leave it ' .
                    'off when the provider should reuse its current account without an extra choice.'
                ),
                'type' => 'checkbox',
                'default' => '0',
                'validate' => fn($value) => [],
            ],
            'openidconnect_origin_policy' => [
                'name' => gettext('WebGUI address policy'),
                'help' => gettext(
                    'Following OPNsense automatically uses its hostname and domain, short hostname, alternate ' .
                    'hostnames, local interface addresses and virtual IPs when the WebGUI itself uses HTTPS. ' .
                    'The current accepted browser address is shown first. Choose Custom for provider-specific ' .
                    'restrictions, a reverse proxy or an external port OPNsense does not know.'
                ),
                'type' => 'dropdown',
                'default' => 'opnsense',
                'options' => [
                    'opnsense' => gettext('Follow OPNsense WebGUI settings'),
                    'custom' => gettext('Custom origins for this provider'),
                ],
                'validate' => fn($value) => in_array($value ?: 'opnsense', self::ORIGIN_POLICIES, true)
                    ? [] : [gettext('Unknown WebGUI address policy.')],
            ],
            'openidconnect_tls_offloading' => [
                'name' => gettext('Trusted reverse-proxy TLS offloading'),
                'help' => gettext(
                    'Advanced exception for a WebGUI configured as HTTP behind one trusted HTTPS reverse proxy. ' .
                    'It requires Custom origins containing the exact public HTTPS addresses. The proxy must be ' .
                    'the only route to the backend, preserve the public Host header and add Secure to OPNsense ' .
                    'session cookies. Configure trusted client-address propagation when OPNsense source-network ' .
                    'ACLs are used. OpenID Connect does not trust X-Forwarded-Proto. Leave this disabled when ' .
                    'OPNsense serves HTTPS itself.'
                ),
                'type' => 'checkbox',
                'default' => '0',
                'validate' => fn($value) => $this->validateTlsOffloading($value),
            ],
            'openidconnect_redirect_urls' => [
                'name' => gettext('Additional or overridden WebGUI origins'),
                'help' => gettext(
                    'Enter only scheme, host or IP address, and optional port, for example ' .
                    '<code>https://192.0.2.1</code> or ' .
                    '<code>https://firewall.example.com:8443</code>. ' .
                    'Do not paste a callback path here; the plugin constructs it using the application code. ' .
                    'In Follow mode these origins supplement the addresses OPNsense supplies; in Custom mode ' .
                    'they replace them. This allow-list is ' .
                    'independent of certificate trust: browsers and identity providers must trust the WebGUI ' .
                    'certificate separately.'
                ),
                'type' => 'text',
                'validate' => function ($value) {
                    $urls = static::splitList($value);
                    if ($urls === []) {
                        return $this->allowsIncompleteDraft() || !$this->postedCustomOrigins()
                            ? [] : [gettext('At least one accepted redirect URL is required.')];
                    }
                    foreach ($urls as $url) {
                        if (!static::isHttpsOrigin($url)) {
                            return [sprintf(gettext(
                                '%s is not an HTTPS origin. Enter only scheme, hostname or IP address, and optional port, without a path.'
                            ), $url)];
                        }
                    }
                    return [];
                },
            ],
            'openidconnect_sector_origin' => [
                'name' => gettext('Pairwise subject sector'),
                'help' => gettext(
                    'Optional stable HTTPS origin used by providers which issue pairwise subject identifiers. ' .
                    'The plugin publishes this server\'s exact callback addresses below that origin. Changing ' .
                    'the sector later can change <code>sub</code> values and break existing identity bindings.'
                ),
                'type' => 'dropdown',
                'default' => '',
                'options' => $this->sectorOriginOptions(),
                'validate' => fn($value) => $this->validateSectorOrigin($value),
            ],
            'openidconnect_max_age' => [
                'name' => gettext('Maximum authentication age'),
                'help' => gettext(
                    'Maximum age in seconds of the authentication at the identity provider when a new ' .
                    'OPNsense login begins. The default <code>14400</code> requires an authentication no ' .
                    'older than four hours; examples are <code>3600</code> for one hour and ' .
                    '<code>28800</code> for eight hours. Use <code>0</code> to require active ' .
                    're-authentication at the provider on every login. This does not shorten an already ' .
                    'established OPNsense WebGUI session; that session follows OPNsense\'s own timeout.'
                ),
                'type' => 'text',
                'default' => (string)self::DEFAULT_MAX_AUTHENTICATION_AGE,
                /* not empty(): zero deliberately means fresh authentication every time */
                'validate' => fn($value) => ctype_digit(trim((string)$value))
                    ? [] : [gettext('Maximum authentication age must be a whole number of seconds, zero or greater.')],
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
            'openidconnect_bootstrap_mode' => [
                'name' => gettext('Admission policy'),
                'help' => gettext(
                    'This is the firewall admission decision, not merely an account lookup. Every accepted ' .
                    'identity is permanently bound by exact issuer and subject to a local numeric user ID. ' .
                    'Approval queues an unknown identity for an administrator without granting a session; ' .
                    'automatic matching is an explicit, less restrictive choice.'
                ),
                'type' => 'dropdown',
                'default' => $this->legacyBootstrapDefault(),
                'options' => [
                    'strict' => gettext('Strict: pre-linked subjects only'),
                    'approval' => gettext('Administrator approval for unknown identities'),
                    'username' => gettext('Bootstrap by exact local username'),
                    'verified_email' => gettext('Bootstrap by unique verified e-mail'),
                    'either' => gettext('Bootstrap by exact username or unique verified e-mail'),
                ],
                'validate' => fn($value) => in_array($value ?: 'strict', self::BOOTSTRAP_MODES, true)
                    ? [] : [gettext('Unknown admission policy.')],
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
                    'stays as it is set here. Empty means no local group. Ignored while Group claim is empty.'
                ),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'openidconnect_allow_all_groups' => [
                'name' => gettext('Allow every local group'),
                'help' => gettext(
                    'Explicitly allow the provider to grant or withdraw every local group. This is ' .
                    'intentionally separate from an empty list because it delegates all local privileges.'
                ),
                'type' => 'checkbox',
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
            'openidconnect_logout_notifications' => [
                'name' => gettext('Provider logout notifications'),
                'help' => gettext(
                    'Both accepts signed server-to-server Back-Channel Logout and browser-based Front-Channel ' .
                    'Logout. This lets a provider use either registered channel, but the provider decides whether ' .
                    'it retries a failed delivery through the other one. Existing sessions remain reachable here ' .
                    'even when this provider is no longer offered for new logins.'
                ),
                'type' => 'dropdown',
                'default' => 'both',
                'options' => [
                    'both' => gettext('Both'),
                    'backchannel' => gettext('Back-channel only'),
                    'frontchannel' => gettext('Front-channel only'),
                    'off' => gettext('Off'),
                ],
                'validate' => fn($value) => in_array($value ?: 'both', self::LOGOUT_NOTIFICATION_MODES, true)
                    ? [] : [gettext('Unknown provider logout notification mode.')],
            ],
            'openidconnect_ssf_enabled' => [
                'name' => gettext('Receive Shared Signals'),
                'help' => gettext(
                    'Allow this provider to end matching OpenID Connect WebGUI sessions by sending signed ' .
                    'Shared Signals Framework events. This exposes a public receiver endpoint, so it is off ' .
                    'until an exact transmitter, audience and strong delivery secret are configured.'
                ),
                'type' => 'checkbox',
                'default' => '0',
                'validate' => fn($value) => [],
            ],
            'openidconnect_ssf_issuer' => [
                'name' => gettext('Shared Signals transmitter issuer'),
                'help' => gettext(
                    'The exact HTTPS issuer published by the SSF transmitter. It may differ from the OpenID ' .
                    'Connect issuer; its discovered metadata and every received SET must match it exactly.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return !$this->submittedSsfEnabled() || static::isIssuerUrl($value)
                        ? [] : [gettext('An exact HTTPS Shared Signals transmitter issuer is required.')];
                },
            ],
            'openidconnect_ssf_audience' => [
                'name' => gettext('Shared Signals audience'),
                'help' => gettext(
                    'The exact audience assigned to this receiver by the transmitter when the stream is created. ' .
                    'It is case-sensitive and is not inferred from a WebGUI address.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return !$this->submittedSsfEnabled()
                        || ($value !== '' && strlen($value) <= 255 && !static::hasControlCharacters($value))
                        ? [] : [gettext('A bounded Shared Signals audience without control characters is required.')];
                },
            ],
            'openidconnect_ssf_delivery_method' => [
                'name' => gettext('Shared Signals delivery method'),
                'help' => gettext(
                    'Push lets the transmitter call this firewall. Poll makes the firewall retrieve events once ' .
                    'per minute from the exact endpoint assigned by a managed stream. Polling is never selected ' .
                    'automatically after a failed push.'
                ),
                'type' => 'dropdown',
                'default' => 'push',
                'options' => [
                    'push' => gettext('Push to this firewall'),
                    'poll' => gettext('Poll from the transmitter'),
                ],
                'validate' => fn($value) => in_array($value ?: 'push', self::SSF_DELIVERY_METHODS, true)
                    ? [] : [gettext('Unknown Shared Signals delivery method.')],
            ],
            'openidconnect_ssf_management_authorization' => [
                'name' => gettext('Shared Signals management authorization'),
                'help' => gettext(
                    'The complete Bearer or Basic authorization value issued for this receiver. It authorizes ' .
                    'stream lifecycle and poll requests and is sent only to discovered management or assigned ' .
                    'poll endpoints. It is required for polling; leave it empty for a manually managed push stream.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    if (!$this->submittedSsfEnabled() || ($value === '' && $this->submittedSsfDelivery() === 'push')) {
                        return [];
                    }
                    try {
                        SharedSignalsClient::validatedAuthorization($value);
                        return [];
                    } catch (\Throwable $e) {
                        return [gettext(
                            'Enter the complete bounded Bearer or Basic Shared Signals authorization value.'
                        )];
                    }
                },
            ],
            'openidconnect_ssf_stream_id' => [
                'name' => gettext('Shared Signals stream ID'),
                'help' => gettext(
                    'The immutable identifier returned when the transmitter creates this receiver stream. Use ' .
                    'Manage stream to create or read it. Polling requires a managed stream ID.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return !$this->submittedSsfEnabled()
                        || ($value === '' && $this->submittedSsfDelivery() === 'push')
                        || preg_match('/^[A-Za-z0-9._~-]{1,255}$/D', $value)
                        ? [] : [gettext('A URL-safe Shared Signals stream ID is required for polling.')];
                },
            ],
            'openidconnect_ssf_poll_endpoint' => [
                'name' => gettext('Shared Signals poll endpoint'),
                'help' => gettext(
                    'The exact HTTPS delivery endpoint returned by the transmitter for this poll stream. Manage ' .
                    'stream fills it from a validated stream response; it is never inferred from failed push delivery.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return !$this->submittedSsfEnabled() || $this->submittedSsfDelivery() !== 'poll'
                        || static::isFetchableUrl($value)
                        ? [] : [gettext('A validated HTTPS Shared Signals poll endpoint is required for polling.')];
                },
            ],
            'openidconnect_ssf_push_secret' => [
                'name' => gettext('Shared Signals delivery secret'),
                'help' => gettext(
                    'A 256-bit bearer secret authenticates the transmitter before the firewall fetches keys or ' .
                    'performs signature work. Generate it here and copy the complete Authorization value into ' .
                    'the transmitter stream. It is required only for push delivery.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return !$this->submittedSsfEnabled() || $this->submittedSsfDelivery() !== 'push'
                        || preg_match('/^[A-Za-z0-9_-]{43}$/D', $value)
                        ? [] : [gettext('Generate a 256-bit Shared Signals delivery secret before enabling it.')];
                },
            ],
            'openidconnect_ssf_previous_push_secret' => [
                'name' => gettext('Previous Shared Signals delivery secret'),
                'help' => gettext(
                    'Optional overlap credential for safe push-secret rotation. First move the old value here and ' .
                    'save the new value above, then update the transmitter stream. Clear this field after the new ' .
                    'credential has delivered successfully.'
                ),
                'type' => 'text',
                'validate' => function ($value): array {
                    $value = trim((string)$value);
                    return $value === '' || preg_match('/^[A-Za-z0-9_-]{43}$/D', $value)
                        ? [] : [gettext(
                            'The previous Shared Signals delivery secret must be a 256-bit generated value.'
                        )];
                },
            ],
            'openidconnect_button_style' => [
                'name' => gettext('Login button style'),
                'type' => 'dropdown',
                'default' => 'button',
                'options' => [
                    'button' => gettext('Button, full width'),
                    'link' => gettext('Link (OPNsense default)'),
                ],
                'validate' => fn($value) => in_array($value, array_merge(self::BUTTON_STYLES, ['']), true)
                    ? [] : [gettext('Unknown button style.')],
            ],
            'openidconnect_button_text_mode' => [
                'name' => gettext('Login button wording'),
                'help' => gettext(
                    'The OPNsense sentence reuses the WebGUI language and places the provider label into ' .
                    'OPNsense\'s standard login wording. Provider label only omits that sentence. Custom full ' .
                    'text is displayed literally and is not translated automatically.'
                ),
                'type' => 'dropdown',
                'default' => 'localized',
                'options' => [
                    'localized' => gettext('OPNsense localized sentence'),
                    'label_only' => gettext('Provider label only'),
                    'custom' => gettext('Custom full text'),
                ],
                'validate' => fn($value) => in_array($value ?: 'localized', self::BUTTON_TEXT_MODES, true)
                    ? [] : [gettext('Unknown login button wording.')],
            ],
            'openidconnect_button_provider_label' => [
                'name' => gettext('Provider label on login button'),
                'help' => gettext(
                    'Optional name shown to users instead of the authentication server\'s Descriptive name. ' .
                    'Leave empty to follow Descriptive name. This label can still be placed inside the ' .
                    'localized OPNsense sentence.'
                ),
                'type' => 'text',
                'validate' => fn($value) => $this->validateButtonText($value, 80, true),
            ],
            'openidconnect_button_custom_text' => [
                'name' => gettext('Custom login button text'),
                'help' => gettext(
                    'The exact complete text shown on the login control. Use this only when one literal wording ' .
                    'is intended for every WebGUI language; HTML is not accepted.'
                ),
                'type' => 'text',
                'validate' => fn($value) => $this->validateButtonText(
                    $value,
                    120,
                    $this->submittedButtonTextMode() !== 'custom'
                ),
            ],
            'openidconnect_icon_url' => [
                'name' => gettext('Icon URL'),
                'help' => gettext(
                    'Every provider profile supplies a local built-in SVG by default. An absolute ' .
                    'PNG or SVG URL is fetched by the firewall and handed on; a path ' .
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
                    if (static::isLocalPath($value) || static::isIconDataUri($value)
                        || static::isFetchableUrl($value)) {
                        return [];
                    }
                    return [gettext(
                        'Icon URL needs an HTTPS address, an image data: URI, or a path starting ' .
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
                    'Bundled icons use transparent cut-outs so their identifying details remain visible. ' .
                    'A custom icon must use transparency rather than white layers for the same result.'
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
     * Generic is a deliberate first choice; vendor profiles are sorted by the labels
     * administrators see, without case affecting where a brand lands. Keeping the sort
     * here prevents a newly added profile from making the dropdown drift out of order.
     *
     * @return array<string,string>
     */
    public static function providerProfileOptions(): array
    {
        $named = [
            'auth0' => 'Auth0',
            'authentik' => 'authentik',
            'authelia' => 'Authelia',
            'cognito' => 'AWS Cognito',
            'duo' => 'Cisco Duo Single Sign-On',
            'dex' => 'Dex',
            'fusionauth' => 'FusionAuth',
            'gitlab' => 'GitLab.com / self-managed GitLab · Social / workforce',
            'google' => 'Google / Google Workspace · Social / workforce',
            'ibm_verify' => 'IBM Security Verify',
            'jumpcloud' => 'JumpCloud',
            'keycloak' => 'Keycloak',
            'linkedin' => 'LinkedIn · Social login',
            'entra' => 'Microsoft Entra ID / Microsoft account · Social / workforce',
            'okta' => 'Okta',
            'onelogin' => 'OneLogin',
            'orcid' => 'ORCID · Social login',
            'oracle_idcs' => 'Oracle Identity Cloud / OCI IAM',
            'ping' => 'Ping Identity',
            'pocketid' => 'Pocket ID',
            'apple' => 'Apple · Social login',
            'slack' => 'Slack · Social / workforce',
            'wso2' => 'WSO2 Identity Server',
            'yahoo' => 'Yahoo · Social login',
            'zitadel' => 'ZITADEL',
        ];
        uasort($named, 'strcasecmp');
        return ['general' => gettext('Generic OpenID Connect')] + $named;
    }

    /**
     * Provider knowledge used by both the settings form and the relying party.
     *
     * A value is a conservative, interoperable starting point. A locked value is an
     * invariant of that provider's public OpenID Connect service and is enforced again
     * server-side; everything else remains an administrator override. Identity admission
     * deliberately defaults to approval for named providers: this makes a first login
     * useful without ever admitting an unknown identity to the WebGUI.
     *
     * @return array<string,array{values:array<string,string>,locked:string[],placeholders:array<string,string>}>
     */
    public static function providerProfilePresets(): array
    {
        $generic = [
            'openidconnect_provider_url' => '',
            'openidconnect_token_auth' => '',
            'openidconnect_username_claim' => 'preferred_username',
            'openidconnect_claims_source' => 'auto',
            'openidconnect_response_mode' => 'query',
            'openidconnect_email_match' => 'verified',
            'openidconnect_scopes' => 'openid,email,profile',
            'openidconnect_bootstrap_mode' => 'strict',
            'openidconnect_button_text_mode' => 'localized',
            'openidconnect_button_provider_label' => '',
            'openidconnect_button_custom_text' => '',
            'openidconnect_icon_url' => static::providerIconUrl('general'),
            'openidconnect_icon_mode' => 'monochrome',
        ];
        $named = array_replace($generic, ['openidconnect_bootstrap_mode' => 'approval']);
        $make = static function (
            array $values = [],
            array $locked = [],
            string $issuerPlaceholder = 'https://id.example.com'
        ) use ($named): array {
            return [
                'values' => array_replace($named, $values),
                'locked' => $locked,
                'placeholders' => ['openidconnect_provider_url' => $issuerPlaceholder],
            ];
        };

        $profiles = [
            'general' => [
                'values' => $generic,
                'locked' => [],
                'placeholders' => ['openidconnect_provider_url' => 'https://id.example.com'],
            ],
            'auth0' => $make([], [], 'https://{tenant}.{region}.auth0.com/'),
            'authelia' => $make([], [], 'https://auth.example.com'),
            'authentik' => $make([], [], 'https://auth.example.com/application/o/opnsense/'),
            'cognito' => $make(
                ['openidconnect_username_claim' => 'cognito:username'],
                [],
                'https://cognito-idp.{region}.amazonaws.com/{user-pool-id}'
            ),
            'duo' => $make(
                ['openidconnect_username_claim' => 'email', 'openidconnect_claims_source' => 'userinfo'],
                [],
                'https://{host}.duosecurity.com/oidc/{integration-id}'
            ),
            'dex' => $make([], [], 'https://dex.example.com'),
            'fusionauth' => $make([], [], 'https://auth.example.com'),
            'gitlab' => $make(
                ['openidconnect_provider_url' => 'https://gitlab.com'],
                [],
                'https://gitlab.example.com'
            ),
            'google' => $make(
                [
                    'openidconnect_provider_url' => 'https://accounts.google.com',
                    'openidconnect_username_claim' => 'email',
                    'openidconnect_claims_source' => 'id_token',
                ],
                ['openidconnect_provider_url']
            ),
            'ibm_verify' => $make([], [], 'https://{tenant}.verify.ibm.com/oidc/endpoint/default'),
            'jumpcloud' => $make([], [], 'https://oauth.id.{region}jumpcloud.com/'),
            'keycloak' => $make([], [], 'https://id.example.com/realms/opnsense'),
            'entra' => $make(
                ['openidconnect_claims_source' => 'id_token'],
                [],
                'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'
            ),
            'okta' => $make([], [], 'https://{yourOktaDomain}/oauth2/default'),
            'onelogin' => $make([], [], 'https://{subdomain}.onelogin.com/oidc/2'),
            'oracle_idcs' => $make([], [], 'https://{identity-domain}.identity.oraclecloud.com'),
            'ping' => $make([], [], 'https://auth.example.com/as'),
            'pocketid' => $make([], [], 'https://id.example.com'),
            'apple' => $make(
                [
                    'openidconnect_provider_url' => 'https://appleid.apple.com',
                    'openidconnect_token_auth' => 'client_secret_post',
                    'openidconnect_username_claim' => 'email',
                    'openidconnect_claims_source' => 'id_token',
                    'openidconnect_response_mode' => 'form_post',
                    'openidconnect_scopes' => 'openid,email,name',
                ],
                [
                    'openidconnect_provider_url',
                    'openidconnect_token_auth',
                    'openidconnect_claims_source',
                    'openidconnect_response_mode',
                ]
            ),
            'wso2' => $make([], [], 'https://id.example.com/oauth2/token'),
            'zitadel' => $make([], [], 'https://id.example.com'),
            'linkedin' => $make(
                [
                    'openidconnect_provider_url' => 'https://www.linkedin.com/oauth',
                    'openidconnect_token_auth' => 'client_secret_post',
                    'openidconnect_username_claim' => 'email',
                    'openidconnect_claims_source' => 'id_token',
                ],
                ['openidconnect_provider_url', 'openidconnect_token_auth']
            ),
            'slack' => $make(
                [
                    'openidconnect_provider_url' => 'https://slack.com',
                    'openidconnect_username_claim' => 'email',
                    'openidconnect_claims_source' => 'id_token',
                ],
                ['openidconnect_provider_url']
            ),
            'yahoo' => $make(
                [
                    'openidconnect_provider_url' => 'https://api.login.yahoo.com',
                    'openidconnect_username_claim' => 'email',
                    'openidconnect_claims_source' => 'userinfo',
                ],
                ['openidconnect_provider_url']
            ),
            'orcid' => $make(
                [
                    'openidconnect_provider_url' => 'https://orcid.org',
                    'openidconnect_token_auth' => 'client_secret_post',
                    'openidconnect_username_claim' => 'sub',
                    'openidconnect_claims_source' => 'id_token',
                    'openidconnect_scopes' => 'openid',
                ],
                ['openidconnect_provider_url', 'openidconnect_token_auth', 'openidconnect_scopes']
            ),
        ];
        foreach ($profiles as $profile => &$preset) {
            $preset['values']['openidconnect_icon_url'] = static::providerIconUrl($profile);
            if (isset(self::FIXED_PROVIDER_BUTTON_LABELS[$profile])) {
                $preset['values']['openidconnect_button_text_mode'] = 'label_only';
                $preset['values']['openidconnect_button_provider_label'] =
                    self::FIXED_PROVIDER_BUTTON_LABELS[$profile];
                $preset['values']['openidconnect_button_custom_text'] = '';
                $preset['locked'] = array_values(array_unique(array_merge($preset['locked'], [
                    'openidconnect_button_text_mode',
                    'openidconnect_button_provider_label',
                ])));
            }
        }
        unset($preset);
        return $profiles;
    }

    /**
     * Safe starting points for the authentication requirement form and accessor.
     * Provider-specific values override the standards-oriented generic values.
     *
     * @return array<string,array<string,array{request:string,acr:string,amr:string}>>
     */
    public static function authenticationRequirementPresets(): array
    {
        return [
            'general' => [
                AuthenticationRequirement::MULTI_FACTOR => [
                    'request' => AuthenticationRequirement::ESSENTIAL_CLAIM,
                    'acr' => 'https://refeds.org/profile/mfa',
                    'amr' => 'mfa,pwd,pin,kba,otp,hwk,sc,sms,swk,tel,pop,face,fpt,iris,retina,vbm',
                ],
                AuthenticationRequirement::PHISHING_RESISTANT => [
                    'request' => AuthenticationRequirement::ESSENTIAL_CLAIM,
                    'acr' => 'phr,phrh',
                    'amr' => 'pop,hwk,swk',
                ],
            ],
            'okta' => [
                AuthenticationRequirement::MULTI_FACTOR => [
                    'request' => AuthenticationRequirement::ACR_VALUES,
                    'acr' => 'urn:okta:loa:2fa:any',
                    'amr' => 'mfa',
                ],
                AuthenticationRequirement::PHISHING_RESISTANT => [
                    'request' => AuthenticationRequirement::ACR_VALUES,
                    'acr' => 'phr,phrh',
                    'amr' => 'pop,hwk,swk',
                ],
            ],
            'entra' => [
                AuthenticationRequirement::MULTI_FACTOR => [
                    'request' => AuthenticationRequirement::ENTRA_CONTEXT,
                    'acr' => '',
                    'amr' => 'mfa',
                ],
                AuthenticationRequirement::PHISHING_RESISTANT => [
                    'request' => AuthenticationRequirement::ENTRA_CONTEXT,
                    'acr' => '',
                    'amr' => 'fido,hwk,x509',
                ],
            ],
        ];
    }

    /** The local public address used by provider profile presets. */
    public static function providerIconUrl(string $profile): string
    {
        return in_array($profile, self::PROVIDER_PROFILES, true)
            ? '/api/openidconnect/auth/builtinicon/' . rawurlencode($profile)
            : '';
    }

    /** @return array<string,string> profile to conventional public login label */
    public static function fixedProviderButtonLabels(): array
    {
        return self::FIXED_PROVIDER_BUTTON_LABELS;
    }

    /** Resolve a profile name to one package-owned SVG without accepting a filesystem path. */
    public static function providerIconPath(string $profile): ?string
    {
        if (!in_array($profile, self::PROVIDER_PROFILES, true)) {
            return null;
        }
        $path = __DIR__ . '/../OpenIDConnect/assets/provider-icons/' . $profile . '.svg';
        return is_file($path) ? $path : null;
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
            'applicationCodes' => array_map(static fn($entry) => [
                'position' => $entry['position'],
                'code' => $entry['code'],
                'name' => $entry['name'],
            ], static::configuredApplicationCodes()),
            'applicationCodeConflictLabel' => gettext('Already used by authentication server'),
            'savedApplicationCode' => $this->applicationCode(),
            'savedSectorOrigin' => $this->sectorOrigin(),
            'savedServerEnabled' => !array_key_exists('openidconnect_enabled', $this->settings)
                || $this->flag('openidconnect_enabled'),
            'sectorOffLabel' => gettext('Off'),
            'profilePresets' => static::providerProfilePresets(),
            'authenticationRequirementPresets' => static::authenticationRequirementPresets(),
            'fixedButtonProfiles' => array_keys(static::fixedProviderButtonLabels()),
            'configuredFields' => array_values(array_filter(
                array_keys($this->settings),
                static fn($name) => str_starts_with((string)$name, 'openidconnect_')
            )),
            'profileAppliedLabel' => gettext('Provider defaults applied'),
            'profileAppliedHelp' => gettext(
                'Recommended values are filled in but remain editable. Values the selected provider fixes are ' .
                'locked here and enforced during sign-in. Client ID, Client Secret and a tenant-specific issuer ' .
                'still have to come from the provider.'
            ),
            'profileGenericHelp' => gettext(
                'Generic OpenID Connect makes no provider-specific assumptions. Existing values remain editable.'
            ),
            'profileFixedLabel' => gettext('Fixed by the selected provider profile'),
            'profileRecommendedLabel' => gettext('Recommended by the selected provider profile; editable'),
            'profileRequiredLabel' => gettext('Enter the value issued by this provider'),
            'profileRestoreLabel' => gettext('Restore profile defaults'),
            'testLabel' => gettext('Test discovery'),
            'testingLabel' => gettext('Testing...'),
            'discoveryAccepted' => gettext('Discovery document accepted'),
            'discoveryRejected' => gettext('Discovery was not accepted.'),
            'checkLabel' => gettext('Check'),
            'resultLabel' => gettext('Result'),
            'statusLabel' => gettext('Status'),
            'statusPassed' => gettext('Passed'),
            'statusWarning' => gettext('Warning'),
            'statusInformation' => gettext('Information'),
            'statusFailed' => gettext('Failed'),
            'testHelp' => gettext(
                'Live server-side preflight of Discovery, JWKS and, when configured, authenticated PAR. ' .
                'The browser does not need the Discovery URL; Test sign-in checks its authorization path. ' .
                'Saving remains independent of this test.'
            ),
            'healthLabel' => gettext('Connection health'),
            'healthLoading' => gettext('Loading connection health...'),
            'healthUnavailable' => gettext('Connection health unavailable.'),
            'signInTestLabel' => gettext('Test sign-in'),
            'signInTestHelp' => gettext(
                'Runs the real browser flow and validates PKCE, the code exchange, ID Token and configured ' .
                'claims source. It does not change the current WebGUI session, local accounts, subject bindings ' .
                'or groups. The identity provider may retain its own SSO session. The generic System > Access > ' .
                'Tester supports username/password connectors only and cannot test OpenID Connect.'
            ),
            'signInTestSaveHelp' => gettext(
                'Save this authentication server first. Saving remains independent of both tests.'
            ),
            'signInTestIncompleteHelp' => gettext(
                'Complete and save `Exact issuer URL`, `Client ID` and `Client Secret` before testing sign-in.'
            ),
            'signInTestTransportHelp' => gettext(
                'OpenID Connect sign-in is blocked until the WebGUI uses HTTPS or the saved trusted ' .
                'reverse-proxy TLS-offloading exception is complete.'
            ),
            'approvalLabel' => gettext('Manage identities'),
            'approvalHelp' => gettext(
                'Review durable issuer/subject bindings, add a carefully verified identity manually, and ' .
                'process pending administrator approvals in one place.'
            ),
            'approvalSaveHelp' => gettext('Save this authentication server before managing its identities.'),
            'approvalEmpty' => gettext('There are no pending identities for this provider.'),
            'bindingHeading' => gettext('Bound identities'),
            'bindingEmpty' => gettext('No identity is currently bound to a local account.'),
            'bindingAdd' => gettext('Add identity binding'),
            'bindingEdit' => gettext('Edit'),
            'bindingDelete' => gettext('Remove'),
            'bindingDeleteTitle' => gettext('Remove identity binding'),
            'bindingDeleteQuestion' => gettext(
                'Remove this binding? The provider identity cannot sign in again until it is rebound or admitted anew.'
            ),
            'bindingIssuer' => gettext('Exact issuer'),
            'bindingSubject' => gettext('Subject (sub)'),
            'bindingAccount' => gettext('Local account'),
            'bindingUnavailable' => gettext('Stored account is no longer available'),
            'bindingLegacy' => gettext('Legacy mapping; save an edit to normalize it'),
            'bindingSave' => gettext('Save binding'),
            'bindingCancel' => gettext('Cancel'),
            'bindingEditorNew' => gettext('Add an identity'),
            'bindingEditorEdit' => gettext('Edit identity binding'),
            'bindingValidation' => gettext(
                'The value is case-sensitive and must be the exact `sub` claim: 1 to 255 UTF-8 bytes, without ' .
                'control characters. Do not enter a username, e-mail address or display name.'
            ),
            'bindingManualWarning' => gettext(
                'Manual binding bypasses the proof supplied by a pending sign-in. Compare issuer and `sub` ' .
                'against a verified ID Token; using the approval workflow is safer.'
            ),
            'bindingReadOnly' => gettext(
                'This account may view authentication servers but has `user-config-readonly`; identity changes ' .
                'are disabled.'
            ),
            'bindingSaveFailed' => gettext('The identity binding could not be saved.'),
            'bindingLoadFailed' => gettext('The identity manager could not be loaded.'),
            'pendingHeading' => gettext('Pending administrator approvals'),
            'pendingPolicyOff' => gettext(
                'The current admission policy does not queue unknown identities for administrator approval.'
            ),
            'approvalIdentity' => gettext('Identity reported by the provider'),
            'approvalStableIdentity' => gettext('Stable OpenID Connect identity'),
            'approvalSeen' => gettext('First / last seen'),
            'approvalAccount' => gettext('Local account'),
            'approvalChooseAccount' => gettext('Choose a local account'),
            'approvalCreateAccount' => gettext('Create a new local account…'),
            'approvalNewAccount' => gettext('New local account'),
            'approvalUsername' => gettext('Username'),
            'approvalAccountCreationHelp' => gettext(
                'The account receives a scrambled password and no groups or privileges. Assign its local WebGUI ' .
                'access under System > Access > Users after saving the binding.'
            ),
            'approvalAccountCreateFailed' => gettext('Enter a new valid local username and try again.'),
            'approvalAccountCreatedBindingFailed' => gettext(
                'The local account was created, but the identity was not bound. Select the new account and retry.'
            ),
            'approvalApprove' => gettext('Approve and bind'),
            'approvalDeny' => gettext('Deny'),
            'approvalRefresh' => gettext('Refresh'),
            'approvalNoAccounts' => gettext('No eligible local account is available.'),
            'approvalRequestLabel' => gettext('Request'),
            'approvalAttemptsLabel' => gettext('Attempts'),
            'approvalLoadFailed' => gettext('The approval requests could not be loaded.'),
            'setupLabel' => gettext('Download provider setup'),
            'setupGuideLabel' => gettext('Open setup guide'),
            'setupGuideTitle' => gettext('Provider setup guide'),
            'setupGeneratingLabel' => gettext('Generating setup file...'),
            'setupHelp' => gettext(
                'Available for authentik and Keycloak. Download the setup file or open its step-by-step guide ' .
                'again without downloading. Both use the unsaved values currently shown, contain no secret, ' .
                'and do not contact or change the identity provider.'
            ),
            'setupChannelLabel' => gettext('Logout channel in setup file'),
            'setupBackchannelLabel' => gettext('Back-channel (recommended when the provider trusts and can reach the WebGUI)'),
            'setupFrontchannelLabel' => gettext('Front-channel (browser based)'),
            'setupDoneLabel' => gettext('Provider setup downloaded'),
            'setupDownloadStartedLabel' => gettext('The provider setup download has started.'),
            'setupDownloadHeading' => gettext('Setup file ready'),
            'setupFileLabel' => gettext('Downloaded file'),
            'setupStepLabel' => gettext('Step'),
            'setupOfLabel' => gettext('of'),
            'setupPreviousLabel' => gettext('Previous'),
            'setupNextLabel' => gettext('Next'),
            'setupCompleteLabel' => gettext('Done'),
            'setupFinishHeading' => gettext('Finish the connection in OPNsense'),
            'setupFinishInstruction' => gettext(
                'Enter the `Exact issuer URL`, `Client ID` and `Client Secret` in this disabled authentication ' .
                'server. Save it, run `Test discovery` and `Test sign-in`, and only then enable `Offer on the ' .
                'login page`.'
            ),
            'setupReviewWarning' => gettext(
                'Importing changes the identity provider. Review the file, its WebGUI addresses and the selected ' .
                'realm or tenant before applying it.'
            ),
            'setupPairwiseSaveHelp' => gettext(
                'Save this authentication server as a disabled draft before generating pairwise-subject setup. ' .
                'The provider must be able to read the saved sector endpoint before it can create the client.'
            ),
            'setupGuides' => [
                'authentik' => [
                    'name' => 'authentik',
                    'artifact' => gettext('Blueprint YAML'),
                    'heading' => gettext('Import the Blueprint into authentik'),
                    'steps' => [
                        [
                            'place' => gettext('Admin interface'),
                            'action' => gettext('Open the authentik administration interface.'),
                        ],
                        [
                            'place' => gettext('Customization > Blueprints > Import'),
                            'action' => gettext('Open the `Blueprint` import page.'),
                        ],
                        [
                            'place' => gettext('File upload'),
                            'action' => gettext(
                                'Choose the downloaded `YAML` file and review the displayed `Blueprint`.'
                            ),
                        ],
                        [
                            'place' => gettext('Import'),
                            'action' => gettext(
                                'Start the import. A green result means the file was validated and applied once. ' .
                                'This import method intentionally creates no visible, monitored `Blueprint` instance.'
                            ),
                        ],
                    ],
                    'providerFinish' => gettext(
                        'Verify the result under `Applications > Applications` and `Applications > Providers`; ' .
                        'select the generated `OAuth2/OpenID` provider. ' .
                        'Restrict the generated application with authentik policy bindings before allowing ' .
                        'firewall administrators to use it.'
                    ),
                    'warning' => gettext(
                        'The `Blueprint` deliberately creates no authentik policy binding. Without an appropriate ' .
                        'user or group restriction, everyone allowed to use the authentik application could ' .
                        'attempt to sign in.'
                    ),
                ],
                'keycloak' => [
                    'name' => 'Keycloak',
                    'artifact' => gettext('Partial realm import JSON'),
                    'heading' => gettext('Import the client into Keycloak'),
                    'steps' => [
                        [
                            'place' => gettext('Realm selector'),
                            'action' => gettext('Select the realm that will authenticate OPNsense administrators.'),
                        ],
                        [
                            'place' => gettext('Realm settings > Action > Partial import'),
                            'action' => gettext('Open `Partial import` inside that realm.'),
                        ],
                        [
                            'place' => gettext('File'),
                            'action' => gettext(
                                'Choose the downloaded `JSON` file and inspect the client to import.'
                            ),
                        ],
                        [
                            'place' => gettext('If a resource exists: Skip'),
                            'action' => gettext(
                                'Use `Skip` for a repeated import; do not overwrite an existing client unintentionally.'
                            ),
                        ],
                    ],
                    'providerFinish' => gettext(
                        'The generated secret is under `Clients > imported client > Credentials`. The exact realm ' .
                        'issuer is shown by `OpenID Endpoint Configuration`.'
                    ),
                    'warning' => gettext(
                        '`Partial import` always applies to the currently selected realm. Verify the realm name ' .
                        'before importing the file.'
                    ),
                ],
            ],
            'setupProfiles' => ['authentik', 'keycloak'],
            'redirectHint' => 'https://firewall.example.net',
            'maximumAuthenticationAgeDefault' => (string)self::DEFAULT_MAX_AUTHENTICATION_AGE,
            'originPolicy' => $this->originPolicy(),
            'webGuiProtocol' => $this->nativeWebGuiUsesHttps() ? 'https' : 'http',
            'webGuiTransportReady' => $this->isWebGuiTransportReady(),
            'tlsOffloadingBlocked' => gettext(
                'OpenID Connect is blocked while the OPNsense WebGUI uses HTTP. Prefer native HTTPS. If one ' .
                'trusted reverse proxy is the only route to this backend, enable the advanced TLS-offloading ' .
                'exception below.'
            ),
            'tlsOffloadingIncomplete' => gettext(
                'TLS offloading is not complete. Select `Custom origins for this provider` and enter at least ' .
                'one exact public HTTPS origin.'
            ),
            'tlsOffloadingActive' => gettext(
                'Advanced TLS-offloading exception active. The trusted proxy must be the only backend route, ' .
                'preserve the public `Host` header, and add `Secure` to OPNsense session cookies. ' .
                'Source-network ACLs also need trusted client-address propagation. `X-Forwarded-Proto` is ' .
                'intentionally ignored.'
            ),
            'microsoftAudience' => $this->microsoftAudience(),
            'opnsenseOrigins' => $this->opnsenseWebGuiOrigins(),
            'endpointLabel' => gettext('Provider endpoint reference'),
            'noEndpointOrigin' => gettext(
                'No accepted HTTPS WebGUI origin is available. Check the WebGUI address policy and origins.'
            ),
            'authorizationEndpointLabel' => gettext('Authorization redirect URI'),
            'postLogoutEndpointLabel' => gettext('Post-logout redirect URI (only when return after logout is enabled)'),
            'backchannelEndpointLabel' => gettext('Back-channel logout URI (server-to-server choice)'),
            'frontchannelEndpointLabel' => gettext('Front-channel logout URI (browser-based alternative)'),
            'sectorEndpointLabel' => gettext('Pairwise sector identifier URI'),
            'ssfEndpointLabel' => gettext('Shared Signals push URI'),
            'ssfGenerateSecretLabel' => gettext('Generate secret'),
            'ssfRotateSecretLabel' => gettext('Prepare rotation'),
            'ssfRotationPrepared' => gettext(
                'Save both credentials before updating the transmitter stream. After successful delivery with ' .
                'the new credential, clear the previous one.'
            ),
            'ssfTestLabel' => gettext('Test Shared Signals'),
            'ssfDiscoveryAccepted' => gettext('Shared Signals discovery accepted.'),
            'ssfAuthorizationLabel' => gettext('Authorization header'),
            'ssfCreateStreamLabel' => gettext('Create stream'),
            'ssfReadStreamLabel' => gettext('Read stream'),
            'ssfUpdateStreamLabel' => gettext('Update stream'),
            'ssfReadStatusLabel' => gettext('Read status'),
            'ssfEnableStreamLabel' => gettext('Enable'),
            'ssfPauseStreamLabel' => gettext('Pause'),
            'ssfDeleteStreamLabel' => gettext('Delete stream'),
            'ssfDeleteStreamConfirm' => gettext('Delete this stream at the transmitter? This cannot be undone.'),
            'ssfStreamStatusLabel' => gettext('Stream status'),
            'ssfStreamDeleted' => gettext('Stream deleted; save this server to clear its local values.'),
            'ssfStreamApplied' => gettext('Stream response accepted; save this server to retain its values.'),
            'endpointHelp' => gettext(
                'Do not register logout addresses as authorization redirect URIs. Provider terminology differs; ' .
                'the provider guide explains which field receives which address.'
            ),
            'sections' => [
                'openidconnect_enabled' => gettext('Provider and client'),
                'openidconnect_required_authentication' => gettext('Authentication requirement'),
                'openidconnect_username_claim' => gettext('Claims and local identity'),
                'openidconnect_group_claim' => gettext('Local authorization'),
                'openidconnect_logout_menu' => gettext('Logout'),
                'openidconnect_ssf_enabled' => gettext('Shared Signals'),
                'openidconnect_button_style' => gettext('Login button'),
            ],
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
    public function localAccountFor(object $claims, string $issuer = '', string $subject = ''): ?string
    {
        $this->bindingConflict = false;
        $this->pendingApprovalId = '';
        $subject = $subject !== '' ? $subject : static::claimString($claims, 'sub', 255);
        if ($issuer === '') {
            $issuer = $this->issuerUrl();
        }
        if ($subject === '' || $issuer === '' || static::hasControlCharacters($subject)) {
            syslog(LOG_ERR, 'OIDC: refusing a login without an exact issuer and usable subject');
            return null;
        }

        $user = $this->boundUser($issuer, $subject);
        if ($this->bindingConflict) {
            syslog(LOG_ERR, 'OIDC: refusing a subject that has conflicting local account bindings');
            return null;
        }
        $created = false;
        if ($user !== null) {
            if (!$this->accountMayBeUsed($user)) {
                return null;
            }
            $account = (string)$user->name;
            if (!$this->persistBinding($issuer, $subject, $user)) {
                syslog(LOG_ERR, 'OIDC: refusing a login because its stable subject binding could not be normalised');
                return null;
            }
            $this->syncGroups($account, $claims, false);
            return $account;
        }

        $claimed = static::claimString($claims, $this->usernameClaim(), 255);
        $this->trace(sprintf(
            'no subject binding yet; claims carry %s; bootstrap username claim %s',
            implode(', ', array_keys(get_object_vars($claims))),
            $claimed === '' ? 'empty' : 'set'
        ));

        $user = null;
        $bootstrap = $this->bootstrapMode();
        if ($bootstrap === 'approval') {
            try {
                $this->pendingApprovalId = PendingIdentityRegistry::record(
                    $this->applicationCode(),
                    $issuer,
                    $subject,
                    [
                        'username' => static::claimString($claims, $this->usernameClaim(), 255),
                        'email' => static::claimString($claims, 'email', 255),
                        'name' => static::claimString($claims, 'name', 255),
                        'email_verified' => $claims->email_verified ?? null,
                    ]
                );
                syslog(LOG_NOTICE, sprintf(
                    'OIDC: queued an unknown identity for administrator approval (%s)',
                    $this->pendingApprovalId
                ));
            } catch (\Throwable $e) {
                syslog(LOG_ERR, sprintf('OIDC: could not queue an unknown identity (%s)', $e->getMessage()));
            }
            return null;
        }
        if (in_array($bootstrap, ['username', 'either'], true) && $claimed !== '') {
            /* Core is case-sensitive by default; keep that exact contract here. */
            $user = $this->getUser($claimed);
        }
        if ($user === null && in_array($bootstrap, ['verified_email', 'either'], true)) {
            $email = $this->matchableEmail($claims);
            $user = $this->userByEmail($email);
        }

        if ($user === null && in_array($bootstrap, ['username', 'verified_email', 'either'], true)
            && $this->createsUsers()) {
            $email = $this->matchableEmail($claims);
            $user = $this->createAccount($claimed !== '' ? $claimed : $email);
            if ($user !== null) {
                $created = true;
            }
        }
        if ($user === null) {
            syslog(LOG_NOTICE, 'OIDC: refusing an unbound subject; no permitted bootstrap found a local account');
            return null;
        }

        if (!$this->accountMayBeUsed($user)) {
            return null;
        }

        $account = (string)$user->name;
        if (!$this->persistBinding($issuer, $subject, $user)) {
            syslog(LOG_ERR, 'OIDC: refusing a login because its stable subject binding could not be saved');
            return null;
        }

        $this->syncGroups($account, $claims, $created);

        return $account;
    }

    public function pendingApprovalId(): string
    {
        return $this->pendingApprovalId;
    }

    /** @return array<int,array<string,mixed>> */
    public function pendingApprovals(): array
    {
        return PendingIdentityRegistry::listing($this->applicationCode());
    }

    /** @return array<int,array{uid:string,name:string}> */
    public function approvableAccounts(): array
    {
        $accounts = [];
        foreach (Config::getInstance()->object()->system->user ?? [] as $user) {
            if (!$this->accountMayBeUsed($user)) {
                continue;
            }
            $uid = (string)($user->uid ?? '');
            $name = (string)($user->name ?? '');
            if ($uid !== '' && ctype_digit($uid) && $name !== '') {
                $accounts[] = ['uid' => $uid, 'name' => $name];
            }
        }
        usort($accounts, static fn(array $a, array $b): int => strcasecmp($a['name'], $b['name']));
        return $accounts;
    }

    /** @return array{uid:string,name:string}|null a newly created local account for an administrator-managed binding */
    public function createManagedAccount(string $username): ?array
    {
        $username = trim($username);
        if ($username === '' || strlen($username) > 320 || static::hasControlCharacters($username)
            || $this->getUser($username) !== null) {
            return null;
        }

        $user = $this->provisionAccount($username, false);
        $uid = $user === null ? '' : (string)($user->uid ?? '');
        $name = $user === null ? '' : (string)($user->name ?? '');
        if ($uid === '' || !ctype_digit($uid) || !hash_equals($username, $name) || !$this->accountMayBeUsed($user)) {
            return null;
        }

        syslog(LOG_NOTICE, sprintf('OIDC: administrator created local account %s for an identity binding', $name));
        return ['uid' => $uid, 'name' => $name];
    }

    /** @return array<int,array<string,mixed>> durable issuer/subject mappings for the manager */
    public function subjectBindingRecords(): array
    {
        $records = [];
        foreach ($this->bindingLines() as $line) {
            $parts = static::parseBindingLine($line);
            if ($parts === null) {
                continue;
            }
            [$issuer, $subject, $canonical] = $this->bindingIdentity($parts[0]);
            $user = str_starts_with($parts[1], 'uid:')
                ? $this->userByUid(substr($parts[1], 4)) : $this->getUser($parts[1]);
            $records[] = [
                'id' => static::bindingRecordId($line),
                'issuer' => $issuer,
                'subject' => $subject,
                'uid' => $user === null ? '' : (string)($user->uid ?? ''),
                'account' => $user === null ? $parts[1] : (string)($user->name ?? $parts[1]),
                'account_available' => $user !== null,
                'canonical' => $canonical,
            ];
        }
        usort($records, static function (array $left, array $right): int {
            return strcasecmp(
                (string)$left['account'] . "\0" . (string)$left['subject'],
                (string)$right['account'] . "\0" . (string)$right['subject']
            );
        });
        return $records;
    }

    /** Guidance only; subject syntax remains the standards-defined opaque string. */
    public function subjectGuidance(): array
    {
        $profile = $this->providerProfile();
        $guidance = match ($profile) {
            'entra' => gettext(
                'Use the exact `sub` claim from an ID Token issued to this OPNsense client. It is a pairwise, ' .
                'opaque identifier and is not the Microsoft Entra Object ID (`oid`). The safest way to obtain ' .
                'it is an attempted sign-in followed by administrator approval.'
            ),
            'apple' => gettext(
                'Use Apple\'s exact opaque `sub` claim, not an e-mail or Private Relay address. An attempted ' .
                'sign-in captures it safely even when Apple sends name and e-mail only once.'
            ),
            'google' => gettext(
                'Use Google\'s exact case-sensitive `sub` claim. It is commonly numeric-looking, but its ' .
                'format must not be guessed or converted from an e-mail address.'
            ),
            'orcid' => gettext(
                'Use the exact authenticated `sub` returned by ORCID. Prefer an attempted sign-in and approval ' .
                'over manually transcribing an ORCID iD.'
            ),
            'authentik', 'keycloak' => gettext(
                'Use the exact `sub` from a verified ID Token. It often looks like a UUID with the default ' .
                'provider settings, but federation and subject-mode mappings can change its format.'
            ),
            default => gettext(
                'Use the exact case-sensitive `sub` claim from a verified ID Token. OpenID Connect treats it ' .
                'as an opaque value scoped by the exact issuer; do not derive it from username or e-mail.'
            ),
        };
        $issuerDefault = $this->discoveryIssuerTemplate() === null ? $this->issuerUrl() : '';
        if ($profile === 'entra' && $this->microsoftAudience() === 'consumers') {
            $issuerDefault = (string)$this->discoveryIssuerTemplate();
        }
        return [
            'text' => $guidance,
            'placeholder' => $profile === 'orcid' ? '0000-0002-1825-0097' : gettext('Paste the exact sub claim'),
            'issuer_default' => $issuerDefault,
            'issuer_editable' => $this->discoveryIssuerTemplate() !== null,
        ];
    }

    public static function normalizeSubjectIdentifier($value): ?string
    {
        $subject = trim((string)$value);
        return $subject !== '' && strlen($subject) <= 255 && !static::hasControlCharacters($subject)
            ? $subject : null;
    }

    public function normalizeBindingIssuer($value): ?string
    {
        $issuer = ProviderMetadata::normalizeIssuerInput(
            $value,
            $this->providerRequiresTrailingIssuerSlash()
        );
        if (!static::isIssuerUrl($issuer)) {
            return null;
        }
        if ($this->discoveryIssuerTemplate() !== null) {
            return $this->acceptsMicrosoftIssuerValue($issuer) ? $issuer : null;
        }
        return hash_equals($this->issuerUrl(), $issuer) ? $issuer : null;
    }

    public function createSubjectBinding(string $issuer, string $subject, string $uid): bool
    {
        return $this->saveManagedBinding('', $issuer, $subject, $uid);
    }

    public function updateSubjectBinding(
        string $bindingId,
        string $issuer,
        string $subject,
        string $uid
    ): bool {
        return $this->saveManagedBinding($bindingId, $issuer, $subject, $uid);
    }

    public function deleteSubjectBinding(string $bindingId): bool
    {
        if (!preg_match('/^[a-f0-9]{32}$/D', $bindingId)) {
            return false;
        }
        return $this->replaceBindingLines(function (array $lines) use ($bindingId): ?array {
            $matches = array_keys(array_filter($lines, static fn(string $line): bool =>
                hash_equals($bindingId, static::bindingRecordId($line))));
            if (count($matches) !== 1) {
                return null;
            }
            unset($lines[$matches[0]]);
            return array_values($lines);
        }, sprintf('removed subject binding %s', $bindingId));
    }

    public function approvePendingIdentity(string $requestId, string $uid): bool
    {
        if (!preg_match('/^[a-f0-9]{20}$/D', $requestId) || !ctype_digit($uid)) {
            return false;
        }
        $record = PendingIdentityRegistry::find($requestId, $this->applicationCode());
        $user = $record === null ? null : $this->userByUid($uid);
        if ($record === null || $user === null || !$this->accountMayBeUsed($user)
            || !is_string($record['issuer'] ?? null) || !is_string($record['subject'] ?? null)) {
            return false;
        }
        if (!$this->persistBinding($record['issuer'], $record['subject'], $user)) {
            return false;
        }
        PendingIdentityRegistry::remove($requestId, $this->applicationCode());
        syslog(LOG_NOTICE, sprintf('OIDC: administrator approved pending identity %s for local uid %s', $requestId, $uid));
        return true;
    }

    public function denyPendingIdentity(string $requestId): bool
    {
        if (!preg_match('/^[a-f0-9]{20}$/D', $requestId)) {
            return false;
        }
        $removed = PendingIdentityRegistry::remove($requestId, $this->applicationCode());
        if ($removed) {
            syslog(LOG_NOTICE, sprintf('OIDC: administrator denied pending identity %s', $requestId));
        }
        return $removed;
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

        $email = static::claimString($claims, 'email', 320);
        if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return '';
        }
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
        if ($claim !== '' && $scope === [] && !$this->allowsAllGroups()) {
            $this->trace('group claim ignored because no assignable groups are allowed');
            return;
        }

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
            if (count($found) >= 256) {
                break;
            }
            if (is_string($name)) {
                $name = trim($name);
                if ($name !== '' && strlen($name) <= 255 && !static::hasControlCharacters($name)) {
                    $found[$name] = $name;
                }
            }
        }

        return array_values($found);
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

        $matches = [];
        foreach ($config->system->user as $user) {
            if (isset($user->email) && strcasecmp(trim((string)$user->email), $email) === 0) {
                $matches[] = $user;
            }
        }
        if (count($matches) > 1) {
            syslog(LOG_ERR, 'OIDC: refusing an e-mail bootstrap because several local accounts use that address');
            return null;
        }
        return $matches[0] ?? null;
    }

    private function boundUser(string $issuer, string $subject): ?object
    {
        /*
         * A subject is only locally unique inside its issuer.  Encoding the exact pair
         * also means that changing an auth server to a different issuer can never make
         * an old subject mapping silently point at the same firewall account.
         */
        $encoded = static::bindingKey($issuer, $subject);
        $legacyEncoded = rtrim(strtr(base64_encode($subject), '+/', '-_'), '=');
        $matches = [];
        foreach (preg_split('/\r?\n/', $this->rawText('openidconnect_subject_bindings')) ?: [] as $line) {
            $parts = static::parseBindingLine($line);
            if ($parts === null) {
                continue;
            }
            $keyMatches = hash_equals($encoded, $parts[0]);
            /*
             * Human-authored mappings may use a raw subject.  The older subject-only
             * encoded spelling is accepted solely as a migration aid, and is scoped to
             * this auth-server entry by the configured issuer.
             */
            if (!$keyMatches && !hash_equals($subject, $parts[0]) && !hash_equals($legacyEncoded, $parts[0])) {
                continue;
            }
            $identity = $parts[1];
            if (str_starts_with($identity, 'uid:')) {
                $user = $this->userByUid(substr($identity, 4));
            } else {
                $user = $this->getUser($identity);
            }
            if ($user !== null) {
                $matches[(string)($user->uid ?? '')] = $user;
            }
        }
        if (count($matches) > 1) {
            $this->bindingConflict = true;
            return null;
        }
        return $matches === [] ? null : reset($matches);
    }

    private function userByUid(string $uid): ?object
    {
        if ($uid === '') {
            return null;
        }
        $config = Config::getInstance()->object();
        foreach ($config->system->user ?? [] as $user) {
            if (isset($user->uid) && hash_equals($uid, (string)$user->uid)) {
                return $user;
            }
        }
        return null;
    }

    /** @return string[] */
    private function bindingLines(): array
    {
        return array_values(array_filter(
            preg_split('/\r?\n/', $this->rawText('openidconnect_subject_bindings')) ?: [],
            static fn(string $line): bool => trim($line) !== ''
        ));
    }

    /** @return array{string,string,bool} issuer, subject and canonical-pair marker */
    private function bindingIdentity(string $key): array
    {
        $padded = strtr($key, '-_', '+/');
        $padding = strlen($padded) % 4;
        if ($padding !== 0) {
            $padded .= str_repeat('=', 4 - $padding);
        }
        $decoded = base64_decode($padded, true);
        if (is_string($decoded) && substr_count($decoded, "\0") === 1) {
            [$issuer, $subject] = explode("\0", $decoded, 2);
            if (static::isIssuerUrl($issuer) && static::normalizeSubjectIdentifier($subject) !== null) {
                return [$issuer, $subject, true];
            }
        }
        /* Human-authored and subject-only legacy keys are scoped to this server. Keep
         * their stored spelling visible; editing them rewrites a canonical pair. */
        return [$this->issuerUrl(), $key, false];
    }

    private static function bindingRecordId(string $line): string
    {
        return substr(hash('sha256', $line), 0, 32);
    }

    private function saveManagedBinding(
        string $bindingId,
        string $issuer,
        string $subject,
        string $uid
    ): bool {
        $issuer = $this->normalizeBindingIssuer($issuer) ?? '';
        $subject = static::normalizeSubjectIdentifier($subject) ?? '';
        $user = ctype_digit($uid) ? $this->userByUid($uid) : null;
        if ($issuer === '' || $subject === '' || $user === null || !$this->accountMayBeUsed($user)
            || ($bindingId !== '' && !preg_match('/^[a-f0-9]{32}$/D', $bindingId))) {
            return false;
        }
        $right = 'uid:' . $uid;
        $canonical = static::bindingKey($issuer, $subject) . '=' . $right;
        return $this->replaceBindingLines(function (array $lines) use (
            $bindingId,
            $issuer,
            $subject,
            $right,
            $canonical
        ): ?array {
            if ($bindingId !== '') {
                $matches = array_keys(array_filter($lines, static fn(string $line): bool =>
                    hash_equals($bindingId, static::bindingRecordId($line))));
                if (count($matches) !== 1) {
                    return null;
                }
                unset($lines[$matches[0]]);
                $lines = array_values($lines);
            }
            foreach ($lines as $line) {
                $parts = static::parseBindingLine($line);
                if ($parts === null) {
                    continue;
                }
                [$existingIssuer, $existingSubject] = $this->bindingIdentity($parts[0]);
                if (hash_equals($issuer, $existingIssuer) && hash_equals($subject, $existingSubject)) {
                    return hash_equals($right, $parts[1]) ? $lines : null;
                }
            }
            $lines[] = $canonical;
            return $lines;
        }, sprintf('%s subject binding for local uid %s', $bindingId === '' ? 'created' : 'updated', $uid));
    }

    /** Atomically mutate only this saved authentication server's binding field. */
    private function replaceBindingLines(callable $mutation, string $audit): bool
    {
        $config = Config::getInstance();
        try {
            $config->lock();
            $root = $config->object();
            foreach ($root->system->authserver ?? [] as $server) {
                if (!$this->bindingServerMatches($server)) {
                    continue;
                }
                $lines = array_values(array_filter(
                    preg_split('/\r?\n/', trim((string)($server->openidconnect_subject_bindings ?? ''))) ?: [],
                    static fn(string $line): bool => trim($line) !== ''
                ));
                $replacement = $mutation($lines);
                if (!is_array($replacement) || static::validateBindings(implode("\n", $replacement)) !== []) {
                    return false;
                }
                $stored = implode("\n", $replacement);
                if ($stored !== implode("\n", $lines)) {
                    $server->openidconnect_subject_bindings = $stored;
                    $config->save();
                }
                $this->settings['openidconnect_subject_bindings'] = $stored;
                syslog(LOG_NOTICE, 'OIDC: administrator ' . $audit);
                return true;
            }
            return false;
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf('OIDC: saving managed subject bindings failed (%s)', $e->getMessage()));
            return false;
        } finally {
            if (method_exists($config, 'unlock')) {
                $config->unlock();
            }
        }
    }

    private function bindingServerMatches(object $server): bool
    {
        if ((string)$server->type !== self::TYPE
            || (string)($server->openidconnect_app_code ?? '') !== $this->applicationCode()) {
            return false;
        }
        if (!empty($this->settings['refid'])) {
            return hash_equals((string)$this->settings['refid'], (string)($server->refid ?? ''));
        }
        return empty($this->settings['name'])
            || hash_equals((string)$this->settings['name'], (string)($server->name ?? ''));
    }

    private function persistBinding(string $issuer, string $subject, object $user): bool
    {
        $uid = (string)($user->uid ?? '');
        if ($uid === '' || !ctype_digit($uid)) {
            return false;
        }
        $encoded = static::bindingKey($issuer, $subject);
        $line = $encoded . '=uid:' . $uid;
        $config = Config::getInstance();
        try {
            $config->lock();
            $root = $config->object();
            foreach ($root->system->authserver ?? [] as $server) {
                if ((string)$server->type !== self::TYPE
                    || (string)($server->openidconnect_app_code ?? '') !== $this->applicationCode()) {
                    continue;
                }
                if (!empty($this->settings['refid'])
                    && !hash_equals((string)$this->settings['refid'], (string)($server->refid ?? ''))) {
                    continue;
                }
                if (empty($this->settings['refid']) && !empty($this->settings['name'])
                    && !hash_equals((string)$this->settings['name'], (string)($server->name ?? ''))) {
                    continue;
                }
                $existing = preg_split('/\r?\n/', trim((string)($server->openidconnect_subject_bindings ?? ''))) ?: [];
                $existing = array_values(array_filter($existing, fn(string $item): bool => trim($item) !== ''));
                foreach ($existing as $item) {
                    $parts = static::parseBindingLine($item);
                    if ($parts !== null && hash_equals($encoded, $parts[0])) {
                        return hash_equals('uid:' . $uid, $parts[1]);
                    }
                }
                $existing[] = $line;
                $server->openidconnect_subject_bindings = implode("\n", $existing);
                $config->save();
                $this->settings['openidconnect_subject_bindings'] = implode("\n", $existing);
                syslog(LOG_NOTICE, sprintf('OIDC: bound a provider subject to local uid %s', $uid));
                return true;
            }
            return false;
        } catch (\Throwable $e) {
            syslog(LOG_ERR, sprintf('OIDC: saving a subject binding failed (%s)', $e->getMessage()));
            return false;
        } finally {
            if (method_exists($config, 'unlock')) {
                $config->unlock();
            }
        }
    }

    private static function bindingKey(string $issuer, string $subject): string
    {
        return rtrim(strtr(base64_encode($issuer . "\0" . $subject), '+/', '-_'), '=');
    }

    /** @return array{string,string}|null */
    private static function parseBindingLine(string $line): ?array
    {
        $position = strrpos($line, '=');
        if ($position === false) {
            return null;
        }
        $left = trim(substr($line, 0, $position));
        $right = trim(substr($line, $position + 1));
        return $left === '' || $right === '' ? null : [$left, $right];
    }

    /**
     * @return object|null the new account, null when creation is off or failed
     */
    private function createAccount(string $username): ?object
    {
        if ($username === '' || !$this->createsUsers()) {
            return null;
        }

        return $this->provisionAccount($username, true);
    }

    /** Core's configd action owns local-account validation, UID allocation, password hashing and synchronization. */
    private function provisionAccount(string $username, bool $firstLogin): ?object
    {
        if ($username === '') {
            return null;
        }

        $output = (new Backend())->configdpRun('auth add user', [$username]);

        /*
         * The account is the authoritative result, not configd's presentation of it.
         * In particular, OPNsense 26.7's add_user.php can prefix its valid JSON with
         * PHP warnings after it has successfully saved the account.  Core's own LDAP
         * connector decodes that output directly and consequently misses the account.
         * Reload and verify the postcondition instead: this also makes a concurrent or
         * previously half-completed first login safe to retry.
         */
        Config::getInstance()->forceReload();
        $user = $this->getUser($username);
        if ($user === null) {
            $answer = json_decode($output, true);
            $status = is_array($answer) ? (string)($answer['status'] ?? 'unknown') : 'invalid response';
            syslog(LOG_ERR, sprintf('OIDC: could not create a local account for %s', $username));
            if ($firstLogin) {
                $this->trace(sprintf('configd account creation failed (%s)', $status));
            }
            return null;
        }

        if ($firstLogin) {
            syslog(LOG_NOTICE, sprintf('OIDC: created local account %s after a first login', $username));
            $this->trace(sprintf('account %s did not exist and was created', $username));
        }

        return $user;
    }

    /* ---------------------------------------------------------------- settings */

    private function text(string $key, string $default = ''): string
    {
        $value = trim((string)($this->settings[$key] ?? ''));

        return $value === '' ? $default : $value;
    }

    private function rawText(string $key): string
    {
        return trim((string)($this->settings[$key] ?? ''));
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
        $value = trim((string)$value);
        return str_starts_with($value, '/') && !str_starts_with($value, '//')
            && !static::hasControlCharacters($value) && !str_contains($value, ' ');
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

    public static function isIconDataUri($value): bool
    {
        $value = trim((string)$value);
        return $value !== '' && !static::hasControlCharacters($value)
            && (bool)preg_match(
                '#^data:image/(?:png|jpeg|gif|webp|svg\+xml|x-icon|vnd\.microsoft\.icon)(?:;charset=[A-Za-z0-9._-]+)?;base64,[A-Za-z0-9+/]*={0,2}$#Di',
                $value
            );
    }

    private function validateApplicationCode($value): array
    {
        $code = trim((string)$value);
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $code) || in_array($code, ['.', '..'], true)) {
            return [gettext(
                'Use 1 to 64 URL-safe letters, digits, dots, underscores, tildes or hyphens; a code cannot be . or ..'
            )];
        }
        $formId = null;
        $submittedId = $_POST['id'] ?? null;
        if ($submittedId === null && (string)($_GET['act'] ?? '') === 'edit') {
            /* OPNsense 26.7 keeps the edited array index in the form action URL, not in a hidden input. */
            $submittedId = $_GET['id'] ?? null;
        }
        if ($submittedId !== null && preg_match('/^(?:0|[1-9][0-9]*)$/D', (string)$submittedId)) {
            $formId = (int)$submittedId;
        }
        foreach (static::configuredApplicationCodes() as $entry) {
            /* system_authservers.php asks AuthenticationFactory for validators before
             * it gives the connector the server being edited. Depending on the core
             * version, its numeric row is in POST or the edit URL. Keep refid/name for
             * direct callers and use the row id for the real form. */
            $same = ($formId !== null && $entry['position'] === $formId)
                || (!empty($this->settings['refid'])
                    ? hash_equals((string)$this->settings['refid'], $entry['refid'])
                    : (!empty($this->settings['name'])
                        && hash_equals((string)$this->settings['name'], $entry['name'])));
            if ($same) {
                continue;
            }
            if (strcasecmp($code, $entry['code']) === 0) {
                return [sprintf(
                    gettext('The application code is already used by authentication server "%s".'),
                    $entry['name']
                )];
            }
        }
        return [];
    }

    private function validateButtonText($value, int $maximum, bool $allowEmpty): array
    {
        $value = trim((string)$value);
        if ($value === '') {
            return $allowEmpty ? [] : [gettext('Enter the complete custom login button text.')];
        }
        if (strlen($value) > $maximum) {
            return [sprintf(gettext('Login button text may contain at most %d bytes.'), $maximum)];
        }
        if (static::hasControlCharacters($value) || $value !== strip_tags($value)) {
            return [gettext('Login button text must be plain text without control characters or HTML.')];
        }
        return [];
    }

    private function validateRequiredAuthentication($value): array
    {
        $value = trim((string)$value);
        if (!in_array($value, array_merge(self::REQUIRED_AUTHENTICATION, ['']), true)) {
            return [gettext('Unknown required authentication policy.')];
        }
        if ($value !== '' && $this->submittedChoice(
            'openidconnect_provider_profile',
            self::PROVIDER_PROFILES,
            'general'
        ) === 'entra' && $this->submittedChoice(
            'openidconnect_microsoft_audience',
            self::MICROSOFT_AUDIENCES,
            'tenant'
        ) !== 'tenant') {
            return [gettext(
                'Microsoft authentication contexts require One specific Entra tenant because c1-c25 have tenant-local meaning.'
            )];
        }
        return [];
    }

    private function validateMicrosoftAuthenticationContext($value): array
    {
        $value = trim((string)$value);
        if ($value !== '' && !preg_match('/^c(?:[1-9]|1[0-9]|2[0-5])$/D', $value)) {
            return [gettext('Microsoft authentication context must be c1 through c25.')];
        }
        $required = $this->submittedChoice(
            'openidconnect_required_authentication',
            self::REQUIRED_AUTHENTICATION,
            ''
        );
        $profile = $this->submittedChoice('openidconnect_provider_profile', self::PROVIDER_PROFILES, 'general');
        if ($required !== '' && $profile === 'entra' && $value === '' && !$this->allowsIncompleteDraft()) {
            return [gettext('Select the Microsoft authentication context enforced by Conditional Access.')];
        }
        return [];
    }

    private static function validateRequirementList($value, int $maximum, int $maximumBytes, string $label): array
    {
        $values = static::splitList($value);
        if (count($values) > $maximum) {
            return [sprintf(gettext('Enter at most %d values for %s.'), $maximum, $label)];
        }
        foreach ($values as $entry) {
            if (strlen($entry) > $maximumBytes || preg_match('/[\x00-\x20\x7f]/', $entry)) {
                return [sprintf(gettext('Each %s must be a bounded value without spaces or control characters.'), $label)];
            }
        }
        return [];
    }

    private function submittedChoice(string $field, array $allowed, string $default): string
    {
        $value = isset($_POST['type']) && (string)$_POST['type'] === self::TYPE
            ? trim((string)($_POST[$field] ?? ''))
            : $this->text($field);
        return in_array($value, $allowed, true) ? $value : $default;
    }

    private function submittedButtonTextMode(): string
    {
        $value = isset($_POST['type']) && (string)$_POST['type'] === self::TYPE
            ? (string)($_POST['openidconnect_button_text_mode'] ?? 'localized')
            : $this->text('openidconnect_button_text_mode', 'localized');
        return in_array($value, self::BUTTON_TEXT_MODES, true) ? $value : 'localized';
    }

    private function submittedSsfEnabled(): bool
    {
        $value = isset($_POST['type']) && (string)$_POST['type'] === self::TYPE
            ? (string)($_POST['openidconnect_ssf_enabled'] ?? '')
            : ($this->flag('openidconnect_ssf_enabled') ? '1' : '0');
        return in_array(strtolower(trim($value)), ['1', 'yes', 'true', 'on'], true);
    }

    private function submittedSsfDelivery(): string
    {
        return $this->submittedChoice('openidconnect_ssf_delivery_method', self::SSF_DELIVERY_METHODS, 'push');
    }

    /** @return array<int,array{position:int,code:string,name:string,refid:string}> */
    private static function configuredApplicationCodes(): array
    {
        try {
            $servers = Config::getInstance()->object()->system->authserver ?? [];
        } catch (\Throwable $e) {
            return [];
        }
        $result = [];
        $position = 0;
        foreach ($servers as $server) {
            /* SimpleXML repeats the element name as the foreach key. Count every
             * authentication server so this stays aligned with core's array index. */
            $serverPosition = $position++;
            if ((string)($server->type ?? '') !== self::TYPE) {
                continue;
            }
            $result[] = [
                'position' => $serverPosition,
                'code' => trim((string)($server->openidconnect_app_code ?? 'main')),
                'name' => (string)($server->name ?? ''),
                'refid' => (string)($server->refid ?? ''),
            ];
        }
        return $result;
    }

    /**
     * A disabled server is a harmless draft and may be saved before its provider exists.
     * Core's server form asks for validators on a fresh connector, so the submitted
     * checkbox is authoritative when present.  An absent checkbox on a submitted OIDC
     * form means disabled; outside a form, use the connector's configured value.
     */
    private function allowsIncompleteDraft(): bool
    {
        if (isset($_POST['type']) && (string)$_POST['type'] === self::TYPE) {
            $enabled = strtolower((string)($_POST['openidconnect_enabled'] ?? ''));
            return !in_array($enabled, ['1', 'yes', 'true', 'on'], true);
        }
        return array_key_exists('openidconnect_enabled', $this->settings)
            ? !$this->flag('openidconnect_enabled') : true;
    }

    private function postedCustomOrigins(): bool
    {
        if (isset($_POST['type']) && (string)$_POST['type'] === self::TYPE) {
            return (string)($_POST['openidconnect_origin_policy'] ?? 'opnsense') === 'custom';
        }
        return $this->originPolicy() === 'custom';
    }

    private function validateTlsOffloading($value): array
    {
        if ($this->nativeWebGuiUsesHttps() || $this->allowsIncompleteDraft()) {
            return [];
        }
        $enabled = in_array(strtolower(trim((string)$value)), ['1', 'yes', 'true', 'on'], true);
        if (!$enabled) {
            return [gettext(
                'OpenID Connect requires an HTTPS WebGUI. For deliberate TLS termination at a trusted reverse ' .
                'proxy, enable this exception and configure exact Custom HTTPS origins.'
            )];
        }
        if (!$this->postedCustomOrigins()) {
            return [gettext('TLS offloading requires Custom origins for this provider.')];
        }
        $origins = static::splitList((string)($_POST['openidconnect_redirect_urls']
            ?? $this->text('openidconnect_redirect_urls')));
        foreach ($origins as $origin) {
            if (static::isHttpsOrigin($origin)) {
                return [];
            }
        }
        return [gettext('TLS offloading requires at least one exact public HTTPS origin.')];
    }

    /** @return array<string,string> */
    private function sectorOriginOptions(): array
    {
        $options = ['' => gettext('Off')];
        foreach ($this->effectiveWebGuiOrigins() as $origin) {
            $options[$origin] = $origin;
        }
        return $options;
    }

    private function validateSectorOrigin($value): array
    {
        $value = trim((string)$value);
        if ($value === '') {
            return [];
        }
        $normalized = static::normalizeHttpsOrigin($value);
        if ($normalized === null || !in_array($normalized, $this->effectiveOriginsForValidation(), true)) {
            return [gettext('Choose one of this provider\'s exact accepted WebGUI origins.')];
        }
        return [];
    }

    /** @return string[] */
    private function effectiveOriginsForValidation(): array
    {
        if (!isset($_POST['type']) || (string)$_POST['type'] !== self::TYPE) {
            return $this->effectiveWebGuiOrigins();
        }
        $policy = (string)($_POST['openidconnect_origin_policy'] ?? 'opnsense');
        $origins = $policy === 'custom' ? [] : $this->opnsenseWebGuiOrigins();
        foreach (static::splitList((string)($_POST['openidconnect_redirect_urls'] ?? '')) as $origin) {
            $normalized = static::normalizeHttpsOrigin($origin);
            if ($normalized !== null) {
                $origins[] = $normalized;
            }
        }
        return array_values(array_unique($origins));
    }

    private function usesManagedMicrosoftIssuer(): bool
    {
        if (isset($_POST['type']) && (string)$_POST['type'] === self::TYPE) {
            $profile = (string)($_POST['openidconnect_provider_profile'] ?? 'general');
            $audience = (string)($_POST['openidconnect_microsoft_audience'] ?? 'tenant');
            return $profile === 'entra' && in_array($audience, ['organizations', 'consumers', 'common'], true);
        }
        return $this->providerProfile() === 'entra' && $this->microsoftAudience() !== 'tenant';
    }

    public static function isIssuerUrl($value): bool
    {
        $value = ProviderMetadata::normalizeIssuerInput($value);
        if (!static::isFetchableUrl($value)) {
            return false;
        }
        $parts = parse_url(trim((string)$value));
        return !isset($parts['user']) && !isset($parts['pass'])
            && !isset($parts['query']) && !isset($parts['fragment']);
    }

    public static function isHttpsOrigin($value): bool
    {
        $value = rtrim(trim((string)$value), '/');
        if (!static::isFetchableUrl($value)) {
            return false;
        }
        $parts = parse_url($value);
        return isset($parts['host']) && !isset($parts['user']) && !isset($parts['pass'])
            && !isset($parts['query']) && !isset($parts['fragment'])
            && (($parts['path'] ?? '') === '');
    }

    /** @return string[] */
    public static function validateBindings($value): array
    {
        $subjects = [];
        foreach (preg_split('/\r?\n/', trim((string)$value)) ?: [] as $line) {
            if (trim($line) === '') {
                continue;
            }
            $parts = static::parseBindingLine($line);
            if ($parts === null
                || strlen($parts[0]) > 4096 || strlen($parts[1]) > 255
                || static::hasControlCharacters($parts[0]) || static::hasControlCharacters($parts[1])) {
                return [gettext('Each stored identity binding must contain a valid subject and local account mapping.')];
            }
            if (isset($subjects[$parts[0]])) {
                return [gettext('Each stored identity may appear only once.')];
            }
            $subjects[$parts[0]] = true;
        }
        return [];
    }

    private static function claimString(object $claims, string $name, int $maximum): string
    {
        $value = $claims->{$name} ?? null;
        if (!is_string($value)) {
            return '';
        }
        $value = trim($value);
        if ($value === '' || strlen($value) > $maximum || static::hasControlCharacters($value)) {
            return '';
        }
        return $value;
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
        if ($this->providerProfile() === 'entra' && $this->microsoftAudience() !== 'tenant') {
            return 'https://login.microsoftonline.com/' . $this->microsoftAudience() . '/v2.0';
        }
        return ProviderMetadata::normalizeIssuerInput(
            $this->profileText('openidconnect_provider_url'),
            $this->providerRequiresTrailingIssuerSlash()
        );
    }

    public function microsoftAudience(): string
    {
        return $this->choice('openidconnect_microsoft_audience', self::MICROSOFT_AUDIENCES, 'tenant');
    }

    /** Profiles whose public issuer is documented with a significant trailing slash. */
    private function providerRequiresTrailingIssuerSlash(): bool
    {
        $profile = isset($_POST['type']) && (string)$_POST['type'] === self::TYPE
            ? (string)($_POST['openidconnect_provider_profile'] ?? 'general')
            : $this->providerProfile();
        return in_array($profile, ['auth0', 'authentik'], true);
    }

    /** Microsoft tenant-independent metadata publishes this literal issuer template. */
    public function discoveryIssuerTemplate(): ?string
    {
        if ($this->providerProfile() !== 'entra' || $this->microsoftAudience() === 'tenant') {
            return null;
        }
        return $this->microsoftAudience() === 'consumers'
            ? 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0'
            : 'https://login.microsoftonline.com/{tenantid}/v2.0';
    }

    /**
     * Validate a tenant-specific Microsoft issuer without weakening issuer checks for any
     * other provider. The tid claim is both syntax checked and required to name the exact
     * tenant in iss; the selected audience then decides whether that tenant is admitted.
     *
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $signingKey
     */
    public function validateMicrosoftIssuer(array $claims, array $signingKey = []): void
    {
        if ($this->discoveryIssuerTemplate() === null) {
            throw new \OPNsense\OpenIDConnect\ProtocolException('No tenant-independent Microsoft issuer is configured');
        }
        $issuer = $claims['iss'] ?? null;
        $tenant = $claims['tid'] ?? null;
        $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
        if (!is_string($issuer) || !is_string($tenant)
            || !preg_match('/^' . $guid . '$/Di', $tenant)
            || !preg_match('#^https://login\.microsoftonline\.com/(' . $guid . ')/v2\.0$#Di', $issuer, $match)
            || strcasecmp($match[1], $tenant) !== 0) {
            throw new \OPNsense\OpenIDConnect\ProtocolException(
                'The Microsoft token issuer and tenant identifier do not form an exact tenant issuer'
            );
        }
        $consumerTenant = '9188040d-6c67-4c5b-b112-36a304b66dad';
        if ($this->microsoftAudience() === 'consumers' && strcasecmp($tenant, $consumerTenant) !== 0) {
            throw new \OPNsense\OpenIDConnect\ProtocolException('The Microsoft token is not a personal account token');
        }
        if ($this->microsoftAudience() === 'organizations' && strcasecmp($tenant, $consumerTenant) === 0) {
            throw new \OPNsense\OpenIDConnect\ProtocolException('Personal Microsoft accounts are not admitted');
        }
        if (!is_string($signingKey['issuer'] ?? null)) {
            throw new \OPNsense\OpenIDConnect\ProtocolException(
                'The tenant-independent Microsoft signing key has no issuer'
            );
        }
        $keyIssuer = str_replace('{tenantid}', strtolower($tenant), strtolower($signingKey['issuer']));
        if (!hash_equals(strtolower($issuer), $keyIssuer)) {
            throw new \OPNsense\OpenIDConnect\ProtocolException(
                'The Microsoft signing key is not issued for the token tenant'
            );
        }
    }

    public function acceptsMicrosoftIssuerValue(string $issuer): bool
    {
        if ($this->discoveryIssuerTemplate() === null) {
            return hash_equals($this->issuerUrl(), $issuer);
        }
        $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
        if (!preg_match('#^https://login\.microsoftonline\.com/(' . $guid . ')/v2\.0$#Di', $issuer, $match)) {
            return false;
        }
        $personal = strcasecmp($match[1], '9188040d-6c67-4c5b-b112-36a304b66dad') === 0;
        return match ($this->microsoftAudience()) {
            'consumers' => $personal,
            'organizations' => !$personal,
            'common' => true,
            default => false,
        };
    }

    public function applicationCode(): string
    {
        return $this->text('openidconnect_app_code', 'main');
    }

    public function receivesSharedSignals(): bool
    {
        return $this->flag('openidconnect_ssf_enabled');
    }

    public function sharedSignalsIssuer(): string
    {
        return $this->text('openidconnect_ssf_issuer');
    }

    public function sharedSignalsAudience(): string
    {
        return $this->text('openidconnect_ssf_audience');
    }

    public function sharedSignalsDeliveryMethod(): string
    {
        return $this->choice('openidconnect_ssf_delivery_method', self::SSF_DELIVERY_METHODS, 'push') === 'poll'
            ? SharedSignalsMetadata::POLL_METHOD : SharedSignalsMetadata::PUSH_METHOD;
    }

    public function sharedSignalsManagementAuthorization(): string
    {
        return $this->text('openidconnect_ssf_management_authorization');
    }

    public function sharedSignalsStreamId(): string
    {
        return $this->text('openidconnect_ssf_stream_id');
    }

    public function sharedSignalsPollEndpoint(): string
    {
        return $this->text('openidconnect_ssf_poll_endpoint');
    }

    public function sharedSignalsPushSecret(): string
    {
        return $this->text('openidconnect_ssf_push_secret');
    }

    public function sharedSignalsPreviousPushSecret(): string
    {
        return $this->text('openidconnect_ssf_previous_push_secret');
    }

    public function providerProfile(): string
    {
        return $this->choice('openidconnect_provider_profile', self::PROVIDER_PROFILES, 'general');
    }

    /** @return array{values:array<string,string>,locked:string[],placeholders:array<string,string>} */
    private function providerPreset(): array
    {
        $presets = static::providerProfilePresets();
        return $presets[$this->providerProfile()] ?? $presets['general'];
    }

    private function profileDefault(string $field, string $fallback = ''): string
    {
        return (string)($this->providerPreset()['values'][$field] ?? $fallback);
    }

    private function profileLocks(string $field): bool
    {
        return in_array($field, $this->providerPreset()['locked'], true);
    }

    private function profileText(string $field, string $fallback = ''): string
    {
        $default = $this->profileDefault($field, $fallback);
        return $this->profileLocks($field) ? $default : $this->text($field, $default);
    }

    public function isEnabled(): bool
    {
        /* Existing hand-written configurations with no field remain enabled. */
        $configured = !array_key_exists('openidconnect_enabled', $this->settings)
            || $this->flag('openidconnect_enabled');
        return $configured && $this->isWebGuiTransportReady();
    }

    public function clientId(): string
    {
        return $this->text('openidconnect_client_id');
    }

    public function clientSecret(): string
    {
        return $this->text('openidconnect_client_secret');
    }

    public function requestObjectSigningKey(): string
    {
        $reference = $this->text('openidconnect_request_object_key');
        return strlen($reference) <= 128 && !preg_match('/[\x00-\x1f\x7f]/', $reference) ? $reference : '';
    }

    /** @return array<string,string> private-key certificates keyed by the RFC 9101 kid sent to the provider */
    public function requestObjectSigningKeyOptions(): array
    {
        $options = ['' => gettext('Disabled')];
        foreach (Config::getInstance()->object()->cert ?? [] as $certificate) {
            $reference = trim((string)($certificate->refid ?? ''));
            $description = trim((string)($certificate->descr ?? ''));
            if ($reference === '' || strlen($reference) > 128 || preg_match('/[\x00-\x1f\x7f]/', $reference)
                || trim((string)($certificate->prv ?? '')) === '') {
                continue;
            }
            $options[$reference] = sprintf(
                '%s (kid: %s)',
                $description === '' ? gettext('Unnamed certificate') : $description,
                $reference
            );
        }
        return $options;
    }

    /** A browser sign-in test always uses the saved confidential-client configuration. */
    public function isSignInTestReady(): bool
    {
        return $this->isWebGuiTransportReady()
            && $this->issuerUrl() !== '' && $this->clientId() !== '' && $this->clientSecret() !== '';
    }

    /** Whether OPNsense itself is configured to serve the WebGUI over HTTPS. */
    public function nativeWebGuiUsesHttps(): bool
    {
        return $this->webGuiProtocol() !== 'http';
    }

    /** Explicit exception for a trusted proxy which terminates TLS in front of HTTP. */
    public function usesTrustedTlsOffloading(): bool
    {
        return !$this->nativeWebGuiUsesHttps() && $this->flag('openidconnect_tls_offloading');
    }

    public function isWebGuiTransportReady(): bool
    {
        if ($this->nativeWebGuiUsesHttps()) {
            return true;
        }
        return $this->usesTrustedTlsOffloading()
            && $this->originPolicy() === 'custom'
            && $this->effectiveWebGuiOrigins() !== [];
    }

    public function webGuiTransportProblem(): string
    {
        if ($this->nativeWebGuiUsesHttps()) {
            return '';
        }
        if (!$this->usesTrustedTlsOffloading()) {
            return gettext(
                'OpenID Connect is blocked because the OPNsense WebGUI is configured as HTTP. Enable native ' .
                'HTTPS, or explicitly configure trusted reverse-proxy TLS offloading.'
            );
        }
        if ($this->originPolicy() !== 'custom' || $this->effectiveWebGuiOrigins() === []) {
            return gettext(
                'Trusted reverse-proxy TLS offloading requires Custom origins with at least one exact public ' .
                'HTTPS origin.'
            );
        }
        return '';
    }

    /** @return string[] */
    public function scopes(): array
    {
        $scopes = static::splitList($this->profileText('openidconnect_scopes', 'openid,email,profile'));
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        return array_values(array_unique($scopes));
    }

    public function usernameClaim(): string
    {
        return $this->profileText('openidconnect_username_claim', 'preferred_username');
    }

    public function claimsSource(): string
    {
        if ($this->profileLocks('openidconnect_claims_source')) {
            return $this->profileDefault('openidconnect_claims_source', 'auto');
        }
        return $this->choice(
            'openidconnect_claims_source',
            self::CLAIMS_SOURCES,
            $this->profileDefault('openidconnect_claims_source', 'auto')
        );
    }

    public function responseMode(): string
    {
        if ($this->profileLocks('openidconnect_response_mode')) {
            return $this->profileDefault('openidconnect_response_mode', 'query');
        }
        return $this->choice(
            'openidconnect_response_mode',
            self::RESPONSE_MODES,
            $this->profileDefault('openidconnect_response_mode', 'query')
        );
    }

    public function requiredAuthentication(): string
    {
        return $this->choice('openidconnect_required_authentication', self::REQUIRED_AUTHENTICATION, '');
    }

    /** The exact policy a relying-party transaction requests and later verifies. */
    public function authenticationRequirement(): ?AuthenticationRequirement
    {
        $tier = $this->requiredAuthentication();
        if ($tier === '') {
            return null;
        }

        $profile = $this->providerProfile();
        $presets = static::authenticationRequirementPresets();
        $presetProfile = in_array($profile, ['okta', 'entra'], true) ? $profile : 'general';
        $preset = $presets[$presetProfile][$tier];
        $methods = static::splitList($this->rawText('openidconnect_amr_values'));
        if ($methods === []) {
            $methods = static::splitList($preset['amr']);
        }

        if ($profile === 'entra') {
            if ($this->microsoftAudience() !== 'tenant') {
                throw new \OPNsense\OpenIDConnect\ProtocolException(
                    'Microsoft authentication contexts require one specific Entra tenant'
                );
            }
            return new AuthenticationRequirement(
                $tier,
                AuthenticationRequirement::ENTRA_CONTEXT,
                [$this->rawText('openidconnect_entra_auth_context')],
                array_values(array_unique($methods))
            );
        }

        $contexts = static::splitList($this->rawText('openidconnect_acr_values'));
        if ($contexts === []) {
            $contexts = static::splitList($preset['acr']);
        }
        $requestMode = $this->text('openidconnect_acr_request');
        if (!in_array($requestMode, self::ACR_REQUEST_MODES, true)) {
            $requestMode = $preset['request'];
        }
        return new AuthenticationRequirement(
            $tier,
            $requestMode,
            array_values(array_unique($contexts)),
            array_values(array_unique($methods))
        );
    }

    public function selectAccount(): bool
    {
        return $this->flag('openidconnect_select_account');
    }
    public function bootstrapMode(): string
    {
        if ($this->legacyBootstrapDefault() === 'either') {
            return 'either';
        }
        return $this->choice(
            'openidconnect_bootstrap_mode',
            self::BOOTSTRAP_MODES,
            $this->profileDefault('openidconnect_bootstrap_mode', $this->legacyBootstrapDefault())
        );
    }

    /** Existing beta configurations predate the admission-policy field and matched either local identifier. */
    private function legacyBootstrapDefault(): string
    {
        return !array_key_exists('openidconnect_bootstrap_mode', $this->settings)
            && trim((string)($this->settings['refid'] ?? '')) !== '' ? 'either' : 'strict';
    }

    /** @return string[] addresses the provider may send the browser back to */
    public function acceptedRedirectUrls(): array
    {
        return static::splitList($this->text('openidconnect_redirect_urls'));
    }

    public function originPolicy(): string
    {
        if (!array_key_exists('openidconnect_origin_policy', $this->settings)) {
            /* Preserve configurations written before this switch existed. */
            return $this->acceptedRedirectUrls() === [] ? 'opnsense' : 'custom';
        }
        return $this->choice('openidconnect_origin_policy', self::ORIGIN_POLICIES, 'opnsense');
    }

    /** @return string[] exact HTTPS origins accepted for this provider */
    public function effectiveWebGuiOrigins(): array
    {
        if (!$this->nativeWebGuiUsesHttps()
            && (!$this->usesTrustedTlsOffloading() || $this->originPolicy() !== 'custom')) {
            return [];
        }
        $origins = $this->originPolicy() === 'custom' ? [] : $this->opnsenseWebGuiOrigins();
        foreach ($this->acceptedRedirectUrls() as $additional) {
            $normalized = static::normalizeHttpsOrigin($additional);
            if ($normalized !== null) {
                $origins[] = $normalized;
            }
        }
        return array_values(array_unique($origins));
    }

    /** Whether an exact HTTPS origin is accepted for this server's callback. */
    public function acceptsWebGuiOrigin(string $origin): bool
    {
        $origin = static::normalizeHttpsOrigin($origin);
        if ($origin === null) {
            return false;
        }
        foreach ($this->effectiveWebGuiOrigins() as $accepted) {
            if (hash_equals($accepted, $origin)) {
                return true;
            }
        }
        return false;
    }

    /** Stable accepted origin whose public endpoint supplies pairwise-sector callback URIs. */
    public function sectorOrigin(): string
    {
        $origin = static::normalizeHttpsOrigin($this->rawText('openidconnect_sector_origin'));
        return $origin !== null && $this->acceptsWebGuiOrigin($origin) ? $origin : '';
    }

    /**
     * Build the WebGUI origins which OPNsense itself can identify without trusting a
     * request Host header: configured names, live interface addresses and virtual IPs.
     *
     * @return string[]
     */
    public function opnsenseWebGuiOrigins(): array
    {
        if (!$this->nativeWebGuiUsesHttps()) {
            return [];
        }
        $port = $this->opnsenseWebGuiPort();
        $hosts = array_merge($this->opnsenseWebGuiHostnames(), $this->opnsenseLocalIpAddresses());
        $origins = [];
        foreach ($hosts as $host) {
            $address = filter_var($host, FILTER_VALIDATE_IP) && str_contains($host, ':')
                ? '[' . $host . ']' : $host;
            $origin = 'https://' . $address . ($port === 443 ? '' : ':' . $port);
            $normalized = static::normalizeHttpsOrigin($origin);
            if ($normalized !== null) {
                $origins[] = $normalized;
            }
        }
        return array_values(array_unique($origins));
    }

    public static function normalizeHttpsOrigin($value): ?string
    {
        if (!static::isHttpsOrigin($value)) {
            return null;
        }
        $parts = parse_url(rtrim(trim((string)$value), '/'));
        if (!is_array($parts)) {
            return null;
        }
        $host = strtolower(trim((string)$parts['host'], '[]'));
        if ($host === '') {
            return null;
        }
        $renderedHost = filter_var($host, FILTER_VALIDATE_IP) && str_contains($host, ':')
            ? '[' . $host . ']' : $host;
        $port = (int)($parts['port'] ?? 443);
        return 'https://' . $renderedHost . ($port === 443 ? '' : ':' . $port);
    }

    /** @return string[] hostnames accepted by core's normal DNS-rebinding policy */
    private function opnsenseWebGuiHostnames(): array
    {
        try {
            $system = Config::getInstance()->object()->system;
        } catch (\Throwable $e) {
            return [];
        }
        $hostname = strtolower(trim((string)($system->hostname ?? '')));
        $domain = strtolower(trim((string)($system->domain ?? '')));
        $hosts = [$hostname];
        if ($hostname !== '' && $domain !== '') {
            $hosts[] = $hostname . '.' . $domain;
        }
        $alternates = preg_split('/[\s,]+/', trim((string)($system->webgui->{'althostnames'} ?? ''))) ?: [];
        foreach ($alternates as $alternate) {
            $hosts[] = strtolower(rtrim(trim($alternate), '.'));
        }
        return array_values(array_unique(array_filter($hosts, static function (string $host): bool {
            return $host !== '' && !static::hasControlCharacters($host)
                && (bool)preg_match(
                    '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/D',
                    $host
                );
        })));
    }

    private function opnsenseWebGuiPort(): int
    {
        try {
            $port = (int)(Config::getInstance()->object()->system->webgui->port ?? 443);
        } catch (\Throwable $e) {
            return 443;
        }
        return $port >= 1 && $port <= 65535 ? $port : 443;
    }

    private function webGuiProtocol(): string
    {
        try {
            $protocol = strtolower(trim((string)(
                Config::getInstance()->object()->system->webgui->protocol ?? ''
            )));
        } catch (\Throwable $e) {
            return 'https';
        }
        /* Older configurations may omit the field; core's secure default is HTTPS. */
        return $protocol === 'http' ? 'http' : 'https';
    }

    /** @return string[] non-loopback addresses currently owned by this firewall */
    private function opnsenseLocalIpAddresses(): array
    {
        $addresses = [];
        try {
            if (!function_exists('get_configured_ip_addresses')) {
                foreach (['/usr/local/etc/inc/interfaces.inc', '/usr/local/etc/inc/util.inc'] as $include) {
                    if (is_readable($include)) {
                        require_once $include;
                    }
                }
            }
            if (function_exists('get_configured_ip_addresses')) {
                $addresses = array_keys((array)\get_configured_ip_addresses());
            }
            foreach (config_read_array('virtualip', 'vip', false) as $vip) {
                if (!empty($vip['subnet'])) {
                    $addresses[] = (string)$vip['subnet'];
                }
            }
        } catch (\Throwable $e) {
            /* Names still provide safe origins if interface discovery is unavailable. */
        }

        $usable = [];
        foreach ($addresses as $address) {
            /* OPNsense appends an interface scope to link-local IPv6 addresses. Such an
             * address is not portable in an OIDC redirect URI, so discard it below. */
            $address = preg_replace('/%.*/', '', trim((string)$address));
            if ($address !== null && $this->isUsableWebGuiIp($address)) {
                $usable[] = strtolower($address);
            }
        }
        return array_values(array_unique($usable));
    }

    private function isUsableWebGuiIp(string $address): bool
    {
        if (!filter_var($address, FILTER_VALIDATE_IP)) {
            return false;
        }
        $binary = inet_pton($address);
        if ($binary === false) {
            return false;
        }
        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $binary !== str_repeat("\0", 4) && ord($binary[0]) !== 127;
        }
        if ($binary === str_repeat("\0", 16) || $binary === str_repeat("\0", 15) . "\1") {
            return false;
        }
        /* fe80::/10 needs a zone identifier which providers cannot use portably. */
        return !(ord($binary[0]) === 0xfe && (ord($binary[1]) & 0xc0) === 0x80);
    }

    /** @return int seconds; zero deliberately requires authentication on every login */
    public function maximumAuthenticationAge(): int
    {
        $value = trim((string)($this->settings['openidconnect_max_age'] ?? ''));
        if ($value === '' || !ctype_digit($value)) {
            /* Empty legacy values and invalid stored data fail closed to the new default. */
            return self::DEFAULT_MAX_AUTHENTICATION_AGE;
        }
        return max(0, (int)$value);
    }

    public function createsUsers(): bool
    {
        return $this->flag('openidconnect_create_users');
    }

    /** @return string when an e-mail address may stand in for the username claim */
    public function emailMatching(): string
    {
        return $this->choice(
            'openidconnect_email_match',
            self::EMAIL_MATCHING,
            $this->profileDefault('openidconnect_email_match', 'verified')
        );
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

    public function buttonTextMode(): string
    {
        if (isset(self::FIXED_PROVIDER_BUTTON_LABELS[$this->providerProfile()])) {
            return 'label_only';
        }
        return $this->choice('openidconnect_button_text_mode', self::BUTTON_TEXT_MODES, 'localized');
    }

    public function buttonProviderLabel(string $descriptiveName): string
    {
        $fixed = self::FIXED_PROVIDER_BUTTON_LABELS[$this->providerProfile()] ?? null;
        if ($fixed !== null) {
            return $fixed;
        }
        $label = $this->text('openidconnect_button_provider_label');
        return $label !== '' && strlen($label) <= 80 && !static::hasControlCharacters($label)
            && $label === strip_tags($label) ? $label : $descriptiveName;
    }

    public function customButtonText(): string
    {
        $text = $this->text('openidconnect_button_custom_text');
        return $text !== '' && strlen($text) <= 120 && !static::hasControlCharacters($text)
            && $text === strip_tags($text) ? $text : '';
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
        return $this->profileText('openidconnect_icon_url');
    }

    public function redirectsLogoutMenu(): bool
    {
        return $this->flag('openidconnect_logout_menu');
    }

    public function parMode(): string
    {
        return $this->choice('openidconnect_par_mode', self::PAR_MODES, 'auto');
    }

    public function logoutNotificationMode(): string
    {
        return $this->choice(
            'openidconnect_logout_notifications',
            self::LOGOUT_NOTIFICATION_MODES,
            'both'
        );
    }

    public function acceptsBackchannelLogout(): bool
    {
        return in_array($this->logoutNotificationMode(), ['both', 'backchannel'], true);
    }

    public function acceptsFrontchannelLogout(): bool
    {
        return in_array($this->logoutNotificationMode(), ['both', 'frontchannel'], true);
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
        $chosen = $this->profileText('openidconnect_token_auth');

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

    public function allowsAllGroups(): bool
    {
        return $this->flag('openidconnect_allow_all_groups');
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
