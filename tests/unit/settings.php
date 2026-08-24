<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Auth\OpenIDConnect;

Checks::group('Reading a list out of a settings field');
Checks::that('comma separated', OpenIDConnect::splitList('a,b,c'), ['a', 'b', 'c']);
Checks::that('one per line', OpenIDConnect::splitList("a\nb\r\nc"), ['a', 'b', 'c']);
Checks::that('surrounding whitespace goes', OpenIDConnect::splitList(' a , b '), ['a', 'b']);
Checks::that('blank entries go', OpenIDConnect::splitList('a,,b,'), ['a', 'b']);
Checks::that('an empty field is an empty list', OpenIDConnect::splitList(''), []);

Checks::group('Telling a local path from an address');
Checks::that('a path', OpenIDConnect::isLocalPath('/ui/themes/x/y.svg'), true);
Checks::that('a protocol-relative external address is not a local path', OpenIDConnect::isLocalPath('//example.net/y.svg'), false);
Checks::that('an absolute url', OpenIDConnect::isLocalPath('https://example.net/y.svg'), false);
Checks::that('a data uri', OpenIDConnect::isLocalPath('data:image/svg+xml;base64,AA'), false);
Checks::that('nothing at all', OpenIDConnect::isLocalPath(''), false);

/**
 * Group names arrive in whichever shape a provider chose. Zitadel's role claim is an
 * object keyed by role name, and treating that as a list is a fatal error mid-login.
 */
Checks::group('Reading group names out of any shape a provider sends');
Checks::that('a plain list', OpenIDConnect::namesIn(['admins', 'users']), ['admins', 'users']);
Checks::that(
    'a map keyed by name, as Zitadel sends roles',
    OpenIDConnect::namesIn((object)['admin' => (object)['1' => 'example.net'], 'viewer' => (object)['1' => 'x']]),
    ['admin', 'viewer']
);
Checks::that('a single name', OpenIDConnect::namesIn('admins'), ['admins']);
Checks::that('entries that are not names are skipped', OpenIDConnect::namesIn(['admins', (object)['x' => 1], '']), ['admins']);
Checks::that('nothing', OpenIDConnect::namesIn(null), []);
Checks::that('an empty list', OpenIDConnect::namesIn([]), []);

Checks::group('Keeping the exact configured issuer');
Checks::that(
    'a bare issuer is left alone',
    connector(['openidconnect_provider_url' => 'https://id.example.net/application/o/fw/'])->issuerUrl(),
    'https://id.example.net/application/o/fw/'
);
Checks::that(
    'a complete discovery URL is reduced to its issuer',
    connector(['openidconnect_provider_url' => 'https://id.example.net/fw/.well-known/openid-configuration'])->issuerUrl(),
    'https://id.example.net/fw'
);
Checks::that(
    'an authentik Discovery URL retains its significant issuer slash',
    connector([
        'openidconnect_provider_profile' => 'authentik',
        'openidconnect_provider_url' => 'https://id.example.net/application/o/fw/.well-known/openid-configuration',
    ])->issuerUrl(),
    'https://id.example.net/application/o/fw/'
);
Checks::that(
    'an Auth0 Discovery URL retains its significant root issuer slash',
    connector([
        'openidconnect_provider_profile' => 'auth0',
        'openidconnect_provider_url' => 'https://tenant.example.net/.well-known/openid-configuration',
    ])->issuerUrl(),
    'https://tenant.example.net/'
);

Checks::group('Defaults when a field is left empty');
Checks::that('scopes', connector([])->scopes(), ['openid', 'email', 'profile']);
Checks::that('scopes as configured', connector(['openidconnect_scopes' => 'openid,groups'])->scopes(), ['openid', 'groups']);
Checks::that('username claim', connector([])->usernameClaim(), 'preferred_username');
Checks::that('button style', connector([])->buttonStyle(), 'button');
Checks::that('button style, nonsense value', connector(['openidconnect_button_style' => 'wobble'])->buttonStyle(), 'button');
Checks::that('button wording follows the localized OPNsense sentence by default',
    connector([])->buttonTextMode(), 'localized');
Checks::that('button wording nonsense falls back to the localized sentence', connector([
    'openidconnect_button_text_mode' => 'wobble',
])->buttonTextMode(), 'localized');
Checks::that('an empty provider label follows Descriptive name',
    connector([])->buttonProviderLabel('Office identity'), 'Office identity');
Checks::that('an installation-specific provider label may differ from Descriptive name', connector([
    'openidconnect_button_provider_label' => 'Company SSO',
])->buttonProviderLabel('Technical server name'), 'Company SSO');
Checks::that('custom full button text is read literally', connector([
    'openidconnect_button_custom_text' => 'Continue through the identity portal',
])->customButtonText(), 'Continue through the identity portal');
Checks::that('Generic OpenID Connect uses the official OpenID icon by default', connector([])->iconUrl(),
    '/api/openidconnect/auth/builtinicon/general');
Checks::that('Generic icon rendering follows the button text colour', connector([])->iconMode(), 'monochrome');
Checks::that('named provider icons follow the button text colour', connector([
    'openidconnect_provider_profile' => 'authentik',
])->iconMode(), 'monochrome');
Checks::that('an invalid named-provider icon mode falls back to single colour', connector([
    'openidconnect_provider_profile' => 'authentik',
    'openidconnect_icon_mode' => 'sepia',
])->iconMode(), 'monochrome');
Checks::that('the named-provider form displays the same single-colour default', connector([
    'openidconnect_provider_profile' => 'authentik',
])->getConfigurationOptions()['openidconnect_icon_mode']['default'], 'monochrome');
Checks::that('maximum age, unset', connector([])->maximumAuthenticationAge(), 14400);
Checks::that('maximum age, legacy empty value', connector(['openidconnect_max_age' => ''])->maximumAuthenticationAge(), 14400);
Checks::that('maximum age, set', connector(['openidconnect_max_age' => '3600'])->maximumAuthenticationAge(), 3600);
Checks::that('maximum age, explicitly zero', connector(['openidconnect_max_age' => '0'])->maximumAuthenticationAge(), 0);
Checks::that('maximum age, not a number', connector(['openidconnect_max_age' => 'soon'])->maximumAuthenticationAge(), 14400);
Checks::that('no authentication strength is required unless asked for', connector([])->requiredAuthentication(), '');
Checks::that(
    'an unknown authentication requirement falls back to provider policy only',
    connector(['openidconnect_required_authentication' => 'passwordless'])->requiredAuthentication(),
    ''
);
$genericMfa = connector([
    'openidconnect_required_authentication' => 'multi-factor',
])->authenticationRequirement();
Checks::that('Generic MFA uses the REFEDS essential claim preset', $genericMfa->toArray(), [
    'tier' => 'multi-factor',
    'request_mode' => 'essential_claim',
    'contexts' => ['https://refeds.org/profile/mfa'],
    'methods' => [
        'mfa', 'pwd', 'pin', 'kba', 'otp', 'hwk', 'sc', 'sms', 'swk', 'tel', 'pop',
        'face', 'fpt', 'iris', 'retina', 'vbm',
    ],
]);
$oktaMfa = connector([
    'openidconnect_provider_profile' => 'okta',
    'openidconnect_required_authentication' => 'multi-factor',
])->authenticationRequirement();
Checks::that('Okta MFA uses its documented ACR preset', $oktaMfa->toArray(), [
    'tier' => 'multi-factor',
    'request_mode' => 'acr_values',
    'contexts' => ['urn:okta:loa:2fa:any'],
    'methods' => ['mfa'],
]);
$customStrength = connector([
    'openidconnect_required_authentication' => 'phishing-resistant',
    'openidconnect_acr_request' => 'acr_values',
    'openidconnect_acr_values' => 'company:phr,company:phr-hardware',
    'openidconnect_amr_values' => 'company-key',
])->authenticationRequirement();
Checks::that('an installation can override its provider-agreed ACR and AMR values', $customStrength->toArray(), [
    'tier' => 'phishing-resistant',
    'request_mode' => 'acr_values',
    'contexts' => ['company:phr', 'company:phr-hardware'],
    'methods' => ['company-key'],
]);
$entraStrength = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'tenant',
    'openidconnect_required_authentication' => 'phishing-resistant',
    'openidconnect_entra_auth_context' => 'c4',
])->authenticationRequirement();
Checks::that('Entra binds its tenant context to documented method evidence', $entraStrength->toArray(), [
    'tier' => 'phishing-resistant',
    'request_mode' => 'entra_context',
    'contexts' => ['c4'],
    'methods' => ['fido', 'hwk', 'x509'],
]);
Checks::throws(
    'a broad Microsoft audience cannot assign tenant-local authentication context semantics',
    fn() => connector([
        'openidconnect_provider_profile' => 'entra',
        'openidconnect_microsoft_audience' => 'organizations',
        'openidconnect_required_authentication' => 'multi-factor',
        'openidconnect_entra_auth_context' => 'c1',
    ])->authenticationRequirement(),
    'one specific Entra tenant'
);
Checks::that('token auth, unset', connector([])->tokenAuthMethod(), null);
Checks::that(
    'token auth, insisted on',
    connector(['openidconnect_token_auth' => 'client_secret_post'])->tokenAuthMethod(),
    'client_secret_post'
);
Checks::that('token auth, nonsense value', connector(['openidconnect_token_auth' => 'wobble'])->tokenAuthMethod(), null);
Checks::that('PAR uses availability-aware automatic mode by default', connector([])->parMode(), 'auto');
Checks::that('PAR can be required', connector(['openidconnect_par_mode' => 'required'])->parMode(), 'required');
Checks::that('an unknown PAR mode falls back to automatic', connector([
    'openidconnect_par_mode' => 'sometimes',
])->parMode(), 'auto');
Checks::that('Request Object signing is off unless a key is selected',
    connector([])->requestObjectSigningKey(), '');
\OPNsense\Core\Config::getInstance()->addCertificate('jar-current', 'JAR current');
\OPNsense\Core\Config::getInstance()->addCertificate('public-only', 'Public only', false);
$jarSettings = connector(['openidconnect_request_object_key' => 'jar-current']);
Checks::that('the selected Request Object signing key is retained as its kid',
    $jarSettings->requestObjectSigningKey(), 'jar-current');
Checks::that('private-key certificates are offered with their kid',
    $jarSettings->requestObjectSigningKeyOptions()['jar-current'], 'JAR current (kid: jar-current)');
Checks::that('a certificate without a private key is not offered',
    isset($jarSettings->requestObjectSigningKeyOptions()['public-only']), false);
Checks::that('the form refuses an unknown Request Object signing key', count(
    connector([])->getConfigurationOptions()['openidconnect_request_object_key']['validate']('missing')
), 1);
Checks::that('a deleted Request Object key remains visible to runtime fail-closed handling',
    connector(['openidconnect_request_object_key' => 'missing'])->requestObjectSigningKey(), 'missing');
Checks::that('both provider logout notification channels are accepted by default', [
    connector([])->acceptsBackchannelLogout(),
    connector([])->acceptsFrontchannelLogout(),
], [true, true]);
Checks::that('logout notification channels can be limited independently', [
    connector(['openidconnect_logout_notifications' => 'backchannel'])->acceptsFrontchannelLogout(),
    connector(['openidconnect_logout_notifications' => 'frontchannel'])->acceptsBackchannelLogout(),
    connector(['openidconnect_logout_notifications' => 'off'])->acceptsBackchannelLogout(),
], [false, false, false]);
$newProtocolOptions = connector([])->getConfigurationOptions();
Checks::that('the form displays automatic PAR as its compatibility default',
    $newProtocolOptions['openidconnect_par_mode']['default'], 'auto');
Checks::that('the form displays both logout notification channels as its compatibility default',
    $newProtocolOptions['openidconnect_logout_notifications']['default'], 'both');
Checks::that('the form refuses an unknown PAR mode',
    count($newProtocolOptions['openidconnect_par_mode']['validate']('sometimes')), 1);
Checks::that('the form refuses an unknown logout notification mode',
    count($newProtocolOptions['openidconnect_logout_notifications']['validate']('sometimes')), 1);
Checks::that('account selection is off unless asked for', connector([])->selectAccount(), false);
Checks::that('account selection can be requested', connector([
    'openidconnect_select_account' => '1',
])->selectAccount(), true);
$sectorSettings = connector([
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.net,https://backup.example.net:8443',
    'openidconnect_sector_origin' => 'https://firewall.example.net',
]);
Checks::that('the pairwise sector is an exact accepted origin', $sectorSettings->sectorOrigin(),
    'https://firewall.example.net');
$sectorOptions = $sectorSettings->getConfigurationOptions()['openidconnect_sector_origin'];
Checks::that('the pairwise sector dropdown lists effective origins', array_keys($sectorOptions['options']), [
    '', 'https://firewall.example.net', 'https://backup.example.net:8443',
]);
Checks::that(
    'an accepted pairwise sector validates',
    $sectorOptions['validate']('https://backup.example.net:8443'),
    []
);
Checks::that(
    'an unrelated pairwise sector is refused',
    count($sectorOptions['validate']('https://other.example.net')),
    1
);
Checks::that('an invalid saved pairwise sector is disabled', connector([
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_sector_origin' => 'https://other.example.net',
])->sectorOrigin(), '');
Checks::that('group claim is off unless asked for', connector([])->groupClaim(), '');
Checks::that('tracing is off unless asked for', connector([])->isTracing(), false);
Checks::that('e-mail matching asks the provider to have checked', connector([])->emailMatching(), 'verified');
Checks::that(
    'e-mail matching, nonsense value',
    connector(['openidconnect_email_match' => 'wobble'])->emailMatching(),
    'verified'
);
Checks::that('root is out of reach unless asked for', connector([])->allowsRoot(), false);
Checks::that('an older configuration without an enabled field stays enabled', connector([])->isEnabled(), true);
Checks::that(
    'a new server explicitly left disabled is not offered',
    connector(['openidconnect_enabled' => '0'])->isEnabled(),
    false
);
Checks::that(
    'a server is offered after it is deliberately enabled',
    connector(['openidconnect_enabled' => '1'])->isEnabled(),
    true
);
Checks::that(
    'the settings form leaves a new server disabled',
    connector([])->getConfigurationOptions()['openidconnect_enabled']['default'],
    '0'
);
Checks::that('identity bootstrap is strict unless asked for', connector([])->bootstrapMode(), 'strict');
Checks::that(
    'a saved beta configuration keeps its earlier matching behaviour',
    connector(['refid' => 'legacy-server'])->bootstrapMode(),
    'either'
);
Checks::that(
    'an explicit strict policy overrides the saved beta fallback',
    connector(['refid' => 'legacy-server', 'openidconnect_bootstrap_mode' => 'strict'])->bootstrapMode(),
    'strict'
);
Checks::that(
    'the settings form preserves the saved beta fallback until an admission policy is chosen',
    connector(['refid' => 'legacy-server'])->getConfigurationOptions()['openidconnect_bootstrap_mode']['default'],
    'either'
);
Checks::that('provider profile is standards-based unless named', connector([])->providerProfile(), 'general');
$profileOptions = OpenIDConnect::providerProfileOptions();
Checks::that('the generic provider profile is always first', array_key_first($profileOptions), 'general');
Checks::that('the generic provider profile has the conventional name', reset($profileOptions), 'Generic OpenID Connect');
Checks::that('the Apple provider profile uses the provider name', $profileOptions['apple'], 'Apple · Social login');
$retiredProfile = connector([
    'openidconnect_provider_profile' => 'removed_vendor_profile',
    'openidconnect_username_claim' => 'email',
]);
Checks::that('a retired named profile safely becomes standards-based', $retiredProfile->providerProfile(), 'general');
Checks::that('a retired profile keeps its explicitly saved claim choice', $retiredProfile->usernameClaim(), 'email');
$namedProfileLabels = array_values(array_slice($profileOptions, 1, null, true));
$sortedProfileLabels = $namedProfileLabels;
usort($sortedProfileLabels, 'strcasecmp');
Checks::that('named provider profiles are alphabetic regardless of case', $namedProfileLabels, $sortedProfileLabels);
$profilePresets = OpenIDConnect::providerProfilePresets();
Checks::that('every selectable provider has exactly one preset', array_keys($profilePresets), OpenIDConnect::PROVIDER_PROFILES);
$completePresetFields = [
    'openidconnect_provider_url',
    'openidconnect_token_auth',
    'openidconnect_username_claim',
    'openidconnect_claims_source',
    'openidconnect_response_mode',
    'openidconnect_email_match',
    'openidconnect_scopes',
    'openidconnect_bootstrap_mode',
    'openidconnect_button_text_mode',
    'openidconnect_button_provider_label',
    'openidconnect_button_custom_text',
    'openidconnect_icon_url',
    'openidconnect_icon_mode',
];
Checks::that('every provider preset covers every provider-dependent field', array_values(array_filter(
    array_keys($profilePresets),
    static fn($profile) => array_keys($profilePresets[$profile]['values']) !== $completePresetFields
)), []);
Checks::that('every locked field has a concrete value', array_values(array_filter(
    array_keys($profilePresets),
    static fn($profile) => array_filter(
        $profilePresets[$profile]['locked'],
        static fn($field) => ($profilePresets[$profile]['values'][$field] ?? '') === ''
    ) !== []
)), []);
$fixedButtonLabels = OpenIDConnect::fixedProviderButtonLabels();
Checks::that('only globally fixed public services have an internal button label', $fixedButtonLabels, [
    'apple' => 'Apple',
    'entra' => 'Microsoft',
    'google' => 'Google',
    'linkedin' => 'LinkedIn',
    'orcid' => 'ORCID',
    'slack' => 'Slack',
    'yahoo' => 'Yahoo',
]);
Checks::that('every global public service uses its short conventional label only', array_values(array_filter(
    $fixedButtonLabels,
    static fn($label, $profile) =>
        $profilePresets[$profile]['values']['openidconnect_button_text_mode'] !== 'label_only'
        || $profilePresets[$profile]['values']['openidconnect_button_provider_label'] !== $label
        || !in_array('openidconnect_button_text_mode', $profilePresets[$profile]['locked'], true)
        || !in_array('openidconnect_button_provider_label', $profilePresets[$profile]['locked'], true),
    ARRAY_FILTER_USE_BOTH
)), []);
Checks::that('a fixed global label cannot be replaced by stale configuration', connector([
    'openidconnect_provider_profile' => 'google',
    'openidconnect_button_text_mode' => 'custom',
    'openidconnect_button_provider_label' => 'Something else',
    'openidconnect_button_custom_text' => 'Something else',
])->buttonTextMode() . ':' . connector([
    'openidconnect_provider_profile' => 'google',
    'openidconnect_button_provider_label' => 'Something else',
])->buttonProviderLabel('Technical Google server'), 'label_only:Google');
Checks::that('a self-hosted provider keeps all three wording choices editable', connector([
    'openidconnect_provider_profile' => 'keycloak',
    'openidconnect_button_text_mode' => 'custom',
    'openidconnect_button_provider_label' => 'Company identity',
    'openidconnect_button_custom_text' => 'Continue to Company identity',
])->buttonTextMode(), 'custom');
Checks::that('Generic OpenID Connect selects the official package icon',
    $profilePresets['general']['values']['openidconnect_icon_url'],
    '/api/openidconnect/auth/builtinicon/general');
Checks::that('Generic keeps the OpenID mark monochrome',
    $profilePresets['general']['values']['openidconnect_icon_mode'], 'monochrome');
$wrongNamedIconModes = array_keys(array_filter(
    $profilePresets,
    static fn($preset, $profile) => $profile !== 'general'
        && ($preset['values']['openidconnect_icon_mode'] ?? '') !== 'monochrome',
    ARRAY_FILTER_USE_BOTH
));
Checks::that('named provider profiles use the normalized single-colour marks', $wrongNamedIconModes, []);
Checks::that('Generic OpenID Connect resolves its package icon',
    basename((string)OpenIDConnect::providerIconPath('general')), 'general.svg');
Checks::that('an unknown profile resolves no package icon',
    OpenIDConnect::providerIconPath('../keycloak'), null);
$missingProfileIcons = [];
$unsafeProfileIcons = [];
foreach ($profilePresets as $profile => $preset) {
    $expectedUrl = '/api/openidconnect/auth/builtinicon/' . rawurlencode($profile);
    if (($preset['values']['openidconnect_icon_url'] ?? '') !== $expectedUrl) {
        $missingProfileIcons[] = $profile . ':preset';
    }
    $path = OpenIDConnect::providerIconPath($profile);
    if (!is_string($path) || !is_file($path)) {
        $missingProfileIcons[] = $profile . ':file';
        continue;
    }
    $svg = file_get_contents($path);
    if (!is_string($svg) || $svg === '' || strlen($svg) > 262144
        || stripos($svg, '<svg') === false
        || preg_match('/<(?:script|foreignObject|iframe|object|embed)\b/i', $svg)
        || preg_match('/\bon[a-z]+\s*=/i', $svg)
        || preg_match('/(?:href|src)\s*=\s*["\']\s*(?:https?:|\/\/)/i', $svg)
        || preg_match('/url\s*\(\s*["\']?\s*(?:https?:|\/\/)/i', $svg)) {
        $unsafeProfileIcons[] = $profile;
    }
}
Checks::that('every provider preset selects its package-owned SVG', $missingProfileIcons, []);
Checks::that('every package-owned provider SVG is small and self-contained', $unsafeProfileIcons, []);
Checks::that('an existing named profile without a saved icon gains the package default', connector([
    'openidconnect_provider_profile' => 'keycloak',
])->iconUrl(), '/api/openidconnect/auth/builtinicon/keycloak');
Checks::that('a named profile may override its package icon for instance branding', connector([
    'openidconnect_provider_profile' => 'keycloak',
    'openidconnect_icon_url' => 'https://id.example.net/brand.svg',
])->iconUrl(), 'https://id.example.net/brand.svg');
Checks::that('named profiles safely queue an unknown first identity for approval', array_values(array_filter(
    array_keys(array_slice($profilePresets, 1, null, true)),
    static fn($profile) => connector([
        'openidconnect_provider_profile' => $profile,
    ])->bootstrapMode() !== 'approval'
)), []);
Checks::that('a fixed Google issuer cannot be replaced by stale configuration', connector([
    'openidconnect_provider_profile' => 'google',
    'openidconnect_provider_url' => 'https://wrong.example.net',
])->issuerUrl(), 'https://accounts.google.com');
Checks::that('an editable GitLab issuer supports a self-managed installation', connector([
    'openidconnect_provider_profile' => 'gitlab',
    'openidconnect_provider_url' => 'https://gitlab.example.net',
])->issuerUrl(), 'https://gitlab.example.net');
$appleProfile = connector([
    'openidconnect_provider_profile' => 'apple',
    'openidconnect_token_auth' => 'client_secret_basic',
    'openidconnect_claims_source' => 'userinfo',
    'openidconnect_response_mode' => 'query',
]);
Checks::that('Apple always exchanges the code with its documented POST method',
    $appleProfile->tokenAuthMethod(), 'client_secret_post');
Checks::that('Apple never tries a UserInfo endpoint it does not publish',
    $appleProfile->claimsSource(), 'id_token');
Checks::that('Apple always receives its scoped response by form POST',
    $appleProfile->responseMode(), 'form_post');
Checks::that('ORCID always requests only its published OpenID scope', connector([
    'openidconnect_provider_profile' => 'orcid',
    'openidconnect_scopes' => 'openid,email,profile',
])->scopes(), ['openid']);
Checks::that('LinkedIn uses the credential placement its authorization-code guide requires', connector([
    'openidconnect_provider_profile' => 'linkedin',
])->tokenAuthMethod(), 'client_secret_post');
Checks::that('recommended values remain overridable where the provider allows it', connector([
    'openidconnect_provider_profile' => 'keycloak',
    'openidconnect_username_claim' => 'email',
    'openidconnect_claims_source' => 'userinfo',
])->usernameClaim() . ':' . connector([
    'openidconnect_provider_profile' => 'keycloak',
    'openidconnect_claims_source' => 'userinfo',
])->claimsSource(), 'email:userinfo');
Checks::that('Microsoft uses one specific tenant unless asked for a broader audience',
    connector(['openidconnect_provider_profile' => 'entra'])->microsoftAudience(), 'tenant');
Checks::that('a Microsoft organizations server gets the canonical tenant-independent authority',
    connector([
        'openidconnect_provider_profile' => 'entra',
        'openidconnect_microsoft_audience' => 'organizations',
        'openidconnect_provider_url' => 'https://wrong.example.net',
    ])->issuerUrl(), 'https://login.microsoftonline.com/organizations/v2.0');
$microsoftCommon = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'common',
]);
Checks::that('Microsoft common publishes the documented tenant issuer template',
    $microsoftCommon->discoveryIssuerTemplate(), 'https://login.microsoftonline.com/{tenantid}/v2.0');
$workIssuer = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0';
$personalIssuer = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';
Checks::that('Microsoft common accepts a structurally exact Entra tenant issuer',
    $microsoftCommon->acceptsMicrosoftIssuerValue($workIssuer), true);
Checks::that('Microsoft common accepts the documented personal-account tenant',
    $microsoftCommon->acceptsMicrosoftIssuerValue($personalIssuer), true);
Checks::that('Microsoft tenant-independent validation rejects lookalike hosts',
    $microsoftCommon->acceptsMicrosoftIssuerValue(
        'https://login.microsoftonline.com.example.net/11111111-2222-3333-4444-555555555555/v2.0'
    ), false);
$organizations = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'organizations',
]);
Checks::that('Microsoft organizations rejects personal accounts',
    $organizations->acceptsMicrosoftIssuerValue($personalIssuer), false);
$consumers = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'consumers',
]);
Checks::that('Microsoft consumers uses its fixed documented Discovery issuer',
    $consumers->discoveryIssuerTemplate(), $personalIssuer);
Checks::that('Microsoft consumers rejects organization tenants',
    $consumers->acceptsMicrosoftIssuerValue($workIssuer), false);
Checks::that('Microsoft token validation binds tid to the exact issuer path', (function () use ($microsoftCommon, $workIssuer) {
    $microsoftCommon->validateMicrosoftIssuer([
        'iss' => $workIssuer,
        'tid' => '11111111-2222-3333-4444-555555555555',
    ], ['issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0']);
    return true;
})(), true);
Checks::throws('Microsoft token validation refuses an issuer/tid mismatch',
    fn() => $microsoftCommon->validateMicrosoftIssuer([
        'iss' => $workIssuer,
        'tid' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ]), 'issuer and tenant');
Checks::throws('Microsoft tenant-independent validation requires a signing-key issuer',
    fn() => $microsoftCommon->validateMicrosoftIssuer([
        'iss' => $workIssuer,
        'tid' => '11111111-2222-3333-4444-555555555555',
    ]), 'signing key has no issuer');
Checks::that('claims are selected automatically unless asked for', connector([])->claimsSource(), 'auto');
Checks::that('authorization answers use query by default', connector([])->responseMode(), 'query');
Checks::that('a provider controls no groups unless explicitly scoped', connector([])->allowsAllGroups(), false);

/* core acts on the lower case spelling and on no other, see the note at defaultGroups() */
Checks::that(
    'default groups arrive in the spelling core compares against',
    connector(['openidconnect_default_groups' => 'Guests, Staff'])->defaultGroups(),
    ['guests', 'staff']
);
Checks::that(
    'assignable groups too',
    connector(['openidconnect_assignable_groups' => 'Admins'])->assignableGroups(),
    ['admins']
);

Checks::group('Telling an address this firewall may fetch from one it may not');
Checks::that('https', OpenIDConnect::isFetchableUrl('https://id.example.net/mark.svg'), true);
Checks::that('http', OpenIDConnect::isFetchableUrl('http://id.example.net/mark.svg'), false);
Checks::that('a local file', OpenIDConnect::isFetchableUrl('file://localhost/conf/config.xml'), false);
Checks::that('ftp', OpenIDConnect::isFetchableUrl('ftp://id.example.net/mark.svg'), false);
Checks::that('a data uri', OpenIDConnect::isFetchableUrl('data:image/svg+xml;base64,AA'), false);
Checks::that('a path', OpenIDConnect::isFetchableUrl('/ui/themes/x/y.svg'), false);
Checks::that('nothing', OpenIDConnect::isFetchableUrl(''), false);
Checks::that(
    'an address with a newline in it, which would be two',
    OpenIDConnect::isFetchableUrl("https://id.example.net/a\nhttps://elsewhere.example.net/b"),
    false
);
Checks::that('an issuer with a query is refused', OpenIDConnect::isIssuerUrl('https://id.example.net/?tenant=x'), false);
Checks::that('a complete discovery URL is accepted as issuer input', OpenIDConnect::isIssuerUrl('https://id.example.net/.well-known/openid-configuration'), true);
Checks::that('an image data uri is an icon', OpenIDConnect::isIconDataUri('data:image/png;base64,AA=='), true);
Checks::that('an HTML data uri is no icon', OpenIDConnect::isIconDataUri('data:text/html;base64,PGgxPng8L2gxPg=='), false);

Checks::group('What the settings form refuses');
$issuer = validator('openidconnect_provider_url');
Checks::that(
    'a syntactically valid unreachable issuer can be saved without Discovery',
    $issuer('https://provider.example.invalid/realms/draft'),
    []
);
Checks::that('an invalid issuer is still refused locally', count($issuer('not a URL')), 1);
Checks::that('an empty issuer is accepted in a disabled draft', $issuer(''), []);
$completeDiscoveryUrl = 'https://id.example.net/realms/firewall/.well-known/openid-configuration';
Checks::that('a complete discovery URL can be saved', $issuer($completeDiscoveryUrl), []);
Checks::that(
    'the issuer input normalizer removes the Discovery suffix',
    OPNsense\OpenIDConnect\ProviderMetadata::normalizeIssuerInput($completeDiscoveryUrl),
    'https://id.example.net/realms/firewall'
);
$discoveryUrlWithQuery = 'https://id.example.net/.well-known/openid-configuration?tenant=x';
Checks::that('a discovery URL carrying a query is still refused', count($issuer($discoveryUrlWithQuery)), 1);

$_POST['type'] = 'openidconnect';
$_POST['openidconnect_enabled'] = 'yes';
$enabledOptions = (new OpenIDConnect())->getConfigurationOptions();
Checks::that('an enabled server requires an issuer', count(
    $enabledOptions['openidconnect_provider_url']['validate']('')
), 1);
Checks::that('an enabled server requires a client ID', count(
    $enabledOptions['openidconnect_client_id']['validate']('')
), 1);
Checks::that('an enabled server requires a client secret', count(
    $enabledOptions['openidconnect_client_secret']['validate']('')
), 1);
Checks::that('an enabled server following OPNsense needs no duplicate address',
    $enabledOptions['openidconnect_redirect_urls']['validate'](''), []);
$_POST['openidconnect_origin_policy'] = 'custom';
Checks::that('an enabled server with a custom policy requires an address', count(
    $enabledOptions['openidconnect_redirect_urls']['validate']('')
), 1);
unset($_POST['type'], $_POST['openidconnect_enabled'], $_POST['openidconnect_origin_policy']);

\OPNsense\Core\Config::reset();
\OPNsense\Core\Config::getInstance()->object()->system->webgui = (object)['protocol' => 'http'];
$_POST['type'] = 'openidconnect';
$_POST['openidconnect_enabled'] = 'yes';
$_POST['openidconnect_origin_policy'] = 'opnsense';
$httpOptions = (new OpenIDConnect())->getConfigurationOptions();
$tlsOffloading = $httpOptions['openidconnect_tls_offloading']['validate'];
Checks::that('an enabled OpenID Connect server is refused on a native HTTP WebGUI',
    count($tlsOffloading('')), 1);
Checks::that('checking offloading is not enough while Follow OPNsense is selected',
    count($tlsOffloading('yes')), 1);
$_POST['openidconnect_origin_policy'] = 'custom';
$_POST['openidconnect_redirect_urls'] = '';
Checks::that('TLS offloading requires an exact public HTTPS origin',
    count($tlsOffloading('yes')), 1);
$_POST['openidconnect_redirect_urls'] = 'https://proxy.example.org:9443';
Checks::that('a complete explicit TLS-offloading exception can be saved enabled',
    $tlsOffloading('yes'), []);
unset($_POST['openidconnect_enabled']);
Checks::that('an incomplete HTTP/offloading configuration can still be saved as a disabled draft',
    $tlsOffloading(''), []);
unset($_POST['type'], $_POST['openidconnect_origin_policy'], $_POST['openidconnect_redirect_urls']);
\OPNsense\Core\Config::reset();

$draftOptions = (new OpenIDConnect())->getConfigurationOptions();
Checks::that('a disabled draft needs no client ID yet', $draftOptions['openidconnect_client_id']['validate'](''), []);
Checks::that('a disabled draft needs no client secret yet', $draftOptions['openidconnect_client_secret']['validate'](''), []);
Checks::that('a disabled draft needs no WebGUI address yet', $draftOptions['openidconnect_redirect_urls']['validate'](''), []);
Checks::that('an issuer alone cannot start a sign-in test', connector([
    'openidconnect_provider_url' => 'https://id.example.net',
    'openidconnect_client_id' => '',
    'openidconnect_client_secret' => '',
])->isSignInTestReady(), false);
Checks::that('an issuer and client ID still cannot start a sign-in test', connector([
    'openidconnect_provider_url' => 'https://id.example.net',
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => '',
])->isSignInTestReady(), false);
Checks::that('a complete confidential client can start a sign-in test', connector([
    'openidconnect_provider_url' => 'https://id.example.net',
    'openidconnect_client_id' => 'client-id',
    'openidconnect_client_secret' => 'secret',
])->isSignInTestReady(), true);
Checks::that('a new server follows OPNsense WebGUI names',
    $draftOptions['openidconnect_origin_policy']['default'], 'opnsense');

$icon = validator('openidconnect_icon_svg');
Checks::that('an empty icon is fine', $icon(''), []);
Checks::that('an svg is fine', $icon('<svg viewBox="0 0 1 1"><path d="M0 0"/></svg>'), []);
Checks::that('something that is not an svg', count($icon('hello')), 1);
Checks::that('an svg carrying a script', count($icon('<svg><script>alert(1)</script></svg>')), 1);
Checks::that('an svg carrying an event handler', count($icon('<svg onload="x()"><path d="M0 0"/></svg>')), 1);
Checks::that('an icon larger than 64 kB', count($icon('<svg ' . str_repeat('x', 70000) . '>')), 1);

$urls = validator('openidconnect_redirect_urls');
Checks::that(
    'two addresses',
    $urls("https://a.example.net\nhttps://b.example.net:8443"),
    []
);
Checks::that('something that is not an address', count($urls('https://ok.example.net/x, not-a-url')), 1);
Checks::that('a full callback path is refused in an origin field', count($urls('https://ok.example.net/x')), 1);
Checks::that(
    'a callback path receives an origin-only explanation',
    str_contains($urls('https://ok.example.net/api/callback')[0], 'without a path'),
    true
);
/* An incomplete disabled draft accepts nothing at runtime and can be finished later. */
Checks::that('no address at all in a disabled draft', $urls(''), []);

$iconUrl = validator('openidconnect_icon_url');
Checks::that('no icon at all is fine', $iconUrl(''), []);
Checks::that('an address', $iconUrl('https://id.example.net/mark.svg'), []);
Checks::that('a path on this firewall', $iconUrl('/ui/themes/x/mark.svg'), []);
Checks::that('a data uri', $iconUrl('data:image/svg+xml;base64,AA=='), []);
Checks::that('a non-image data uri', count($iconUrl('data:text/html;base64,PGgxPng8L2gxPg==')), 1);
Checks::that('something curl would fetch but a browser would not', count($iconUrl('file:///conf/config.xml')), 1);
/* it ends up inside a css url() on the page that is served before anyone has signed in */
Checks::that('an address carrying a newline', count($iconUrl("/mark.svg\n\") } body { display:none")), 1);

$buttonMode = validator('openidconnect_button_text_mode');
Checks::that('a known button wording mode', $buttonMode('label_only'), []);
Checks::that('an unknown button wording mode', count($buttonMode('sentence-ish')), 1);
$buttonLabel = validator('openidconnect_button_provider_label');
Checks::that('an empty optional button label follows Descriptive name', $buttonLabel(''), []);
Checks::that('a plain installation-specific button label', $buttonLabel('Company SSO'), []);
Checks::that('button labels refuse HTML', count($buttonLabel('<strong>Company SSO</strong>')), 1);
Checks::that('button labels refuse control characters', count($buttonLabel("Company\nSSO")), 1);
Checks::that('button labels are bounded', count($buttonLabel(str_repeat('x', 81))), 1);
$_POST['type'] = 'openidconnect';
$_POST['openidconnect_button_text_mode'] = 'custom';
$customButtonText = (new OpenIDConnect())->getConfigurationOptions()['openidconnect_button_custom_text']['validate'];
Checks::that('custom wording requires a complete literal text', count($customButtonText('')), 1);
Checks::that('custom wording accepts plain text', $customButtonText('Continue through the identity portal'), []);
Checks::that('custom wording refuses HTML', count($customButtonText('<em>Continue</em>')), 1);
Checks::that('custom wording is bounded', count($customButtonText(str_repeat('x', 121))), 1);
$_POST['openidconnect_button_text_mode'] = 'localized';
Checks::that('unused custom wording may remain empty', $customButtonText(''), []);
unset($_POST['type'], $_POST['openidconnect_button_text_mode']);

\OPNsense\Core\Config::reset();
\OPNsense\Core\Config::getInstance()->addAuthServer([
    'name' => 'first', 'type' => 'openidconnect', 'openidconnect_app_code' => 'shared',
]);
$newServer = new OpenIDConnect();
$newServer->setProperties(['name' => 'second']);
$applicationCode = $newServer->getConfigurationOptions()['openidconnect_app_code']['validate'];
Checks::that('a unique application code', $applicationCode('second'), []);
Checks::that('a duplicate application code', count($applicationCode('shared')), 1);
Checks::that('application code uniqueness ignores capitalization', count($applicationCode('SHARED')), 1);
Checks::that('a URL dot segment is not an application code', count($applicationCode('..')), 1);
Checks::that(
    'a duplicate application code names the conflicting authentication server',
    str_contains($applicationCode('shared')[0], 'first'),
    true
);
$existingServer = new OpenIDConnect();
$existingServer->setProperties(['name' => 'first']);
$existingCode = $existingServer->getConfigurationOptions()['openidconnect_app_code']['validate'];
Checks::that('an existing server keeps its own application code', $existingCode('shared'), []);
$_POST['id'] = '0';
$coreFormConnector = new OpenIDConnect();
$coreFormCode = $coreFormConnector->getConfigurationOptions()['openidconnect_app_code']['validate'];
Checks::that('the core edit form identifies that server only by its posted row id', $coreFormCode('shared'), []);
$_POST['id'] = '1';
Checks::that('a posted id cannot exempt a different server row', count($coreFormCode('shared')), 1);
unset($_POST['id']);
$_GET['act'] = 'edit';
$_GET['id'] = '0';
Checks::that('the OPNsense 26.7 edit URL identifies the existing server row', $coreFormCode('shared'), []);
$_GET['act'] = 'new';
Checks::that('an id outside an edit action cannot exempt a server row', count($coreFormCode('shared')), 1);
unset($_GET['act'], $_GET['id']);

\OPNsense\Core\Config::reset();
\OPNsense\Core\Config::getInstance()->addAuthServer([
    'name' => 'local', 'type' => 'local',
]);
\OPNsense\Core\Config::getInstance()->addAuthServer([
    'name' => 'oidc', 'type' => 'openidconnect', 'openidconnect_app_code' => 'after-local',
]);
$_POST['id'] = '1';
$mixedServerCode = (new OpenIDConnect())->getConfigurationOptions()['openidconnect_app_code']['validate'];
Checks::that(
    'the core row id counts non-OIDC authentication servers too',
    $mixedServerCode('after-local'),
    []
);
unset($_POST['id']);

Checks::that(
    'a subject binding cannot occur twice because runtime would otherwise refuse it as ambiguous',
    count(OpenIDConnect::validateBindings("same-subject = first\nsame-subject = second")),
    1
);
Checks::that('the raw subject-binding text field is no longer rendered',
    array_key_exists('openidconnect_subject_bindings', (new OpenIDConnect())->getConfigurationOptions()), false);
Checks::that('a valid opaque subject is accepted by the identity manager',
    OpenIDConnect::normalizeSubjectIdentifier('opaque.Pairwise-Subject_123'), 'opaque.Pairwise-Subject_123');
Checks::that('an empty subject is refused by the identity manager',
    OpenIDConnect::normalizeSubjectIdentifier(''), null);
Checks::that('a subject with a control character is refused by the identity manager',
    OpenIDConnect::normalizeSubjectIdentifier("subject\nother"), null);
Checks::that('a subject longer than the runtime claim boundary is refused',
    OpenIDConnect::normalizeSubjectIdentifier(str_repeat('s', 256)), null);

$emailMatch = validator('openidconnect_email_match');
Checks::that('a known e-mail matching mode', $emailMatch('always'), []);
Checks::that('an unset one, which means the default', $emailMatch(''), []);
Checks::that('one that is not a mode', count($emailMatch('sometimes')), 1);

$ageOptions = (new OPNsense\Auth\OpenIDConnect())->getConfigurationOptions()['openidconnect_max_age'];
$age = $ageOptions['validate'];
Checks::that('the displayed default is four hours', $ageOptions['default'], '14400');
Checks::that('an empty age is refused', count($age('')), 1);
Checks::that('a number', $age('43200'), []);
Checks::that('not a number', count($age('soon')), 1);
Checks::that('zero requests re-authentication every time', $age('0'), []);

$savedPost = $_POST;
$_POST = [
    'type' => 'openidconnect',
    'openidconnect_enabled' => '1',
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'tenant',
    'openidconnect_required_authentication' => 'multi-factor',
];
$strengthOptions = (new OpenIDConnect())->getConfigurationOptions();
$requiredAuthentication = $strengthOptions['openidconnect_required_authentication']['validate'];
$entraContext = $strengthOptions['openidconnect_entra_auth_context']['validate'];
Checks::that('the two supported authentication policies can be saved', $requiredAuthentication('multi-factor'), []);
Checks::that('the removed passwordless category is refused', count($requiredAuthentication('passwordless')), 1);
Checks::that('an enabled Entra requirement needs its tenant context', count($entraContext('')), 1);
Checks::that('the first Microsoft authentication context is accepted', $entraContext('c1'), []);
Checks::that('the last Microsoft authentication context is accepted', $entraContext('c25'), []);
Checks::that('a Microsoft context outside the tenant range is refused', count($entraContext('c26')), 1);
$_POST['openidconnect_microsoft_audience'] = 'organizations';
Checks::that(
    'the form refuses tenant-local context semantics for a broad Microsoft audience',
    count($requiredAuthentication('multi-factor')),
    1
);
$_POST['openidconnect_enabled'] = '0';
$_POST['openidconnect_microsoft_audience'] = 'tenant';
Checks::that('a disabled Entra draft may leave its context incomplete', $entraContext(''), []);
$_POST = $savedPost;

$acrValues = validator('openidconnect_acr_values');
$amrValues = validator('openidconnect_amr_values');
Checks::that('several exact ACR values are accepted', $acrValues("phr\nphrh"), []);
Checks::that('an ACR value containing spaces is refused', count($acrValues('not an acr')), 1);
Checks::that('a bounded provider-specific AMR value is accepted', $amrValues('company-key'), []);
Checks::that('an AMR value containing a control character is refused', count($amrValues("fido\tother")), 1);
