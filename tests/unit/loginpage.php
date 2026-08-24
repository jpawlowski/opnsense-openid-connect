<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Auth\SSOProviders\OpenIDConnectContainer;
use OPNsense\Auth\OpenIDConnect;

$container = new OpenIDConnectContainer();
$loginUri = '/api/openidconnect/auth/login?provider=example';

/**
 * Three ways to name an icon, and the one that never leaves the firewall matters most: an
 * absolute address is fetched and handed on, everything else the browser resolves itself.
 */
Checks::group('Where the login button gets its icon');
Checks::that(
    'the Generic profile default never leaves this firewall',
    inspect($container, 'iconAddress', connector([]), 'example'),
    '/api/openidconnect/auth/builtinicon/general'
);
Checks::that(
    'a path on this firewall is used as it stands',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_url' => '/ui/themes/x/mark.svg']), 'example'),
    '/ui/themes/x/mark.svg'
);
Checks::that(
    'a named profile package icon never leaves this firewall',
    inspect(
        $container,
        'iconAddress',
        connector(['openidconnect_icon_url' => OpenIDConnect::providerIconUrl('keycloak')]),
        'example'
    ),
    '/api/openidconnect/auth/builtinicon/keycloak'
);
Checks::that(
    'a data uri is passed through',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_url' => 'data:image/svg+xml;base64,QQ==']), 'example'),
    'data:image/svg+xml;base64,QQ=='
);
Checks::that(
    'an address elsewhere is fetched by the firewall instead',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_url' => 'https://id.example.net/mark.svg']), 'example'),
    '/api/openidconnect/auth/icon?provider=example'
);
Checks::that(
    'markup becomes a data uri and never reaches the page as markup',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_svg' => '<svg/>']), 'example'),
    'data:image/svg+xml;base64,' . base64_encode('<svg/>')
);
/* the address is written into a css url() on a page served before anyone has signed in */
Checks::that(
    'an address carrying a newline is no icon at all',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_url' => "/mark.svg\n\") } body{display:none"]), 'example'),
    ''
);
Checks::that(
    'markup wins over an address',
    inspect(
        $container,
        'iconAddress',
        connector(['openidconnect_icon_svg' => '<svg/>', 'openidconnect_icon_url' => 'https://id.example.net/mark.svg']),
        'example'
    ),
    'data:image/svg+xml;base64,' . base64_encode('<svg/>')
);

Checks::group('What the login page is handed');
Checks::that(
    'the link style leaves it to core',
    inspect($container, 'entryMarkup', connector(['openidconnect_button_style' => 'link']), 'example', $loginUri),
    null
);

$button = inspect($container, 'entryMarkup', connector([]), 'Example Provider', $loginUri);
Checks::that('a button carries the login address', str_contains($button, 'href="' . htmlspecialchars($loginUri, ENT_QUOTES) . '"'), true);
Checks::that('a button reuses the localized OPNsense login sentence',
    str_contains($button, 'Login using Example Provider'), true);
Checks::that('a button brings its styles', str_contains($button, '.login-sso-link-container'), true);
Checks::that('the Generic profile contributes its neutral icon',
    str_contains($button, 'mask: url("/api/openidconnect/auth/builtinicon/general")'), true);

$renamed = inspect($container, 'entryMarkup', connector([
    'openidconnect_button_provider_label' => 'Company SSO',
]), 'Technical server name', $loginUri);
Checks::that('the localized sentence may name something other than Descriptive name',
    str_contains($renamed, 'Login using Company SSO'), true);
$labelOnly = inspect($container, 'entryMarkup', connector([
    'openidconnect_button_text_mode' => 'label_only',
    'openidconnect_button_provider_label' => 'Company SSO',
]), 'Technical server name', $loginUri);
Checks::that('provider-label-only wording omits the OPNsense sentence',
    str_contains($labelOnly, '>Company SSO</a>'), true);
Checks::that('provider-label-only wording contains no login prefix',
    str_contains($labelOnly, 'Login using'), false);
$customText = inspect($container, 'entryMarkup', connector([
    'openidconnect_button_text_mode' => 'custom',
    'openidconnect_button_custom_text' => 'Continue through the identity portal',
]), 'Technical server name', $loginUri);
Checks::that('custom wording replaces the complete visible string',
    str_contains($customText, '>Continue through the identity portal</a>'), true);
$globalService = inspect($container, 'entryMarkup', connector([
    'openidconnect_provider_profile' => 'google',
    'openidconnect_button_text_mode' => 'custom',
    'openidconnect_button_custom_text' => 'Anything else',
]), 'Internal Google server row', $loginUri);
Checks::that('a global public service always uses its conventional short label',
    str_contains($globalService, '>Google</a>'), true);

$_GET['url'] = '/ui/dashboard';
$targeted = inspect($container, 'entryMarkup', connector([
    'openidconnect_button_text_mode' => 'label_only',
]), 'Example Provider', $loginUri);
Checks::that('custom-rendered wording preserves the local page target core normally adds',
    str_contains($targeted, 'redir=%2Fui%2Fdashboard'), true);
unset($_GET['url']);
Checks::that(
    'a missing local page target leaves the login address unchanged',
    inspect($container, 'withLocalTarget', $loginUri),
    $loginUri
);

$tinted = inspect($container, 'entryMarkup', connector(['openidconnect_icon_url' => '/mark.svg']), 'x', $loginUri);
Checks::that('a single colour icon is drawn as a mask', str_contains($tinted, 'mask: url("/mark.svg")'), true);
Checks::that('a single colour icon follows the text colour', str_contains($tinted, 'currentColor'), true);

$original = inspect(
    $container,
    'entryMarkup',
    connector(['openidconnect_icon_url' => '/mark.svg', 'openidconnect_icon_mode' => 'original']),
    'x',
    $loginUri
);
Checks::that('an original colour icon is an image', str_contains($original, '<img class="login-sso-mark" src="/mark.svg"'), true);

/* a provider name is written by whoever configures the server, but it still ends up in a
   page served before anyone has signed in, so it is escaped rather than trusted */
$hostile = inspect($container, 'entryMarkup', connector([]), 'x"><script>alert(1)</script>', $loginUri);
Checks::that('a provider name cannot open a tag', str_contains($hostile, '<script>'), false);
Checks::that('a provider name is escaped', str_contains($hostile, '&lt;script&gt;'), true);
