<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Auth\SSOProviders\OpenIDConnectContainer;

$container = new OpenIDConnectContainer();
$loginUri = '/api/openidconnect/auth/login?provider=example';

/**
 * Three ways to name an icon, and the one that never leaves the firewall matters most: an
 * absolute address is fetched and handed on, everything else the browser resolves itself.
 */
Checks::group('Where the login button gets its icon');
Checks::that(
    'nothing configured, nothing shown',
    inspect($container, 'iconAddress', connector([]), 'example'),
    ''
);
Checks::that(
    'a path on this firewall is used as it stands',
    inspect($container, 'iconAddress', connector(['openidconnect_icon_url' => '/ui/themes/x/mark.svg']), 'example'),
    '/ui/themes/x/mark.svg'
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
Checks::that('a button names the provider', str_contains($button, 'Login with Example Provider'), true);
Checks::that('a button brings its styles', str_contains($button, '.login-sso-link-container'), true);
Checks::that('no icon configured, no icon element', preg_match('/<(span|img)[^>]*login-sso-mark/', $button), 0);

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

$custom = inspect(
    $container,
    'entryMarkup',
    connector([
            'openidconnect_custom_button' => '<a href="%url%" title="%name%"><img src="%icon%"></a>',
            'openidconnect_icon_url' => '/mark.svg',
        ]),
    'Example',
    $loginUri
);
Checks::that(
    'a custom button gets its placeholders filled',
    $custom,
    '<a href="' . $loginUri . '" title="Example"><img src="/mark.svg"></a>'
);

/* a provider name is written by whoever configures the server, but it still ends up in a
   page served before anyone has signed in, so it is escaped rather than trusted */
$hostile = inspect($container, 'entryMarkup', connector([]), 'x"><script>alert(1)</script>', $loginUri);
Checks::that('a provider name cannot open a tag', str_contains($hostile, '<script>'), false);
Checks::that('a provider name is escaped', str_contains($hostile, '&lt;script&gt;'), true);
