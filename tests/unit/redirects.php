<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Mvc\Request;
use OPNsense\OpenIDConnect\RelyingParty;

/**
 * The address the provider is sent back to decides whether a login can finish at all. It
 * is an allow list, and a name that is not on it has to be refused rather than sent
 * somewhere it has no session - an empty list therefore accepts nothing, rather than
 * accepting every name a browser cares to ask under.
 */
Checks::group('Choosing the address the provider returns to');

$listed = [
    'openidconnect_redirect_urls' => "https://firewall.example.net/api/openidconnect/auth/callback\n"
        . 'https://firewall.example.net:8443/api/openidconnect/auth/callback',
];

Checks::that(
    'the address implied by the name the browser used',
    RelyingParty::intendedRedirectUri(new Request('https', 'firewall.example.net')),
    'https://firewall.example.net/api/openidconnect/auth/callback'
);

Checks::that(
    'a listed name is matched',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net')),
    'https://firewall.example.net/api/openidconnect/auth/callback'
);
Checks::that(
    'the port is part of the name, so the other entry is chosen',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net:8443')),
    'https://firewall.example.net:8443/api/openidconnect/auth/callback'
);
Checks::that(
    'a name that is not listed is refused',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', '192.0.2.1:8443')),
    null
);
Checks::that(
    'a look-alike name is refused',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net.evil.test')),
    null
);
Checks::that(
    'http is not https',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('http', 'firewall.example.net')),
    null
);
Checks::that(
    'a trailing slash in the list does not matter',
    RelyingParty::acceptedRedirectUri(
        connector(['openidconnect_redirect_urls' => 'https://firewall.example.net/api/openidconnect/auth/callback/']),
        new Request('https', 'firewall.example.net')
    ),
    'https://firewall.example.net/api/openidconnect/auth/callback/'
);
Checks::that(
    'an empty list accepts nothing at all',
    RelyingParty::acceptedRedirectUri(connector([]), new Request('https', 'anything.example.net')),
    null
);
/**
 * The name the browser used has to be a name before it is matched against anything - a
 * header carrying a newline is two values pretending to be one.
 */
$byAddress = [
    'openidconnect_redirect_urls' => "https://192.0.2.1:8443/api/openidconnect/auth/callback\n"
        . 'https://[2001:db8::1]:8443/api/openidconnect/auth/callback',
];

Checks::that(
    'a Host header with a newline in it is not a name',
    RelyingParty::acceptedRedirectUri(
        connector($listed),
        new Request('https', "firewall.example.net\r\nX-Anything: 1")
    ),
    null
);
Checks::that(
    'nor is one with a space',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net /x')),
    null
);
Checks::that(
    'nor an empty one',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', '')),
    null
);
Checks::that(
    'an address with a port is a name',
    RelyingParty::acceptedRedirectUri(connector($byAddress), new Request('https', '192.0.2.1:8443')),
    'https://192.0.2.1:8443/api/openidconnect/auth/callback'
);
Checks::that(
    'and so is a bracketed IPv6 address',
    RelyingParty::acceptedRedirectUri(connector($byAddress), new Request('https', '[2001:db8::1]:8443')),
    'https://[2001:db8::1]:8443/api/openidconnect/auth/callback'
);

