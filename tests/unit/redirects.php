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
    'openidconnect_redirect_urls' => "https://firewall.example.net\n"
        . 'https://firewall.example.net:8443',
];
$listedSettings = connector($listed);

Checks::that(
    'the address implied by the name the browser used',
    RelyingParty::intendedRedirectUri($listedSettings, new Request('https', 'firewall.example.net')),
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);

Checks::that(
    'a listed name is matched',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net')),
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
);
Checks::that(
    'the port is part of the name, so the other entry is chosen',
    RelyingParty::acceptedRedirectUri(connector($listed), new Request('https', 'firewall.example.net:8443')),
    'https://firewall.example.net:8443/api/openidconnect/auth/callback/main'
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
        connector(['openidconnect_redirect_urls' => 'https://firewall.example.net/']),
        new Request('https', 'firewall.example.net')
    ),
    'https://firewall.example.net/api/openidconnect/auth/callback/main'
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
    'openidconnect_redirect_urls' => "https://192.0.2.1:8443\n"
        . 'https://[2001:db8::1]:8443',
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
    'https://192.0.2.1:8443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'and so is a bracketed IPv6 address',
    RelyingParty::acceptedRedirectUri(connector($byAddress), new Request('https', '[2001:db8::1]:8443')),
    'https://[2001:db8::1]:8443/api/openidconnect/auth/callback/main'
);

\OPNsense\Core\Config::reset();
$system = \OPNsense\Core\Config::getInstance()->object()->system;
$system->hostname = 'firewall';
$system->domain = 'example.net';
$system->webgui = (object)[
    'althostnames' => 'admin.example.net secondary.example.net 198.51.100.9',
    'port' => '8443',
];
\OidcTestNetwork::$virtualIps = [['subnet' => '198.51.100.8']];
$inherited = connector(['openidconnect_origin_policy' => 'opnsense']);
Checks::that(
    'the normal OPNsense hostname, domain and configured port need no duplicate OIDC setting',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'firewall.example.net:8443')),
    'https://firewall.example.net:8443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'the OPNsense short hostname is inherited too',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'firewall:8443')),
    'https://firewall:8443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'an OPNsense alternate hostname uses the configured WebGUI port',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'admin.example.net:8443')),
    'https://admin.example.net:8443/api/openidconnect/auth/callback/main'
);
Checks::that('a different external port needs an explicit additional or custom origin',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'admin.example.net:9443')), null);
Checks::that('standard HTTPS stays closed for inherited names unless it is explicitly enabled',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'admin.example.net')), null);
$standardHttps = connector([
    'openidconnect_origin_policy' => 'opnsense',
    'openidconnect_standard_https_port' => '1',
]);
Checks::that('the standard-port option adds the configured fully qualified hostname',
    RelyingParty::acceptedRedirectUri($standardHttps, new Request('https', 'firewall.example.net')),
    'https://firewall.example.net/api/openidconnect/auth/callback/main');
Checks::that('the standard-port option adds configured alternate DNS hostnames',
    RelyingParty::acceptedRedirectUri($standardHttps, new Request('https', 'admin.example.net')),
    'https://admin.example.net/api/openidconnect/auth/callback/main');
Checks::that('the standard-port option does not widen an alternate IP address',
    RelyingParty::acceptedRedirectUri($standardHttps, new Request('https', '198.51.100.9')), null);
Checks::that('the standard-port option does not widen a local interface address',
    RelyingParty::acceptedRedirectUri($standardHttps, new Request('https', '192.0.2.1')), null);
Checks::that(
    'following OPNsense does not mean trusting an arbitrary Host header',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', 'unlisted.example.net')),
    null
);
Checks::that(
    'a real local interface address is inherited',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', '192.0.2.1:8443')),
    'https://192.0.2.1:8443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'an arbitrary IP literal is not trusted',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', '198.51.100.1:8443')),
    null
);
Checks::that(
    'a configured virtual IP is inherited',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', '198.51.100.8:8443')),
    'https://198.51.100.8:8443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'a globally usable local IPv6 address is bracketed',
    RelyingParty::acceptedRedirectUri($inherited, new Request('https', '[2001:db8::1]:8443')),
    'https://[2001:db8::1]:8443/api/openidconnect/auth/callback/main'
);
Checks::that('loopback is not exported as a provider redirect origin',
    in_array('https://127.0.0.1:8443', $inherited->opnsenseWebGuiOrigins(), true), false);

$withAdditional = connector([
    'openidconnect_origin_policy' => 'opnsense',
    'openidconnect_redirect_urls' => 'https://proxy.example.org:9443',
]);
Checks::that(
    'follow mode supplements OPNsense with an additional reverse-proxy origin',
    RelyingParty::acceptedRedirectUri($withAdditional, new Request('https', 'proxy.example.org:9443')),
    'https://proxy.example.org:9443/api/openidconnect/auth/callback/main'
);
Checks::that(
    'custom mode replaces rather than supplements OPNsense origins',
    RelyingParty::acceptedRedirectUri(connector([
        'openidconnect_origin_policy' => 'custom',
        'openidconnect_redirect_urls' => 'https://proxy.example.org:9443',
    ]), new Request('https', 'firewall.example.net:8443')),
    null
);
Checks::that('explicit HTTPS port 443 normalizes to the standard origin',
    \OPNsense\Auth\OpenIDConnect::normalizeHttpsOrigin('https://FIREWALL.example.net:443/'),
    'https://firewall.example.net');

$system->webgui->protocol = 'http';
$blockedHttp = connector([
    'openidconnect_enabled' => '1',
    'openidconnect_origin_policy' => 'opnsense',
]);
Checks::that('native HTTP produces no invented HTTPS OPNsense origins',
    $blockedHttp->opnsenseWebGuiOrigins(), []);
Checks::that('an enabled provider fails closed after the WebGUI is changed to HTTP',
    $blockedHttp->isEnabled(), false);
Checks::that('a forwarded-proto header cannot turn an ordinary HTTP request into HTTPS',
    RelyingParty::acceptedRedirectUri(
        $blockedHttp,
        new Request('http', 'firewall.example.net:8443', [], [], ['X-Forwarded-Proto' => 'https'])
    ),
    null
);

$offloaded = connector([
    'openidconnect_enabled' => '1',
    'openidconnect_tls_offloading' => '1',
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://proxy.example.org:9443',
]);
Checks::that('a complete explicit TLS-offloading exception enables the provider',
    $offloaded->isEnabled(), true);
Checks::that('the trusted HTTP backend request renders the exact public HTTPS callback',
    RelyingParty::acceptedRedirectUri($offloaded, new Request('http', 'proxy.example.org:9443')),
    'https://proxy.example.org:9443/api/openidconnect/auth/callback/main'
);
Checks::that('TLS offloading still refuses an arbitrary Host header',
    RelyingParty::acceptedRedirectUri($offloaded, new Request('http', 'unlisted.example.org:9443')),
    null
);
Checks::that('offloading without Custom origins remains blocked', connector([
    'openidconnect_tls_offloading' => '1',
    'openidconnect_origin_policy' => 'opnsense',
    'openidconnect_redirect_urls' => 'https://proxy.example.org:9443',
])->isWebGuiTransportReady(), false);
\OPNsense\Core\Config::reset();
