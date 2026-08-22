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

/**
 * A provider url may be given either way round. Getting this wrong once turned every
 * bare issuer into an empty string, which failed later and elsewhere.
 */
Checks::group('Finding the issuer in whatever was typed');
Checks::that(
    'a bare issuer is left alone',
    connector(['openidconnect_provider_url' => 'https://id.example.net/application/o/fw/'])->issuerUrl(),
    'https://id.example.net/application/o/fw/'
);
Checks::that(
    'a discovery url is cut back to the issuer',
    connector(['openidconnect_provider_url' => 'https://id.example.net/fw/.well-known/openid-configuration'])->issuerUrl(),
    'https://id.example.net/fw/'
);

Checks::group('Defaults when a field is left empty');
Checks::that('scopes', connector([])->scopes(), ['openid', 'email', 'profile']);
Checks::that('scopes as configured', connector(['openidconnect_scopes' => 'openid,groups'])->scopes(), ['openid', 'groups']);
Checks::that('username claim', connector([])->usernameClaim(), 'preferred_username');
Checks::that('button style', connector([])->buttonStyle(), 'button');
Checks::that('button style, nonsense value', connector(['openidconnect_button_style' => 'wobble'])->buttonStyle(), 'button');
Checks::that('icon rendering', connector([])->iconMode(), 'monochrome');
Checks::that('maximum age, unset', connector([])->maximumAuthenticationAge(), 0);
Checks::that('maximum age, set', connector(['openidconnect_max_age' => '3600'])->maximumAuthenticationAge(), 3600);
Checks::that('maximum age, not a number', connector(['openidconnect_max_age' => 'soon'])->maximumAuthenticationAge(), 0);
Checks::that('token auth, unset', connector([])->tokenAuthMethod(), null);
Checks::that(
    'token auth, insisted on',
    connector(['openidconnect_token_auth' => 'client_secret_post'])->tokenAuthMethod(),
    'client_secret_post'
);
Checks::that('token auth, nonsense value', connector(['openidconnect_token_auth' => 'wobble'])->tokenAuthMethod(), null);
Checks::that('group claim is off unless asked for', connector([])->groupClaim(), '');
Checks::that('tracing is off unless asked for', connector([])->isTracing(), false);
Checks::that('e-mail matching asks the provider to have checked', connector([])->emailMatching(), 'verified');
Checks::that(
    'e-mail matching, nonsense value',
    connector(['openidconnect_email_match' => 'wobble'])->emailMatching(),
    'verified'
);
Checks::that('root is out of reach unless asked for', connector([])->allowsRoot(), false);

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
Checks::that('http', OpenIDConnect::isFetchableUrl('http://id.example.net/mark.svg'), true);
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

Checks::group('What the settings form refuses');
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
    $urls("https://a.example.net/api/openidconnect/auth/callback\nhttps://b.example.net/api/openidconnect/auth/callback"),
    []
);
Checks::that('something that is not an address', count($urls('https://ok.example.net/x, not-a-url')), 1);
/* an empty list would accept nothing, so it is refused where somebody can still fix it */
Checks::that('no address at all', count($urls('')), 1);

$iconUrl = validator('openidconnect_icon_url');
Checks::that('no icon at all is fine', $iconUrl(''), []);
Checks::that('an address', $iconUrl('https://id.example.net/mark.svg'), []);
Checks::that('a path on this firewall', $iconUrl('/ui/themes/x/mark.svg'), []);
Checks::that('a data uri', $iconUrl('data:image/svg+xml;base64,AA=='), []);
Checks::that('something curl would fetch but a browser would not', count($iconUrl('file:///conf/config.xml')), 1);
/* it ends up inside a css url() on the page that is served before anyone has signed in */
Checks::that('an address carrying a newline', count($iconUrl("/mark.svg\n\") } body { display:none")), 1);

$emailMatch = validator('openidconnect_email_match');
Checks::that('a known e-mail matching mode', $emailMatch('always'), []);
Checks::that('an unset one, which means the default', $emailMatch(''), []);
Checks::that('one that is not a mode', count($emailMatch('sometimes')), 1);

$age = validator('openidconnect_max_age');
Checks::that('an empty age is fine', $age(''), []);
Checks::that('a number', $age('43200'), []);
Checks::that('not a number', count($age('soon')), 1);
Checks::that('zero', count($age('0')), 1);
