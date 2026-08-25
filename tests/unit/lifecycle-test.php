<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\LifecycleTestRegistry;

Checks::group('Disposable browser lifecycle tests');

@unlink((string)constant('OPENIDCONNECT_TEST_LIFECYCLE_REGISTRY'));
$testId = LifecycleTestRegistry::create(
    'main',
    'Office identity',
    'https://id.example.net',
    'opaque-subject',
    'provider-session',
    'signed.id.token',
    'https://firewall.example.net/api/openidconnect/auth/logouttestcallback/main',
    '/system_authservers.php?act=edit&id=3',
    ['frontchannel', 'backchannel']
);
Checks::that('a lifecycle test receives an unguessable URL-safe identifier',
    (bool)preg_match('/^[A-Za-z0-9_-]{43}$/D', $testId), true);
$initial = LifecycleTestRegistry::status($testId);
Checks::that('the configured channels begin unobserved and testable', [
    $initial['expected'],
    $initial['testable'],
    $initial['observed'],
    $initial['started'],
], [
    ['frontchannel', 'backchannel'],
    ['frontchannel' => true, 'backchannel' => true],
    [],
    null,
]);
$stored = (string)file_get_contents((string)constant('OPENIDCONNECT_TEST_LIFECYCLE_REGISTRY'));
Checks::that('the short-lived registry retains the ID Token needed for RP-initiated logout',
    str_contains($stored, 'signed.id.token'), true);
Checks::that('opaque identity values are retained only as digests', [
    str_contains($stored, 'opaque-subject'),
    str_contains($stored, 'provider-session'),
], [false, false]);

LifecycleTestRegistry::observe(
    'main', 'frontchannel', 'https://id.example.net', 'provider-session', null
);
Checks::that('a notification before the authenticated logout start proves nothing',
    LifecycleTestRegistry::status($testId)['observed'], []);
$start = LifecycleTestRegistry::start($testId);
Checks::that('only the authenticated start receives the secret-bearing logout material', [
    $start['provider'],
    $start['issuer'],
    $start['id_token'],
    $start['return_uri'],
], [
    'Office identity',
    'https://id.example.net',
    'signed.id.token',
    'https://firewall.example.net/api/openidconnect/auth/logouttestcallback/main',
]);
Checks::that('the one-time start atomically removes the persisted ID Token', str_contains(
    (string)file_get_contents((string)constant('OPENIDCONNECT_TEST_LIFECYCLE_REGISTRY')),
    'signed.id.token'
), false);
Checks::throws('the same lifecycle logout cannot be started twice',
    fn() => LifecycleTestRegistry::start($testId), 'already started');

LifecycleTestRegistry::observe('other', 'frontchannel', 'https://id.example.net', 'provider-session', null);
LifecycleTestRegistry::observe('main', 'frontchannel', 'https://other.example.net', 'provider-session', null);
LifecycleTestRegistry::observe('main', 'frontchannel', 'https://id.example.net', 'other-session', null);
LifecycleTestRegistry::observe(
    'main', 'backchannel', 'https://id.example.net', 'other-session', 'opaque-subject'
);
Checks::that('lookalike logout notifications cannot satisfy the test',
    LifecycleTestRegistry::status($testId)['observed'], []);
LifecycleTestRegistry::observe('main', 'frontchannel', 'https://id.example.net', 'provider-session', null);
LifecycleTestRegistry::observe('main', 'backchannel', 'https://id.example.net', null, 'opaque-subject');
$observed = LifecycleTestRegistry::status($testId)['observed'];
Checks::that('both independently validated configured logout channels can be observed', [
    is_int($observed['frontchannel'] ?? null),
    is_int($observed['backchannel'] ?? null),
], [true, true]);
Checks::throws('a return under another application code is refused',
    fn() => LifecycleTestRegistry::returned($testId, 'other'), 'does not match');
Checks::that('the exact provider return retains the saved authentication-server row',
    LifecycleTestRegistry::returned($testId, 'main'), '/system_authservers.php?act=edit&id=3');
Checks::that('the result reports the provider return without exposing the ID Token', [
    is_int(LifecycleTestRegistry::status($testId)['returned']),
    array_key_exists('id_token', LifecycleTestRegistry::status($testId)),
], [true, false]);

$noSid = LifecycleTestRegistry::create(
    'without-sid',
    'Office identity',
    'https://id.example.net',
    'another-subject',
    '',
    'another.id.token',
    'https://firewall.example.net/api/openidconnect/auth/logouttestcallback/without-sid',
    '/system_authservers.php',
    ['frontchannel']
);
Checks::that('front-channel logout is reported as untestable when the ID Token has no sid',
    LifecycleTestRegistry::status($noSid)['testable']['frontchannel'], false);
Checks::throws('a lifecycle test cannot redirect an administrator outside the saved server pages', function (): void {
    LifecycleTestRegistry::create(
        'unsafe',
        'Office identity',
        'https://id.example.net',
        'subject',
        'sid',
        'id.token',
        'https://firewall.example.net/api/openidconnect/auth/logouttestcallback/unsafe',
        '//other.example.net',
        []
    );
}, 'cannot be stored safely');
