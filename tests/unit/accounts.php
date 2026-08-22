<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Auth\Directory;
use OPNsense\Auth\Recorder;

/**
 * Which local account a set of claims resolves to, and whether that account may be used.
 *
 * Two questions, and they are not the same one. The provider answers who somebody is; the
 * firewall decides whether that person gets in. A local account that is disabled is how an
 * administrator ends someone's access, and it has to mean that here as well - core's own
 * connector refuses one, and nothing looks at it again once a session exists.
 */

$ok = ['name' => 'mikah', 'email' => 'mikah@example.net'];

Checks::group('Which local account a login is');

directory($ok);
Checks::that(
    'the username claim names one',
    connector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    'mikah'
);

directory(['name' => 'Mikah', 'email' => 'mikah@example.net']);
Checks::that(
    'the name comes back as the configuration spells it, not as the claim does',
    connector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    'Mikah'
);

directory($ok);
Checks::that(
    'nobody of that name, and nothing to fall back on',
    connector(['openidconnect_email_match' => 'off'])->localAccountFor(claims(['preferred_username' => 'nobody'])),
    null
);

Checks::group('An account that may not be used');

directory(['name' => 'mikah', 'disabled' => '1']);
Checks::that(
    'a disabled account is refused, the way a password login is refused',
    connector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    null
);

directory(['name' => 'mikah', 'expires' => date('m/d/Y', strtotime('-2 days'))]);
Checks::that(
    'an expired account is refused',
    connector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    null
);

directory(['name' => 'mikah', 'expires' => date('m/d/Y', strtotime('+2 days'))]);
Checks::that(
    'an account that has not expired yet is not',
    connector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    'mikah'
);

directory(['name' => 'root', 'uid' => '0']);
Checks::that(
    'root is out of reach of an identity provider',
    connector([])->localAccountFor(claims(['preferred_username' => 'root'])),
    null
);
Checks::that(
    'unless an installation says otherwise',
    connector(['openidconnect_allow_root' => '1'])->localAccountFor(claims(['preferred_username' => 'root'])),
    'root'
);

directory(['name' => 'toor', 'uid' => '0']);
Checks::that(
    'and uid 0 under another name is still root',
    connector([])->localAccountFor(claims(['preferred_username' => 'toor'])),
    null
);

/**
 * An address says who somebody is only where the provider checked that it is theirs.
 * Wherever a person can type their own, an unverified one is a way onto somebody else's
 * account - so the default asks, and an installation whose provider sends no answer has
 * to say so rather than have it assumed.
 */
Checks::group('Matching by e-mail address');

directory($ok);
Checks::that(
    'a verified address matches',
    connector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => true])),
    'mikah'
);
Checks::that(
    'so does the string some providers send instead',
    connector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => 'true'])),
    'mikah'
);
Checks::that(
    'an address the provider says nothing about does not',
    connector([])->localAccountFor(claims(['email' => 'mikah@example.net'])),
    null
);
Checks::that(
    'nor one it reports as unverified',
    connector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => false])),
    null
);
Checks::that(
    'an installation may accept whatever the provider says, for one that reports nothing',
    connector(['openidconnect_email_match' => 'always'])->localAccountFor(claims(['email' => 'mikah@example.net'])),
    'mikah'
);
Checks::that(
    'or leave the decision to the username claim alone',
    connector(['openidconnect_email_match' => 'off'])
        ->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => true])),
    null
);

Checks::group('Creating an account on first sight');

directory($ok);
Checks::that(
    'off by default, so an unknown person is refused',
    connector([])->localAccountFor(claims(['preferred_username' => 'anna'])),
    null
);
Checks::that('and nothing was asked of configd', Recorder::$backendCalls, []);

directory($ok);
Checks::that(
    'switched on, the username claim names the new account',
    connector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['preferred_username' => 'anna'])),
    'anna'
);
Checks::that(
    'through the same configd action the rest of OPNsense uses',
    Recorder::$backendCalls,
    [['event' => 'auth add user', 'params' => ['anna']]]
);

directory($ok);
Checks::that(
    'an address may name it, where the provider vouches for the address',
    connector(['openidconnect_create_users' => '1'])
        ->localAccountFor(claims(['email' => 'anna@example.net', 'email_verified' => true])),
    'anna@example.net'
);

directory($ok);
Checks::that(
    'but an unverified address names nothing, so nothing is created',
    connector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['email' => 'anna@example.net'])),
    null
);
Checks::that('and configd was left alone', Recorder::$backendCalls, []);

directory();
Directory::$creationWorks = false;
Checks::that(
    'a creation configd refuses is a login refused',
    connector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['preferred_username' => 'anna'])),
    null
);
directory();
