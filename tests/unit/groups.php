<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\Auth\Recorder;

/**
 * What this plugin hands to core when it syncs group membership.
 *
 * Core compares against strtolower() of the local group name and acts only on groups
 * within the scope it is given, so both of those are the whole of the behaviour: a scope
 * spelled with a capital matches nothing and the sync silently does nothing at all, and a
 * scope that is empty means every local group there is. Neither failure says anything in
 * a log, which is why they are checked here.
 */

/** run one login and report the single call core would have seen */
function membership(array $settings, array $values, array $users = [['name' => 'mikah']]): ?array
{
    directory(...$users);
    connector($settings + ['openidconnect_bootstrap_mode' => 'username'])->localAccountFor(claims($values));

    return Recorder::$groupCalls[0] ?? null;
}

Checks::group('Group membership is left alone unless asked for');
Checks::that(
    'no group claim and no default groups, so core is never called',
    membership([], ['preferred_username' => 'mikah']),
    null
);
Checks::that(
    'assignable groups on their own change nothing',
    membership(['openidconnect_assignable_groups' => 'admins'], ['preferred_username' => 'mikah']),
    null
);

Checks::group('What the provider offers');
$granted = membership(
    ['openidconnect_group_claim' => 'groups', 'openidconnect_assignable_groups' => 'Admins, Viewers'],
    ['preferred_username' => 'mikah', 'groups' => ['admins', 'nowhere']]
);
Checks::that('core reads an LDAP shaped list', $granted['memberof'], "cn=admins\ncn=nowhere");
Checks::that('the account is named as configured', $granted['username'], 'mikah');
Checks::that('this plugin never creates a user through core', $granted['create'], false);
Checks::that(
    'the assignable groups arrive in the only spelling core acts on',
    $granted['scope'],
    ['admins', 'viewers']
);
Checks::that(
    'an empty assignable list grants no provider-controlled groups by default',
    membership(
        ['openidconnect_group_claim' => 'groups'],
        ['preferred_username' => 'mikah', 'groups' => ['admins']]
    ),
    null
);
Checks::that(
    'an explicit opt-in allows the provider to control every local group',
    membership(
        ['openidconnect_group_claim' => 'groups', 'openidconnect_allow_all_groups' => '1'],
        ['preferred_username' => 'mikah', 'groups' => ['admins']]
    )['scope'],
    []
);

/**
 * Default groups are what an account starts with. Handing them to core on every login
 * would make them something everyone who signs in gets, which is not what the field says
 * and not what anyone would expect of a firewall.
 */
Checks::group('Default groups belong to the login that creates the account');
$created = membership(
    ['openidconnect_create_users' => '1', 'openidconnect_default_groups' => 'Guests'],
    ['preferred_username' => 'anna'],
    []
);
Checks::that('a new account is placed in them', $created['default'], ['guests']);
Checks::that(
    'and the scope is those groups alone, so nothing else is touched',
    $created['scope'],
    ['guests']
);

Checks::that(
    'an account that already existed is left where it is',
    membership(
        ['openidconnect_create_users' => '1', 'openidconnect_default_groups' => 'Guests'],
        ['preferred_username' => 'mikah']
    ),
    null
);

$both = membership(
    ['openidconnect_create_users' => '1', 'openidconnect_default_groups' => 'Guests', 'openidconnect_group_claim' => 'groups',
        'openidconnect_assignable_groups' => 'Admins'],
    ['preferred_username' => 'anna', 'groups' => ['Admins']],
    []
);
Checks::that(
    'with a group claim as well, both reach core',
    [$both['default'], $both['scope']],
    [['guests'], ['admins']]
);
Checks::that('and the claim is passed on as the provider spelled it', $both['memberof'], 'cn=Admins');

/* leave nothing behind for whichever file the runner globs next */
directory();
