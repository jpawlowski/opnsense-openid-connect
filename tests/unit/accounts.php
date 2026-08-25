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

/** Account matching in these examples is an explicitly enabled first-login bootstrap. */
function accountConnector(array $settings): OPNsense\Auth\OpenIDConnect
{
    return connector($settings + ['openidconnect_bootstrap_mode' => 'either']);
}

/** @return string[] exact UIDs stored on one local group */
function membersOf(string $name): array
{
    foreach (Directory::$groups as $group) {
        if ((string)($group->name ?? '') === $name) {
            return array_values(array_filter(explode(',', implode(',', (array)($group->member ?? [])))));
        }
    }
    return [];
}

Checks::group('Which local account a login is');

directory($ok);
Checks::that(
    'the username claim names one',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    'mikah'
);

directory(['name' => 'Mikah', 'email' => 'mikah@example.net']);
Checks::that(
    'username bootstrap is exact and does not cross case variants',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    null
);

directory($ok);
Checks::that(
    'nobody of that name, and nothing to fall back on',
    accountConnector(['openidconnect_email_match' => 'off'])->localAccountFor(claims(['preferred_username' => 'nobody'])),
    null
);

Checks::group('Stable issuer and subject bindings');
directory($ok);
$legacy = connector(['refid' => 'server-written-before-admission-policies']);
Checks::that(
    'a saved beta configuration can still bootstrap the account it matched before the field existed',
    $legacy->localAccountFor(claims(['sub' => 'legacy-subject', 'preferred_username' => 'mikah'])),
    'mikah'
);
Checks::that(
    'the compatibility match immediately creates a stable issuer and subject binding',
    $legacy->localAccountFor(claims(['sub' => 'legacy-subject', 'preferred_username' => 'someone-else'])),
    'mikah'
);

directory($ok);
$stable = accountConnector([]);
Checks::that(
    'an explicitly allowed first match creates the binding',
    $stable->localAccountFor(claims(['sub' => 'opaque-subject', 'preferred_username' => 'mikah'])),
    'mikah'
);
Directory::$users[0]->name = 'renamed-locally';
Checks::that(
    'a later local rename does not break or redirect the identity',
    $stable->localAccountFor(claims(['sub' => 'opaque-subject', 'preferred_username' => 'someone-else'])),
    'renamed-locally'
);
Checks::that(
    'the same subject under a different issuer is a different identity',
    $stable->localAccountFor(
        claims(['sub' => 'opaque-subject', 'preferred_username' => 'someone-else']),
        'https://other-id.example.net',
        'opaque-subject'
    ),
    null
);

directory(['name' => 'mikah'], ['name' => 'anna']);
Checks::that(
    'conflicting manual mappings are refused instead of taking the first line',
    connector([
        'openidconnect_subject_bindings' => "opaque=subject=mikah\nopaque=subject=anna",
    ])->localAccountFor(claims(['sub' => 'opaque=subject'])),
    null
);

Checks::group('An account that may not be used');

directory(['name' => 'mikah', 'disabled' => '1']);
Checks::that(
    'a disabled account is refused, the way a password login is refused',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    null
);

directory(['name' => 'mikah', 'expires' => date('m/d/Y', strtotime('-2 days'))]);
Checks::that(
    'an expired account is refused',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    null
);

directory(['name' => 'mikah', 'expires' => date('m/d/Y', strtotime('+2 days'))]);
Checks::that(
    'an account that has not expired yet is not',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'mikah'])),
    'mikah'
);

directory(['name' => 'root', 'uid' => '0']);
Checks::that(
    'root is out of reach of an identity provider',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'root'])),
    null
);
Checks::that(
    'unless an installation says otherwise',
    accountConnector(['openidconnect_allow_root' => '1'])->localAccountFor(claims(['preferred_username' => 'root'])),
    'root'
);

directory(['name' => 'toor', 'uid' => '0']);
Checks::that(
    'and uid 0 under another name is still root',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'toor'])),
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
    accountConnector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => true])),
    'mikah'
);
Checks::that(
    'so does the string some providers send instead',
    accountConnector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => 'true'])),
    'mikah'
);
Checks::that(
    'an address the provider says nothing about does not',
    accountConnector([])->localAccountFor(claims(['email' => 'mikah@example.net'])),
    null
);
Checks::that(
    'nor one it reports as unverified',
    accountConnector([])->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => false])),
    null
);
Checks::that(
    'an installation may accept whatever the provider says, for one that reports nothing',
    accountConnector(['openidconnect_email_match' => 'always'])->localAccountFor(claims(['email' => 'mikah@example.net'])),
    'mikah'
);
Checks::that(
    'or leave the decision to the username claim alone',
    accountConnector(['openidconnect_email_match' => 'off'])
        ->localAccountFor(claims(['email' => 'mikah@example.net', 'email_verified' => true])),
    null
);

Checks::group('Creating an account on first sight');

directory($ok);
Checks::that(
    'off by default, so an unknown person is refused',
    accountConnector([])->localAccountFor(claims(['preferred_username' => 'anna'])),
    null
);
Checks::that('and nothing was asked of configd', Recorder::$backendCalls, []);

directory($ok);
Checks::that(
    'switched on, the username claim names the new account',
    accountConnector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['preferred_username' => 'anna'])),
    'anna'
);
Checks::that(
    'through the same configd action the rest of OPNsense uses',
    Recorder::$backendCalls,
    [['event' => 'auth add user', 'params' => ['anna']]]
);

directory($ok);
Checks::that(
    'a public provider profile cannot create an account even from stale enabled configuration',
    connector([
        'openidconnect_provider_profile' => 'google',
        'openidconnect_bootstrap_mode' => 'username',
        'openidconnect_create_users' => '1',
    ])->localAccountFor(claims(['preferred_username' => 'anna'])),
    null
);
Checks::that('the public-provider refusal never asks configd to create an account', Recorder::$backendCalls, []);

directory($ok);
Directory::$creationOutput = "\nWarning: Undefined variable in add_user.php\n" . json_encode([
    'status' => 'ok',
    'uid' => '1002',
    'name' => 'anna',
]);
Checks::that(
    'a saved account is accepted even when OPNsense prefixes its JSON with PHP warnings',
    accountConnector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['preferred_username' => 'anna'])),
    'anna'
);

directory($ok);
Checks::that(
    'an address may name it, where the provider vouches for the address',
    accountConnector(['openidconnect_create_users' => '1'])
        ->localAccountFor(claims(['email' => 'anna@example.net', 'email_verified' => true])),
    'anna@example.net'
);

directory($ok);
Checks::that(
    'but an unverified address names nothing, so nothing is created',
    accountConnector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['email' => 'anna@example.net'])),
    null
);
Checks::that('and configd was left alone', Recorder::$backendCalls, []);

directory();
Directory::$creationWorks = false;
Checks::that(
    'a creation configd refuses is a login refused',
    accountConnector(['openidconnect_create_users' => '1'])->localAccountFor(claims(['preferred_username' => 'anna'])),
    null
);
directory();

Checks::group('Administrator approval admission policy');
directory($ok);
$approval = connector(['openidconnect_bootstrap_mode' => 'approval']);
Checks::that(
    'an unknown identity is refused even when its username already names a local account',
    $approval->localAccountFor(claims([
        'sub' => 'apple-private-subject',
        'preferred_username' => 'mikah',
        'email' => 'private-relay@privaterelay.example',
        'email_verified' => true,
    ])),
    null
);
$requestId = $approval->pendingApprovalId();
Checks::that('the refusal produces a short administrator request reference',
    (bool)preg_match('/^[a-f0-9]{20}$/D', $requestId), true);
$pending = $approval->pendingApprovals();
Checks::that('the pending request retains the exact issuer and subject',
    [$pending[0]['issuer'] ?? '', $pending[0]['subject'] ?? ''],
    ['https://id.example.net', 'apple-private-subject']);
Checks::that('the one-time relay address is retained only as an administrator hint',
    $pending[0]['hints']['email'] ?? '', 'private-relay@privaterelay.example');
Checks::that('an administrator can bind it to an existing local uid',
    $approval->approvePendingIdentity($requestId, (string)Directory::$users[0]->uid), true);
Checks::that('the approved exact subject signs in even when Apple no longer repeats the e-mail claim',
    $approval->localAccountFor(claims(['sub' => 'apple-private-subject'])), 'mikah');
Checks::that('approval consumes the pending request', $approval->pendingApprovals(), []);

Checks::group('Administrator-managed local account creation');
directory($ok);
Directory::addGroup(['name' => 'Admins']);
$accountManager = connector(['openidconnect_bootstrap_mode' => 'strict']);
$managedAccount = $accountManager->createManagedAccount('new-local-account');
Checks::that('an administrator can create a local account independently of first-login provisioning',
    $managedAccount, ['uid' => '1001', 'name' => 'new-local-account']);
Checks::that('managed creation uses the same native configd account action', Recorder::$backendCalls,
    [['event' => 'auth add user', 'params' => ['new-local-account']]]);
Checks::that('the newly returned uid can be bound without another account lookup',
    $accountManager->createSubjectBinding(
        'https://id.example.net',
        'new-local-subject',
        (string)($managedAccount['uid'] ?? ''),
        ['Admins']
    ), true);
Checks::that('selected existing groups are applied with the new account binding', membersOf('Admins'), ['1001']);
Checks::that('the native account synchronization is requested after membership changes', Recorder::$backendCalls[1],
    ['event' => 'auth user changed', 'params' => ['new-local-account']]);
Checks::that('the new account resolves through its durable binding',
    $accountManager->localAccountFor(claims(['sub' => 'new-local-subject'])), 'new-local-account');
Checks::that('the managed creation path never reuses an existing local account',
    $accountManager->createManagedAccount('new-local-account'), null);
Checks::that('reusing an account does not ask configd to add it a second time', count(array_filter(
    Recorder::$backendCalls,
    static fn(array $call): bool => $call['event'] === 'auth add user'
)), 1);

directory();
Directory::$creationWorks = false;
Checks::that('a refused native account creation cannot yield a managed account',
    connector([])->createManagedAccount('not-created'), null);

Checks::group('Administrator-managed identity bindings');
directory($ok, ['name' => 'anna', 'email' => 'anna@example.net']);
Directory::addGroup(['name' => 'Viewers', 'member' => [(string)Directory::$users[0]->uid]]);
Directory::addGroup(['name' => 'Admins', 'member' => [(string)Directory::$users[1]->uid]]);
$manager = connector(['openidconnect_bootstrap_mode' => 'strict']);
$issuer = 'https://id.example.net';
Checks::that('an administrator can add an exact subject binding without editing raw text',
    $manager->createSubjectBinding($issuer, 'manual-subject', (string)Directory::$users[0]->uid), true);
$managedBindings = $manager->subjectBindingRecords();
Checks::that('the identity manager lists issuer, subject and resolved local account', [
    $managedBindings[0]['issuer'] ?? '',
    $managedBindings[0]['subject'] ?? '',
    $managedBindings[0]['account'] ?? '',
    $managedBindings[0]['canonical'] ?? false,
], [$issuer, 'manual-subject', 'mikah', true]);
Checks::that('the identity manager lists the selected account memberships',
    $managedBindings[0]['groups'] ?? [], ['Viewers']);
Checks::that('an already bound local account is absent from new-binding choices',
    array_column($manager->approvableAccounts(), 'name'), ['anna']);
Checks::that('an eligible existing account carries its memberships into the picker',
    $manager->approvableAccounts()[0]['groups'] ?? [], ['Admins']);
Checks::that('a second identity cannot be assigned to the same local account',
    $manager->createSubjectBinding($issuer, 'another-subject', (string)Directory::$users[0]->uid), false);
Checks::that('the manually bound exact subject signs in under strict admission',
    $manager->localAccountFor(claims(['sub' => 'manual-subject']), $issuer), 'mikah');
Checks::that('the same issuer and subject cannot be rebound silently to another account',
    $manager->createSubjectBinding($issuer, 'manual-subject', (string)Directory::$users[1]->uid), false);
$bindingId = (string)($managedBindings[0]['id'] ?? '');
Checks::that('an administrator can edit the subject and local account atomically',
    $manager->updateSubjectBinding($bindingId, $issuer, 'replacement-subject',
        (string)Directory::$users[1]->uid), true);
Checks::that('the replaced subject no longer resolves',
    $manager->localAccountFor(claims(['sub' => 'manual-subject']), $issuer), null);
Checks::that('the replacement resolves to the selected account',
    $manager->localAccountFor(claims(['sub' => 'replacement-subject']), $issuer), 'anna');
$replacement = $manager->subjectBindingRecords()[0] ?? [];
Checks::that('an administrator can remove a binding by its concurrency-safe identifier',
    $manager->deleteSubjectBinding((string)($replacement['id'] ?? '')), true);
Checks::that('a removed identity is refused by strict admission',
    $manager->localAccountFor(claims(['sub' => 'replacement-subject']), $issuer), null);
Checks::that('a manual binding cannot name a different issuer',
    $manager->createSubjectBinding('https://lookalike.example.net', 'subject',
        (string)Directory::$users[0]->uid), false);

Checks::group('Administrator-selected local groups');
directory($ok, ['name' => 'anna', 'email' => 'anna@example.net']);
Directory::addGroup(['name' => 'Operators', 'member' => ['65000']]);
Directory::addGroup(['name' => 'Admins', 'member' => [(string)Directory::$users[0]->uid]]);
$groupManager = connector(['openidconnect_bootstrap_mode' => 'strict']);
Checks::that('only existing local groups are offered in stable display order',
    $groupManager->manageableGroups(), ['Admins', 'Operators']);
$groupAccounts = array_column($groupManager->approvableAccounts(), null, 'name');
Checks::that('an existing account starts with its current memberships selected',
    $groupAccounts['mikah']['groups'] ?? [], ['Admins']);
Checks::that('one or more selected groups are saved with a binding',
    $groupManager->createSubjectBinding($issuer, 'group-subject', (string)Directory::$users[1]->uid,
        ['Admins', 'Operators']), true);
Checks::that('adding one account preserves every other group member', membersOf('Admins'), ['1000', '1001']);
Checks::that('membership is also added to a second selected group', membersOf('Operators'), ['65000', '1001']);
Checks::that('a conflicting binding cannot apply its requested membership changes',
    $groupManager->createSubjectBinding($issuer, 'group-subject', (string)Directory::$users[0]->uid,
        ['Operators']), false);
Checks::that('the rejected binding leaves that account in its original group', membersOf('Admins'), ['1000', '1001']);
$groupBinding = $groupManager->subjectBindingRecords()[0] ?? [];
Checks::that('saved memberships are returned with the binding',
    $groupBinding['groups'] ?? [], ['Admins', 'Operators']);
Checks::that('saving a smaller selection removes only this account from deselected groups',
    $groupManager->updateSubjectBinding((string)($groupBinding['id'] ?? ''), $issuer, 'group-subject',
        (string)Directory::$users[1]->uid, ['Operators']), true);
Checks::that('the other account remains in the deselected group', membersOf('Admins'), ['1000']);
Checks::that('an unknown group is refused without changing the saved selection',
    $groupManager->updateSubjectBinding((string)($groupBinding['id'] ?? ''), $issuer, 'group-subject',
        (string)Directory::$users[1]->uid, ['Missing']), false);
Checks::that('the last valid membership remains after the refusal', membersOf('Operators'), ['65000', '1001']);
Checks::that('selecting no group is valid',
    $groupManager->updateSubjectBinding((string)($groupBinding['id'] ?? ''), $issuer, 'group-subject',
        (string)Directory::$users[1]->uid, []), true);
Checks::that('an empty selection removes this account from every local group', membersOf('Operators'), ['65000']);

$entraManager = connector([
    'openidconnect_provider_profile' => 'entra',
    'openidconnect_microsoft_audience' => 'organizations',
]);
$entraTenantIssuer = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0';
Checks::that('a multitenant Microsoft binding accepts an exact admitted tenant issuer',
    $entraManager->normalizeBindingIssuer($entraTenantIssuer), $entraTenantIssuer);
Checks::that('the Microsoft subject guidance explicitly distinguishes sub from oid',
    str_contains($entraManager->subjectGuidance()['text'], '`oid`'), true);

directory($ok);
$denied = connector(['openidconnect_bootstrap_mode' => 'approval']);
$denied->localAccountFor(claims(['sub' => 'unknown-subject', 'preferred_username' => 'somebody']));
$deniedId = $denied->pendingApprovalId();
Checks::that('an administrator may deny an unknown identity', $denied->denyPendingIdentity($deniedId), true);
Checks::that('a denied request is removed', $denied->pendingApprovals(), []);

directory($ok);
Checks::that(
    'strict admission cannot be bypassed by enabling local account creation',
    connector([
        'openidconnect_bootstrap_mode' => 'strict',
        'openidconnect_create_users' => '1',
    ])->localAccountFor(claims(['preferred_username' => 'unexpected'])),
    null
);
Checks::that('strict admission asks configd to create nothing', Recorder::$backendCalls, []);
