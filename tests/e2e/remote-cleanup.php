#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

require_once('/usr/local/etc/inc/legacy_bindings.inc');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\PendingIdentityRegistry;

[$script, $username, $applicationCode, $action] = $argv + [null, '', '', 'cleanup'];
if (!preg_match('/^oidc-e2e-[a-f0-9]{8}$/D', $username)
    || !preg_match('/^e2e-[a-f0-9]{8}$/D', $applicationCode)
    || !in_array($action, ['cleanup', 'remove-privileges'], true)) {
    fwrite(STDERR, "Refusing cleanup outside the disposable E2E namespace.\n");
    exit(2);
}

$config = Config::getInstance()->lock(true);
$root = $config->object();
$uid = null;
$removedUser = false;
$removedServer = false;
$removedPending = 0;

for ($index = count($root->system->user) - 1; $index >= 0; $index--) {
    $user = $root->system->user[$index];
    if ((string)$user->name === $username && (string)($user->scope ?? '') === 'automation') {
        $uid = (string)$user->uid;
        if ($action === 'cleanup') {
            unset($root->system->user[$index]);
            $removedUser = true;
        }
    }
}

if ($uid !== null) {
    foreach ($root->system->group as $group) {
        $members = array_values(array_filter(
            explode(',', implode(',', (array)$group->member)),
            static fn($member) => $member !== '' && $member !== $uid
        ));
        unset($group->member);
        if ($members !== []) {
            $group->addChild('member', implode(',', $members));
        }
    }
}

if ($action === 'remove-privileges') {
    $config->save();
    $config->unlock();
    if ($uid === null) {
        fwrite(STDERR, "The disposable E2E user does not exist.\n");
        exit(1);
    }
    (new Backend())->configdpRun('auth sync user', [$username]);
    echo json_encode(['removed_group_memberships' => true]), "\n";
    exit(0);
}

for ($index = count($root->system->authserver) - 1; $index >= 0; $index--) {
    $server = $root->system->authserver[$index];
    if ((string)($server->type ?? '') === 'openidconnect'
        && (string)($server->openidconnect_app_code ?? '') === $applicationCode) {
        unset($root->system->authserver[$index]);
        $removedServer = true;
    }
}

$config->save();
$config->unlock();
if ($removedUser) {
    (new Backend())->configdpRun('auth sync user', [$username]);
}

foreach (PendingIdentityRegistry::listing($applicationCode) as $pending) {
    if (is_string($pending['id'] ?? null)
        && PendingIdentityRegistry::remove($pending['id'], $applicationCode)) {
        $removedPending++;
    }
}

echo json_encode([
    'removed_user' => $removedUser,
    'removed_server' => $removedServer,
    'removed_pending' => $removedPending,
]), "\n";
