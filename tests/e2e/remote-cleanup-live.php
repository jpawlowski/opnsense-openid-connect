#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

require_once('/usr/local/etc/inc/legacy_bindings.inc');

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

[$script, $action, $serverName, $applicationCode] = $argv + [null, '', '', ''];
if (!preg_match('/^(?:entra|okta|apple) live E2E ([a-f0-9]{8})$/D', $serverName, $matches)
    || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/D', $applicationCode)
    || !in_array($action, ['snapshot', 'cleanup'], true)) {
    fwrite(STDERR, "Refusing cleanup outside the disposable live E2E server namespace.\n");
    exit(2);
}
$statePath = '/tmp/opnsense-oidc-e2e-live-users-' . $matches[1] . '.json';

$config = Config::getInstance()->lock(true);
$root = $config->object();
$existingUids = [];
if ($action === 'snapshot') {
    foreach ($root->system->user ?? [] as $user) {
        $uid = (string)($user->uid ?? '');
        if ($uid !== '' && ctype_digit($uid)) {
            $existingUids[$uid] = true;
        }
    }
    $config->unlock();
    $state = json_encode([
        'schema' => 1,
        'server_name' => $serverName,
        'application_code' => $applicationCode,
        'existing_uids' => array_keys($existingUids),
    ], JSON_UNESCAPED_SLASHES);
    if (!is_string($state) || file_put_contents($statePath, $state . "\n", LOCK_EX) === false
        || !chmod($statePath, 0600)) {
        fwrite(STDERR, "Could not record the live E2E account baseline.\n");
        exit(1);
    }
    echo json_encode(['snapshotted_users' => count($existingUids)]), "\n";
    exit(0);
}

$state = json_decode((string)@file_get_contents($statePath), true);
if (!is_array($state) || ($state['schema'] ?? null) !== 1
    || !hash_equals($serverName, (string)($state['server_name'] ?? ''))
    || !hash_equals($applicationCode, (string)($state['application_code'] ?? ''))
    || !is_array($state['existing_uids'] ?? null)) {
    $config->unlock();
    fwrite(STDERR, "Refusing live E2E account cleanup without its exact baseline.\n");
    exit(1);
}
foreach ($state['existing_uids'] as $uid) {
    if ((!is_string($uid) && !is_int($uid)) || !ctype_digit((string)$uid)) {
        $config->unlock();
        fwrite(STDERR, "Refusing an invalid live E2E account baseline.\n");
        exit(1);
    }
    $existingUids[(string)$uid] = true;
}

$removedServer = false;
$boundUids = [];
for ($index = count($root->system->authserver) - 1; $index >= 0; $index--) {
    $server = $root->system->authserver[$index];
    if ((string)($server->type ?? '') === 'openidconnect'
        && (string)($server->name ?? '') === $serverName
        && (string)($server->openidconnect_app_code ?? '') === $applicationCode) {
        foreach (preg_split('/\r?\n/', trim((string)($server->openidconnect_subject_bindings ?? ''))) ?: [] as $line) {
            $separator = strrpos($line, '=');
            $identity = $separator === false ? '' : trim(substr($line, $separator + 1));
            if (preg_match('/^uid:([0-9]+)$/D', $identity, $binding)) {
                $boundUids[$binding[1]] = true;
            }
        }
        unset($root->system->authserver[$index]);
        $removedServer = true;
    }
}

$removedUids = [];
$removedUsernames = [];
foreach (array_keys($boundUids) as $uid) {
    if (!isset($existingUids[$uid])) {
        $removedUids[$uid] = true;
    }
}
for ($index = count($root->system->user) - 1; $index >= 0; $index--) {
    $user = $root->system->user[$index];
    $uid = (string)($user->uid ?? '');
    if (isset($removedUids[$uid])) {
        $removedUsernames[] = (string)$user->name;
        unset($root->system->user[$index]);
    }
}
if ($removedUids !== []) {
    foreach ($root->system->group ?? [] as $group) {
        $members = array_values(array_filter(
            explode(',', implode(',', (array)($group->member ?? []))),
            static fn($member) => $member !== '' && !isset($removedUids[$member])
        ));
        unset($group->member);
        if ($members !== []) {
            $group->addChild('member', implode(',', $members));
        }
    }
}
$config->save();
$config->unlock();
foreach ($removedUsernames as $username) {
    (new Backend())->configdpRun('auth sync user', [$username]);
}
if (!unlink($statePath)) {
    fwrite(STDERR, "Could not remove the live E2E account baseline.\n");
    exit(1);
}
echo json_encode([
    'removed_server' => $removedServer,
    'removed_users' => count($removedUsernames),
]), "\n";
