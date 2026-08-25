#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

require_once('/usr/local/etc/inc/legacy_bindings.inc');

use OPNsense\Core\Config;

[$script, $serverName, $applicationCode] = $argv + [null, '', ''];
if (!preg_match('/^(?:entra|okta|apple) live E2E [a-f0-9]{8}$/D', $serverName)
    || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/D', $applicationCode)) {
    fwrite(STDERR, "Refusing cleanup outside the disposable live E2E server namespace.\n");
    exit(2);
}

$config = Config::getInstance()->lock(true);
$root = $config->object();
$removed = false;
for ($index = count($root->system->authserver) - 1; $index >= 0; $index--) {
    $server = $root->system->authserver[$index];
    if ((string)($server->type ?? '') === 'openidconnect'
        && (string)($server->name ?? '') === $serverName
        && (string)($server->openidconnect_app_code ?? '') === $applicationCode) {
        unset($root->system->authserver[$index]);
        $removed = true;
    }
}
$config->save();
$config->unlock();
echo json_encode(['removed_server' => $removed]), "\n";
