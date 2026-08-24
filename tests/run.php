<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 *
 * Runs the unit checks. See tests/README.md for what is and is not covered here.
 */

$root = dirname(__DIR__);

define('OPENIDCONNECT_TEST_PENDING_REGISTRY', sys_get_temp_dir() . '/openidconnect-pending-' . getmypid() . '.json');
$sessionTestDirectory = sys_get_temp_dir() . '/openidconnect-sessions-' . getmypid();
$runtimeTestDirectory = sys_get_temp_dir() . '/openidconnect-runtime-' . getmypid();
$cacheTestDirectory = sys_get_temp_dir() . '/openidconnect-cache-' . getmypid();
@mkdir($sessionTestDirectory, 0700);
@mkdir($runtimeTestDirectory, 0700);
@mkdir($cacheTestDirectory, 0700);
define('OPENIDCONNECT_TEST_RUNTIME_DIRECTORY', $runtimeTestDirectory);
define('OPENIDCONNECT_TEST_CACHE_DIRECTORY', $cacheTestDirectory);
define('OPENIDCONNECT_TEST_SESSION_DIRECTORY', $sessionTestDirectory);
define('OPENIDCONNECT_TEST_SESSION_REGISTRY', $sessionTestDirectory . '/index.json');
define('OPENIDCONNECT_TEST_SIGNAL_REPLAYS', $sessionTestDirectory . '/signals.json');
ini_set('session.save_path', $sessionTestDirectory);
register_shutdown_function(static function (): void {
    @unlink((string)constant('OPENIDCONNECT_TEST_PENDING_REGISTRY'));
    foreach (glob((string)constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir((string)constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY'));
    foreach (glob((string)constant('OPENIDCONNECT_TEST_RUNTIME_DIRECTORY') . '/*') ?: [] as $file) {
        @unlink($file);
    }
    foreach (glob((string)constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY') . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir((string)constant('OPENIDCONNECT_TEST_RUNTIME_DIRECTORY'));
    @rmdir((string)constant('OPENIDCONNECT_TEST_CACHE_DIRECTORY'));
});

require __DIR__ . '/stubs/opnsense.php';
require __DIR__ . '/harness.php';

/* the code under test, in dependency order */
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProtocolException.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderUnavailableException.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/AuthenticationRequirement.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/OpenIDConnectContainer.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/HttpResponse.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/HttpClient.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderCache.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderMetadata.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SharedSignalsMetadata.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderSetup.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/JwtVerifier.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SecurityEventException.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SecurityEventVerifier.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/PendingIdentityRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SessionRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SessionGrant.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/TransactionRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/WebGuiAccess.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderRuntimeState.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ParClient.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/RelyingParty.php';
require $root . '/src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/AuthController.php';
require $root . '/src/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/SsfController.php';

foreach (glob(__DIR__ . '/unit/*.php') as $file) {
    require $file;
}

exit(Checks::report());
