<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 *
 * Runs the unit checks. See tests/README.md for what is and is not covered here.
 */

$root = dirname(__DIR__);

define('OPENIDCONNECT_TEST_PENDING_REGISTRY', sys_get_temp_dir() . '/openidconnect-pending-' . getmypid() . '.json');
register_shutdown_function(static function (): void {
    @unlink((string)constant('OPENIDCONNECT_TEST_PENDING_REGISTRY'));
});

require __DIR__ . '/stubs/opnsense.php';
require __DIR__ . '/harness.php';

/* the code under test, in dependency order */
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProtocolException.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/AuthenticationRequirement.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/OpenIDConnectContainer.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/HttpResponse.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/HttpClient.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderMetadata.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/ProviderSetup.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/JwtVerifier.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/PendingIdentityRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/SessionRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/TransactionRegistry.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/WebGuiAccess.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/RelyingParty.php';

foreach (glob(__DIR__ . '/unit/*.php') as $file) {
    require $file;
}

exit(Checks::report());
