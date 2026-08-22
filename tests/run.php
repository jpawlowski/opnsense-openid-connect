<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 *
 * Runs the unit checks. See tests/README.md for what is and is not covered here.
 */

$root = dirname(__DIR__);

require __DIR__ . '/stubs/opnsense.php';
require __DIR__ . '/harness.php';

/* the code under test, in dependency order */
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/OpenIDConnectContainer.php';
require $root . '/src/opnsense/mvc/app/library/OPNsense/OpenIDConnect/RelyingParty.php';

foreach (glob(__DIR__ . '/unit/*.php') as $file) {
    require $file;
}

exit(Checks::report());
