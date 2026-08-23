<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\WebGuiAccess;

Checks::group('local WebGUI authorization');

$acl = static function (array $accessible, $landing): object {
    return new class ($accessible, $landing) {
        private array $accessible;
        private $landing;

        public function __construct(array $accessible, $landing)
        {
            $this->accessible = $accessible;
            $this->landing = $landing;
        }

        public function isPageAccessible(string $account, string $target): bool
        {
            return in_array($account . ':' . $target, $this->accessible, true);
        }

        public function getLandingPage(string $account)
        {
            return $this->landing;
        }
    };
};

Checks::that(
    'an accessible requested page is kept',
    (new WebGuiAccess($acl(['alice:/ui/core/dashboard'], 'ui/diagnostics')))
        ->authorizedTarget('alice', '/ui/core/dashboard'),
    '/ui/core/dashboard'
);
Checks::that(
    'the root target is checked as the core dashboard page',
    (new WebGuiAccess($acl(['alice:/index.php'], null)))->authorizedTarget('alice', '/'),
    '/'
);
Checks::that(
    'an inaccessible target falls back to an authorized landing page',
    (new WebGuiAccess($acl(['alice:/ui/diagnostics'], 'ui/diagnostics')))
        ->authorizedTarget('alice', '/ui/firewall/automation'),
    '/ui/diagnostics'
);
Checks::that(
    'the core logout fallback is not mistaken for a usable privilege',
    (new WebGuiAccess($acl(['alice:/index.php?logout'], 'index.php?logout')))
        ->authorizedTarget('alice', '/'),
    null
);
Checks::that(
    'an API-only ACL entry is not a browser landing page',
    (new WebGuiAccess($acl(['alice:/api/core/menu'], 'api/core/menu/*')))
        ->authorizedTarget('alice', '/'),
    null
);
Checks::that(
    'an inaccessible landing-page suggestion fails closed',
    (new WebGuiAccess($acl([], 'ui/core/dashboard')))->authorizedTarget('alice', '/'),
    null
);
Checks::that(
    'an external landing-page suggestion fails closed',
    (new WebGuiAccess($acl(['alice:/https://evil.example'], 'https://evil.example')))
        ->authorizedTarget('alice', '/'),
    null
);
Checks::that(
    'a protocol-relative requested target fails closed',
    (new WebGuiAccess($acl(['alice://evil.example/path'], null)))
        ->authorizedTarget('alice', '//evil.example/path'),
    null
);
