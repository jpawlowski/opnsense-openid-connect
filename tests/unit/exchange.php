<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\RelyingParty;

/**
 * What this firewall insists on before it acts on an answer at all.
 *
 * These are the checks the bundled library either leaves to its caller or performs later
 * than it should, so they are the ones that would break silently when the library is
 * updated: nothing about them shows up in a signature, and a login goes on working while
 * a check quietly stops firing. See packaging/VENDOR.md.
 */

/** a relying party that was never configured, so only its own checks can speak */
$exchange = new class extends RelyingParty {
    public static $issued = false;

    public function __construct()
    {
    }

    protected function getState()
    {
        return self::$issued;
    }
};

/** what the provider's answer put in the query string */
function answered(array $request): void
{
    $_REQUEST = $request;
}

Checks::group('An answer has to be one this firewall asked for');

$exchange::$issued = 'issued-state';

answered(['code' => 'abc', 'state' => 'somebody-elses']);
Checks::throws(
    'a code with the wrong state',
    fn() => $exchange->authenticate(),
    'does not carry the state'
);

answered(['code' => 'abc']);
Checks::throws(
    'a code with no state at all',
    fn() => $exchange->authenticate(),
    'does not carry the state'
);

$exchange::$issued = false;
answered(['code' => 'abc', 'state' => 'issued-state']);
Checks::throws(
    'a code answered to an exchange this firewall never began',
    fn() => $exchange->authenticate(),
    'does not carry the state'
);

/* the point of checking here rather than leaving it to the library: it checks after the
   code has been handed to the token endpoint, so a matching state is what may be spent */
$exchange::$issued = 'issued-state';
answered(['code' => 'abc', 'state' => 'issued-state']);
Checks::throws(
    'a matching state, and the library takes it from there',
    fn() => $exchange->authenticate(),
    'provider URL'
);

answered([]);
Checks::throws(
    'no answer at all is a start, and needs a configured provider',
    fn() => $exchange->authenticate(),
    'provider URL'
);

/**
 * A token made out to several audiences has to say which client it was for, or one minted
 * for a neighbour at the same provider would pass as this firewall's.
 */
Checks::group('Whom a token was issued for');
Checks::that(
    'one audience needs nothing further',
    RelyingParty::issuedForThisFirewall((object)['aud' => 'client-id'], 'client-id'),
    true
);
Checks::that(
    'several audiences and the authorized party is this firewall',
    RelyingParty::issuedForThisFirewall((object)['aud' => ['client-id', 'other'], 'azp' => 'client-id'], 'client-id'),
    true
);
Checks::that(
    'several audiences and it is somebody else',
    RelyingParty::issuedForThisFirewall((object)['aud' => ['client-id', 'other'], 'azp' => 'other'], 'client-id'),
    false
);
Checks::that(
    'several audiences and nobody is named',
    RelyingParty::issuedForThisFirewall((object)['aud' => ['client-id', 'other']], 'client-id'),
    false
);

/**
 * Every address in a discovery document is the provider's to write, and curl speaks a
 * good deal more than the web does.
 */
Checks::group('Where the provider may send this firewall');
Checks::throws(
    'a token endpoint on the local filesystem',
    fn() => inspect($exchange, 'fetchURL', 'file:///conf/config.xml'),
    'will not fetch'
);
Checks::throws(
    'a jwks address over ftp',
    fn() => inspect($exchange, 'fetchURL', 'ftp://id.example.net/keys'),
    'will not fetch'
);
Checks::throws(
    'and a browser is not sent to one either',
    fn() => $exchange->redirect('file:///etc/passwd'),
    'will not send anyone to'
);

answered([]);
