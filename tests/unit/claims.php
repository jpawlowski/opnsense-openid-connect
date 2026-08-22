<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\RelyingParty;

/**
 * Providers disagree about where a claim belongs, so both sources are read. Microsoft
 * Entra ID is the case that forces it: its UserInfo response can only ever carry sub,
 * name, family_name, given_name, picture and email, and preferred_username is in the
 * id_token and nowhere else. Reading UserInfo alone meant Entra could never be used.
 */
Checks::group('Reading claims from the id_token as well as UserInfo');

/** a relying party whose id_token payload we get to choose */
function withIdToken(object $payload): RelyingParty
{
    $party = new class extends RelyingParty {
        public static object $payload;

        public function __construct()
        {
        }

        public function getIdTokenPayload()
        {
            return self::$payload;
        }
    };
    $party::$payload = $payload;

    (new ReflectionProperty(RelyingParty::class, 'settings'))->setValue($party, connector([]));

    return $party;
}

$entraIdToken = (object)[
    'sub' => 'pairwise-abc',
    'preferred_username' => 'mikah@contoso.example',
    'email' => 'stale@contoso.example',
    'given_name' => 'Mikah',
    'iss' => 'https://login.example.net/tenant/v2.0',
    'aud' => 'client-id',
    'exp' => 1,
    'iat' => 1,
    'nonce' => 'n',
    'at_hash' => 'h',
    'auth_time' => 1,
    'acr' => '1',
];
$entraUserInfo = (object)['sub' => 'pairwise-abc', 'name' => 'Mikah O', 'email' => 'mikoll@contoso.example'];

$merged = inspect(withIdToken($entraIdToken), 'withIdTokenClaims', $entraUserInfo);

Checks::that(
    'a claim only the id_token carries is available',
    $merged->preferred_username ?? null,
    'mikah@contoso.example'
);
Checks::that('UserInfo wins where the two overlap', $merged->email, 'mikoll@contoso.example');
Checks::that('a claim only UserInfo carries is available', $merged->name, 'Mikah O');
Checks::that('the subject is there', $merged->sub, 'pairwise-abc');
Checks::that(
    'protocol claims are kept out',
    array_values(array_intersect(
        array_keys((array)$merged),
        ['iss', 'aud', 'exp', 'iat', 'nonce', 'at_hash', 'auth_time', 'acr']
    )),
    []
);

$plain = inspect(
    withIdToken((object)['sub' => 's', 'iss' => 'x']),
    'withIdTokenClaims',
    (object)['sub' => 's', 'preferred_username' => 'anna', 'groups' => ['admins']]
);
Checks::that('a provider that answers fully through UserInfo is unaffected', $plain->preferred_username, 'anna');
Checks::that('a list claim survives intact', $plain->groups, ['admins']);
