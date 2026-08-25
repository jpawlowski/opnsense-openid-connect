<?php

use OPNsense\OpenIDConnect\RelyingParty;

Checks::group('Separating identity claims from protocol claims');

$party = new class extends RelyingParty {
    public function __construct()
    {
    }
};

$person = inspect($party, 'personClaims', [
    'sub' => 'pairwise-abc',
    'preferred_username' => 'mikah@example.net',
    'email' => 'mikah@example.net',
    'groups' => ['admins'],
    'iss' => 'https://id.example.net',
    'aud' => 'client-id',
    'exp' => 100,
    'nonce' => 'n',
    'at_hash' => 'h',
    'auth_time' => 90,
    'acr' => 'phr',
    'acrs' => ['c1'],
    'amr' => ['fido'],
]);

Checks::that('a username claim remains available', $person['preferred_username'], 'mikah@example.net');
Checks::that('a list claim survives intact', $person['groups'], ['admins']);
Checks::that('the stable subject remains available', $person['sub'], 'pairwise-abc');
Checks::that(
    'protocol claims cannot turn into account attributes',
    array_values(array_intersect(
        array_keys($person),
        ['iss', 'aud', 'exp', 'nonce', 'at_hash', 'auth_time', 'acr', 'acrs', 'amr']
    )),
    []
);

$onlySubject = inspect($party, 'personClaims', ['sub' => 's', str_repeat('x', 129) => 'ignored']);
Checks::that('a claim name that is too long is ignored', $onlySubject, ['sub' => 's']);
