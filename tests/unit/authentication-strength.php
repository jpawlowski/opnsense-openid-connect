<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\AuthenticationRequirement;

Checks::group('Authentication strength requirements');

$mfa = new AuthenticationRequirement(
    AuthenticationRequirement::MULTI_FACTOR,
    AuthenticationRequirement::ESSENTIAL_CLAIM,
    ['https://refeds.org/profile/mfa'],
    ['mfa']
);
$mfaParameters = $mfa->authorizationParameters();
$mfaClaimsRequest = json_decode($mfaParameters['claims'], true, 16, JSON_THROW_ON_ERROR);
Checks::that(
    'standards-based MFA is requested as an essential ID Token claim',
    $mfaClaimsRequest['id_token']['acr'],
    ['essential' => true, 'values' => ['https://refeds.org/profile/mfa']]
);
Checks::that(
    'the same request asks the provider to report authentication methods',
    $mfaClaimsRequest['id_token']['amr'],
    ['essential' => true]
);
$mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd', 'mfa']]);
Checks::that('matching context and method evidence are accepted together', true, true);
Checks::throws(
    'a matching context without MFA method evidence is refused',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd']]),
    'authentication method'
);
Checks::throws(
    'method evidence without the required context is refused',
    fn() => $mfa->assertSatisfied(['acr' => 'other', 'amr' => ['mfa']]),
    'authentication context'
);

$okta = new AuthenticationRequirement(
    AuthenticationRequirement::MULTI_FACTOR,
    AuthenticationRequirement::ACR_VALUES,
    ['urn:okta:loa:2fa:any'],
    ['mfa']
);
Checks::that(
    'an Okta requirement uses the documented acr_values parameter',
    $okta->authorizationParameters(),
    ['acr_values' => 'urn:okta:loa:2fa:any']
);

$phishingResistant = new AuthenticationRequirement(
    AuthenticationRequirement::PHISHING_RESISTANT,
    AuthenticationRequirement::ESSENTIAL_CLAIM,
    ['phr', 'phrh'],
    ['fido', 'pop', 'hwk', 'swk']
);
$phishingResistant->assertSatisfied(['acr' => 'phrh', 'amr' => ['hwk']]);
Checks::that('a stronger hardware-protected phishing-resistant context is accepted', true, true);
Checks::throws(
    'user presence alone is not phishing-resistant evidence',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['user']]),
    'authentication method'
);
Checks::throws(
    'the nonstandard hw spelling is not hardware-key evidence',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['hw']]),
    'authentication method'
);
Checks::throws(
    'an ACR name repeated as an authentication method is not method evidence',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['phr']]),
    'authentication method'
);
Checks::throws(
    'a scalar authentication-method claim is refused rather than coerced',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => 'fido']),
    'authentication methods'
);

$entra = new AuthenticationRequirement(
    AuthenticationRequirement::PHISHING_RESISTANT,
    AuthenticationRequirement::ENTRA_CONTEXT,
    ['c7'],
    ['fido', 'hwk', 'x509']
);
$entraRequest = json_decode($entra->authorizationParameters()['claims'], true, 16, JSON_THROW_ON_ERROR);
Checks::that(
    'Microsoft receives its tenant authentication context as an essential ID Token claim',
    $entraRequest['id_token']['acrs'],
    ['essential' => true, 'value' => 'c7']
);
$entra->assertSatisfied(['acrs' => ['c2', 'c7'], 'amr' => ['fido', 'mfa']]);
Checks::that('the exact Microsoft context and a documented phishing-resistant method are accepted', true, true);
Checks::throws(
    'a different Microsoft tenant context is refused',
    fn() => $entra->assertSatisfied(['acrs' => ['c2'], 'amr' => ['fido']]),
    'Microsoft authentication context'
);
Checks::throws(
    'an out-of-range Microsoft context cannot become transaction policy',
    fn() => new AuthenticationRequirement(
        AuthenticationRequirement::MULTI_FACTOR,
        AuthenticationRequirement::ENTRA_CONTEXT,
        ['c26'],
        ['mfa']
    ),
    'Microsoft authentication context'
);

$roundTrip = AuthenticationRequirement::fromArray($entra->toArray());
Checks::that('the exact requirement survives transaction serialization', $roundTrip->equals($entra), true);
