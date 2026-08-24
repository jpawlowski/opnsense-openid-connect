<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\AuthenticationRequirement;

Checks::group('Authentication strength requirements');

$standardMfaMethods = [
    'mfa', 'pwd', 'pin', 'kba', 'otp', 'hwk', 'sc', 'sms', 'swk', 'tel', 'pop',
    'face', 'fpt', 'iris', 'retina', 'vbm',
];
$mfa = new AuthenticationRequirement(
    AuthenticationRequirement::MULTI_FACTOR,
    AuthenticationRequirement::ESSENTIAL_CLAIM,
    ['https://refeds.org/profile/mfa'],
    $standardMfaMethods
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
$mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd', 'otp']]);
Checks::that('knowledge and possession methods are independent MFA evidence', true, true);
$mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd', 'fpt']]);
Checks::that('knowledge and inherence methods are independent MFA evidence', true, true);
$mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['hwk', 'face']]);
Checks::that('possession and inherence methods are independent MFA evidence', true, true);
Checks::throws(
    'a matching context without MFA method evidence is refused',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd']]),
    'authentication method'
);
Checks::throws(
    'two knowledge methods do not become two factors',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['pwd', 'pin']]),
    'authentication method'
);
Checks::throws(
    'two possession methods do not become two factors',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['otp', 'sms']]),
    'authentication method'
);
Checks::throws(
    'method evidence without the required context is refused',
    fn() => $mfa->assertSatisfied(['acr' => 'other', 'amr' => ['mfa']]),
    'authentication context'
);
foreach (['geo', 'mca', 'rba', 'user', 'wia'] as $ambiguousMethod) {
    $ambiguousMfa = new AuthenticationRequirement(
        AuthenticationRequirement::MULTI_FACTOR,
        AuthenticationRequirement::ESSENTIAL_CLAIM,
        ['https://refeds.org/profile/mfa'],
        [$ambiguousMethod]
    );
    Checks::throws(
        sprintf('%s does not unambiguously establish an authentication factor', $ambiguousMethod),
        fn() => $ambiguousMfa->assertSatisfied([
            'acr' => 'https://refeds.org/profile/mfa',
            'amr' => [$ambiguousMethod],
        ]),
        'authentication method'
    );
}
Checks::throws(
    'an unknown unconfigured method cannot raise MFA assurance',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['unknown']]),
    'authentication method'
);
Checks::throws(
    'a case-mistyped registered method cannot raise MFA assurance',
    fn() => $mfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['MFA']]),
    'authentication method'
);
$mappedMfa = new AuthenticationRequirement(
    AuthenticationRequirement::MULTI_FACTOR,
    AuthenticationRequirement::ESSENTIAL_CLAIM,
    ['https://refeds.org/profile/mfa'],
    ['provider:mfa']
);
$mappedMfa->assertSatisfied(['acr' => 'https://refeds.org/profile/mfa', 'amr' => ['provider:mfa']]);
Checks::that('an exact administrator-supplied provider MFA mapping is accepted', true, true);

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
    ['pop', 'hwk', 'swk']
);
$phishingResistant->assertSatisfied(['acr' => 'phrh', 'amr' => ['hwk']]);
Checks::that('a stronger hardware-protected phishing-resistant context is accepted', true, true);
$phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['swk']]);
Checks::that('a software-secured key can support the non-hardware phishing-resistant context', true, true);
$phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['pop']]);
Checks::that('the EAP proof-of-possession method can support its phishing-resistant context', true, true);
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
    'software-key evidence contradicts a hardware-protected context',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phrh', 'amr' => ['swk']]),
    'authentication method'
);
Checks::throws(
    'unspecified key protection cannot satisfy a hardware-protected context',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phrh', 'amr' => ['pop']]),
    'authentication method'
);
Checks::throws(
    'ordinary MFA evidence cannot satisfy a phishing-resistant requirement',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['mfa']]),
    'authentication method'
);
Checks::throws(
    'an absent authentication-method claim is refused',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr']),
    'authentication methods'
);
Checks::throws(
    'an empty authentication-method claim is refused',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => []]),
    'authentication methods'
);
Checks::throws(
    'a scalar authentication-method claim is refused rather than coerced',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => 'fido']),
    'authentication methods'
);
Checks::throws(
    'an associative authentication-method claim is refused rather than flattened',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['method' => 'hwk']]),
    'authentication methods'
);
Checks::throws(
    'a mistyped authentication-method entry is refused rather than skipped',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['hwk', 7]]),
    'invalid authentication methods'
);
Checks::throws(
    'an unknown unconfigured method cannot raise phishing-resistant assurance',
    fn() => $phishingResistant->assertSatisfied(['acr' => 'phr', 'amr' => ['fido']]),
    'authentication method'
);

$customPhishingResistant = new AuthenticationRequirement(
    AuthenticationRequirement::PHISHING_RESISTANT,
    AuthenticationRequirement::ACR_VALUES,
    ['company:phr'],
    ['company:key']
);
$customPhishingResistant->assertSatisfied(['acr' => 'company:phr', 'amr' => ['company:key']]);
Checks::that('an exact provider-specific context and method mapping remains usable', true, true);
Checks::throws(
    'a custom context cannot turn ordinary MFA into phishing-resistant evidence',
    fn() => (new AuthenticationRequirement(
        AuthenticationRequirement::PHISHING_RESISTANT,
        AuthenticationRequirement::ACR_VALUES,
        ['company:phr'],
        ['mfa']
    ))->assertSatisfied(['acr' => 'company:phr', 'amr' => ['mfa']]),
    'authentication method'
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
$entra->assertSatisfied(['acrs' => ['c7'], 'amr' => ['hwk', 'mfa', 'ngcmfa']]);
Checks::that('Microsoft hardware-key evidence is accepted only with its MFA signal', true, true);
$entra->assertSatisfied(['acrs' => ['c7'], 'amr' => ['x509', 'mfa']]);
Checks::that('Microsoft certificate evidence is accepted only with its MFA signal', true, true);
Checks::throws(
    'a different Microsoft tenant context is refused',
    fn() => $entra->assertSatisfied(['acrs' => ['c2'], 'amr' => ['fido']]),
    'Microsoft authentication context'
);
Checks::throws(
    'Microsoft FIDO evidence without MFA is a downgrade',
    fn() => $entra->assertSatisfied(['acrs' => ['c7'], 'amr' => ['fido']]),
    'authentication method'
);
Checks::throws(
    'Microsoft x509 alone does not prove phishing-resistant MFA',
    fn() => $entra->assertSatisfied(['acrs' => ['c7'], 'amr' => ['x509']]),
    'authentication method'
);
foreach (['emailotp', 'hotp', 'ngcmfa', 'rsa', 'totp'] as $nonPhishingResistantMethod) {
    $lowerEntra = new AuthenticationRequirement(
        AuthenticationRequirement::PHISHING_RESISTANT,
        AuthenticationRequirement::ENTRA_CONTEXT,
        ['c7'],
        [$nonPhishingResistantMethod]
    );
    Checks::throws(
        sprintf('Microsoft %s does not become phishing-resistant beside MFA', $nonPhishingResistantMethod),
        fn() => $lowerEntra->assertSatisfied([
            'acrs' => ['c7'],
            'amr' => ['mfa', $nonPhishingResistantMethod],
        ]),
        'authentication method'
    );
}
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
