<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SessionRegistry;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;
use OPNsense\OpenIDConnect\Api\SsfController;
use OPNsense\Auth\Directory;
use OPNsense\Mvc\Request;

Checks::group('Shared Signals settings');
$ssfOptions = (new OPNsense\Auth\OpenIDConnect())->getConfigurationOptions();
Checks::that('Shared Signals is off by default', $ssfOptions['openidconnect_ssf_enabled']['default'], '0');
$_POST = ['type' => 'openidconnect', 'openidconnect_ssf_enabled' => '1'];
Checks::that(
    'an enabled receiver requires an exact issuer',
    count($ssfOptions['openidconnect_ssf_issuer']['validate']('http://id.example.net')),
    1
);
Checks::that(
    'an enabled receiver requires a generated secret',
    count($ssfOptions['openidconnect_ssf_push_secret']['validate']('short')),
    1
);
Checks::that(
    'a 256-bit base64url secret is accepted',
    $ssfOptions['openidconnect_ssf_push_secret']['validate'](str_repeat('a', 43)),
    []
);
$_POST = [];
$ssfConnector = connector([
    'openidconnect_ssf_enabled' => '1',
    'openidconnect_ssf_issuer' => 'https://signals.example.net/tenant',
    'openidconnect_ssf_audience' => 'firewall-receiver',
    'openidconnect_ssf_push_secret' => str_repeat('b', 43),
]);
Checks::that('the receiver setting has a typed accessor', $ssfConnector->receivesSharedSignals(), true);
Checks::that(
    'the transmitter issuer has a typed accessor',
    $ssfConnector->sharedSignalsIssuer(),
    'https://signals.example.net/tenant'
);

Checks::group('Shared Signals push boundary');
Directory::reset();
connector([
    'name' => 'Signals provider',
    'openidconnect_ssf_enabled' => '1',
    'openidconnect_ssf_issuer' => 'https://signals.example.net',
    'openidconnect_ssf_audience' => 'firewall-receiver',
    'openidconnect_ssf_push_secret' => str_repeat('b', 43),
]);
$push = new SsfController(new Request(
    'https',
    'firewall.example.net',
    [],
    [],
    ['CONTENT_TYPE' => 'application/secevent+jwt', 'AUTHORIZATION' => 'Bearer wrong'],
    'signed',
    'POST'
));
$push->beforeExecuteRoute(new class {
    public function getActionName(): string
    {
        return 'push';
    }
});
Checks::that('the public push boundary retains a private response policy', [
    $push->response->headers['Cache-Control'],
    $push->response->headers['Referrer-Policy'],
    $push->response->headers['X-Content-Type-Options'],
], ['no-store', 'no-referrer', 'nosniff']);
$pushFailure = json_decode($push->pushAction('main'), true);
Checks::that('a wrong delivery secret fails before transmitter discovery', [
    $push->response->status,
    $pushFailure['err'] ?? '',
], [[400, 'Bad Request'], 'authentication_failed']);
$unknownPush = new SsfController(new Request(
    'https',
    'firewall.example.net',
    [],
    [],
    ['CONTENT_TYPE' => 'application/secevent+jwt'],
    'signed',
    'POST'
));
$unknownFailure = json_decode($unknownPush->pushAction('unknown'), true);
Checks::that('an unknown receiver reveals only the generic authorization result', [
    $unknownPush->response->status,
    $unknownFailure['err'] ?? '',
], [[400, 'Bad Request'], 'access_denied']);

Checks::group('Shared Signals discovery');
Checks::that(
    'well-known discovery precedes an issuer path',
    SharedSignalsMetadata::discoveryUrl('https://signals.example.net/tenant'),
    'https://signals.example.net/.well-known/ssf-configuration/tenant'
);
$ssfMetadata = SharedSignalsMetadata::fromArray('https://signals.example.net', [
    'spec_version' => '1_0',
    'issuer' => 'https://signals.example.net',
    'jwks_uri' => 'https://signals.example.net/keys',
    'delivery_methods_supported' => [SharedSignalsMetadata::PUSH_METHOD],
    'critical_subject_members' => ['user'],
]);
Checks::that('push metadata exposes its exact issuer', $ssfMetadata->issuer(), 'https://signals.example.net');
Checks::throws(
    'metadata for another issuer is refused',
    fn() => SharedSignalsMetadata::fromArray('https://signals.example.net', [
        'issuer' => 'https://other.example.net',
        'jwks_uri' => 'https://signals.example.net/keys',
    ]),
    'exactly match'
);
Checks::throws(
    'metadata that excludes push is refused',
    fn() => SharedSignalsMetadata::fromArray('https://signals.example.net', [
        'issuer' => 'https://signals.example.net',
        'jwks_uri' => 'https://signals.example.net/keys',
        'delivery_methods_supported' => ['urn:ietf:rfc:8936'],
    ]),
    'push delivery'
);

Checks::group('Shared Signals event profile');
$now = time();
$eventClaims = [
    'iss' => 'https://signals.example.net',
    'aud' => 'firewall-receiver',
    'iat' => $now,
    'jti' => 'signal-once',
    'sub_id' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'subject-1'],
    'events' => [SecurityEventVerifier::CAEP_SESSION_REVOKED => ['event_timestamp' => $now - 5]],
];
$fakeJwt = new class(new HttpClient()) extends JwtVerifier {
    public array $header = ['typ' => 'secevent+jwt', 'alg' => 'RS256'];
    public array $claims = [];
    public function verifySignedJwt(string $jwt, string $jwksUri, array $advertisedAlgorithms = []): array
    {
        return ['header' => $this->header, 'claims' => $this->claims, 'key' => []];
    }
};
$fakeJwt->claims = $eventClaims;
$events = new SecurityEventVerifier($fakeJwt);
$verifyEvent = static function (
    string $type,
    array $event,
    ?array $subject = null,
    array $overrides = []
) use ($eventClaims, $fakeJwt, $events, $ssfMetadata, $now): array {
    $fakeJwt->header = ['typ' => 'secevent+jwt', 'alg' => 'RS256'];
    $fakeJwt->claims = array_replace($eventClaims, $overrides);
    $fakeJwt->claims['events'] = [$type => $event];
    if ($subject !== null) {
        $fakeJwt->claims['sub_id'] = $subject;
    }
    return $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    );
};
$accepted = $events->verify(
    'signed',
    $ssfMetadata,
    'firewall-receiver',
    'https://id.example.net',
    'general',
    $now
);
Checks::that('a supported event is actionable', $accepted['actionable'], true);
Checks::that('the subject remains opaque to local account policy', $accepted['subject'], 'subject-1');
Checks::that('the event time limits affected sessions', $accepted['cutoff'], $now - 5);

$knownCaepEvents = [
    SecurityEventVerifier::CAEP_SESSION_REVOKED,
    SecurityEventVerifier::CAEP_TOKEN_CLAIMS_CHANGE,
    SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE,
    SecurityEventVerifier::CAEP_ASSURANCE_LEVEL_CHANGE,
    SecurityEventVerifier::CAEP_DEVICE_COMPLIANCE_CHANGE,
    SecurityEventVerifier::CAEP_SESSION_ESTABLISHED,
    SecurityEventVerifier::CAEP_SESSION_PRESENTED,
    SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE,
];
Checks::that('the complete CAEP event profile is inventoried', SecurityEventVerifier::CAEP_EVENTS, $knownCaepEvents);
$actionableCaepEvents = [
    SecurityEventVerifier::CAEP_SESSION_REVOKED,
    SecurityEventVerifier::CAEP_TOKEN_CLAIMS_CHANGE,
    SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE,
    SecurityEventVerifier::CAEP_ASSURANCE_LEVEL_CHANGE,
    SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE,
];
Checks::that(
    'every CAEP event with a safe session consequence is selected',
    SecurityEventVerifier::ACTIONABLE_CAEP_EVENTS,
    $actionableCaepEvents
);

$knownRiscEvents = [
    SecurityEventVerifier::RISC_CREDENTIAL_REQUIRED,
    SecurityEventVerifier::RISC_ACCOUNT_PURGED,
    SecurityEventVerifier::RISC_ACCOUNT_DISABLED,
    SecurityEventVerifier::RISC_ACCOUNT_ENABLED,
    SecurityEventVerifier::RISC_IDENTIFIER_CHANGED,
    SecurityEventVerifier::RISC_IDENTIFIER_RECYCLED,
    SecurityEventVerifier::RISC_CREDENTIAL_COMPROMISE,
    SecurityEventVerifier::RISC_OPT_IN,
    SecurityEventVerifier::RISC_OPT_OUT_INITIATED,
    SecurityEventVerifier::RISC_OPT_OUT_CANCELLED,
    SecurityEventVerifier::RISC_OPT_OUT_EFFECTIVE,
    SecurityEventVerifier::RISC_RECOVERY_ACTIVATED,
    SecurityEventVerifier::RISC_RECOVERY_INFORMATION_CHANGED,
    SecurityEventVerifier::RISC_SESSIONS_REVOKED,
];
Checks::that('the complete RISC event profile is inventoried', SecurityEventVerifier::RISC_EVENTS, $knownRiscEvents);
$actionableRiscEvents = [
    SecurityEventVerifier::RISC_CREDENTIAL_REQUIRED,
    SecurityEventVerifier::RISC_ACCOUNT_PURGED,
    SecurityEventVerifier::RISC_ACCOUNT_DISABLED,
    SecurityEventVerifier::RISC_CREDENTIAL_COMPROMISE,
    SecurityEventVerifier::RISC_RECOVERY_ACTIVATED,
    SecurityEventVerifier::RISC_RECOVERY_INFORMATION_CHANGED,
    SecurityEventVerifier::RISC_SESSIONS_REVOKED,
];
Checks::that(
    'every RISC event with a safe session consequence is selected',
    SecurityEventVerifier::ACTIONABLE_RISC_EVENTS,
    $actionableRiscEvents
);
foreach ($actionableRiscEvents as $index => $type) {
    $profile = ['event_timestamp' => $now - $index - 10];
    if ($type === SecurityEventVerifier::RISC_CREDENTIAL_COMPROMISE) {
        $profile['credential_type'] = 'password';
    }
    $fakeJwt->claims = array_replace($eventClaims, [
        'jti' => 'risc-action-' . $index,
        'events' => [$type => $profile],
    ]);
    $result = $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    );
    Checks::that('the actionable RISC profile ends matching pre-event sessions: ' . $type, [
        $result['actionable'],
        $result['event'],
        $result['cutoff'],
    ], [true, $type, $now - $index - 10]);
}

$informationalRiscEvents = array_values(array_diff($knownRiscEvents, $actionableRiscEvents));
foreach ($informationalRiscEvents as $index => $type) {
    $claims = array_replace($eventClaims, [
        'jti' => 'risc-no-action-' . $index,
        'events' => [$type => []],
    ]);
    if (in_array($type, [
        SecurityEventVerifier::RISC_IDENTIFIER_CHANGED,
        SecurityEventVerifier::RISC_IDENTIFIER_RECYCLED,
    ], true)) {
        $claims['sub_id'] = ['format' => 'email', 'email' => 'person@example.net'];
    }
    $fakeJwt->claims = $claims;
    Checks::that(
        'a RISC profile without a safe local session consequence is acknowledged: ' . $type,
        $events->verify(
            'signed',
            $ssfMetadata,
            'firewall-receiver',
            'https://id.example.net',
            'general',
            $now
        )['actionable'],
        false
    );
}
$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [SecurityEventVerifier::RISC_IDENTIFIER_CHANGED => []],
]);
Checks::throws(
    'an identifier event with a forbidden issuer-and-subject profile is refused',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'email or phone'
);

$fakeJwt->claims = array_replace($eventClaims, [
    'events' => ['https://schemas.example.net/informational' => []],
]);
Checks::that(
    'an unknown valid event is acknowledged without action',
    $verifyEvent('https://schemas.example.net/informational', [])['actionable'],
    false
);
Checks::that(
    'an unknown event may define another subject field without changing the primary binding',
    $verifyEvent('https://schemas.example.net/informational', [
        'subject' => ['format' => 'opaque', 'id' => 'another-principal'],
    ])['actionable'],
    false
);
$opaqueSession = $verifyEvent(
    SecurityEventVerifier::CAEP_SESSION_REVOKED,
    [],
    ['format' => 'opaque', 'id' => 'provider-session']
);
Checks::that('an exact opaque session subject is actionable', [
    $opaqueSession['subject'],
    $opaqueSession['session_id'],
], [null, 'provider-session']);
$complexTarget = $verifyEvent(
    SecurityEventVerifier::CAEP_SESSION_REVOKED,
    [],
    [
        'format' => 'complex',
        'user' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'subject-1'],
        'session' => ['format' => 'opaque', 'id' => 'provider-session'],
    ]
);
Checks::that('a complete user and session subject retains both selectors', [
    $complexTarget['subject'],
    $complexTarget['session_id'],
], ['subject-1', 'provider-session']);
Checks::that(
    'an unindexed complex subject member prevents a broader session action',
    $verifyEvent(SecurityEventVerifier::CAEP_SESSION_REVOKED, [], [
        'format' => 'complex',
        'user' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'subject-1'],
        'device' => ['format' => 'opaque', 'id' => 'device'],
    ])['actionable'],
    false
);

$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [
        'https://schemas.example.net/alternate' => [],
        SecurityEventVerifier::RISC_ACCOUNT_DISABLED => ['event_timestamp' => $now - 9],
    ],
]);
Checks::throws(
    'distinct event URIs are refused as ambiguous',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'ambiguous'
);
$fakeJwt->claims = array_replace($eventClaims, [
    'sub_id' => ['format' => 'iss_sub', 'iss' => 'https://another.example.net', 'sub' => 'subject-1'],
]);
Checks::that(
    'an issuer and subject from another namespace cannot target a local session',
    $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    )['actionable'],
    false
);
$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [SecurityEventVerifier::RISC_RECOVERY_ACTIVATED => [
        'subject' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'another-subject'],
    ]],
]);
Checks::throws(
    'an event-level subject cannot differ from the primary subject',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'differs'
);
$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [SecurityEventVerifier::RISC_CREDENTIAL_COMPROMISE => []],
]);
Checks::throws(
    'a credential compromise without its required credential type is refused',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'credential type'
);
$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [SecurityEventVerifier::RISC_RECOVERY_ACTIVATED => ['event_timestamp' => (string)$now]],
]);
Checks::throws(
    'an actionable RISC event with a malformed timestamp is refused',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'event time'
);
$fakeJwt->claims = $eventClaims + ['exp' => $now + 60];
Checks::throws(
    'an SSF SET may not carry exp',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'forbidden'
);
$fakeJwt->claims = array_replace($eventClaims, ['aud' => 'another-receiver']);
Checks::throws(
    'a SET for another audience is refused',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'receiver'
);
$fakeJwt->claims = array_replace($eventClaims, ['iss' => 'https://other-signals.example.net']);
Checks::throws(
    'a SET issuer must exactly match transmitter discovery',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'issuer'
);
$fakeJwt->claims = array_replace($eventClaims, ['iat' => (string)$now]);
Checks::throws(
    'a SET issue time is not coerced from a string',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'issue time'
);
$fakeJwt->claims = $eventClaims;
$fakeJwt->header['typ'] = 'JWT';
Checks::throws(
    'a generic JWT type is refused before event processing',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'explicit'
);
Checks::throws(
    'a future event time is refused',
    fn() => $verifyEvent(
        SecurityEventVerifier::CAEP_SESSION_REVOKED,
        ['event_timestamp' => $now + JwtVerifier::CLOCK_TOLERANCE + 1]
    ),
    'event time'
);
Checks::throws(
    'an event time is not coerced from a string',
    fn() => $verifyEvent(
        SecurityEventVerifier::CAEP_SESSION_REVOKED,
        ['event_timestamp' => (string)($now - 1)]
    ),
    'event time'
);

$actionableProfiles = [
    SecurityEventVerifier::CAEP_TOKEN_CLAIMS_CHANGE => ['claims' => ['groups' => ['operators']]],
    SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE => [
        'credential_type' => 'password',
        'change_type' => 'update',
    ],
    SecurityEventVerifier::CAEP_ASSURANCE_LEVEL_CHANGE => [
        'namespace' => 'NIST-AAL',
        'current_level' => 'nist-aal1',
        'previous_level' => 'nist-aal2',
        'change_direction' => 'decrease',
    ],
    SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE => [
        'principal' => 'USER',
        'current_level' => 'HIGH',
        'previous_level' => 'LOW',
    ],
];
foreach ($actionableProfiles as $type => $profile) {
    Checks::that(
        'the session-action inventory includes ' . basename($type),
        $verifyEvent($type, $profile)['actionable'],
        true
    );
}
$informationalProfiles = [
    SecurityEventVerifier::CAEP_DEVICE_COMPLIANCE_CHANGE => [
        'previous_status' => 'compliant',
        'current_status' => 'not-compliant',
    ],
    SecurityEventVerifier::CAEP_SESSION_ESTABLISHED => ['amr' => ['pwd']],
    SecurityEventVerifier::CAEP_SESSION_PRESENTED => ['ext_id' => 'external-session'],
];
foreach ($informationalProfiles as $type => $profile) {
    Checks::that(
        'the inventory keeps ' . basename($type) . ' non-actionable',
        $verifyEvent($type, $profile)['actionable'],
        false
    );
}
Checks::that(
    'a low user risk does not end an established session',
    $verifyEvent(SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE, [
        'principal' => 'USER',
        'current_level' => 'LOW',
        'previous_level' => 'HIGH',
    ])['actionable'],
    false
);
Checks::that(
    'a high device risk cannot be broadened to every session of a user',
    $verifyEvent(SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE, [
        'principal' => 'DEVICE',
        'current_level' => 'HIGH',
    ])['actionable'],
    false
);
$sessionRisk = $verifyEvent(
    SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE,
    ['principal' => 'SESSION', 'current_level' => 'MEDIUM'],
    ['format' => 'opaque', 'id' => 'provider-session']
);
Checks::that('a medium or high exact session risk is actionable', $sessionRisk['session_id'], 'provider-session');
Checks::that(
    'an opaque assurance subject is not assumed to be an OIDC provider session',
    $verifyEvent(
        SecurityEventVerifier::CAEP_ASSURANCE_LEVEL_CHANGE,
        ['namespace' => 'NIST-AAL', 'current_level' => 'nist-aal1'],
        ['format' => 'opaque', 'id' => 'ambiguous-principal']
    )['actionable'],
    false
);

foreach ([
    [SecurityEventVerifier::CAEP_TOKEN_CLAIMS_CHANGE, [], 'claims claim'],
    [
        SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE,
        ['credential_type' => 'password', 'change_type' => 'rotate'],
        'change_type claim',
    ],
    [
        SecurityEventVerifier::CAEP_DEVICE_COMPLIANCE_CHANGE,
        ['previous_status' => 'compliant', 'current_status' => true],
        'current_status claim',
    ],
    [SecurityEventVerifier::CAEP_SESSION_ESTABLISHED, ['amr' => 'pwd'], 'amr claim'],
    [
        SecurityEventVerifier::CAEP_RISK_LEVEL_CHANGE,
        ['principal' => 'USER', 'current_level' => 'CRITICAL'],
        'current_level claim',
    ],
] as [$type, $profile, $message]) {
    Checks::throws(
        basename($type) . ' enforces its event-specific claim types',
        fn() => $verifyEvent($type, $profile),
        $message
    );
}

$fakeJwt->claims = $eventClaims;
unset($fakeJwt->claims['sub_id']);
$fakeJwt->claims['events'] = [SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE => [
    'subject' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'okta-subject'],
    'event_timestamp' => ($now - 2) * 1000,
    'credential_type' => 'password',
    'change_type' => 'update',
]];
$okta = $events->verify('signed', $ssfMetadata, 'firewall-receiver', 'https://id.example.net', 'okta', $now);
Checks::that('Okta legacy event subjects are narrowly accepted', $okta['subject'], 'okta-subject');
Checks::that('Okta millisecond timestamps are normalized', $okta['cutoff'], $now - 2);
$fakeJwt->claims = array_replace($eventClaims, [
    'sub_id' => [
        'subject_type' => 'iss_sub',
        'iss' => 'https://id.example.net',
        'sub' => 'google-subject',
    ],
    'events' => [SecurityEventVerifier::RISC_RECOVERY_ACTIVATED => []],
]);
$google = $events->verify('signed', $ssfMetadata, 'firewall-receiver', 'https://id.example.net', 'google', $now);
Checks::that('Google legacy subject_type is narrowly accepted', [
    $google['actionable'],
    $google['subject'],
], [true, 'google-subject']);
Checks::that(
    'Google legacy subject_type is not accepted for an unnamed profile',
    $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    )['actionable'],
    false
);
$fakeJwt->claims['sub_id']['format'] = 'email';
$fakeJwt->claims['sub_id']['email'] = 'person@example.net';
Checks::that(
    'a conforming Google format takes precedence over its legacy subject_type',
    $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'google',
        $now
    )['actionable'],
    false
);
$fakeJwt->claims['sub_id'] = [
    'format' => 'complex',
    'user' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'subject-1'],
    'device' => ['format' => 'opaque', 'id' => 'device'],
];
$riscComplex = $events->verify(
    'signed',
    $ssfMetadata,
    'firewall-receiver',
    'https://id.example.net',
    'general',
    $now
);
Checks::that('a RISC complex subject consumes only its exact user member', [
    $riscComplex['actionable'],
    $riscComplex['session_id'],
], [true, null]);
$criticalMetadata = SharedSignalsMetadata::fromArray('https://signals.example.net', [
    'issuer' => 'https://signals.example.net',
    'jwks_uri' => 'https://signals.example.net/keys',
    'critical_subject_members' => ['device'],
]);
Checks::throws(
    'an unsupported critical subject member discards the event',
    fn() => $events->verify(
        'signed',
        $criticalMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'okta',
        $now
    ),
    'critical subject'
);
$fakeJwt->claims = array_replace($eventClaims, [
    'events' => [SecurityEventVerifier::CAEP_SESSION_REVOKED => [
        'subject' => [
            'format' => 'iss_sub',
            'iss' => 'https://id.example.net',
            'sub' => 1,
        ],
    ]],
]);
Checks::throws(
    'an event-level subject cannot change the primary subject type',
    fn() => $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    ),
    'differs'
);

Checks::group('Shared Signals replay and session cutoff');
$oldId = 'oldsession123456789';
$newId = 'newsession123456789';
$otherIssuerId = 'otherissuer12345678';
file_put_contents(constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $oldId, 'old');
file_put_contents(constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $newId, 'new');
file_put_contents(constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $otherIssuerId, 'other');
SessionRegistry::record($oldId, 'SSO', 'https://id.example.net', 'subject-1', '', $now + 600, $now - 60);
SessionRegistry::record($newId, 'SSO', 'https://id.example.net', 'subject-1', '', $now + 600, $now + 120);
SessionRegistry::record(
    $otherIssuerId,
    'SSO',
    'https://another.example.net',
    'subject-1',
    '',
    $now + 600,
    $now - 60
);
Checks::that(
    'only sessions existing at the event time are terminated',
    SessionRegistry::terminateForSecurityEvent('SSO', 'https://id.example.net', 'subject-1', $now),
    1
);
Checks::that('the newer session remains', file_exists(
    constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $newId
), true);
Checks::that('the same subject from another issuer remains', file_exists(
    constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $otherIssuerId
), true);
$matchingSidId = 'matchingsid123456789';
$differentSidId = 'differentsid1234567';
file_put_contents(constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $matchingSidId, 'matching');
file_put_contents(constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $differentSidId, 'different');
SessionRegistry::record(
    $matchingSidId,
    'SSO',
    'https://id.example.net',
    'subject-1',
    'provider-session',
    $now + 600,
    $now - 60
);
SessionRegistry::record(
    $differentSidId,
    'SSO',
    'https://id.example.net',
    'subject-1',
    'another-session',
    $now + 600,
    $now - 60
);
Checks::that(
    'a security event can terminate one exact indexed provider session',
    SessionRegistry::terminateForSecurityEvent(
        'SSO',
        'https://id.example.net',
        'subject-1',
        $now,
        'provider-session'
    ),
    1
);
Checks::that('another provider session for the same user remains', file_exists(
    constant('OPENIDCONNECT_TEST_SESSION_DIRECTORY') . '/sess_' . $differentSidId
), true);
Checks::that(
    'a security event replay is accepted once',
    SessionRegistry::acceptSecurityEvent('SSO', 'https://signals.example.net', 'aud', 'one'),
    true
);
Checks::that(
    'the same security event replay is then refused',
    SessionRegistry::acceptSecurityEvent('SSO', 'https://signals.example.net', 'aud', 'one'),
    false
);
SessionRegistry::releaseSecurityEvent('SSO', 'https://signals.example.net', 'aud', 'one');
Checks::that(
    'a failed action can release its replay marker',
    SessionRegistry::acceptSecurityEvent('SSO', 'https://signals.example.net', 'aud', 'one'),
    true
);
