<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\ProviderRuntimeState;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SessionRegistry;
use OPNsense\OpenIDConnect\SharedSignalsClient;
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
$_POST = [
    'type' => 'openidconnect',
    'openidconnect_ssf_enabled' => '1',
    'openidconnect_ssf_delivery_method' => 'poll',
];
Checks::that(
    'explicit polling requires management authorization',
    count($ssfOptions['openidconnect_ssf_management_authorization']['validate']('')),
    1
);
Checks::that(
    'explicit polling requires a managed stream ID',
    count($ssfOptions['openidconnect_ssf_stream_id']['validate']('')),
    1
);
Checks::that(
    'explicit polling requires its assigned HTTPS endpoint',
    count($ssfOptions['openidconnect_ssf_poll_endpoint']['validate']('')),
    1
);
Checks::that(
    'polling never requires a push secret as fallback',
    $ssfOptions['openidconnect_ssf_push_secret']['validate'](''),
    []
);
Checks::that(
    'a bounded Bearer management authorization is accepted',
    $ssfOptions['openidconnect_ssf_management_authorization']['validate']('Bearer management-token'),
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
Checks::that('push remains the compatibility delivery default', $ssfConnector->sharedSignalsDeliveryMethod(),
    SharedSignalsMetadata::PUSH_METHOD);
Checks::that('polling is selected only by its explicit setting', connector([
    'openidconnect_ssf_delivery_method' => 'poll',
])->sharedSignalsDeliveryMethod(), SharedSignalsMetadata::POLL_METHOD);
ProviderRuntimeState::ssfPollSuccess('shared-signals-health', 2, 1000);
Checks::that('a recent successful poll is observable', ProviderRuntimeState::ssfStatus(
    'shared-signals-health',
    1100
)['status'], 'fresh');
Checks::that('a stopped poll worker becomes observable', ProviderRuntimeState::ssfStatus(
    'shared-signals-health',
    1200
)['status'], 'stale');

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
    'delivery_methods_supported' => [SharedSignalsMetadata::PUSH_METHOD, SharedSignalsMetadata::POLL_METHOD],
    'configuration_endpoint' => 'https://signals.example.net/streams',
    'status_endpoint' => 'https://signals.example.net/status',
    'authorization_schemes' => [['spec_urn' => SharedSignalsMetadata::OAUTH_AUTHORIZATION]],
    'critical_subject_members' => ['user'],
]);
Checks::that('push metadata exposes its exact issuer', $ssfMetadata->issuer(), 'https://signals.example.net');
Checks::that('management endpoints come only from validated metadata', $ssfMetadata->configurationEndpoint(),
    'https://signals.example.net/streams');
Checks::throws(
    'metadata for another issuer is refused',
    fn() => SharedSignalsMetadata::fromArray('https://signals.example.net', [
        'issuer' => 'https://other.example.net',
        'jwks_uri' => 'https://signals.example.net/keys',
    ]),
    'exactly match'
);
$pollOnlyMetadata = SharedSignalsMetadata::fromArray('https://signals.example.net', [
    'issuer' => 'https://signals.example.net',
    'jwks_uri' => 'https://signals.example.net/keys',
    'delivery_methods_supported' => [SharedSignalsMetadata::POLL_METHOD],
]);
Checks::that('poll-only metadata cannot silently receive push',
    $pollOnlyMetadata->supportsDelivery(SharedSignalsMetadata::PUSH_METHOD), false);
Checks::that('poll-only metadata explicitly supports polling',
    $pollOnlyMetadata->supportsDelivery(SharedSignalsMetadata::POLL_METHOD), true);
$legacyMetadata = SharedSignalsMetadata::fromArray('https://signals.example.net', [
    'issuer' => 'https://signals.example.net',
    'jwks_uri' => 'https://signals.example.net/keys',
]);
Checks::that('omitted delivery metadata retains only legacy push compatibility', [
    $legacyMetadata->supportsDelivery(SharedSignalsMetadata::PUSH_METHOD),
    $legacyMetadata->supportsDelivery(SharedSignalsMetadata::POLL_METHOD),
], [true, false]);

Checks::group('Shared Signals stream lifecycle client');
$managementCalls = [];
$managementResponses = [];
$managementHttp = new HttpClient(static function (
    string $method,
    string $url,
    ?string $body,
    array $headers,
    int $maximum
) use (&$managementCalls, &$managementResponses): array {
    $managementCalls[] = compact('method', 'url', 'body', 'headers', 'maximum');
    return array_shift($managementResponses);
});
$management = new SharedSignalsClient($managementHttp);
$noDefaultSubjects = SharedSignalsMetadata::fromArray('https://signals.example.net', [
    'issuer' => 'https://signals.example.net',
    'jwks_uri' => 'https://signals.example.net/keys',
    'delivery_methods_supported' => [SharedSignalsMetadata::PUSH_METHOD],
    'configuration_endpoint' => 'https://signals.example.net/streams',
    'default_subjects' => 'NONE',
]);
Checks::throws(
    'stream creation refuses an empty default subject set without subject management',
    fn() => $management->createStream(
        $noDefaultSubjects,
        'Bearer management-token',
        SharedSignalsMetadata::PUSH_METHOD,
        'https://firewall.example.net/api/openidconnect/ssf/push/main',
        'Bearer ' . str_repeat('s', 43)
    ),
    'subject management'
);
$pushConfiguration = [
    'stream_id' => 'stream-1',
    'iss' => 'https://signals.example.net',
    'aud' => 'firewall-receiver',
    'delivery' => [
        'method' => SharedSignalsMetadata::PUSH_METHOD,
        'endpoint_url' => 'https://firewall.example.net/api/openidconnect/ssf/push/main',
    ],
    'events_requested' => SecurityEventVerifier::ACTIONABLE_EVENTS,
    'events_delivered' => [SecurityEventVerifier::CAEP_SESSION_REVOKED],
];
$managementResponses[] = [
    'status' => 201,
    'content_type' => 'application/json',
    'body' => json_encode($pushConfiguration),
    'location' => '',
    'headers' => [],
];
$createdStream = $management->createStream(
    $ssfMetadata,
    'Bearer management-token',
    SharedSignalsMetadata::PUSH_METHOD,
    'https://firewall.example.net/api/openidconnect/ssf/push/main',
    'Bearer ' . str_repeat('s', 43),
    'OPNsense'
);
Checks::that('stream creation accepts the transmitter-assigned ID and audience', [
    $createdStream['stream_id'], $createdStream['audience'],
], ['stream-1', 'firewall-receiver']);
Checks::that('stream creation uses the discovered configuration endpoint', [
    $managementCalls[0]['method'], $managementCalls[0]['url'],
], ['POST', 'https://signals.example.net/streams']);
Checks::that('stream management credentials are sent only as a request header', [
    in_array('Authorization: Bearer management-token', $managementCalls[0]['headers'], true),
    str_contains((string)$managementCalls[0]['body'], 'management-token'),
], [true, false]);

$managementResponses[] = [
    'status' => 200,
    'content_type' => 'application/json',
    'body' => json_encode(['stream_id' => 'stream-1', 'status' => 'paused', 'reason' => 'maintenance']),
    'location' => '',
    'headers' => [],
];
Checks::that('the discovered status endpoint reports a bounded lifecycle state',
    $management->readStatus($ssfMetadata, 'Bearer management-token', 'stream-1')['status'], 'paused');

$pollConfiguration = array_replace($pushConfiguration, [
    'delivery' => [
        'method' => SharedSignalsMetadata::POLL_METHOD,
        'endpoint_url' => 'https://signals.example.net/poll/stream-1',
    ],
]);
$managementResponses[] = [
    'status' => 200,
    'content_type' => 'application/json',
    'body' => json_encode($pollConfiguration),
    'location' => '',
    'headers' => [],
];
$readPoll = $management->readStream(
    $ssfMetadata,
    'Bearer management-token',
    'stream-1',
    SharedSignalsMetadata::POLL_METHOD,
    'https://signals.example.net/poll/stream-1',
    'firewall-receiver'
);
Checks::that('a poll endpoint is accepted only from the validated stream response',
    $readPoll['poll_endpoint'], 'https://signals.example.net/poll/stream-1');

$managementResponses[] = [
    'status' => 200,
    'content_type' => 'application/json',
    'body' => json_encode(['sets' => ['urn:uuid:poll-jti' => 'signed-set'], 'moreAvailable' => false]),
    'location' => '',
    'headers' => [],
];
$polled = $management->poll(
    $ssfMetadata,
    'Bearer management-token',
    'https://signals.example.net/poll/stream-1'
);
Checks::that('poll delivery returns a bounded jti-to-SET collection', $polled, [
    'sets' => ['urn:uuid:poll-jti' => 'signed-set'],
    'more_available' => false,
]);
Checks::that('polling is an explicit short POST with a batch limit', [
    $managementCalls[3]['method'],
    json_decode((string)$managementCalls[3]['body'], true),
], ['POST', ['maxEvents' => 20, 'returnImmediately' => true]]);

$managementResponses[] = [
    'status' => 200,
    'content_type' => 'application/json',
    'body' => json_encode(['sets' => (object)[]]),
    'location' => '',
    'headers' => [],
];
$management->poll(
    $ssfMetadata,
    'Bearer management-token',
    'https://signals.example.net/poll/stream-1',
    ['urn:uuid:poll-jti'],
    ['urn:uuid:refused-jti' => [
        'err' => 'invalid_key',
        'description' => 'The Security Event Token was not accepted.',
    ]],
    0
);
$pollAcknowledgement = json_decode((string)$managementCalls[4]['body'], true);
Checks::that('poll acknowledgements preserve opaque SET identifiers', $pollAcknowledgement['ack'], [
    'urn:uuid:poll-jti',
]);
Checks::that('poll errors use the shared registered SET error code and language', [
    $pollAcknowledgement['setErrs']['urn:uuid:refused-jti']['err'],
    in_array('Content-Language: en', $managementCalls[4]['headers'], true),
], ['invalid_key', true]);

$mismatchedConfiguration = array_replace($pushConfiguration, ['iss' => 'https://other.example.net']);
$managementResponses[] = [
    'status' => 200,
    'content_type' => 'application/json',
    'body' => json_encode($mismatchedConfiguration),
    'location' => '',
    'headers' => [],
];
Checks::throws(
    'a stream response for another issuer is refused',
    fn() => $management->readStream(
        $ssfMetadata,
        'Bearer management-token',
        'stream-1',
        SharedSignalsMetadata::PUSH_METHOD,
        'https://firewall.example.net/api/openidconnect/ssf/push/main',
        'firewall-receiver'
    ),
    'issuer'
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
    'events' => [
        'https://schemas.example.net/alternate' => [],
        SecurityEventVerifier::RISC_ACCOUNT_DISABLED => ['event_timestamp' => $now - 9],
    ],
]);
$multiple = $events->verify(
    'signed',
    $ssfMetadata,
    'firewall-receiver',
    'https://id.example.net',
    'general',
    $now
);
Checks::that('multiple event URIs retain a supported session action', $multiple['actionable'], true);
Checks::that('multiple event URIs retain the earliest supported event time', $multiple['cutoff'], $now - 9);
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
$fakeJwt->claims = $eventClaims;
unset($fakeJwt->claims['sub_id']);
$fakeJwt->claims['events'] = [SecurityEventVerifier::CAEP_CREDENTIAL_CHANGE => [
    'subject' => ['format' => 'iss_sub', 'iss' => 'https://id.example.net', 'sub' => 'okta-subject'],
    'event_timestamp' => ($now - 2) * 1000,
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
Checks::that(
    'a complex subject can identify the same user session without consuming its device member',
    $events->verify(
        'signed',
        $ssfMetadata,
        'firewall-receiver',
        'https://id.example.net',
        'general',
        $now
    )['actionable'],
    true
);
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
