<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\OpenIDConnect;

/** Signature, SET-profile and narrowly actionable CAEP/RISC validation. */
final class SecurityEventVerifier
{
    public const CAEP_SESSION_REVOKED =
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked';
    public const CAEP_TOKEN_CLAIMS_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/token-claims-change';
    public const CAEP_CREDENTIAL_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/credential-change';
    public const CAEP_ASSURANCE_LEVEL_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change';
    public const CAEP_DEVICE_COMPLIANCE_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change';
    public const CAEP_SESSION_ESTABLISHED =
        'https://schemas.openid.net/secevent/caep/event-type/session-established';
    public const CAEP_SESSION_PRESENTED =
        'https://schemas.openid.net/secevent/caep/event-type/session-presented';
    public const CAEP_RISK_LEVEL_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';

    public const RISC_CREDENTIAL_REQUIRED =
        'https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required';
    public const RISC_ACCOUNT_PURGED =
        'https://schemas.openid.net/secevent/risc/event-type/account-purged';
    public const RISC_ACCOUNT_DISABLED =
        'https://schemas.openid.net/secevent/risc/event-type/account-disabled';
    public const RISC_ACCOUNT_ENABLED =
        'https://schemas.openid.net/secevent/risc/event-type/account-enabled';
    public const RISC_IDENTIFIER_CHANGED =
        'https://schemas.openid.net/secevent/risc/event-type/identifier-changed';
    public const RISC_IDENTIFIER_RECYCLED =
        'https://schemas.openid.net/secevent/risc/event-type/identifier-recycled';
    public const RISC_CREDENTIAL_COMPROMISE =
        'https://schemas.openid.net/secevent/risc/event-type/credential-compromise';
    public const RISC_RECOVERY_ACTIVATED =
        'https://schemas.openid.net/secevent/risc/event-type/recovery-activated';
    public const RISC_RECOVERY_INFORMATION_CHANGED =
        'https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed';
    public const RISC_SESSIONS_REVOKED =
        'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked';
    public const RISC_OPT_IN =
        'https://schemas.openid.net/secevent/risc/event-type/opt-in';
    public const RISC_OPT_OUT_INITIATED =
        'https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated';
    public const RISC_OPT_OUT_CANCELLED =
        'https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled';
    public const RISC_OPT_OUT_EFFECTIVE =
        'https://schemas.openid.net/secevent/risc/event-type/opt-out-effective';

    public const CAEP_EVENTS = [
        self::CAEP_SESSION_REVOKED,
        self::CAEP_TOKEN_CLAIMS_CHANGE,
        self::CAEP_CREDENTIAL_CHANGE,
        self::CAEP_ASSURANCE_LEVEL_CHANGE,
        self::CAEP_DEVICE_COMPLIANCE_CHANGE,
        self::CAEP_SESSION_ESTABLISHED,
        self::CAEP_SESSION_PRESENTED,
        self::CAEP_RISK_LEVEL_CHANGE,
    ];
    public const ACTIONABLE_CAEP_EVENTS = [
        self::CAEP_SESSION_REVOKED,
        self::CAEP_TOKEN_CLAIMS_CHANGE,
        self::CAEP_CREDENTIAL_CHANGE,
        self::CAEP_ASSURANCE_LEVEL_CHANGE,
        self::CAEP_RISK_LEVEL_CHANGE,
    ];
    public const RISC_EVENTS = [
        self::RISC_CREDENTIAL_REQUIRED,
        self::RISC_ACCOUNT_PURGED,
        self::RISC_ACCOUNT_DISABLED,
        self::RISC_ACCOUNT_ENABLED,
        self::RISC_IDENTIFIER_CHANGED,
        self::RISC_IDENTIFIER_RECYCLED,
        self::RISC_CREDENTIAL_COMPROMISE,
        self::RISC_OPT_IN,
        self::RISC_OPT_OUT_INITIATED,
        self::RISC_OPT_OUT_CANCELLED,
        self::RISC_OPT_OUT_EFFECTIVE,
        self::RISC_RECOVERY_ACTIVATED,
        self::RISC_RECOVERY_INFORMATION_CHANGED,
        self::RISC_SESSIONS_REVOKED,
    ];
    public const ACTIONABLE_RISC_EVENTS = [
        self::RISC_CREDENTIAL_REQUIRED,
        self::RISC_ACCOUNT_PURGED,
        self::RISC_ACCOUNT_DISABLED,
        self::RISC_CREDENTIAL_COMPROMISE,
        self::RISC_RECOVERY_ACTIVATED,
        self::RISC_RECOVERY_INFORMATION_CHANGED,
        self::RISC_SESSIONS_REVOKED,
    ];
    public const ACTIONABLE_EVENTS = [
        self::CAEP_SESSION_REVOKED,
        self::CAEP_TOKEN_CLAIMS_CHANGE,
        self::CAEP_CREDENTIAL_CHANGE,
        self::CAEP_ASSURANCE_LEVEL_CHANGE,
        self::CAEP_RISK_LEVEL_CHANGE,
        self::RISC_CREDENTIAL_REQUIRED,
        self::RISC_ACCOUNT_PURGED,
        self::RISC_ACCOUNT_DISABLED,
        self::RISC_CREDENTIAL_COMPROMISE,
        self::RISC_RECOVERY_ACTIVATED,
        self::RISC_RECOVERY_INFORMATION_CHANGED,
        self::RISC_SESSIONS_REVOKED,
    ];

    public function __construct(private readonly JwtVerifier $jwt)
    {
    }

    /**
     * @return array{
     *     jti:string,
     *     subject:?string,
     *     subject_issuer:?string,
     *     session_id:?string,
     *     cutoff:int,
     *     actionable:bool,
     *     event:string
     * }
     */
    public function verify(
        string $set,
        SharedSignalsMetadata $metadata,
        string $audience,
        string $oidcIssuer,
        string $providerProfile = 'general',
        ?int $now = null
    ): array {
        try {
            $verified = $this->jwt->verifySignedJwt($set, $metadata->jwksUri());
        } catch (\Throwable $e) {
            throw new SecurityEventException('invalid_key', 'The SET signature or signing key is invalid', $e);
        }
        $header = $verified['header'];
        $claims = $verified['claims'];
        $now ??= time();
        if (!is_string($header['typ'] ?? null) || !hash_equals('secevent+jwt', $header['typ'])) {
            $this->fail('invalid_request', 'The SET has no explicit Security Event Token type');
        }
        if (!is_string($claims['iss'] ?? null) || !hash_equals($metadata->issuer(), $claims['iss'])) {
            $this->fail('invalid_issuer', 'The SET issuer does not exactly match discovery');
        }
        $audiences = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? null);
        if (!is_array($audiences) || !array_is_list($audiences)
            || array_filter($audiences, 'is_string') !== $audiences || !in_array($audience, $audiences, true)) {
            $this->fail('invalid_audience', 'The SET was not issued to this receiver');
        }
        foreach ($audiences as $candidate) {
            if ($candidate === '' || strlen($candidate) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $candidate)) {
                $this->fail('invalid_audience', 'The SET carries an invalid receiver audience');
            }
        }
        if (!is_int($claims['iat'] ?? null) || $claims['iat'] < 0
            || $claims['iat'] > $now + JwtVerifier::CLOCK_TOLERANCE) {
            $this->fail('invalid_request', 'The SET has no valid issue time');
        }
        if (array_key_exists('nbf', $claims)
            && (!is_int($claims['nbf']) || $claims['nbf'] < 0
                || $claims['nbf'] > $now + JwtVerifier::CLOCK_TOLERANCE)) {
            $this->fail('invalid_request', 'The SET is not yet valid');
        }
        if (array_key_exists('exp', $claims) || array_key_exists('sub', $claims)) {
            $this->fail('invalid_request', 'The SET carries a JWT claim forbidden by Shared Signals');
        }
        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '' || strlen($jti) > 255 || preg_match('/[\x00-\x1f\x7f]/', $jti)) {
            $this->fail('invalid_request', 'The SET has no usable token identifier');
        }
        $events = $claims['events'] ?? null;
        if (!is_array($events) || $events === [] || array_is_list($events)) {
            $this->fail('invalid_request', 'The SET must contain at least one event object');
        }
        foreach ($events as $type => $event) {
            if (!is_string($type) || $type === '' || strlen($type) > 512
                || preg_match('/[\x00-\x1f\x7f]/', $type) || !is_array($event)
                || ($event !== [] && array_is_list($event))) {
                $this->fail('invalid_request', 'The SET contains an invalid event');
            }
        }
        /* SSF permits several URIs only when they are aliases for one event; this receiver knows no aliases. */
        if (count($events) !== 1) {
            $this->fail('invalid_request', 'The SET contains ambiguous event types');
        }
        $eventType = (string)array_key_first($events);
        $event = $events[$eventType];
        $knownEvent = in_array($eventType, self::CAEP_EVENTS, true)
            || in_array($eventType, self::RISC_EVENTS, true);

        $subjectValue = $claims['sub_id'] ?? null;
        if ($subjectValue === null && $providerProfile === 'okta' && $knownEvent) {
            $subjectValue = $event['subject'] ?? null;
        }
        if (!is_array($subjectValue)) {
            $this->fail('invalid_request', 'The SET has no primary subject');
        }
        $googleCompatibility = $providerProfile === 'google';
        $this->validateRiscSubjectProfile($eventType, $subjectValue, $googleCompatibility);
        $subject = $this->subjectSelectors(
            $subjectValue,
            $metadata->criticalSubjectMembers(),
            $googleCompatibility
        );
        if ($knownEvent && array_key_exists('subject', $event)) {
            if (!is_array($event['subject']) || !$this->sameJsonValue($event['subject'], $subjectValue)) {
                $this->fail('invalid_request', 'The SET event subject differs from its primary subject');
            }
            $this->subjectSelectors(
                $event['subject'],
                $metadata->criticalSubjectMembers(),
                $googleCompatibility
            );
        }

        $cutoff = $this->validateEvent($eventType, $event, $claims['iat'], $now, $providerProfile);
        $target = $this->actionTarget($eventType, $event, $subject, $oidcIssuer);

        return [
            'jti' => $jti,
            'subject' => $target['subject'] ?? null,
            'subject_issuer' => $target === null ? null : $oidcIssuer,
            'session_id' => $target['session_id'] ?? null,
            'cutoff' => $cutoff,
            'actionable' => $target !== null,
            'event' => $eventType,
        ];
    }

    /**
     * @return array{
     *     user:?array{iss:string,sub:string},
     *     session_id:?string,
     *     complete:bool
     * }
     */
    private function subjectSelectors(array $subject, array $criticalMembers, bool $googleCompatibility): array
    {
        $format = $this->subjectFormat($subject, $googleCompatibility);
        if ($format === 'complex') {
            if (count($subject) < 2) {
                $this->fail('invalid_request', 'The SET carries an empty complex subject');
            }
            foreach ($criticalMembers as $member) {
                if (array_key_exists($member, $subject) && !in_array($member, ['user', 'session'], true)) {
                    $this->fail('invalid_request', 'The SET has an unsupported critical subject member');
                }
            }
            foreach ($subject as $member => $identifier) {
                if ($member === 'format' || ($googleCompatibility && $member === 'subject_type')) {
                    continue;
                }
                if (!is_string($member) || $member === '' || strlen($member) > 64
                    || preg_match('/[\x00-\x1f\x7f]/', $member) || !is_array($identifier)
                    || $this->subjectFormat($identifier, $googleCompatibility) === 'complex') {
                    $this->fail('invalid_request', sprintf('The SET has an invalid %s subject', $member));
                }
            }
            $user = is_array($subject['user'] ?? null)
                ? $this->issuerSubject($subject['user'], $googleCompatibility) : null;
            $sessionId = is_array($subject['session'] ?? null)
                ? $this->opaqueId($subject['session'], $googleCompatibility) : null;
            foreach (['user' => $user, 'session' => $sessionId] as $member => $selector) {
                if (in_array($member, $criticalMembers, true) && array_key_exists($member, $subject)
                    && $selector === null) {
                    $this->fail('invalid_request', sprintf(
                        'The SET has an unsupported critical %s subject',
                        $member
                    ));
                }
            }
            $members = array_diff(
                array_keys($subject),
                $googleCompatibility ? ['format', 'subject_type', 'user', 'session'] : ['format', 'user', 'session']
            );
            return [
                'user' => $user,
                'session_id' => $sessionId,
                'complete' => $members === [] && ($user !== null || $sessionId !== null),
            ];
        }
        $user = $this->issuerSubject($subject, $googleCompatibility);
        if ($user !== null) {
            return ['user' => $user, 'session_id' => null, 'complete' => true];
        }
        $sessionId = $this->opaqueId($subject, $googleCompatibility);
        return ['user' => null, 'session_id' => $sessionId, 'complete' => $sessionId !== null];
    }

    private function subjectFormat(array $subject, bool $googleCompatibility): ?string
    {
        $format = $subject['format'] ?? null;
        if ($format === null && $googleCompatibility) {
            $format = $subject['subject_type'] ?? null;
        }
        if ($format === null) {
            return null;
        }
        if (!is_string($format) || $format === '' || strlen($format) > 64
            || preg_match('/[\x00-\x1f\x7f]/', $format)) {
            $this->fail('invalid_request', 'The SET carries an invalid subject format');
        }
        return $format;
    }

    /** @return array{iss:string,sub:string}|null */
    private function issuerSubject(array $subject, bool $googleCompatibility): ?array
    {
        if ($this->subjectFormat($subject, $googleCompatibility) !== 'iss_sub') {
            return null;
        }
        $members = array_keys($subject);
        if ($googleCompatibility && array_key_exists('format', $subject)) {
            $members = array_values(array_diff($members, ['subject_type']));
        }
        sort($members);
        $expected = $googleCompatibility && !array_key_exists('format', $subject)
            ? ['iss', 'sub', 'subject_type'] : ['format', 'iss', 'sub'];
        if ($members !== $expected) {
            $this->fail('invalid_request', 'The SET carries an invalid issuer and subject identifier');
        }
        $issuer = $subject['iss'] ?? null;
        $sub = $subject['sub'] ?? null;
        if (!is_string($issuer) || $issuer === '' || strlen($issuer) > 4096
            || !is_string($sub) || $sub === '' || strlen($sub) > 255
            || preg_match('/[\x00-\x1f\x7f]/', $issuer . $sub)) {
            $this->fail('invalid_request', 'The SET carries an invalid issuer and subject identifier');
        }
        return ['iss' => $issuer, 'sub' => $sub];
    }

    private function opaqueId(array $subject, bool $googleCompatibility): ?string
    {
        if ($this->subjectFormat($subject, $googleCompatibility) !== 'opaque') {
            return null;
        }
        $members = array_keys($subject);
        if ($googleCompatibility && array_key_exists('format', $subject)) {
            $members = array_values(array_diff($members, ['subject_type']));
        }
        sort($members);
        $expected = $googleCompatibility && !array_key_exists('format', $subject)
            ? ['id', 'subject_type'] : ['format', 'id'];
        if ($members !== $expected) {
            $this->fail('invalid_request', 'The SET carries an invalid opaque subject identifier');
        }
        $id = $subject['id'] ?? null;
        if (!is_string($id) || $id === '' || strlen($id) > 255 || preg_match('/[\x00-\x1f\x7f]/', $id)) {
            $this->fail('invalid_request', 'The SET carries an invalid opaque subject identifier');
        }
        return $id;
    }

    private function validateRiscSubjectProfile(string $type, array $subject, bool $googleCompatibility): void
    {
        if (!in_array($type, [self::RISC_IDENTIFIER_CHANGED, self::RISC_IDENTIFIER_RECYCLED], true)) {
            return;
        }
        if (!in_array($this->subjectFormat($subject, $googleCompatibility), ['email', 'phone'], true)) {
            $this->fail('invalid_request', 'The RISC identifier event requires an email or phone subject');
        }
    }

    private function validateEvent(
        string $type,
        array $event,
        int $issuedAt,
        int $now,
        string $providerProfile
    ): int {
        $cutoff = $issuedAt;
        if (in_array($type, self::CAEP_EVENTS, true)) {
            $cutoff = $this->validateCaepCommon($event, $issuedAt, $now, $providerProfile === 'okta');
        } elseif (!in_array($type, self::RISC_EVENTS, true)) {
            return $cutoff;
        } elseif (in_array($type, self::ACTIONABLE_RISC_EVENTS, true)
            && array_key_exists('event_timestamp', $event)) {
            $cutoff = min(
                $issuedAt,
                $this->eventTimestamp($event['event_timestamp'], $now, $providerProfile === 'okta')
            );
        }

        switch ($type) {
            case self::CAEP_TOKEN_CLAIMS_CHANGE:
                $this->objectClaim($event, 'claims');
                break;
            case self::CAEP_CREDENTIAL_CHANGE:
                $this->stringClaim($event, 'credential_type');
                $this->enumClaim($event, 'change_type', ['create', 'revoke', 'update', 'delete']);
                foreach (['friendly_name', 'x509_issuer', 'x509_serial', 'fido2_aaguid'] as $claim) {
                    $this->optionalStringClaim($event, $claim);
                }
                break;
            case self::CAEP_ASSURANCE_LEVEL_CHANGE:
                $this->stringClaim($event, 'namespace');
                $this->stringClaim($event, 'current_level');
                $this->optionalStringClaim($event, 'previous_level');
                $this->optionalEnumClaim($event, 'change_direction', ['increase', 'decrease']);
                break;
            case self::CAEP_DEVICE_COMPLIANCE_CHANGE:
                $this->enumClaim($event, 'previous_status', ['compliant', 'not-compliant']);
                $this->enumClaim($event, 'current_status', ['compliant', 'not-compliant']);
                break;
            case self::CAEP_SESSION_ESTABLISHED:
                foreach (['fp_ua', 'acr', 'ext_id'] as $claim) {
                    $this->optionalStringClaim($event, $claim);
                }
                $this->optionalStringListClaim($event, 'amr');
                break;
            case self::CAEP_SESSION_PRESENTED:
                foreach (['fp_ua', 'ext_id'] as $claim) {
                    $this->optionalStringClaim($event, $claim);
                }
                break;
            case self::CAEP_RISK_LEVEL_CHANGE:
                $this->stringClaim($event, 'principal');
                $this->enumClaim($event, 'current_level', ['LOW', 'MEDIUM', 'HIGH']);
                $this->optionalEnumClaim($event, 'previous_level', ['LOW', 'MEDIUM', 'HIGH']);
                $this->optionalStringClaim($event, 'risk_reason');
                break;
            case self::RISC_ACCOUNT_DISABLED:
                $this->optionalEnumClaim($event, 'reason', ['hijacking', 'bulk-account']);
                break;
            case self::RISC_IDENTIFIER_CHANGED:
                $this->optionalStringClaim($event, 'new-value');
                break;
            case self::RISC_CREDENTIAL_COMPROMISE:
                $credentialType = $event['credential_type'] ?? null;
                if (!is_string($credentialType) || $credentialType === '' || strlen($credentialType) > 128
                    || preg_match('/[\x00-\x1f\x7f]/', $credentialType)) {
                    $this->fail(
                        'invalid_request',
                        'The credential compromise event has no usable credential type'
                    );
                }
                break;
        }
        return $cutoff;
    }

    private function validateCaepCommon(array $event, int $issuedAt, int $now, bool $oktaCompatibility): int
    {
        $cutoff = $issuedAt;
        if (array_key_exists('event_timestamp', $event)) {
            $cutoff = min(
                $issuedAt,
                $this->eventTimestamp($event['event_timestamp'], $now, $oktaCompatibility)
            );
        }
        $this->optionalEnumClaim($event, 'initiating_entity', ['admin', 'user', 'policy', 'system']);
        foreach (['reason_admin', 'reason_user'] as $claim) {
            if (!array_key_exists($claim, $event)) {
                continue;
            }
            $messages = $event[$claim];
            if (!is_array($messages) || $messages === [] || array_is_list($messages)) {
                $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
            }
            foreach ($messages as $language => $message) {
                if (!is_string($language) || $language === '' || strlen($language) > 64
                    || !is_string($message) || $message === '' || strlen($message) > 4096) {
                    $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
                }
            }
        }
        return $cutoff;
    }

    private function eventTimestamp(mixed $value, int $now, bool $oktaCompatibility): int
    {
        if ($oktaCompatibility && is_int($value) && $value > 9999999999) {
            $value = intdiv($value, 1000);
        }
        if (!is_int($value) || $value < 0 || $value > $now + JwtVerifier::CLOCK_TOLERANCE) {
            $this->fail('invalid_request', 'The SET event has an invalid event time');
        }
        return $value;
    }

    /**
     * @param array{user:?array{iss:string,sub:string},session_id:?string,complete:bool} $subject
     * @return array{subject:?string,session_id:?string}|null
     */
    private function actionTarget(string $type, array $event, array $subject, string $oidcIssuer): ?array
    {
        if (in_array($type, self::ACTIONABLE_RISC_EVENTS, true)) {
            /* RISC user events retain their user-wide consequence even when a session member is also present. */
            return $this->target($subject, $oidcIssuer, false, false);
        }
        if (!in_array($type, self::ACTIONABLE_CAEP_EVENTS, true) || !$subject['complete']) {
            return null;
        }
        if ($type === self::CAEP_RISK_LEVEL_CHANGE) {
            if (!in_array($event['current_level'], ['MEDIUM', 'HIGH'], true)) {
                return null;
            }
            if ($event['principal'] === 'SESSION') {
                return $subject['session_id'] === null ? null : $this->target($subject, $oidcIssuer, true);
            }
            if ($event['principal'] !== 'USER') {
                return null;
            }
            return $this->target($subject, $oidcIssuer, false, false);
        }
        if ($type === self::CAEP_SESSION_REVOKED) {
            return $this->target($subject, $oidcIssuer, true);
        }
        if ($type === self::CAEP_CREDENTIAL_CHANGE) {
            return $this->target($subject, $oidcIssuer, false, false);
        }
        return $this->target($subject, $oidcIssuer, false);
    }

    /**
     * @param array{user:?array{iss:string,sub:string},session_id:?string,complete:bool} $subject
     * @return array{subject:?string,session_id:?string}|null
     */
    private function target(
        array $subject,
        string $oidcIssuer,
        bool $sessionOnlyAllowed,
        bool $includeSession = true
    ): ?array
    {
        $user = $subject['user'];
        $sessionId = $includeSession ? $subject['session_id'] : null;
        if ($user !== null && !hash_equals($oidcIssuer, $user['iss'])) {
            return null;
        }
        if ($user === null && (!$sessionOnlyAllowed || $sessionId === null)) {
            return null;
        }
        return ['subject' => $user['sub'] ?? null, 'session_id' => $sessionId];
    }

    private function objectClaim(array $event, string $claim): void
    {
        $value = $event[$claim] ?? null;
        if (!is_array($value) || $value === [] || array_is_list($value)) {
            $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
        }
    }

    private function stringClaim(array $event, string $claim): string
    {
        $value = $event[$claim] ?? null;
        if (!is_string($value) || $value === '' || strlen($value) > 4096
            || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
        }
        return $value;
    }

    private function optionalStringClaim(array $event, string $claim): void
    {
        if (array_key_exists($claim, $event)) {
            $this->stringClaim($event, $claim);
        }
    }

    private function enumClaim(array $event, string $claim, array $values): string
    {
        $value = $this->stringClaim($event, $claim);
        if (!in_array($value, $values, true)) {
            $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
        }
        return $value;
    }

    private function optionalEnumClaim(array $event, string $claim, array $values): void
    {
        if (array_key_exists($claim, $event)) {
            $this->enumClaim($event, $claim, $values);
        }
    }

    private function optionalStringListClaim(array $event, string $claim): void
    {
        if (!array_key_exists($claim, $event)) {
            return;
        }
        $value = $event[$claim];
        if (!is_array($value) || !array_is_list($value) || count($value) > 128
            || array_filter($value, 'is_string') !== $value) {
            $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
        }
        foreach ($value as $item) {
            if ($item === '' || strlen($item) > 255 || preg_match('/[\x00-\x1f\x7f]/', $item)) {
                $this->fail('invalid_request', sprintf('The SET event has an invalid %s claim', $claim));
            }
        }
    }

    private function sameJsonValue(mixed $left, mixed $right): bool
    {
        if (gettype($left) !== gettype($right)) {
            return false;
        }
        if (!is_array($left)) {
            return $left === $right;
        }
        if (array_is_list($left) !== array_is_list($right) || count($left) !== count($right)) {
            return false;
        }
        if (!array_is_list($left)) {
            ksort($left);
            ksort($right);
            if (array_keys($left) !== array_keys($right)) {
                return false;
            }
        }
        foreach ($left as $key => $value) {
            if (!array_key_exists($key, $right) || !$this->sameJsonValue($value, $right[$key])) {
                return false;
            }
        }
        return true;
    }

    private function fail(string $category, string $message): never
    {
        throw new SecurityEventException($category, $message);
    }
}
