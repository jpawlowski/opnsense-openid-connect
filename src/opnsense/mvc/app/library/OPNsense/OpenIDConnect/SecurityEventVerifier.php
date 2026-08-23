<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** Signature, SET-profile and narrowly actionable CAEP/RISC validation. */
final class SecurityEventVerifier
{
    public const CAEP_SESSION_REVOKED =
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked';
    public const CAEP_CREDENTIAL_CHANGE =
        'https://schemas.openid.net/secevent/caep/event-type/credential-change';
    public const RISC_CREDENTIAL_REQUIRED =
        'https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required';
    public const RISC_ACCOUNT_PURGED =
        'https://schemas.openid.net/secevent/risc/event-type/account-purged';
    public const RISC_ACCOUNT_DISABLED =
        'https://schemas.openid.net/secevent/risc/event-type/account-disabled';
    public const RISC_CREDENTIAL_COMPROMISE =
        'https://schemas.openid.net/secevent/risc/event-type/credential-compromise';
    public const ACTIONABLE_EVENTS = [
        self::CAEP_SESSION_REVOKED,
        self::CAEP_CREDENTIAL_CHANGE,
        self::RISC_CREDENTIAL_REQUIRED,
        self::RISC_ACCOUNT_PURGED,
        self::RISC_ACCOUNT_DISABLED,
        self::RISC_CREDENTIAL_COMPROMISE,
    ];

    public function __construct(private readonly JwtVerifier $jwt)
    {
    }

    /**
     * @return array{jti:string,subject:?string,subject_issuer:?string,cutoff:int,actionable:bool,event:string}
     */
    public function verify(
        string $set,
        SharedSignalsMetadata $metadata,
        string $audience,
        string $oidcIssuer,
        bool $oktaCompatibility = false,
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
        if (!is_int($claims['iat'] ?? null) || $claims['iat'] > $now + JwtVerifier::CLOCK_TOLERANCE) {
            $this->fail('invalid_request', 'The SET has no valid issue time');
        }
        if (isset($claims['nbf'])
            && (!is_int($claims['nbf']) || $claims['nbf'] > $now + JwtVerifier::CLOCK_TOLERANCE)) {
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
            if (!is_string($type) || $type === '' || strlen($type) > 512 || !is_array($event)) {
                $this->fail('invalid_request', 'The SET contains an invalid event');
            }
        }

        $subjectValue = $claims['sub_id'] ?? null;
        if ($subjectValue === null && $oktaCompatibility && count($events) === 1) {
            $subjectValue = reset($events)['subject'] ?? null;
        }
        if (!is_array($subjectValue)) {
            $this->fail('invalid_request', 'The SET has no primary subject');
        }
        $identity = $this->subjectIdentity($subjectValue, $metadata->criticalSubjectMembers());
        foreach ($events as $event) {
            if (!isset($event['subject'])) {
                continue;
            }
            if (!is_array($event['subject'])
                || $this->subjectIdentity($event['subject'], $metadata->criticalSubjectMembers()) !== $identity) {
                $this->fail('invalid_request', 'The SET event subject differs from its primary subject');
            }
        }

        $eventType = (string)array_key_first($events);
        $actionable = false;
        $cutoff = $claims['iat'];
        foreach ($events as $type => $event) {
            if (!in_array($type, self::ACTIONABLE_EVENTS, true)) {
                continue;
            }
            $actionable = true;
            $eventType = $type;
            if (isset($event['event_timestamp'])) {
                $timestamp = $event['event_timestamp'];
                if ($oktaCompatibility && is_int($timestamp) && $timestamp > 9999999999) {
                    $timestamp = intdiv($timestamp, 1000);
                }
                if (!is_int($timestamp) || $timestamp > $now + JwtVerifier::CLOCK_TOLERANCE) {
                    $this->fail('invalid_request', 'The SET event has an invalid event time');
                }
                $cutoff = min($cutoff, $timestamp);
            }
        }

        return [
            'jti' => $jti,
            'subject' => $identity === null ? null : $identity['sub'],
            'subject_issuer' => $identity === null ? null : $identity['iss'],
            'cutoff' => $cutoff,
            'actionable' => $actionable && $identity !== null
                && hash_equals($oidcIssuer, $identity['iss']),
            'event' => $eventType,
        ];
    }

    /** @return array{iss:string,sub:string}|null */
    private function subjectIdentity(array $subject, array $criticalMembers): ?array
    {
        $format = $subject['format'] ?? null;
        if ($format === 'complex') {
            foreach ($criticalMembers as $member) {
                if (array_key_exists($member, $subject) && $member !== 'user') {
                    $this->fail('invalid_request', 'The SET has an unsupported critical subject member');
                }
            }
            $identity = is_array($subject['user'] ?? null)
                ? $this->subjectIdentity($subject['user'], []) : null;
            if (in_array('user', $criticalMembers, true) && $identity === null) {
                $this->fail('invalid_request', 'The SET has an unsupported critical user subject');
            }
            return $identity;
        }
        if ($format !== 'iss_sub') {
            return null;
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

    private function fail(string $category, string $message): never
    {
        throw new SecurityEventException($category, $message);
    }
}
