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

use OPNsense\Auth\OpenIDConnect;

/** Applies one verified Shared Signals event through the common push/poll boundary. */
final class SharedSignalsEventProcessor
{
    public function __construct(private readonly HttpClient $http)
    {
    }

    /** @return array{jti:string,event:string,count:int,duplicate:bool} */
    public function process(
        string $set,
        string $serverName,
        OpenIDConnect $settings,
        ?SharedSignalsMetadata $metadata = null
    ): array {
        $metadata ??= SharedSignalsMetadata::discover($settings->sharedSignalsIssuer(), $this->http);
        $event = $this->verify($set, $settings, $metadata);
        return $this->apply($event, $serverName, $settings, $metadata);
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
    public function verify(string $set, OpenIDConnect $settings, SharedSignalsMetadata $metadata): array
    {
        return (new SecurityEventVerifier(new JwtVerifier($this->http, 'ssf-jwks')))->verify(
            $set,
            $metadata,
            $settings->sharedSignalsAudience(),
            $settings->issuerUrl(),
            $settings->providerProfile()
        );
    }

    /**
     * @param array{
     *     jti:string,
     *     subject:?string,
     *     subject_issuer:?string,
     *     session_id:?string,
     *     cutoff:int,
     *     actionable:bool,
     *     event:string
     * } $event
     * @return array{jti:string,event:string,count:int,duplicate:bool}
     */
    public function apply(
        array $event,
        string $serverName,
        OpenIDConnect $settings,
        SharedSignalsMetadata $metadata
    ): array {
        if (!SessionRegistry::acceptSecurityEvent(
            $serverName,
            $metadata->issuer(),
            $settings->sharedSignalsAudience(),
            $event['jti']
        )) {
            return ['jti' => $event['jti'], 'event' => $event['event'], 'count' => 0, 'duplicate' => true];
        }
        try {
            $count = $event['actionable'] && $event['subject_issuer'] !== null
                && ($event['subject'] !== null || $event['session_id'] !== null)
                ? SessionRegistry::terminateForSecurityEvent(
                    $serverName,
                    $event['subject_issuer'],
                    $event['subject'],
                    $event['cutoff'],
                    $event['session_id']
                ) : 0;
        } catch (\Throwable $e) {
            try {
                SessionRegistry::releaseSecurityEvent(
                    $serverName,
                    $metadata->issuer(),
                    $settings->sharedSignalsAudience(),
                    $event['jti']
                );
            } catch (\Throwable $releaseError) {
                syslog(LOG_ERR, 'OIDC: a Shared Signals replay marker could not be released');
            }
            throw $e;
        }
        return ['jti' => $event['jti'], 'event' => $event['event'], 'count' => $count, 'duplicate' => false];
    }
}
