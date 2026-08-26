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

/** One bounded RFC 8936 short-poll cycle with prompt acknowledgements. */
final class SharedSignalsPoller
{
    public const MAX_BATCHES = 5;

    public function __construct(
        private readonly SharedSignalsClient $client,
        private readonly SharedSignalsEventProcessor $events
    ) {
    }

    /** @return array{deliveries:int,sessions:int,errors:int,batches:int} */
    public function run(
        string $serverName,
        OpenIDConnect $settings,
        SharedSignalsMetadata $metadata
    ): array {
        if ($settings->sharedSignalsDeliveryMethod() !== SharedSignalsMetadata::POLL_METHOD
            || $settings->sharedSignalsStreamId() === '' || $settings->sharedSignalsPollEndpoint() === '') {
            throw new ProtocolException('Shared Signals polling is not explicitly and completely configured');
        }
        $authorization = $settings->sharedSignalsManagementAuthorization();
        $acknowledged = [];
        $errors = [];
        $deliveries = 0;
        $sessions = 0;
        $errorCount = 0;
        $batches = 0;
        $more = false;

        do {
            $result = $this->client->poll(
                $metadata,
                $authorization,
                $settings->sharedSignalsPollEndpoint(),
                $acknowledged,
                $errors
            );
            $acknowledged = [];
            $errors = [];
            $batches++;
            foreach ($result['sets'] as $transportJti => $set) {
                $transportJti = (string)$transportJti;
                $deliveries++;
                try {
                    $event = $this->events->verify($set, $settings, $metadata);
                    if (!hash_equals($transportJti, $event['jti'])) {
                        throw new SecurityEventException(
                            'invalid_request',
                            'The poll response key does not match the SET identifier'
                        );
                    }
                    $applied = $this->events->apply($event, $serverName, $settings, $metadata);
                    $sessions += $applied['count'];
                    $acknowledged[] = $transportJti;
                } catch (SecurityEventException $e) {
                    $errors[$transportJti] = [
                        'err' => $e->errorCategory(),
                        'description' => 'The Security Event Token was not accepted.',
                    ];
                    $errorCount++;
                }
            }
            $more = $result['more_available'];
        } while ($more && $batches < self::MAX_BATCHES);

        if ($acknowledged !== [] || $errors !== []) {
            $this->client->poll(
                $metadata,
                $authorization,
                $settings->sharedSignalsPollEndpoint(),
                $acknowledged,
                $errors,
                0
            );
        }
        return [
            'deliveries' => $deliveries,
            'sessions' => $sessions,
            'errors' => $errorCount,
            'batches' => $batches,
        ];
    }
}
