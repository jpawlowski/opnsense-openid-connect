<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
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
