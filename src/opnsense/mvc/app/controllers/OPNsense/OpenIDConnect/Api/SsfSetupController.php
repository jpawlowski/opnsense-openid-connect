<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SharedSignalsClient;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;

/** Authenticated SSF discovery and stream-lifecycle helpers for the server form. */
class SsfSetupController extends PrivateApiControllerBase
{
    public function secretAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        return ['status' => 'ok', 'secret' => JwtVerifier::base64UrlEncode(random_bytes(32))];
    }

    public function probeAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            $method = $this->deliveryMethod();
            if (!$metadata->supportsDelivery($method)) {
                throw new \RuntimeException('The transmitter does not advertise the selected delivery method.');
            }
            return [
                'issuer' => $metadata->issuer(),
                'delivery_methods' => $metadata->deliveryMethods(),
                'configuration' => $metadata->configurationEndpoint() !== null,
                'status_endpoint' => $metadata->statusEndpoint() !== null,
                'authorization_schemes' => $metadata->authorizationSchemes(),
                'default_subjects' => $metadata->defaultSubjects(),
                'events' => SecurityEventVerifier::ACTIONABLE_EVENTS,
            ];
        });
    }

    public function createAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            $method = $this->deliveryMethod();
            $configuration = (new SharedSignalsClient(new HttpClient()))->createStream(
                $metadata,
                $this->authorization(),
                $method,
                $method === SharedSignalsMetadata::PUSH_METHOD ? $this->pushEndpoint() : null,
                $method === SharedSignalsMetadata::PUSH_METHOD ? $this->pushAuthorization() : null,
                $this->description()
            );
            return $this->configurationAnswer($configuration);
        });
    }

    public function readAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            $method = $this->deliveryMethod();
            $configuration = (new SharedSignalsClient(new HttpClient()))->readStream(
                $metadata,
                $this->authorization(),
                $this->streamId(),
                $method,
                $method === SharedSignalsMetadata::PUSH_METHOD ? $this->pushEndpoint() : $this->pollEndpoint(),
                $this->audience()
            );
            return $this->configurationAnswer($configuration);
        });
    }

    public function updateAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            $method = $this->deliveryMethod();
            $configuration = (new SharedSignalsClient(new HttpClient()))->updateStream(
                $metadata,
                $this->authorization(),
                $this->streamId(),
                $method,
                $method === SharedSignalsMetadata::PUSH_METHOD ? $this->pushEndpoint() : null,
                $method === SharedSignalsMetadata::PUSH_METHOD ? $this->pushAuthorization() : null,
                $this->audience(),
                $this->description()
            );
            return $this->configurationAnswer($configuration);
        });
    }

    public function deleteAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            (new SharedSignalsClient(new HttpClient()))->deleteStream(
                $metadata,
                $this->authorization(),
                $this->streamId()
            );
            return ['deleted' => true];
        });
    }

    public function statusAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            return ['stream_status' => (new SharedSignalsClient(new HttpClient()))->readStatus(
                $metadata,
                $this->authorization(),
                $this->streamId()
            )];
        });
    }

    public function setstatusAction(): array
    {
        return $this->answer(function (SharedSignalsMetadata $metadata): array {
            return ['stream_status' => (new SharedSignalsClient(new HttpClient()))->updateStatus(
                $metadata,
                $this->authorization(),
                $this->streamId(),
                trim((string)$this->request->getPost('status_value', null, '')),
                trim((string)$this->request->getPost('reason', null, ''))
            )];
        });
    }

    /** @return array<string,mixed> */
    private function answer(callable $operation): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $metadata = SharedSignalsMetadata::discover($this->issuer(), new HttpClient(), true, false);
            return ['status' => 'ok'] + $operation($metadata);
        } catch (\Throwable $e) {
            return [
                'status' => 'error',
                'message' => gettext('Shared Signals operation was not accepted: ') . $e->getMessage(),
            ];
        }
    }

    /** @return array<string,mixed> */
    private function configurationAnswer(array $configuration): array
    {
        return [
            'stream_id' => (string)$configuration['stream_id'],
            'audience' => (string)$configuration['audience'],
            'delivery_method' => (string)$configuration['delivery']['method'],
            'poll_endpoint' => (string)$configuration['poll_endpoint'],
            'events_delivered' => $configuration['events_delivered'],
        ];
    }

    private function issuer(): string
    {
        return trim((string)$this->request->getPost('issuer', null, ''));
    }

    private function authorization(): string
    {
        return SharedSignalsClient::validatedAuthorization(
            trim((string)$this->request->getPost('authorization', null, ''))
        );
    }

    private function deliveryMethod(): string
    {
        return match (trim((string)$this->request->getPost('delivery_method', null, 'push'))) {
            'push' => SharedSignalsMetadata::PUSH_METHOD,
            'poll' => SharedSignalsMetadata::POLL_METHOD,
            default => throw new \RuntimeException('Unknown Shared Signals delivery method.'),
        };
    }

    private function streamId(): string
    {
        $value = trim((string)$this->request->getPost('stream_id', null, ''));
        if (!preg_match('/^[A-Za-z0-9._~-]{1,255}$/D', $value)) {
            throw new \RuntimeException('The Shared Signals stream ID is invalid.');
        }
        return $value;
    }

    private function audience(): string
    {
        $value = trim((string)$this->request->getPost('audience', null, ''));
        if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            throw new \RuntimeException('The Shared Signals audience is invalid.');
        }
        return $value;
    }

    private function pushAuthorization(): string
    {
        $secret = trim((string)$this->request->getPost('push_secret', null, ''));
        if (!preg_match('/^[A-Za-z0-9_-]{43}$/D', $secret)) {
            throw new \RuntimeException('The Shared Signals push secret is invalid.');
        }
        return 'Bearer ' . $secret;
    }

    private function pollEndpoint(): string
    {
        $value = trim((string)$this->request->getPost('poll_endpoint', null, ''));
        HttpClient::assertHttpsUrl($value);
        return $value;
    }

    private function pushEndpoint(): string
    {
        $origin = rtrim(trim((string)$this->request->getPost('receiver_origin', null, '')), '/');
        HttpClient::assertHttpsUrl($origin);
        $parts = parse_url($origin);
        if (isset($parts['query']) || (($parts['path'] ?? '') !== '' && ($parts['path'] ?? '') !== '/')) {
            throw new \RuntimeException('The Shared Signals receiver origin is invalid.');
        }
        $code = trim((string)$this->request->getPost('application_code', null, 'main'));
        if (!preg_match('/^[A-Za-z0-9._~-]{1,64}$/D', $code) || in_array($code, ['.', '..'], true)) {
            throw new \RuntimeException('The Shared Signals application code is invalid.');
        }
        return $origin . '/api/openidconnect/ssf/push/' . rawurlencode($code);
    }

    private function description(): string
    {
        return trim((string)$this->request->getPost('description', null, ''));
    }
}
