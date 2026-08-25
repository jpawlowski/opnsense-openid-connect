<?php

namespace OPNsense\OpenIDConnect;

use OPNsense\Auth\OpenIDConnect;
use phpseclib3\Crypt\EC;

/** Bounded, mode-0600 custody and rotation for one provider's RFC 9449 key. */
final class DpopKeyStore
{
    public const ROTATE_AFTER = 7776000;
    public const RETAIN_RETIRED_FOR = 31968000;
    public const MAX_RETIRED_KEYS = 5;

    private readonly string $binding;
    private readonly string $directory;

    private function __construct(
        string $bindingId,
        ?string $directory = null,
        private readonly mixed $generator = null
    )
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $bindingId)) {
            throw new \InvalidArgumentException('A valid DPoP provider binding identifier is required');
        }
        $this->binding = $bindingId;
        $this->directory = $directory ?? (defined('OPENIDCONNECT_TEST_DPOP_DIRECTORY')
            ? (string)constant('OPENIDCONNECT_TEST_DPOP_DIRECTORY') : '/var/db/openid-connect/dpop');
    }

    public static function forSettings(OpenIDConnect $settings): self
    {
        return self::forBinding(json_encode([
            $settings->issuerUrl(),
            $settings->clientId(),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public static function forBinding(
        string $binding,
        ?string $directory = null,
        mixed $generator = null
    ): self {
        if ($binding === '') {
            throw new \InvalidArgumentException('A DPoP provider binding is required');
        }
        return new self(hash('sha256', $binding), $directory, $generator);
    }

    /** Reopen the exact namespace frozen into a server-side login session. */
    public static function fromBindingId(string $bindingId, ?string $directory = null): self
    {
        return new self($bindingId, $directory);
    }

    public function active(?int $now = null): DpopProof
    {
        $now ??= time();
        return $this->locked(function () use ($now): DpopProof {
            $state = $this->readState();
            if ($state === []) {
                $state = ['version' => 1, 'active' => $this->generate($now), 'retired' => []];
                $this->writeState($state);
            } elseif (($state['active']['created'] ?? 0) <= $now - self::ROTATE_AFTER) {
                $state = $this->rotatedState($state, $now);
                $this->writeState($state);
            }
            return DpopProof::fromStored($this->record($state['active'] ?? null));
        });
    }

    public function rotate(?int $now = null): DpopProof
    {
        $now ??= time();
        return $this->locked(function () use ($now): DpopProof {
            $state = $this->readState();
            if ($state === []) {
                $state = ['version' => 1, 'active' => $this->generate($now), 'retired' => []];
            } else {
                $state = $this->rotatedState($state, $now);
            }
            $this->writeState($state);
            return DpopProof::fromStored($this->record($state['active'] ?? null));
        });
    }

    public function find(string $keyId): DpopProof
    {
        return $this->locked(function () use ($keyId): DpopProof {
            $state = $this->readState();
            $records = array_merge(
                isset($state['active']) ? [$state['active']] : [],
                is_array($state['retired'] ?? null) ? $state['retired'] : []
            );
            foreach ($records as $candidate) {
                $record = $this->record($candidate);
                if (hash_equals($record['id'], $keyId)) {
                    return DpopProof::fromStored($record);
                }
            }
            throw new ProtocolException('The DPoP proof key for this grant is no longer available');
        });
    }

    public function nonce(string $endpoint): ?string
    {
        $path = $this->noncePath($endpoint);
        $body = @file_get_contents($path);
        if (!is_string($body) || $body === '') {
            if (is_file($path) || is_link($path)) {
                throw new ProtocolException('The stored DPoP nonce could not be read');
            }
            return null;
        }
        try {
            $state = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ProtocolException('The stored DPoP nonce is invalid', 0, $e);
        }
        $nonce = $state['nonce'] ?? null;
        if (!is_string($nonce)) {
            throw new ProtocolException('The stored DPoP nonce is invalid');
        }
        DpopProof::assertNonce($nonce);
        return $nonce;
    }

    /** Save a nonce supplied on any success or challenge response. */
    public function acceptNonce(string $endpoint, HttpResponse $response): bool
    {
        $value = $response->headers['dpop-nonce'] ?? null;
        if ($value === null) {
            return false;
        }
        if (!is_string($value)) {
            throw new ProtocolException('The provider returned more than one DPoP nonce');
        }
        DpopProof::assertNonce($value);
        $this->ensureDirectory();
        $this->atomicWrite($this->noncePath($endpoint), [
            'version' => 1,
            'nonce' => $value,
            'updated' => time(),
        ]);
        return true;
    }

    public function statePath(): string
    {
        return $this->directory . '/key-' . $this->binding . '.json';
    }

    public function bindingId(): string
    {
        return $this->binding;
    }

    /**
     * Remove only state for configurations absent for longer than the retired-key
     * retention window. A recently removed provider may still have live PHP sessions.
     *
     * @param string[] $activeBindings
     */
    public static function pruneUnused(array $activeBindings, ?string $directory = null, ?int $now = null): void
    {
        $directory ??= defined('OPENIDCONNECT_TEST_DPOP_DIRECTORY')
            ? (string)constant('OPENIDCONNECT_TEST_DPOP_DIRECTORY') : '/var/db/openid-connect/dpop';
        if (!is_dir($directory)) {
            return;
        }
        $now ??= time();
        $active = array_fill_keys(array_filter(
            $activeBindings,
            static fn($value): bool => is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value)
        ), true);
        foreach (glob($directory . '/*') ?: [] as $path) {
            $name = basename($path);
            if (!preg_match('/^(?:key|nonce)-([a-f0-9]{64})(?:-[a-f0-9]{64})?\.(?:json|lock)$/D', $name, $matches)
                || isset($active[$matches[1]])) {
                continue;
            }
            $modified = @filemtime($path);
            if (is_int($modified) && $modified <= $now - self::RETAIN_RETIRED_FOR) {
                @unlink($path);
            }
        }
    }

    /** @param array<string,mixed> $state @return array<string,mixed> */
    private function rotatedState(array $state, int $now): array
    {
        $active = $this->record($state['active'] ?? null);
        $active['retired'] = $now;
        $retired = is_array($state['retired'] ?? null) ? $state['retired'] : [];
        array_unshift($retired, $active);
        $retired = array_values(array_filter($retired, static function ($candidate) use ($now): bool {
            return is_array($candidate) && is_int($candidate['retired'] ?? null)
                && $candidate['retired'] > $now - self::RETAIN_RETIRED_FOR;
        }));
        return [
            'version' => 1,
            'active' => $this->generate($now),
            'retired' => array_slice($retired, 0, self::MAX_RETIRED_KEYS),
        ];
    }

    /** @return array<string,mixed> */
    private function generate(int $now): array
    {
        if ($this->generator !== null) {
            $record = ($this->generator)($now);
            return $this->record($record);
        }
        JwtVerifier::prepareRuntime();
        try {
            $private = EC::createKey('secp256r1');
            $export = json_decode(
                $private->getPublicKey()->toString('JWK'),
                true,
                16,
                JSON_THROW_ON_ERROR
            );
            $public = is_array($export['keys'][0] ?? null) ? $export['keys'][0] : $export;
            $record = [
                'id' => DpopProof::thumbprint($public),
                'created' => $now,
                'private_key' => $private->toString('PKCS8'),
                'public_jwk' => $public,
            ];
        } catch (\Throwable $e) {
            throw new ProtocolException('A DPoP proof key could not be generated', 0, $e);
        }
        return $this->record($record);
    }

    /** @return array<string,mixed> */
    private function readState(): array
    {
        $body = @file_get_contents($this->statePath());
        if ($body === false) {
            if (is_file($this->statePath()) || is_link($this->statePath())) {
                throw new ProtocolException('The DPoP key store could not be read');
            }
            return [];
        }
        try {
            $state = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ProtocolException('The DPoP key store is invalid', 0, $e);
        }
        if (!is_array($state) || array_is_list($state) || ($state['version'] ?? null) !== 1) {
            throw new ProtocolException('The DPoP key store is invalid');
        }
        $this->record($state['active'] ?? null);
        if (!is_array($state['retired'] ?? null) || count($state['retired']) > self::MAX_RETIRED_KEYS) {
            throw new ProtocolException('The DPoP key store has an invalid retired-key list');
        }
        foreach ($state['retired'] as $record) {
            $this->record($record, true);
        }
        return $state;
    }

    /** @return array<string,mixed> */
    private function record(mixed $value, bool $retired = false): array
    {
        if (!is_array($value) || !is_string($value['id'] ?? null) || strlen($value['id']) !== 43
            || !is_int($value['created'] ?? null) || $value['created'] < 0
            || !is_string($value['private_key'] ?? null) || strlen($value['private_key']) > 16384
            || !is_array($value['public_jwk'] ?? null)
            || ($retired && !is_int($value['retired'] ?? null))) {
            throw new ProtocolException('The DPoP key store contains an invalid key');
        }
        if (!hash_equals($value['id'], DpopProof::thumbprint($value['public_jwk']))) {
            throw new ProtocolException('The DPoP key store contains a mismatched public key');
        }
        return $value;
    }

    private function noncePath(string $endpoint): string
    {
        $target = DpopProof::targetUri($endpoint);
        return $this->directory . '/nonce-' . $this->binding . '-' . hash('sha256', $target) . '.json';
    }

    private function ensureDirectory(): void
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new ProtocolException('The DPoP key directory could not be created');
        }
        if (!@chmod($this->directory, 0700)) {
            throw new ProtocolException('The DPoP key directory could not be protected');
        }
    }

    private function locked(callable $operation): mixed
    {
        $this->ensureDirectory();
        $lockPath = $this->directory . '/key-' . $this->binding . '.lock';
        $lock = @fopen($lockPath, 'c+');
        if ($lock === false || !@chmod($lockPath, 0600) || !flock($lock, LOCK_EX)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new ProtocolException('The DPoP key store could not be locked');
        }
        try {
            return $operation();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** @param array<string,mixed> $state */
    private function writeState(array $state): void
    {
        $this->atomicWrite($this->statePath(), $state);
    }

    /** @param array<string,mixed> $value */
    private function atomicWrite(string $path, array $value): void
    {
        $body = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $temporary = $path . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($temporary, $body, LOCK_EX) !== strlen($body)
            || !@chmod($temporary, 0600) || !@rename($temporary, $path)) {
            @unlink($temporary);
            throw new ProtocolException('The DPoP key state could not be written');
        }
    }
}
