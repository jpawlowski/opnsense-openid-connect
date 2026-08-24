<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

/**
 * A very small test harness.
 *
 * Not PHPUnit on purpose: this plugin ships without a dependency manager and installs on a
 * machine that has none, and a test suite needing Composer to run would be the only part of
 * the project that does. Forty lines buy the three things that matter - a name per check, a
 * readable failure, and a non-zero exit code.
 */

final class Checks
{
    private static int $passed = 0;
    private static array $failures = [];
    private static string $group = '';
    private static array $executed = [];

    public static function group(string $name): void
    {
        self::$group = $name;
        printf("\n%s\n", $name);
    }

    public static function that(string $what, $actual, $expected): void
    {
        self::record($what);
        if ($actual === $expected) {
            self::$passed++;
            printf("  ok    %s\n", $what);
            return;
        }

        self::$failures[] = sprintf('%s / %s', self::$group, $what);
        printf(
            "  FAIL  %s\n        expected %s\n        got      %s\n",
            $what,
            self::render($expected),
            self::render($actual)
        );
    }

    public static function throws(string $what, callable $run, string $expectedMessage = ''): void
    {
        self::record($what);
        try {
            $run();
        } catch (\Throwable $e) {
            if ($expectedMessage === '' || str_contains($e->getMessage(), $expectedMessage)) {
                self::$passed++;
                printf("  ok    %s\n", $what);
                return;
            }
            self::$failures[] = sprintf('%s / %s', self::$group, $what);
            printf(
                "  FAIL  %s\n        expected a message containing %s\n        got      %s\n",
                $what,
                self::render($expectedMessage),
                self::render($e->getMessage())
            );
            return;
        }

        self::$failures[] = sprintf('%s / %s', self::$group, $what);
        printf("  FAIL  %s\n        expected it to be refused, nothing was thrown\n", $what);
    }

    private static function render($value): string
    {
        return is_string($value) ? "'" . $value . "'" : var_export($value, true);
    }

    public static function report(): int
    {
        self::publishExecutedTests();
        printf("\n%d checks passed", self::$passed);
        if (self::$failures === []) {
            printf(", none failed.\n");
            return 0;
        }
        printf(", %d FAILED:\n", count(self::$failures));
        foreach (self::$failures as $failure) {
            printf("  %s\n", $failure);
        }

        return 1;
    }

    private static function record(string $what): void
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $source = (string)($trace[1]['file'] ?? '');
        $root = dirname(__DIR__) . DIRECTORY_SEPARATOR;
        if (str_starts_with($source, $root)) {
            $source = str_replace(DIRECTORY_SEPARATOR, '/', substr($source, strlen($root)));
        }
        self::$executed[$source . "\0" . $what] = ['path' => $source, 'test' => $what];
    }

    private static function publishExecutedTests(): void
    {
        $destination = getenv('OPENIDCONNECT_EXECUTED_TESTS');
        if (!is_string($destination) || $destination === '') {
            return;
        }
        $current = [];
        if (is_file($destination) && filesize($destination) > 0) {
            $decoded = json_decode((string)file_get_contents($destination), true);
            $current = is_array($decoded['executed_tests'] ?? null) ? $decoded['executed_tests'] : [];
        }
        foreach ($current as $record) {
            if (is_array($record) && is_string($record['path'] ?? null) && is_string($record['test'] ?? null)) {
                self::$executed[$record['path'] . "\0" . $record['test']] = $record;
            }
        }
        usort(self::$executed, static function (array $left, array $right): int {
            return [$left['path'], $left['test']] <=> [$right['path'], $right['test']];
        });
        $payload = json_encode(
            ['schema_version' => 1, 'executed_tests' => array_values(self::$executed)],
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
        if (!is_string($payload)) {
            return;
        }
        $temporary = dirname($destination) . '/.' . basename($destination) . '.' . getmypid() . '.tmp';
        file_put_contents($temporary, $payload . "\n", LOCK_EX);
        chmod($temporary, 0600);
        rename($temporary, $destination);
    }
}

/** call a private or protected method, so a test can reach the piece it means to */
function inspect(object $subject, string $method, ...$arguments)
{
    /* no setAccessible(): reflection has reached private members by itself since PHP 8.1,
       and saying so again is a deprecation warning per call on 8.5 */
    return (new ReflectionMethod($subject, $method))->invoke($subject, ...$arguments);
}

/** build a configured connector without going near a config file */
function connector(array $settings): OPNsense\Auth\OpenIDConnect
{
    $settings += [
        'type' => 'openidconnect',
        'openidconnect_app_code' => 'main',
        'openidconnect_provider_url' => 'https://id.example.net',
    ];
    $connector = new OPNsense\Auth\OpenIDConnect();
    $connector->setProperties($settings);
    OPNsense\Core\Config::getInstance()->addAuthServer($settings);

    return $connector;
}

/** Stable issuer/subject binding as stored by the connector. */
function binding(string $issuer, string $subject, string $identity): string
{
    $key = rtrim(strtr(base64_encode($issuer . "\0" . $subject), '+/', '-_'), '=');
    return $key . '=' . $identity;
}

/** the local accounts of the machine a test is pretending to be, and a clean recorder */
function directory(array ...$users): void
{
    OPNsense\Auth\Directory::reset();
    OPNsense\Auth\Recorder::reset();
    foreach ($users as $user) {
        OPNsense\Auth\Directory::add($user);
    }
}

/** a set of claims, the shape a verified answer reaches the connector in */
function claims(array $values): object
{
    if (!array_key_exists('sub', $values)) {
        $seed = (string)($values['preferred_username'] ?? $values['email'] ?? 'test-subject');
        $values['sub'] = 'subject:' . $seed;
    }
    return (object)$values;
}

/** Create a short-lived real certificate/key pair inside the OPNsense Trust Store stub. */
function installClientCertificate(string $reference, string $description = 'OIDC client'): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $request = openssl_csr_new(['commonName' => $reference], $key, ['digest_alg' => 'sha256']);
    $certificate = openssl_csr_sign($request, null, $key, 30, ['digest_alg' => 'sha256']);
    if ($key === false || $request === false || $certificate === false
        || !openssl_pkey_export($key, $privateKey) || !openssl_x509_export($certificate, $pem)) {
        throw new RuntimeException('Could not create the client-certificate fixture');
    }
    $stored = ['descr' => $description, 'crt' => $pem, 'prv' => $privateKey];
    OPNsense\Trust\Store::$certificates[$reference] = $stored;
    return $stored;
}

/** the validator of one settings field, as the form would call it */
function validator(string $field): callable
{
    $options = (new OPNsense\Auth\OpenIDConnect())->getConfigurationOptions();

    return $options[$field]['validate'];
}
