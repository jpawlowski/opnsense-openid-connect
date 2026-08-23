#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 *
 * Run only on an OPNsense host after installing the package. It exercises the
 * cryptography and filesystem that local stubs deliberately cannot reproduce.
 */

use OPNsense\OpenIDConnect\HttpClient;
use OPNsense\OpenIDConnect\JwtVerifier;
use OPNsense\OpenIDConnect\PendingIdentityRegistry;
use OPNsense\OpenIDConnect\ProviderMetadata;
use OPNsense\OpenIDConnect\SessionRegistry;
use OPNsense\OpenIDConnect\SecurityEventVerifier;
use OPNsense\OpenIDConnect\SharedSignalsMetadata;
use OPNsense\OpenIDConnect\TransactionRegistry;
use OPNsense\OpenIDConnect\WebGuiAccess;
use OPNsense\OpenIDConnect\Api\ApprovalController;
use OPNsense\Core\ACL;
use OPNsense\Core\Config;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Auth\SSOProviders\OpenIDConnectContainer;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

$evidencePath = null;
foreach ($argv as $argument) {
    if (str_starts_with($argument, '--evidence=')) {
        $evidencePath = substr($argument, strlen('--evidence='));
    }
}
if ($evidencePath !== null) {
    $evidenceDirectory = dirname($evidencePath);
    if (
        $evidencePath === ''
        || !str_starts_with($evidencePath, '/')
        || !is_dir($evidenceDirectory)
        || !is_writable($evidenceDirectory)
        || is_dir($evidencePath)
    ) {
        fwrite(STDERR, "FAIL: --evidence requires a writable absolute output path\n");
        exit(1);
    }
    if ((is_file($evidencePath) || is_link($evidencePath)) && !unlink($evidencePath)) {
        fwrite(STDERR, "FAIL: stale audit evidence could not be removed\n");
        exit(1);
    }
}

require_once('/usr/local/etc/inc/legacy_bindings.inc');

$library = '/usr/local/opnsense/mvc/app/library/OPNsense/OpenIDConnect/';
foreach ([
    'ProtocolException', 'SecurityEventException', 'HttpResponse', 'HttpClient', 'ProviderMetadata',
    'SharedSignalsMetadata', 'JwtVerifier', 'SecurityEventVerifier', 'PendingIdentityRegistry',
    'SessionRegistry', 'TransactionRegistry', 'WebGuiAccess',
] as $class) {
    require_once $library . $class . '.php';
}
require_once '/usr/local/opnsense/mvc/app/library/OPNsense/Auth/OpenIDConnect.php';
require_once '/usr/local/opnsense/mvc/app/library/OPNsense/Auth/SSOProviders/OpenIDConnectContainer.php';
require_once '/usr/local/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/PrivateApiControllerBase.php';
require_once '/usr/local/opnsense/mvc/app/controllers/OPNsense/OpenIDConnect/Api/ApprovalController.php';

$identityValue = static function (string $command, string $pattern): ?string {
    if (!function_exists('shell_exec')) {
        return null;
    }
    $value = shell_exec($command);
    if (!is_string($value)) {
        return null;
    }
    $value = trim($value);
    return preg_match($pattern, $value) === 1 ? $value : null;
};
$packageVersion = null;
$sourceRevision = null;
$opnsenseVersion = null;
if ($evidencePath !== null) {
    $packageVersion = $identityValue(
        "pkg query '%v' os-openid-connect 2>/dev/null",
        '/^[0-9A-Za-z._,+-]{1,128}$/D'
    );
    $sourceRevision = $identityValue(
        "pkg annotate -Sq os-openid-connect built_from 2>/dev/null",
        '/^[0-9a-f]{40}(?:\\.dirty)?$/D'
    );
    $opnsenseVersion = $identityValue('opnsense-version -v 2>/dev/null', '/^[0-9A-Za-z._,+-]{1,128}$/D');
}

$checks = 0;
$capabilities = [];
$writeEvidence = static function (string $status) use (
    &$capabilities,
    &$checks,
    $evidencePath,
    $packageVersion,
    $sourceRevision,
    $opnsenseVersion,
    $argv
): void {
    if ($evidencePath === null) {
        return;
    }

    $limitations = [];
    if ($packageVersion === null) {
        $limitations[] = 'installed package version could not be determined';
    }
    if ($sourceRevision === null) {
        $limitations[] = 'installed package could not be bound to a source revision';
    } elseif (str_ends_with($sourceRevision, '.dirty')) {
        $limitations[] = 'installed package was built from a dirty source tree';
    }
    if ($opnsenseVersion === null) {
        $limitations[] = 'OPNsense version could not be determined';
    }
    $evidence = [
        'schema' => 'opnsense-openid-connect.audit-evidence/v1',
        'tier' => 'installed-integration',
        'generated_at' => gmdate('Y-m-d\\TH:i:s\\Z'),
        'subject' => [
            'package' => array_filter([
                'name' => 'os-openid-connect',
                'version' => $packageVersion,
            ], static fn ($value): bool => $value !== null),
            'source' => array_filter([
                'revision' => $sourceRevision,
            ], static fn ($value): bool => $value !== null),
            'opnsense' => array_filter([
                'version' => $opnsenseVersion,
            ], static fn ($value): bool => $value !== null),
        ],
        'execution' => [
            'status' => $status,
            'network' => in_array('--network', $argv, true) ? 'included' : 'not-requested',
            'checks_passed' => $checks,
        ],
        'capabilities' => array_map(
            static fn (string $id): array => ['id' => $id, 'status' => 'passed'],
            array_keys($capabilities)
        ),
        'limitations' => $limitations,
    ];

    $directory = dirname($evidencePath);
    if (!is_dir($directory) || !is_writable($directory) || is_dir($evidencePath)) {
        throw new RuntimeException('the evidence output path is not writable');
    }
    $previousUmask = umask(0077);
    $temporary = tempnam($directory, '.openidconnect-audit-');
    umask($previousUmask);
    if ($temporary === false) {
        throw new RuntimeException('could not create the evidence file');
    }
    try {
        $json = json_encode($evidence, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        if (file_put_contents($temporary, $json, LOCK_EX) === false || !chmod($temporary, 0600)) {
            throw new RuntimeException('could not write the evidence file');
        }
        if (!rename($temporary, $evidencePath)) {
            throw new RuntimeException('could not publish the evidence file');
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
};
$check = static function (bool $condition, string $message) use (&$checks, $writeEvidence): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        try {
            $writeEvidence('failed');
        } catch (\Throwable $e) {
            fwrite(STDERR, "FAIL: audit evidence could not be written\n");
        }
        exit(1);
    }
    $checks++;
    echo "ok: {$message}\n";
};
$validated = static function (string $capability) use (&$capabilities): void {
    $capabilities[$capability] = true;
};
try {
    $writeEvidence('running');
} catch (\Throwable $e) {
    fwrite(STDERR, "FAIL: audit evidence could not be written\n");
    exit(1);
}

$verifier = new class(new HttpClient()) extends JwtVerifier {
    public function signature(string $algorithm, array $jwk, string $payload, string $signature): bool
    {
        return $this->verifySignature($algorithm, $jwk, $payload, $signature);
    }
};

$payload = 'OPNsense OpenID Connect runtime cryptography';
$rsa = RSA::createKey(2048);
$rsaJwk = json_decode($rsa->getPublicKey()->toString('JWK'), true, 16, JSON_THROW_ON_ERROR);
$rsaSignature = $rsa->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1)->sign($payload);
$check($verifier->signature('RS256', $rsaJwk, $payload, $rsaSignature), 'RS256 through OPNsense phpseclib');

$pssSignature = $rsa->withHash('sha256')->withMGFHash('sha256')->withSaltLength(32)
    ->withPadding(RSA::SIGNATURE_PSS)->sign($payload);
$check($verifier->signature('PS256', $rsaJwk, $payload, $pssSignature), 'PS256 with exact salt policy');

$ec = EC::createKey('secp256r1');
$ecJwk = json_decode($ec->getPublicKey()->toString('JWK'), true, 16, JSON_THROW_ON_ERROR);
$ecSignature = $ec->withHash('sha256')->withSignatureFormat('IEEE')->sign($payload);
$check($verifier->signature('ES256', $ecJwk, $payload, $ecSignature), 'ES256 IEEE signature through OPNsense phpseclib');
$validated('runtime-jws-crypto');

$ssfIssuer = 'https://signals.runtime.example.com';
$ssfAudience = 'runtime-receiver';
$ssfHeader = JwtVerifier::base64UrlEncode((string)json_encode([
    'typ' => 'secevent+jwt', 'alg' => 'RS256', 'kid' => 'runtime',
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
$ssfClaims = JwtVerifier::base64UrlEncode((string)json_encode([
    'iss' => $ssfIssuer,
    'aud' => $ssfAudience,
    'iat' => time(),
    'jti' => 'runtime-security-event',
    'sub_id' => ['format' => 'iss_sub', 'iss' => $ssfIssuer, 'sub' => 'runtime-subject'],
    'events' => [SecurityEventVerifier::CAEP_SESSION_REVOKED => []],
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
$ssfSigningInput = $ssfHeader . '.' . $ssfClaims;
$ssfSignature = $rsa->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1)->sign($ssfSigningInput);
$ssfSet = $ssfSigningInput . '.' . JwtVerifier::base64UrlEncode($ssfSignature);
$ssfHttp = new HttpClient(static fn(): array => [
    'status' => 200,
    'content_type' => 'application/jwk-set+json',
    'body' => (string)json_encode(['keys' => [['kid' => 'runtime'] + $rsaJwk]], JSON_THROW_ON_ERROR),
    'location' => '',
]);
$ssfMetadata = SharedSignalsMetadata::fromArray($ssfIssuer, [
    'issuer' => $ssfIssuer,
    'jwks_uri' => $ssfIssuer . '/keys',
    'delivery_methods_supported' => [SharedSignalsMetadata::PUSH_METHOD],
]);
$ssfEvent = (new SecurityEventVerifier(new JwtVerifier($ssfHttp)))->verify(
    $ssfSet,
    $ssfMetadata,
    $ssfAudience,
    $ssfIssuer
);
$check($ssfEvent['actionable'] && $ssfEvent['subject'] === 'runtime-subject', 'signed SSF SET through phpseclib');
$validated('runtime-shared-signals');

$jti = JwtVerifier::base64UrlEncode(random_bytes(24));
$check(SessionRegistry::acceptLogoutToken('https://runtime.example.com/', $jti, time() + 60), 'first logout token is accepted');
$check(!SessionRegistry::acceptLogoutToken('https://runtime.example.com/', $jti, time() + 60), 'replayed logout token is refused');
SessionRegistry::releaseLogoutToken('https://runtime.example.com/', $jti);
$check(
    SessionRegistry::acceptLogoutToken('https://runtime.example.com/', $jti, time() + 60),
    'a failed logout can release its replay marker for a provider retry'
);
$check(
    SessionRegistry::acceptSecurityEvent('runtime', $ssfIssuer, $ssfAudience, 'runtime-replay'),
    'first Shared Signals event is accepted'
);
$check(
    !SessionRegistry::acceptSecurityEvent('runtime', $ssfIssuer, $ssfAudience, 'runtime-replay'),
    'replayed Shared Signals event is refused'
);

$sessionId = bin2hex(random_bytes(16));
SessionRegistry::record($sessionId, 'runtime', 'https://runtime.example.com/', 'subject', 'sid', time() + 60);
SessionRegistry::remove($sessionId);
$state = 'p.' . JwtVerifier::base64UrlEncode(random_bytes(32));
TransactionRegistry::store($state, ['created' => time(), 'app_code' => 'runtime']);
$transaction = TransactionRegistry::consume($state, 'runtime');
$check(($transaction['app_code'] ?? '') === 'runtime', 'form-post transaction is consumed once');
try {
    TransactionRegistry::consume($state, 'runtime');
    $check(false, 'form-post transaction replay is refused');
} catch (\Throwable $e) {
    $check(true, 'form-post transaction replay is refused');
}
$pendingId = PendingIdentityRegistry::record(
    'runtime',
    'https://runtime.example.com/',
    'pending-subject',
    ['email' => 'pending@example.com', 'email_verified' => true]
);
$check(PendingIdentityRegistry::find($pendingId, 'runtime') !== null, 'pending identity is stored');
$check(PendingIdentityRegistry::remove($pendingId, 'runtime'), 'pending identity is removed');
foreach ([
    '.openidconnect-sessions', '.openidconnect-logout-tokens', '.openidconnect-security-events',
    '.openidconnect-transactions', '.openidconnect-pending-identities',
] as $file) {
    $path = rtrim((string)ini_get('session.save_path'), '/') . '/' . $file;
    $check(is_file($path) && (fileperms($path) & 0777) === 0600, $file . ' has mode 0600');
}
$validated('runtime-state-registries');

$unprivilegedProbe = 'openidconnect-acl-probe-' . bin2hex(random_bytes(8));
$check(
    (new WebGuiAccess(new ACL()))->authorizedTarget($unprivilegedProbe, '/') === null,
    'an account without privileges has no technical logout route accepted as a WebGUI landing page'
);

/* The plugin deliberately extends core's existing authentication-server privilege.
 * Exercise the real pluggable ACL merge: a delegated administrator must retain the
 * core page and gain only this manager API, without receiving the other OIDC APIs. */
$system = Config::getInstance()->object()->system;
$aclProbe = $system->addChild('user');
$aclProbeName = 'openidconnect-authserver-admin-' . bin2hex(random_bytes(6));
$aclProbe->addChild('name', $aclProbeName);
$aclProbe->addChild('uid', '65001');
$aclProbe->addChild('priv', 'page-system-authservers,user-config-readonly');
$aclWriter = $system->addChild('user');
$aclWriterName = 'openidconnect-authserver-writer-' . bin2hex(random_bytes(6));
$aclWriter->addChild('name', $aclWriterName);
$aclWriter->addChild('uid', '65002');
$aclWriter->addChild('priv', 'page-system-authservers');
$delegatedAcl = new ACL();
$check($delegatedAcl->isPageAccessible($aclProbeName, '/system_authservers.php'),
    'authentication-server privilege retains the core server page');
$check($delegatedAcl->isPageAccessible($aclProbeName, '/api/openidconnect/approval/list'),
    'authentication-server privilege includes the OIDC identity manager API');
$check(!$delegatedAcl->isPageAccessible($aclProbeName, '/api/openidconnect/test/start'),
    'identity management does not grant the separate OIDC sign-in-test privilege');
$check($delegatedAcl->hasPrivilege($aclProbeName, 'user-config-readonly'),
    'the real ACL exposes the read-only guard used by identity mutations');
$managerGuard = new class extends ApprovalController {
    public function assumeUser(string $username): void
    {
        $this->logged_in_user = $username;
    }
};
$guardMethod = new ReflectionMethod(ApprovalController::class, 'requireAuthenticationServerAdministration');
$managerGuard->assumeUser($aclWriterName);
try {
    $guardMethod->invoke($managerGuard, true);
    $check(true, 'a delegated writable authentication-server administrator passes the manager write guard');
} catch (\Throwable $e) {
    $check(false, 'a delegated writable authentication-server administrator passes the manager write guard');
}
$managerGuard->assumeUser($aclProbeName);
try {
    $guardMethod->invoke($managerGuard, true);
    $check(false, 'the identity manager refuses a user-config-readonly mutation');
} catch (\Throwable $e) {
    $check(true, 'the identity manager refuses a user-config-readonly mutation');
}
$validated('runtime-core-acl');

/* Exercise the connector against the real core configuration object without saving a
 * temporary protocol change to config.xml. */
$profileIcon = new OpenIDConnect();
$profileIcon->setProperties(['openidconnect_provider_profile' => 'keycloak']);
$check(
    $profileIcon->iconUrl() === '/api/openidconnect/auth/builtinicon/keycloak',
    'a named profile receives its package-owned icon without a saved override'
);
$iconPath = OpenIDConnect::providerIconPath('keycloak');
$check(
    is_string($iconPath) && is_readable($iconPath) && str_contains((string)file_get_contents($iconPath), '<svg'),
    'the selected provider icon is installed as a readable SVG'
);
$genericIcon = new OpenIDConnect();
$genericIcon->setProperties(['openidconnect_provider_profile' => 'general']);
$genericIconPath = OpenIDConnect::providerIconPath('general');
$check(
    $genericIcon->iconUrl() === '/api/openidconnect/auth/builtinicon/general'
        && is_string($genericIconPath)
        && is_readable($genericIconPath)
        && str_contains((string)file_get_contents($genericIconPath), '>OIDC</text>'),
    'Generic OpenID Connect receives the installed neutral OIDC icon'
);
$fixedButton = new OpenIDConnect();
$fixedButton->setProperties([
    'openidconnect_provider_profile' => 'google',
    'openidconnect_button_text_mode' => 'custom',
    'openidconnect_button_provider_label' => 'Ignored label',
    'openidconnect_button_custom_text' => 'Ignored text',
]);
$check(
    $fixedButton->buttonTextMode() === 'label_only'
        && $fixedButton->buttonProviderLabel('Technical row') === 'Google',
    'a global public provider keeps its conventional short login label'
);
$previousLocale = setlocale(LC_ALL, '0');
$check(setlocale(LC_ALL, 'de_DE.UTF-8') !== false, 'the installed German WebGUI locale is available');
bindtextdomain('OPNsense', '/usr/local/share/locale');
bind_textdomain_codeset('OPNsense', 'UTF-8');
textdomain('OPNsense');
$localizedCaption = (new ReflectionMethod(OpenIDConnectContainer::class, 'localizedCoreCaption'))
    ->invoke(new OpenIDConnectContainer(), 'Keycloak');
$check(
    $localizedCaption !== 'Login using Keycloak' && str_contains($localizedCaption, 'Keycloak'),
    'the custom full-width button reuses the installed OPNsense translation'
);
if (is_string($previousLocale) && $previousLocale !== '') {
    setlocale(LC_ALL, $previousLocale);
}
$validated('runtime-login-presentation');
$originalProtocol = (string)($system->webgui->protocol ?? 'https');
$system->webgui->protocol = 'http';
$nativeHttp = new OpenIDConnect();
$nativeHttp->setProperties([
    'openidconnect_enabled' => '1',
    'openidconnect_origin_policy' => 'opnsense',
]);
$check(!$nativeHttp->isWebGuiTransportReady(), 'real OPNsense config blocks native HTTP for OIDC');
$offloadedHttp = new OpenIDConnect();
$offloadedHttp->setProperties([
    'openidconnect_enabled' => '1',
    'openidconnect_tls_offloading' => '1',
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.com',
]);
$check($offloadedHttp->isWebGuiTransportReady(), 'real OPNsense config accepts complete explicit TLS offloading');
$system->webgui->protocol = $originalProtocol;
$validated('runtime-transport-policy');

if (in_array('--network', $argv, true)) {
    foreach ([
        'Google' => 'https://accounts.google.com',
        'Apple' => 'https://appleid.apple.com',
        'JumpCloud US' => 'https://oauth.id.jumpcloud.com/',
        'LinkedIn' => 'https://www.linkedin.com/oauth',
        'Slack' => 'https://slack.com',
        'Yahoo' => 'https://api.login.yahoo.com',
        'ORCID' => 'https://orcid.org',
    ] as $name => $issuer) {
        $metadata = ProviderMetadata::discover($issuer, new HttpClient());
        $check(hash_equals($issuer, $metadata->issuer()), $name . ' exact discovery issuer');
    }
    $microsoftTemplate = 'https://login.microsoftonline.com/{tenantid}/v2.0';
    $microsoftCommon = ProviderMetadata::discover(
        'https://login.microsoftonline.com/common/v2.0',
        new HttpClient(),
        $microsoftTemplate
    );
    $check(hash_equals($microsoftTemplate, $microsoftCommon->issuer()),
        'Microsoft common documented tenant issuer template');
    $personalIssuer = 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0';
    $microsoftConsumers = ProviderMetadata::discover(
        'https://login.microsoftonline.com/consumers/v2.0',
        new HttpClient(),
        $personalIssuer
    );
    $check(hash_equals($personalIssuer, $microsoftConsumers->issuer()),
        'Microsoft consumers fixed personal-account issuer');
    $validated('public-provider-discovery');
}

try {
    $writeEvidence('passed');
} catch (\Throwable $e) {
    fwrite(STDERR, "FAIL: audit evidence could not be written\n");
    exit(1);
}
echo "{$checks} OPNsense integration checks passed.\n";
