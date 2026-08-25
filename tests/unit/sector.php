<?php

use OPNsense\Auth\Directory;
use OPNsense\Mvc\Request;
use OPNsense\OpenIDConnect\Api\AuthController;

Checks::group('Pairwise subject sector endpoint');

Directory::reset();
connector([
    'name' => 'Pairwise provider',
    'openidconnect_enabled' => '0',
    'openidconnect_app_code' => 'pairwise',
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.net,https://backup.example.net:8443',
    'openidconnect_sector_origin' => 'https://firewall.example.net',
]);
$sector = new AuthController(new Request('https', 'firewall.example.net'));
$sector->beforeExecuteRoute(new class {
    public function getActionName(): string
    {
        return 'sector';
    }
});
Checks::that('a disabled saved draft publishes all exact callback URIs', $sector->sectorAction('pairwise'), [
    'https://firewall.example.net/api/openidconnect/auth/callback/pairwise',
    'https://backup.example.net:8443/api/openidconnect/auth/callback/pairwise',
]);
Checks::that('the sector response is JSON', $sector->response->headers['Content-Type'], 'application/json; charset=UTF-8');
Checks::that('the public sector document cannot be cached or leak a referrer', [
    $sector->response->headers['Cache-Control'],
    $sector->response->headers['Referrer-Policy'],
    $sector->response->headers['X-Content-Type-Options'],
], ['no-store', 'no-referrer', 'nosniff']);

$wrongHost = new AuthController(new Request('https', 'backup.example.net:8443'));
Checks::that('a different accepted origin receives only a generic not-found response', [
    $wrongHost->sectorAction('pairwise'),
    $wrongHost->response->status,
], ['Not Found.', [404, 'Not Found']]);

$unknown = new AuthController(new Request('https', 'firewall.example.net'));
Checks::that('an unknown application code receives the same response', [
    $unknown->sectorAction('unknown'),
    $unknown->response->status,
], ['Not Found.', [404, 'Not Found']]);

connector([
    'name' => 'Duplicate provider',
    'openidconnect_enabled' => '0',
    'openidconnect_app_code' => 'pairwise',
    'openidconnect_origin_policy' => 'custom',
    'openidconnect_redirect_urls' => 'https://firewall.example.net',
    'openidconnect_sector_origin' => 'https://firewall.example.net',
]);
$duplicate = new AuthController(new Request('https', 'firewall.example.net'));
Checks::that('a duplicate application code receives the same response', [
    $duplicate->sectorAction('pairwise'),
    $duplicate->response->status,
], ['Not Found.', [404, 'Not Found']]);
