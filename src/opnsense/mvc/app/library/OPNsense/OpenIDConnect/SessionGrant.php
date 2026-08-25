<?php

namespace OPNsense\OpenIDConnect;

/** Names and read-only origin lookup for the grant retained in an elevated PHP session. */
final class SessionGrant
{
    public const PROVIDER = 'openidconnect_grant_provider';
    public const ISSUER = 'openidconnect_grant_issuer';
    public const ID_TOKEN = 'openidconnect_grant_id_token';
    public const TOKENS = 'openidconnect_grant_tokens';
    public const CLIENT_AUTHENTICATION = 'openidconnect_grant_client_authentication';
    public const DPOP_KEY = 'openidconnect_grant_dpop_key';
    public const DPOP_BINDING = 'openidconnect_grant_dpop_binding';

    public static function currentProvider(): string
    {
        $opened = false;
        if (session_status() === PHP_SESSION_NONE && !isset($_SESSION[self::PROVIDER])) {
            $opened = @session_start();
        }
        $provider = is_string($_SESSION[self::PROVIDER] ?? null) ? $_SESSION[self::PROVIDER] : '';
        if ($opened) {
            session_abort();
        }
        return $provider !== '' && strlen($provider) <= 255 && !preg_match('/[\x00-\x1f\x7f]/', $provider)
            ? $provider : '';
    }
}
