<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect;

/** Names and read-only origin lookup for the grant retained in an elevated PHP session. */
final class SessionGrant
{
    public const PROVIDER = 'openidconnect_grant_provider';
    public const ISSUER = 'openidconnect_grant_issuer';
    public const ID_TOKEN = 'openidconnect_grant_id_token';
    public const TOKENS = 'openidconnect_grant_tokens';

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
