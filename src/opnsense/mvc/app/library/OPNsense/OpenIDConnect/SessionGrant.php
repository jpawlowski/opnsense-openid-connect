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
