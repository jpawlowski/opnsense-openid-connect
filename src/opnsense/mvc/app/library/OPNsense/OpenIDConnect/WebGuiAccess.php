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

/**
 * Choose a page a locally authorized WebGUI user can actually open.
 *
 * OPNsense's ACL is the authority here: it combines direct user privileges,
 * group privileges and group source-network restrictions. Its landing-page
 * helper can, however, return an always-allowed technical route such as the
 * logout endpoint when an account has no usable WebGUI privilege. Such a route
 * is not a successful authorization result and would only create a login/logout
 * loop after OpenID Connect had authenticated the user.
 */
final class WebGuiAccess
{
    /** @var object OPNsense\Core\ACL in production; kept structural for focused unit tests */
    private object $acl;

    public function __construct(object $acl)
    {
        $this->acl = $acl;
    }

    /**
     * @return string|null requested page, an authorized fallback, or null when
     *                     this account has no usable WebGUI page
     */
    public function authorizedTarget(string $account, string $requested): ?string
    {
        $checkedRequest = $requested === '/' ? '/index.php' : $requested;
        if ($this->isNavigableWebGuiTarget($requested)
            && $this->acl->isPageAccessible($account, $checkedRequest)) {
            return $requested;
        }

        $landing = $this->acl->getLandingPage($account);
        if (!is_string($landing) || trim($landing) === '') {
            return null;
        }
        $landing = trim($landing);
        if (str_starts_with($landing, '//')
            || preg_match('/^[A-Za-z][A-Za-z0-9+.-]*:/', $landing)) {
            return null;
        }
        $landing = '/' . ltrim($landing, "/\\");
        $checkedLanding = $landing === '/' ? '/index.php' : $landing;
        if (!$this->isNavigableWebGuiTarget($landing)
            || !$this->acl->isPageAccessible($account, $checkedLanding)) {
            return null;
        }

        return $landing;
    }

    /** Technical API, logout and ACL-pattern routes are not pages to send a person to. */
    private function isNavigableWebGuiTarget(string $target): bool
    {
        if ($target === '' || $target[0] !== '/' || preg_match('/[\x00-\x1f\x7f*]/', $target)) {
            return false;
        }
        $parts = parse_url($target);
        if (!is_array($parts)
            || isset($parts['scheme'])
            || isset($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['fragment'])) {
            return false;
        }
        $path = '/' . ltrim((string)($parts['path'] ?? ''), '/');
        if ($path === '/api' || str_starts_with($path, '/api/')) {
            return false;
        }
        if ($path === '/index.php' && isset($parts['query'])) {
            parse_str((string)$parts['query'], $query);
            if (array_key_exists('logout', $query)) {
                return false;
            }
        }

        return true;
    }
}
