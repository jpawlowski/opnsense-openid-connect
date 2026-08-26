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

namespace OPNsense\OpenIDConnect\Menu;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Base\Menu\MenuContainer;
use OPNsense\Core\Config;
use OPNsense\OpenIDConnect\SessionGrant;

/**
 * Points Lobby > Log Out at this plugin, so that leaving the web interface also ends the
 * session at the identity provider.
 *
 * Core's own logout drops the local session and nothing more, and the link in the page
 * header lives in authgui.inc where a plugin cannot reach it. The menu entry, however, is
 * an ordinary menu item, and MenuItem::append() matches an existing item by its id and
 * overwrites its properties - so declaring Lobby.Logout here replaces the address core
 * put there.
 *
 * Collected on every request rather than shipped as a Menu.xml, because whether this
 * happens at all is a setting.
 */
class Menu extends MenuContainer
{
    public function collect()
    {
        $provider = SessionGrant::currentProvider();
        if ($provider === '' || !$this->providerWantsIt($provider)) {
            return;
        }

        /* the endpoint decides for itself whether there is a provider session to end */
        $this->appendItem('Lobby', 'Logout', [
            'url' => '/api/openidconnect/auth/logout',
            'cssClass' => 'fa fa-sign-out fa-fw',
            'order' => '3',
        ]);
    }

    private function providerWantsIt(string $provider): bool
    {
        try {
            $config = Config::getInstance()->object();
            if (!isset($config->system->authserver)) {
                return false;
            }

            $found = false;
            foreach ($config->system->authserver as $server) {
                if ((string)$server->type === OpenIDConnect::TYPE
                    && hash_equals($provider, (string)$server->name)) {
                    $found = true;
                    break;
                }
            }
            $settings = $found ? (new AuthenticationFactory())->get($provider) : null;
            return $settings instanceof OpenIDConnect && $settings->redirectsLogoutMenu();
        } catch (\Throwable $e) {
            /* the menu is drawn on every page; never let this be the reason one fails */
            return false;
        }

        return false;
    }
}
