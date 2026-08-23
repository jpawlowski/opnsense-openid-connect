<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
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
