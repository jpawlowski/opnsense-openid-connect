<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\Auth\SSOProviders;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Core\Config;

/**
 * Offers every configured OpenID Connect server to the login page.
 *
 * Core calls this while it is rendering the login form, and it does not guard the call:
 * AuthenticationFactory::listSSOproviders() has no try/catch, so anything thrown here
 * surfaces on the login page itself. Every provider is therefore built defensively and a
 * broken one is skipped rather than allowed to take the page down with it.
 */
class OpenIDConnectContainer implements ISSOContainer
{
    /** where the styles for a generated button live */
    private const STYLESHEET = __DIR__ . '/../../OpenIDConnect/assets/login-button.css';

    public function listProviders(): \Generator
    {
        foreach ($this->configuredNames() as $name) {
            try {
                $settings = (new AuthenticationFactory())->get($name);
                if (!$settings instanceof OpenIDConnect) {
                    continue;
                }

                $loginUri = '/api/openidconnect/auth/login?provider=' . rawurlencode($name);
                $properties = [
                    /* id and appcode are carried by core since 26.7; older releases ignore them */
                    'id' => 'openidconnect-' . $name,
                    'appcode' => OpenIDConnect::TYPE,
                    'service' => 'WebGui',
                    'name' => $name,
                    'login_uri' => $loginUri,
                ];

                $markup = $this->entryMarkup($settings, $name, $loginUri);
                if ($markup !== null) {
                    $properties['html_content'] = $markup;
                }

                $provider = new Provider($properties);
            } catch (\Throwable $e) {
                syslog(LOG_ERR, sprintf('OIDC: leaving out an unusable SSO provider (%s)', $e->getMessage()));
                continue;
            }

            yield $provider;
        }
    }

    /**
     * @return string[] names of the authentication servers that speak OpenID Connect
     */
    private function configuredNames(): array
    {
        try {
            $config = Config::getInstance()->object();
        } catch (\Throwable $e) {
            return [];
        }

        if (!isset($config->system->authserver)) {
            return [];
        }

        $names = [];
        foreach ($config->system->authserver as $server) {
            $name = (string)$server->name;
            if ((string)$server->type === OpenIDConnect::TYPE && $name !== '') {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * @return string|null markup for the login page, null to let core write its own sentence
     */
    private function entryMarkup(OpenIDConnect $settings, string $name, string $loginUri): ?string
    {
        $icon = $this->iconAddress($settings, $name);

        $custom = $settings->customButton();
        if ($custom !== '') {
            return str_replace(['%icon%', '%name%', '%url%'], [$icon, $name, $loginUri], $custom);
        }

        if ($settings->buttonStyle() === 'link') {
            return null;
        }

        $mark = '';
        if ($icon !== '') {
            $mark = $settings->iconMode() === 'original'
                ? sprintf('<img class="login-sso-mark" src="%s" alt="" />', htmlspecialchars($icon, ENT_QUOTES))
                : '<span class="login-sso-mark login-sso-mark-tinted" aria-hidden="true"></span>';
        }

        return sprintf(
            '<a href="%s" class="btn btn-primary">%s%s</a><style>%s</style>',
            htmlspecialchars($loginUri, ENT_QUOTES),
            $mark,
            sprintf(gettext('Login with %s'), htmlspecialchars($name, ENT_QUOTES)),
            $this->stylesheet($icon)
        );
    }

    /**
     * @param string $icon address of the icon, placed inside a css url("...")
     */
    private function stylesheet(string $icon): string
    {
        $css = @file_get_contents(self::STYLESHEET);
        if ($css === false) {
            return '';
        }

        /* strip the file's own comment, it is for whoever reads the source, not the browser */
        $css = preg_replace('#^/\*.*?\*/\s*#s', '', $css);

        /**
         * Everything a css string cannot carry as itself, escaped the way css spells it:
         * the quote and the backslash, and the control characters - a newline ends the
         * string outright, and what follows it would be read as style of its own.
         */
        $quoted = preg_replace_callback(
            '/["\\\\\x00-\x1f\x7f]/',
            fn(array $found) => sprintf('\\%02x ', ord($found[0])),
            $icon
        );

        return strtr($css, ['{{icon}}' => $quoted]);
    }

    /**
     * Three ways to name an icon, in order of precedence:
     *
     *  - markup kept in the configuration, for when there is nowhere to host a file. It
     *    becomes a data: URI and is never inlined into the page, so it is only ever
     *    treated as an image, where scripting is disabled.
     *  - a path on this firewall, or a data: URI, which the browser resolves by itself
     *  - anything else is an address the firewall fetches and hands on
     *
     * @return string empty when no icon is configured
     */
    private function iconAddress(OpenIDConnect $settings, string $name): string
    {
        $markup = $settings->iconMarkup();
        if ($markup !== '') {
            return 'data:image/svg+xml;base64,' . base64_encode($markup);
        }

        $configured = $settings->iconUrl();
        if ($configured === '') {
            return '';
        }

        /**
         * The stylesheet escapes what it embeds, so this is the second of two. It is here
         * because the address also reaches an <img src> and the admin-supplied custom
         * button markup, and because an address with a newline in it is not an address
         * whatever it is being put into. The settings form refuses these; a configuration
         * written by hand does not go through the form, and is refused here.
         */
        if (OpenIDConnect::hasControlCharacters($configured)) {
            syslog(LOG_ERR, sprintf('OIDC: ignoring the icon of %s, its address carries control characters', $name));
            return '';
        }

        if (OpenIDConnect::isLocalPath($configured) || str_starts_with($configured, 'data:')) {
            return $configured;
        }

        return '/api/openidconnect/auth/icon?provider=' . rawurlencode($name);
    }
}
