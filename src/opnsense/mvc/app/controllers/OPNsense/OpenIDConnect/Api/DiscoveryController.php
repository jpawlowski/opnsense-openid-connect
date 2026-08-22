<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\OpenIDConnect;
use OPNsense\Base\ApiControllerBase;
use OPNsense\OpenIDConnect\RelyingParty;

/**
 * Reads a provider's discovery document and reports what it says, so that a provider URL
 * can be checked while it is being typed rather than at the next login attempt.
 *
 * A read, so GET: no CSRF dance, and nothing but the address travels - in particular not
 * the client secret, which this has no use for. It makes the firewall fetch an address
 * someone else chose, so it is behind a session and behind a privilege of its own; see
 * models/OPNsense/OpenIDConnect/ACL/ACL.xml.
 */
class DiscoveryController extends ApiControllerBase
{
    private const WELL_KNOWN = '.well-known/openid-configuration';

    /** a discovery document is a few kilobytes; anything larger is not one */
    private const MAX_BYTES = 262144;

    /**
     * @return array what the provider offers, or why it could not be asked
     */
    public function probeAction()
    {
        $this->response->setContentType('application/json', 'UTF-8');

        $given = trim((string)$this->request->get('url'));
        if (!OpenIDConnect::isFetchableUrl($given)) {
            return ['status' => 'error', 'message' => gettext('That is not an http or https address.')];
        }

        $document = $this->fetch($this->wellKnownFor($given));
        if (!is_array($document)) {
            return ['status' => 'error', 'message' => $document];
        }

        return ['status' => 'ok', 'summary' => $this->summarise($document)];
    }

    private function wellKnownFor(string $given): string
    {
        $marker = strpos($given, self::WELL_KNOWN);

        return $marker === false ? rtrim($given, '/') . '/' . self::WELL_KNOWN : $given;
    }

    /**
     * @return array|string the decoded document, or a sentence saying what went wrong
     */
    private function fetch(string $url)
    {
        $answer = RelyingParty::fetchOverWeb($url, self::MAX_BYTES);

        /* an answer over the size is a transfer curl gave up on, and says so in plain words */
        if (!$answer['ok']) {
            return sprintf(gettext('The firewall could not reach it: %s'), $answer['problem']);
        }
        if ($answer['status'] !== 200) {
            return sprintf(gettext('The provider answered with HTTP %s.'), $answer['status']);
        }

        $document = json_decode($answer['body'], true);
        if (!is_array($document) || empty($document['issuer'])) {
            return gettext('The answer is not an OpenID Connect discovery document.');
        }

        return $document;
    }

    /**
     * Reports the things this plugin actually depends on, rather than everything the
     * document happens to contain.
     */
    private function summarise(array $document): string
    {
        $list = function (string $key) use ($document): array {
            $value = $document[$key] ?? [];

            return is_array($value) ? $value : [];
        };

        $algorithms = array_intersect($list('id_token_signing_alg_values_supported'), RelyingParty::SIGNING_ALGORITHMS);
        $lines = [
            sprintf(gettext('Issuer: %s'), $document['issuer']),
            sprintf(gettext('Scopes: %s'), implode(', ', $list('scopes_supported')) ?: gettext('not stated')),
            sprintf(gettext('Claims: %s'), implode(', ', $list('claims_supported')) ?: gettext('not stated')),
            sprintf(
                gettext('Usable signatures: %s'),
                implode(', ', $algorithms) ?: gettext('none this firewall accepts')
            ),
            sprintf(
                gettext('PKCE: %s'),
                in_array('S256', $list('code_challenge_methods_supported'), true)
                    ? gettext('S256 offered') : gettext('not offered')
            ),
            sprintf(
                gettext('Sign-out endpoint: %s'),
                empty($document['end_session_endpoint']) ? gettext('none') : gettext('offered')
            ),
            sprintf(
                gettext('Revocation endpoint: %s'),
                empty($document['revocation_endpoint']) ? gettext('none') : gettext('offered')
            ),
        ];

        if ($algorithms === []) {
            $lines[] = gettext('Warning: a login would be refused, no acceptable signature algorithm.');
        }

        return implode("\n", $lines);
    }
}
