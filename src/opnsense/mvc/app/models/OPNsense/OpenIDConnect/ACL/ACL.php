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

namespace OPNsense\OpenIDConnect\ACL;

/** Add OIDC identity management to core's existing authentication-server privilege. */
class ACL extends \OPNsense\Core\ACL\ACL
{
    /**
     * Core's pluggable ACL loader normally replaces entries with the same identifier.
     * Identity bindings are part of administering an authentication server, so append
     * our API patterns to that existing privilege instead of inventing a second grant.
     */
    public function update(&$acltags)
    {
        foreach ($this->get() as $aclId => $aclNode) {
            if ($aclId === 'page-system-authservers' && isset($acltags[$aclId])) {
                $existing = $acltags[$aclId]['match'] ?? [];
                $acltags[$aclId]['match'] = array_values(array_unique(array_merge(
                    is_array($existing) ? $existing : [],
                    $aclNode['match'] ?? []
                )));
                continue;
            }
            $acltags[$aclId] = $aclNode;
        }
    }
}
