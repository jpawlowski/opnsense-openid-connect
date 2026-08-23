<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
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
