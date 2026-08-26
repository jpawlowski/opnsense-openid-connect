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

namespace OPNsense\OpenIDConnect\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OpenIDConnect;
use OPNsense\Core\ACL;

/** Authenticated management of durable bindings and pending identity approvals. */
class ApprovalController extends PrivateApiControllerBase
{
    public function listAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration();
            $settings = $this->settings();
            return [
                'status' => 'ok',
                'requests' => $settings->pendingApprovals(),
                'bindings' => $settings->subjectBindingRecords(),
                'accounts' => $settings->approvableAccounts(),
                'groups' => $settings->manageableGroups(),
                'subject_guidance' => $settings->subjectGuidance(),
                'approval_enabled' => $settings->bootstrapMode() === 'approval',
                'writable' => $this->mayWriteConfiguration(),
                'account_creation_allowed' => $this->mayCreateAccounts(),
                'account_groups_writable' => $this->mayCreateAccounts(),
            ];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    public function createAccountAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration(true);
            $this->requireAccountAdministration();
            $username = trim((string)$this->request->getPost('username', null, ''));
            $account = $this->settings()->createManagedAccount($username);
            if ($account === null) {
                throw new \RuntimeException(gettext(
                    'The local account could not be created. Choose a new valid username and try again.'
                ));
            }
            return [
                'status' => 'ok',
                'message' => gettext('The local account was created with no local login password.'),
                'account' => $account,
            ];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    public function approveAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration(true);
            $settings = $this->settings();
            $requestId = trim((string)$this->request->getPost('request_id', null, ''));
            $uid = trim((string)$this->request->getPost('uid', null, ''));
            if (!$settings->approvePendingIdentity($requestId, $uid)) {
                throw new \RuntimeException(gettext(
                    'The request or local account is no longer available, or the binding could not be saved.'
                ));
            }
            return ['status' => 'ok', 'message' => gettext('The identity was approved and bound to the local account.')];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    public function denyAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration(true);
            $settings = $this->settings();
            $requestId = trim((string)$this->request->getPost('request_id', null, ''));
            if (!$settings->denyPendingIdentity($requestId)) {
                throw new \RuntimeException(gettext('The pending request is no longer available.'));
            }
            return ['status' => 'ok', 'message' => gettext('The pending identity was denied and removed.')];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    public function createAction(): array
    {
        return $this->saveBinding(false);
    }

    public function updateAction(): array
    {
        return $this->saveBinding(true);
    }

    public function deleteAction(): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration(true);
            $settings = $this->settings();
            $bindingId = trim((string)$this->request->getPost('binding_id', null, ''));
            if (!$settings->deleteSubjectBinding($bindingId)) {
                throw new \RuntimeException(gettext(
                    'The binding is no longer available or could not be removed.'
                ));
            }
            return ['status' => 'ok', 'message' => gettext('The identity binding was removed.')];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    private function saveBinding(bool $update): array
    {
        $this->response->setContentType('application/json', 'UTF-8');
        try {
            $this->requireAuthenticationServerAdministration(true);
            $settings = $this->settings();
            $issuerInput = trim((string)$this->request->getPost('issuer', null, ''));
            $subjectInput = trim((string)$this->request->getPost('subject', null, ''));
            $uid = trim((string)$this->request->getPost('uid', null, ''));
            $issuer = $settings->normalizeBindingIssuer($issuerInput);
            $subject = OpenIDConnect::normalizeSubjectIdentifier($subjectInput);
            if ($issuer === null) {
                throw new \RuntimeException(gettext(
                    'The issuer must be an exact HTTPS issuer accepted by this authentication server.'
                ));
            }
            if ($subject === null) {
                throw new \RuntimeException(gettext(
                    'The subject must contain 1 to 255 UTF-8 bytes, with no control characters.'
                ));
            }
            if (!ctype_digit($uid)) {
                throw new \RuntimeException(gettext('Choose an available local account.'));
            }
            $groupSelection = $this->postedGroupSelection();
            $groups = $groupSelection['selected'] ?? null;
            $expectedGroups = $groupSelection['expected'] ?? null;
            $saved = $update
                ? $settings->updateSubjectBinding(
                    trim((string)$this->request->getPost('binding_id', null, '')),
                    $issuer,
                    $subject,
                    $uid,
                    $groups,
                    $expectedGroups
                )
                : $settings->createSubjectBinding($issuer, $subject, $uid, $groups, $expectedGroups);
            if (!$saved) {
                throw new \RuntimeException(gettext(
                    'The binding conflicts with an existing identity, the local account is unavailable, or ' .
                    'the authentication server or group memberships changed while it was being edited.'
                ));
            }
            return ['status' => 'ok', 'message' => $update
                ? gettext('The identity binding was updated.')
                : gettext('The identity was bound to the local account.')];
        } catch (\Throwable $e) {
            return ['status' => 'error', 'message' => $e->getMessage()];
        }
    }

    private function requireAuthenticationServerAdministration(bool $write = false): void
    {
        $acl = new ACL();
        $username = (string)$this->getUserName();
        if (!$acl->hasPrivilege($username, 'page-all')
            && !$acl->hasPrivilege($username, 'page-system-authservers')) {
            throw new \RuntimeException(gettext(
                'Managing OpenID Connect identities requires the System: Authentication Servers privilege.'
            ));
        }
        if ($write) {
            $this->throwReadOnly();
        }
    }

    private function mayWriteConfiguration(): bool
    {
        return !(new ACL())->hasPrivilege((string)$this->getUserName(), 'user-config-readonly');
    }

    private function requireAccountAdministration(): void
    {
        if (!$this->mayCreateAccounts()) {
            throw new \RuntimeException(gettext(
                'Creating a local account or changing its groups also requires the System: Access: Management ' .
                'privilege.'
            ));
        }
    }

    /** @return array{selected:string[],expected:string[]}|null null leaves memberships unchanged */
    private function postedGroupSelection(): ?array
    {
        if (!$this->request->hasPost('groups_json')) {
            return null;
        }
        $this->requireAccountAdministration();
        if (!$this->request->hasPost('groups_expected_json')) {
            throw new \RuntimeException(gettext('Reload the identities before changing local group memberships.'));
        }
        return [
            'selected' => $this->postedGroupList('groups_json'),
            'expected' => $this->postedGroupList('groups_expected_json'),
        ];
    }

    /** @return string[] */
    private function postedGroupList(string $field): array
    {
        try {
            $groups = json_decode(
                (string)$this->request->getPost($field, null, ''),
                true,
                16,
                JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $e) {
            throw new \RuntimeException(gettext('Choose only existing local groups.'));
        }
        if (!is_array($groups) || !array_is_list($groups)) {
            throw new \RuntimeException(gettext('Choose only existing local groups.'));
        }
        return $groups;
    }

    private function mayCreateAccounts(): bool
    {
        if (!$this->mayWriteConfiguration()) {
            return false;
        }
        $acl = new ACL();
        $username = (string)$this->getUserName();
        return $acl->hasPrivilege($username, 'page-all')
            || $acl->hasPrivilege($username, 'page-system-usermanager');
    }

    private function settings(): OpenIDConnect
    {
        $name = trim((string)$this->request->getPost('provider', null, ''));
        if ($name === '' || strlen($name) > 255 || preg_match('/[\x00-\x1f\x7f]/', $name)) {
            throw new \RuntimeException(gettext('Select a saved OpenID Connect server.'));
        }
        $settings = (new AuthenticationFactory())->get($name);
        if (!$settings instanceof OpenIDConnect) {
            throw new \RuntimeException(gettext('The selected server is not an OpenID Connect server.'));
        }
        return $settings;
    }
}
