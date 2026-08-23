<?php

/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
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
                'subject_guidance' => $settings->subjectGuidance(),
                'approval_enabled' => $settings->bootstrapMode() === 'approval',
                'writable' => $this->mayWriteConfiguration(),
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
            $saved = $update
                ? $settings->updateSubjectBinding(
                    trim((string)$this->request->getPost('binding_id', null, '')),
                    $issuer,
                    $subject,
                    $uid
                )
                : $settings->createSubjectBinding($issuer, $subject, $uid);
            if (!$saved) {
                throw new \RuntimeException(gettext(
                    'The binding conflicts with an existing identity, the local account is unavailable, or ' .
                    'the authentication server changed while it was being edited.'
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
