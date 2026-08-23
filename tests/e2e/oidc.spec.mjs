/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { expect, request as playwrightRequest, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const required = [
  'E2E_OPNSENSE_URL', 'E2E_OPNSENSE_USERNAME', 'E2E_OPNSENSE_PASSWORD',
  'E2E_KEYCLOAK_URL', 'E2E_KEYCLOAK_REALM', 'E2E_KEYCLOAK_ADMIN_USERNAME',
  'E2E_KEYCLOAK_ADMIN_PASSWORD', 'E2E_KEYCLOAK_CLIENT_ID',
  'E2E_KEYCLOAK_CLIENT_SECRET', 'E2E_TEST_USERNAME', 'E2E_TEST_PASSWORD',
  'E2E_SERVER_NAME', 'E2E_APPLICATION_CODE', 'E2E_BACKCHANNEL_URL', 'E2E_ZAP_PROXY',
];
for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`${name} is required; start this test through tests/e2e/run.sh`);
  }
}

const opnsense = new URL(process.env.E2E_OPNSENSE_URL);
const keycloak = new URL(process.env.E2E_KEYCLOAK_URL);
const origin = opnsense.origin;
const issuer = `${keycloak.origin}/realms/${process.env.E2E_KEYCLOAK_REALM}`;
const callbackPath = `/api/openidconnect/auth/callback/${process.env.E2E_APPLICATION_CODE}`;
const runCommand = promisify(execFile);

function opnsenseRequestContextOptions() {
  return {
    ignoreHTTPSErrors: true,
    proxy: { server: process.env.E2E_ZAP_PROXY },
  };
}

function expectPrivateResponseHeaders(response, { legacyNoCache = true } = {}) {
  const headers = response.headers();
  expect(headers['cache-control'] || '').toContain('no-store');
  if (legacyNoCache) {
    expect(headers.pragma || '').toContain('no-cache');
  }
  expect(headers['referrer-policy']).toBe('no-referrer');
  expect(headers['x-content-type-options']).toBe('nosniff');
}

function expectStandaloneHtmlHeaders(response) {
  expectPrivateResponseHeaders(response);
  const headers = response.headers();
  expect(headers['content-type'] || '').toContain('text/html');
  const policy = headers['content-security-policy'] || '';
  expect(policy).toContain("default-src 'none'");
  expect(policy).toContain("style-src 'unsafe-inline'");
  expect(policy).toContain("frame-ancestors 'none'");
  expect(policy).toContain("base-uri 'none'");
  expect(policy).toContain("form-action 'none'");
}

async function localLogin(page) {
  await page.goto(origin);
  await page.getByRole('textbox', { name: 'Username:' }).fill(process.env.E2E_OPNSENSE_USERNAME);
  await page.getByRole('textbox', { name: 'Password:' }).fill(process.env.E2E_OPNSENSE_PASSWORD);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page).toHaveURL(/\/ui\/core\/dashboard/);
}

async function setFlatList(page, name, values) {
  await page.locator(`input[name="${name}"]`).evaluate((element, entries) => {
    const value = entries.join(',');
    element.value = value;
    element.setAttribute('value', value);
    element.dispatchEvent(new Event('change', { bubbles: true }));
  }, values);
}

async function setGroupList(page, name, values) {
  const input = page.locator(`input[name="${name}"]`);
  await input.evaluate((element, entries) => {
    element.value = entries.join(',');
    element.dispatchEvent(new Event('change', { bubbles: true }));
  }, values);
  const picker = input.locator('xpath=following-sibling::select[1]');
  if (await picker.count()) {
    await picker.selectOption(values, { force: true });
  }
}

async function configureServer(page) {
  let discoveryRequests = 0;
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/openidconnect/discovery/probe') {
      discoveryRequests += 1;
    }
  });
  await page.goto(`${origin}/system_authservers.php?act=new`);
  await page.locator('select[name="type"]').selectOption('openidconnect');
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toBeVisible();
  await expect(page.locator('input[name="openidconnect_tls_offloading"]')
    .locator('xpath=ancestor::tr')).toBeHidden();
  await expect(page.locator('input[name="openidconnect_max_age"]')).toHaveValue('14400');
  await expect(page.locator('[name="openidconnect_subject_bindings"]')).toHaveCount(0);
  const profileLabels = (await page.locator(
    'select[name="openidconnect_provider_profile"] option'
  ).allTextContents()).map(label => label.trim());
  expect(profileLabels[0]).toBe('Generic OpenID Connect');
  const namedProfileLabels = profileLabels.slice(1);
  const sortedProfileLabels = [...namedProfileLabels].sort((left, right) => {
    const leftFolded = left.toLowerCase();
    const rightFolded = right.toLowerCase();
    return leftFolded < rightFolded ? -1 : leftFolded > rightFolded ? 1 : 0;
  });
  expect(namedProfileLabels).toEqual(sortedProfileLabels);
  expect(profileLabels).toContain('LinkedIn · Social login');
  expect(profileLabels).toContain('Apple · Social login');
  expect(profileLabels).toContain('GitLab.com / self-managed GitLab · Social / workforce');
  expect(profileLabels).toContain('Microsoft Entra ID / Microsoft account · Social / workforce');
  expect(profileLabels).not.toContain('GitHub');
  expect(profileLabels).not.toContain('Discord');
  expect(profileLabels).not.toContain('Login with Amazon');
  const providerProfile = page.locator('select[name="openidconnect_provider_profile"]');
  const issuerField = page.locator('input[name="openidconnect_provider_url"]');
  const iconField = page.locator('input[name="openidconnect_icon_url"]');
  const buttonTextMode = page.locator('select[name="openidconnect_button_text_mode"]');
  const buttonProviderLabel = page.locator('input[name="openidconnect_button_provider_label"]');
  const customButtonText = page.locator('input[name="openidconnect_button_custom_text"]');
  await expect(buttonTextMode).toHaveValue('localized');
  await expect(buttonTextMode.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(customButtonText.locator('xpath=ancestor::tr')).toBeHidden();
  await providerProfile.selectOption('apple');
  await expect(issuerField).toHaveValue('https://appleid.apple.com');
  await expect(issuerField).toHaveAttribute('readonly', 'readonly');
  await expect(page.locator('select[name="openidconnect_token_auth"]')).toBeDisabled();
  await expect(page.locator('input[data-oidc-profile-shadow="openidconnect_token_auth"]'))
    .toHaveValue('client_secret_post');
  await expect(page.locator('select[name="openidconnect_claims_source"]')).toBeDisabled();
  await expect(page.locator('select[name="openidconnect_response_mode"]')).toBeDisabled();
  await expect(page.locator('select[name="openidconnect_bootstrap_mode"]')).toHaveValue('approval');
  await expect(page.locator('input[name="openidconnect_scopes"]')).toHaveValue('openid,email,name');
  await expect(iconField).toHaveValue('/api/openidconnect/auth/builtinicon/apple');
  await expect(buttonTextMode).toBeDisabled();
  await expect(page.locator('input[data-oidc-profile-shadow="openidconnect_button_text_mode"]'))
    .toHaveValue('label_only');
  await expect(buttonProviderLabel).toHaveValue('Apple');
  await expect(buttonTextMode.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(customButtonText.locator('xpath=ancestor::tr')).toBeHidden();
  await page.locator('input[name="openidconnect_username_claim"]').fill('sub');
  await page.getByRole('button', { name: 'Restore profile defaults' }).click();
  await expect(page.locator('input[name="openidconnect_username_claim"]')).toHaveValue('email');
  await providerProfile.selectOption('orcid');
  await expect(issuerField).toHaveValue('https://orcid.org');
  await expect(page.locator('input[name="openidconnect_scopes"]')).toHaveValue('openid');
  await providerProfile.selectOption('keycloak');
  await expect(iconField).toHaveValue('/api/openidconnect/auth/builtinicon/keycloak');
  await expect(buttonTextMode).toBeEnabled();
  await expect(buttonTextMode).toHaveValue('localized');
  await expect(buttonTextMode.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeVisible();
  await buttonProviderLabel.fill('Company identity');
  await buttonTextMode.selectOption('custom');
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(customButtonText.locator('xpath=ancestor::tr')).toBeVisible();
  await customButtonText.fill('Continue through Company identity');
  await buttonTextMode.selectOption('localized');
  await buttonProviderLabel.fill('');
  await expect(issuerField).not.toHaveAttribute('readonly');
  await expect(page.locator('select[name="openidconnect_token_auth"]')).toBeEnabled();
  await expect(issuerField).toHaveAttribute('placeholder', 'https://id.example.com/realms/opnsense');
  await providerProfile.selectOption('authentik');
  await issuerField.fill(
    'https://auth.example.com/application/o/firewall/.well-known/openid-configuration'
  );
  await issuerField.blur();
  await expect(issuerField).toHaveValue('https://auth.example.com/application/o/firewall/');
  await page.locator('select[name="openidconnect_provider_profile"]').selectOption('entra');
  const microsoftAudience = page.locator('select[name="openidconnect_microsoft_audience"]');
  await expect(microsoftAudience.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(microsoftAudience.locator('option')).toHaveCount(4);
  await microsoftAudience.selectOption('common');
  await expect(page.locator('input[name="openidconnect_provider_url"]'))
    .toHaveValue('https://login.microsoftonline.com/common/v2.0');
  await expect(page.locator('input[name="openidconnect_provider_url"]'))
    .toHaveAttribute('readonly', 'readonly');
  await page.locator('select[name="openidconnect_provider_profile"]').selectOption('keycloak');
  await expect(microsoftAudience.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue('');
  await expect(page.locator('select[name="openidconnect_origin_policy"]')).toHaveValue('opnsense');
  await expect(page.locator('input[name="openidconnect_redirect_urls"]').locator('xpath=ancestor::tr')).toBeVisible();
  await page.locator('input[name="name"]').fill(process.env.E2E_SERVER_NAME);
  await page.locator('input[name="openidconnect_app_code"]').fill(process.env.E2E_APPLICATION_CODE);
  await expect(page.locator('.oidc-endpoints code').first()).toHaveText(`${origin}${callbackPath}`);
  await page.locator('select[name="openidconnect_provider_profile"]').selectOption('keycloak');
  await page.locator('select[name="openidconnect_bootstrap_mode"]').selectOption('username');
  await page.locator('input[name="openidconnect_username_claim"]').fill('preferred_username');
  await page.locator('select[name="openidconnect_claims_source"]').selectOption('auto');
  await page.locator('select[name="openidconnect_response_mode"]').selectOption('query');
  await setFlatList(page, 'openidconnect_scopes', ['openid', 'email', 'profile']);
  await page.locator('input[name="openidconnect_create_users"]').check();
  await setGroupList(page, 'openidconnect_default_groups', ['admins']);
  await page.locator('input[name="openidconnect_logout_menu"]').check();
  await page.locator('input[name="openidconnect_logout_redirect"]').check();
  await page.locator('input[name="openidconnect_debug"]').check();

  // The current unsaved form is sufficient to produce a no-secret provider import.
  const setupResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/setup/generate'
  ));
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download provider setup' }).click();
  expectPrivateResponseHeaders(await setupResponsePromise);
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^opnsense-.+-keycloak-partial-import\.json$/);
  const setup = JSON.parse(await readFile(await download.path(), 'utf8'));
  const generatedClient = setup.clients[0];
  expect(setup.ifResourceExists).toBe('SKIP');
  expect(generatedClient.secret).toBeUndefined();
  expect(generatedClient.redirectUris[0]).toBe(`${origin}${callbackPath}`);
  expect(generatedClient.redirectUris).toContain(`${origin}${callbackPath}`);
  expect(generatedClient.webOrigins[0]).toBe(origin);
  expect(generatedClient.webOrigins).toContain(origin);
  expect(generatedClient.redirectUris.every(uri => uri.endsWith(callbackPath))).toBeTruthy();
  const keycloakSetupDialog = page.getByRole('dialog');
  const keycloakSetupResult = keycloakSetupDialog.locator(
    '.oidc-setup-result[data-provider="keycloak"]'
  );
  await expect(keycloakSetupResult.locator('.alert-success')).toBeVisible();
  await expect(keycloakSetupResult.locator('.oidc-setup-file code')).toHaveText(download.suggestedFilename());
  await expect(keycloakSetupResult.locator('.oidc-setup-progress-label')).toHaveText('Step 1 of 3');
  await expect(keycloakSetupResult.locator('[data-step="download"]')).toBeVisible();
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click();
  await expect(keycloakSetupResult.locator('.oidc-setup-progress-label')).toHaveText('Step 2 of 3');
  await expect(keycloakSetupResult.locator('[data-step="import"]')).toBeVisible();
  await expect(keycloakSetupResult.locator('.oidc-setup-steps li')).toHaveCount(4);
  await expect(keycloakSetupResult).toContainText('Realm settings > Action > Partial import');
  await expect(keycloakSetupResult).toContainText('If a resource exists: Skip');
  await expect(keycloakSetupResult.locator('.oidc-setup-steps .text-muted code')).toHaveText([
    'Partial import',
    'JSON',
    'Skip',
  ]);
  await expect(keycloakSetupResult.locator('.oidc-setup-warning')).toContainText('currently selected realm');
  await expect(keycloakSetupResult.locator('.oidc-setup-warning code')).toHaveText('Partial import');
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click();
  await expect(keycloakSetupResult.locator('.oidc-setup-progress-label')).toHaveText('Step 3 of 3');
  await expect(keycloakSetupResult.locator('[data-step="finish"]')).toBeVisible();
  await expect(keycloakSetupResult.locator('[data-step="finish"]')).toContainText('Credentials tab');
  await expect(keycloakSetupResult.locator('.oidc-setup-finish code').filter({
    hasText: 'Clients > imported client > Credentials',
  })).toHaveCount(1);
  await expect(keycloakSetupResult.locator('.oidc-setup-finish code').filter({
    hasText: 'Test discovery',
  })).toHaveCount(1);
  await expect(keycloakSetupResult.getByRole('button', { name: 'Done' })).toBeVisible();
  await keycloakSetupResult.getByRole('button', { name: 'Previous' }).click();
  await expect(keycloakSetupResult.locator('[data-step="import"]')).toBeVisible();
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click();
  await keycloakSetupResult.getByRole('button', { name: 'Done' }).click();
  await expect(keycloakSetupDialog).toBeHidden();

  // Each supported profile receives concrete instructions for its own import UI.
  await page.locator('select[name="openidconnect_provider_profile"]').selectOption('authentik');
  const authentikDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download provider setup' }).click();
  const authentikDownload = await authentikDownloadPromise;
  expect(authentikDownload.suggestedFilename()).toMatch(/-authentik-blueprint\.yaml$/);
  const authentikSetupDialog = page.getByRole('dialog');
  const authentikSetupResult = authentikSetupDialog.locator(
    '.oidc-setup-result[data-provider="authentik"]'
  );
  await expect(authentikSetupResult.locator('.alert-success')).toBeVisible();
  await expect(authentikSetupResult.locator('[data-step="download"]')).toBeVisible();
  await authentikSetupResult.getByRole('button', { name: 'Next' }).click();
  await expect(authentikSetupResult.locator('[data-step="import"]')).toBeVisible();
  await expect(authentikSetupResult.locator('.oidc-setup-steps li')).toHaveCount(4);
  await expect(authentikSetupResult).toContainText('Customization > Blueprints > Import');
  await expect(authentikSetupResult).toContainText('File upload');
  await expect(authentikSetupResult.locator('.oidc-setup-steps .text-muted code')).toHaveText([
    'Blueprint',
    'YAML',
    'Blueprint',
    'Blueprint',
  ]);
  await expect(authentikSetupResult).toContainText(
    'creates no visible, monitored Blueprint instance'
  );
  await expect(authentikSetupResult.locator('[data-step="finish"]')).toContainText(
    'Applications > Applications'
  );
  await expect(authentikSetupResult.locator('.oidc-setup-warning')).toContainText(
    'creates no authentik policy binding'
  );
  await authentikSetupResult.getByRole('button', { name: 'Next' }).click();
  await expect(authentikSetupResult.locator('[data-step="finish"]')).toBeVisible();
  await expect(authentikSetupResult.locator('[data-step="finish"]')).toContainText(
    'Applications > Providers'
  );
  await expect(authentikSetupResult.locator('.oidc-setup-finish code').filter({
    hasText: 'Applications > Providers',
  })).toHaveCount(1);
  await authentikSetupResult.getByRole('button', { name: 'Done' }).click();
  await expect(authentikSetupDialog).toBeHidden();

  // The provider-specific instructions remain available without downloading again.
  let guideDownloadCount = 0;
  page.on('download', () => { guideDownloadCount += 1; });
  await page.getByRole('button', { name: 'Open setup guide' }).click();
  const standaloneGuideDialog = page.getByRole('dialog');
  const standaloneGuide = standaloneGuideDialog.locator(
    '.oidc-setup-result[data-provider="authentik"]'
  );
  await expect(standaloneGuide.locator('.oidc-setup-progress-label')).toHaveText('Step 1 of 2');
  await expect(standaloneGuide.locator('[data-step="download"]')).toHaveCount(0);
  await expect(standaloneGuide.locator('[data-step="import"]')).toBeVisible();
  await expect(standaloneGuide.locator('.oidc-setup-steps .text-muted code')).toHaveText([
    'Blueprint',
    'YAML',
    'Blueprint',
    'Blueprint',
  ]);
  await standaloneGuide.getByRole('button', { name: 'Next' }).click();
  await expect(standaloneGuide.locator('.oidc-setup-progress-label')).toHaveText('Step 2 of 2');
  await expect(standaloneGuide.locator('.oidc-setup-finish code').filter({
    hasText: 'Applications > Providers',
  })).toHaveCount(1);
  expect(guideDownloadCount).toBe(0);
  await standaloneGuide.getByRole('button', { name: 'Done' }).click();
  await expect(standaloneGuideDialog).toBeHidden();
  await page.locator('select[name="openidconnect_provider_profile"]').selectOption('keycloak');
  // Selecting a named profile deliberately restores its complete safe starting point.
  // Apply this test's less restrictive JIT policy only after the final profile choice.
  await page.locator('select[name="openidconnect_bootstrap_mode"]').selectOption('username');

  // Saving a disabled draft needs no provider-side values and never contacts Discovery.
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
  expect(discoveryRequests).toBe(0);
  const serverRow = page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) });
  await expect(serverRow).toBeVisible();

  // Callback routing is unambiguous only while every OIDC application code is unique.
  await page.goto(`${origin}/system_authservers.php?act=new`);
  await page.locator('select[name="type"]').selectOption('openidconnect');
  await page.locator('input[name="name"]').fill('duplicate-code-probe');
  await page.locator('input[name="openidconnect_app_code"]').fill(process.env.E2E_APPLICATION_CODE);
  await expect(page.locator('.oidc-app-code-conflict')).toBeVisible();
  await expect(page.locator('.oidc-app-code-conflict code')).toHaveText(process.env.E2E_SERVER_NAME);
  await expect(page.locator('input[name="openidconnect_app_code"]')).toHaveAttribute('aria-invalid', 'true');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.locator('body')).toContainText(
    `The application code is already used by authentication server "${process.env.E2E_SERVER_NAME}".`
  );
  await page.goto(`${origin}/system_authservers.php`);
  await expect(page.getByRole('row', { name: /duplicate-code-probe/ })).toHaveCount(0);

  await serverRow.getByRole('link', { name: 'Edit' }).click();
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue('');
  await expect(page.locator('input[name="openidconnect_client_id"]')).toHaveValue('');
  await expect(page.locator('input[name="openidconnect_client_secret"]')).toHaveValue('');
  await expect(page.locator('input[name="openidconnect_max_age"]')).toHaveValue('14400');
  const signInTestButton = page.getByRole('button', { name: 'Test sign-in' });
  await expect(signInTestButton).toBeDisabled();

  await page.locator('input[name="openidconnect_provider_url"]')
    .fill(`${issuer}/.well-known/openid-configuration`);
  await expect(signInTestButton).toBeDisabled();
  await expect(page.locator('.oidc-signin-help')).toContainText(
    'Complete and save Exact issuer URL, Client ID and Client Secret'
  );
  const refusedTestResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/test/start'
  ));
  const refusedIncompleteTest = await page.evaluate(serverName => new Promise(resolve => {
    window.jQuery.ajax({
      type: 'POST',
      url: '/api/openidconnect/test/start',
      data: { provider: serverName },
    }).done(resolve).fail(xhr => resolve({ status: 'transport-error', message: xhr.responseText }));
  }), process.env.E2E_SERVER_NAME);
  expectPrivateResponseHeaders(await refusedTestResponsePromise);
  expect(refusedIncompleteTest.status).toBe('error');
  expect(refusedIncompleteTest.message).toContain(
    'Complete and save Exact issuer URL, Client ID and Client Secret'
  );
  await page.locator('input[name="openidconnect_client_id"]').fill(process.env.E2E_KEYCLOAK_CLIENT_ID);
  await expect(signInTestButton).toBeDisabled();
  await page.locator('input[name="openidconnect_client_secret"]').fill(process.env.E2E_KEYCLOAK_CLIENT_SECRET);
  // All three current fields are populated, but the sign-in test uses saved values only.
  await expect(signInTestButton).toBeDisabled();
  const discoveryResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/discovery/probe'
  ));
  await page.getByRole('button', { name: 'Test discovery' }).click();
  expectPrivateResponseHeaders(await discoveryResponsePromise);
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue(issuer);
  const dialog = page.getByRole('dialog');
  await expect(dialog.locator('.oidc-discovery-result .alert-success')).toBeVisible();
  await expect(dialog.locator('.oidc-discovery-results')).toBeVisible();
  await expect(dialog.locator('.oidc-discovery-results tbody tr')).toHaveCount(13);
  await expect(dialog.locator('.oidc-discovery-results tr[data-status="success"]').first()).toBeVisible();
  await expect(dialog.locator('.oidc-discovery-results tr[data-status="info"]').first()).toBeVisible();
  await expect(dialog).toContainText(issuer);
  await expect(dialog).toContainText('RS256');
  await expect(dialog).toContainText('client_secret_post');
  await dialog.getByRole('button', { name: '×' }).click();

  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
  expect(discoveryRequests).toBe(1);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue(issuer);
  await expect(page.getByRole('button', { name: 'Test sign-in' })).toBeEnabled();
}

async function editServer(page, change) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await change(page);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
}

async function testSignIn(page, { expectNoLocalAccount = false } = {}) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  const startResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/test/start'
  ));
  const callbackResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === callbackPath
  ));
  await page.getByRole('button', { name: 'Test sign-in' }).click();
  expectPrivateResponseHeaders(await startResponsePromise);

  let arrival = 'waiting';
  await expect.poll(async () => {
    if (keycloak.origin === new URL(page.url()).origin) {
      arrival = 'provider';
    } else if (await page.getByRole('heading', { name: 'Sign-in test succeeded' }).count()) {
      arrival = 'result';
    }
    return arrival;
  }).not.toBe('waiting');

  if (arrival === 'provider' && await page.getByRole('textbox', { name: 'Username' }).isVisible()) {
    await page.getByRole('textbox', { name: 'Username' }).fill(process.env.E2E_TEST_USERNAME);
    await page.getByRole('textbox', { name: 'Password' }).fill(process.env.E2E_TEST_PASSWORD);
    await page.getByRole('button', { name: 'Sign In' }).click();
  }

  await expect(page.getByRole('heading', { name: 'Sign-in test succeeded' })).toBeVisible();
  const callbackResponse = await callbackResponsePromise;
  expectStandaloneHtmlHeaders(callbackResponse);
  await expect(page.locator('.oidc-signin-result .hero-icon')).toHaveText('✓');
  await expect(page.locator('.oidc-signin-result .card')).toHaveCount(3);
  await expect(page.locator('.oidc-signin-results tr')).toHaveCount(6);
  await expect(page.locator('body')).toContainText('PKCE binding');
  await expect(page.locator('body')).toContainText(process.env.E2E_TEST_USERNAME);
  await expect(page.locator('body')).toContainText(
    'No login session, local account, subject binding or group membership was changed.'
  );
  await page.getByRole('link', { name: 'Return to authentication servers' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
  await expect(page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })).toBeVisible();

  if (expectNoLocalAccount) {
    await page.goto(`${origin}/ui/auth/user`);
    await expect(page.getByRole('row', { name: new RegExp(process.env.E2E_TEST_USERNAME) })).toHaveCount(0);
  }
}

async function providerLogin(page, { formPost = false } = {}) {
  let callback = null;
  let authorization = null;
  page.on('request', request => {
    const requestUrl = new URL(request.url());
    if (requestUrl.origin === keycloak.origin
      && requestUrl.pathname.endsWith('/protocol/openid-connect/auth')) {
      authorization = requestUrl;
    }
    if (requestUrl.pathname === callbackPath) {
      callback = {
        url: request.url(),
        method: request.method(),
        contentType: request.headers()['content-type'] || '',
        body: request.postData() || '',
      };
    }
  });
  await page.goto(origin);
  const before = (await page.context().cookies(origin)).find(cookie => cookie.name === 'PHPSESSID')?.value;
  await page.getByRole('link', { name: `Login using ${process.env.E2E_SERVER_NAME}` }).click();

  await expect.poll(() => authorization?.toString() || '').not.toBe('');
  expect(authorization.searchParams.get('response_type')).toBe('code');
  expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorization.searchParams.get('state')).toBeTruthy();
  expect(authorization.searchParams.get('nonce')).toBeTruthy();
  expect(authorization.searchParams.get('response_mode')).toBe(formPost ? 'form_post' : null);

  const providerUsername = page.getByRole('textbox', { name: 'Username' });
  let arrival = 'waiting';
  await expect.poll(async () => {
    if (await providerUsername.isVisible()) {
      arrival = 'provider';
    } else if (/\/ui\/core\/dashboard/.test(new URL(page.url()).pathname)) {
      arrival = 'dashboard';
    }
    return arrival;
  }).not.toBe('waiting');
  if (arrival === 'provider') {
    await providerUsername.fill(process.env.E2E_TEST_USERNAME);
    await page.getByRole('textbox', { name: 'Password' }).fill(process.env.E2E_TEST_PASSWORD);
    await page.getByRole('button', { name: 'Sign In' }).click();
  }

  await expect(page).toHaveURL(/\/ui\/core\/dashboard/);
  await expect(page.locator('body')).toContainText(`${process.env.E2E_TEST_USERNAME}@`);
  const after = (await page.context().cookies(origin)).find(cookie => cookie.name === 'PHPSESSID')?.value;
  expect(before).toBeTruthy();
  expect(after).toBeTruthy();
  expect(after).not.toBe(before);
  expect(callback).not.toBeNull();
  if (formPost) {
    expect(callback.method).toBe('POST');
    expect(callback.contentType).toContain('application/x-www-form-urlencoded');
    expect(callback.body).toContain('code=');
    expect(callback.body).toContain('state=');
  } else {
    expect(callback.method).toBe('GET');
  }
  return callback.url;
}

async function keycloakAdmin() {
  const api = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
  const tokenResponse = await api.post(`${keycloak.origin}/realms/master/protocol/openid-connect/token`, {
    form: {
      grant_type: 'password',
      client_id: 'admin-cli',
      username: process.env.E2E_KEYCLOAK_ADMIN_USERNAME,
      password: process.env.E2E_KEYCLOAK_ADMIN_PASSWORD,
    },
  });
  expect(tokenResponse.ok()).toBeTruthy();
  const token = (await tokenResponse.json()).access_token;
  const headers = { Authorization: `Bearer ${token}` };
  return { api, headers };
}

async function setFrontChannel(enabled) {
  const { api, headers } = await keycloakAdmin();
  const list = await api.get(`${keycloak.origin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients`, {
    headers,
    params: { clientId: process.env.E2E_KEYCLOAK_CLIENT_ID },
  });
  const clientId = (await list.json())[0].id;
  const response = await api.get(
    `${keycloak.origin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients/${clientId}`,
    { headers }
  );
  const client = await response.json();
  client.frontchannelLogout = enabled;
  const update = await api.put(
    `${keycloak.origin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients/${clientId}`,
    { headers, data: client }
  );
  expect(update.ok()).toBeTruthy();
  await api.dispose();
}

async function terminateProviderSession() {
  const { api, headers } = await keycloakAdmin();
  const list = await api.get(`${keycloak.origin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/users`, {
    headers,
    params: { username: process.env.E2E_TEST_USERNAME, exact: 'true' },
  });
  const userId = (await list.json())[0].id;
  const logout = await api.post(
    `${keycloak.origin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/users/${userId}/logout`,
    { headers }
  );
  expect(logout.ok()).toBeTruthy();
  await api.dispose();
}

async function removeLocalPrivileges() {
  const runId = process.env.E2E_TEST_USERNAME.replace(/^oidc-e2e-/, '');
  const helper = `/tmp/opnsense-oidc-e2e-cleanup-${runId}.php`;
  const remoteCommand = [
    'php', helper, process.env.E2E_TEST_USERNAME,
    process.env.E2E_APPLICATION_CODE, 'remove-privileges',
  ].map(value => `'${value.replaceAll("'", "'\\''")}'`).join(' ');
  await runCommand('ssh', ['-o', 'BatchMode=yes', process.env.E2E_OPNSENSE_SSH, remoteCommand]);
}

test('real OPNsense login, session binding and logout interoperability', async ({ browser }) => {
  const unauthenticated = await playwrightRequest.newContext(opnsenseRequestContextOptions());
  const builtInIcon = await unauthenticated.get(
    `${origin}/api/openidconnect/auth/builtinicon/keycloak`,
    { maxRedirects: 0 }
  );
  expect(builtInIcon.status()).toBe(200);
  expect(builtInIcon.headers()['content-type']).toContain('image/svg+xml');
  expect(builtInIcon.headers()['cache-control']).toContain('public');
  expect(builtInIcon.headers()['content-security-policy']).toContain('sandbox');
  expect(await builtInIcon.text()).toContain('<svg');
  const unknownBuiltInIcon = await unauthenticated.get(
    `${origin}/api/openidconnect/auth/builtinicon/unknown`,
    { maxRedirects: 0 }
  );
  expect(unknownBuiltInIcon.status()).toBe(404);
  expectPrivateResponseHeaders(unknownBuiltInIcon, { legacyNoCache: false });
  const missingIcon = await unauthenticated.get(
    `${origin}/api/openidconnect/auth/icon?provider=missing`,
    { maxRedirects: 0 }
  );
  expect(missingIcon.status()).toBe(404);
  expectPrivateResponseHeaders(missingIcon, { legacyNoCache: false });
  expect(missingIcon.headers()['content-type']).toContain('text/plain');
  expect(missingIcon.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  const deniedTest = await unauthenticated.post(`${origin}/api/openidconnect/test/start`, {
    form: { provider: process.env.E2E_SERVER_NAME },
    maxRedirects: 0,
  });
  expect(deniedTest.status()).toBe(302);
  expect(deniedTest.headers().location).toBe('/?url=/api/openidconnect/test/start');
  expectPrivateResponseHeaders(deniedTest);
  const admin = await browser.newContext();
  const adminPage = await admin.newPage();
  await localLogin(adminPage);
  await configureServer(adminPage);
  const invalidBackchannel = await unauthenticated.post(
    `${origin}/api/openidconnect/auth/backchannel/${process.env.E2E_APPLICATION_CODE}`,
    { form: { logout_token: '' }, maxRedirects: 0 }
  );
  expect(invalidBackchannel.status()).toBe(400);
  expectPrivateResponseHeaders(invalidBackchannel);
  expect(invalidBackchannel.headers()['content-type']).toContain('text/plain');
  expect(invalidBackchannel.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  await unauthenticated.dispose();
  await testSignIn(adminPage, { expectNoLocalAccount: true });
  await editServer(adminPage, async page => {
    await page.locator('input[name="openidconnect_enabled"]').check();
  });

  const localFallback = await browser.newContext();
  const localPage = await localFallback.newPage();
  await localLogin(localPage);
  await expect(localPage.locator('body')).toContainText(`${process.env.E2E_OPNSENSE_USERNAME}@`);
  await localFallback.close();

  const user = await browser.newContext();
  const userPage = await user.newPage();
  const callback = await providerLogin(userPage);

  const replay = await browser.newContext();
  const replayPage = await replay.newPage();
  const replayResponse = await replayPage.goto(callback);
  expect(replayResponse.status()).toBe(403);
  expectPrivateResponseHeaders(replayResponse);
  await expect(replayPage.locator('body')).toContainText('OpenID Connect could not complete this request');
  await replay.close();

  await adminPage.goto(`${origin}/ui/auth/user`);
  const accountRow = adminPage.getByRole('row', { name: new RegExp(process.env.E2E_TEST_USERNAME) });
  await expect(accountRow).toContainText('admins');

  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);
  const keycloakCookies = await user.cookies(keycloak.origin);
  expect(keycloakCookies.some(cookie => ['KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION'].includes(cookie.name))).toBeFalsy();

  await editServer(adminPage, async page => {
    await page.locator('input[name="openidconnect_create_users"]').uncheck();
  });
  await providerLogin(userPage);

  await setFrontChannel(false);
  await terminateProviderSession();
  await userPage.reload();
  await expect(userPage).toHaveTitle(/Login/);

  await setFrontChannel(true);
  await providerLogin(userPage);
  const providerLogoutPage = await user.newPage();
  let frontChannelResponse = null;
  providerLogoutPage.on('response', response => {
    if (new URL(response.url()).pathname
      === `/api/openidconnect/auth/frontchannel/${process.env.E2E_APPLICATION_CODE}`) {
      frontChannelResponse = response;
    }
  });
  await providerLogoutPage.goto(`${issuer}/account/`);
  await providerLogoutPage.getByTestId('options-toggle').click();
  await providerLogoutPage.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect.poll(() => frontChannelResponse).not.toBeNull();
  expectPrivateResponseHeaders(frontChannelResponse);
  expect(frontChannelResponse.headers()['content-security-policy']).toContain('frame-ancestors *');
  await userPage.reload();
  await expect(userPage).toHaveTitle(/Login/);
  await providerLogoutPage.close();

  await editServer(adminPage, async page => {
    await page.locator('select[name="openidconnect_token_auth"]').selectOption('client_secret_post');
    await page.locator('select[name="openidconnect_response_mode"]').selectOption('form_post');
  });
  await testSignIn(adminPage);
  await providerLogin(userPage, { formPost: true });
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);

  // Removing the established binding under the Approval policy must queue the
  // identity without granting a session, then require an explicit local-UID choice.
  await editServer(adminPage, async page => {
    await page.locator('select[name="openidconnect_bootstrap_mode"]').selectOption('approval');
    await expect(page.locator('input[name="openidconnect_create_users"]')
      .locator('xpath=ancestor::tr')).toBeHidden();
    await expect(page.locator('[name="openidconnect_subject_bindings"]')).toHaveCount(0);
    const managerButton = page.getByRole('button', { name: 'Manage identities' });
    await expect(managerButton).toBeVisible();
    const approvalListResponsePromise = page.waitForResponse(response => (
      new URL(response.url()).pathname === '/api/openidconnect/approval/list'
    ));
    await managerButton.click();
    expectPrivateResponseHeaders(await approvalListResponsePromise);
    const manager = page.getByRole('dialog', { name: 'Manage identities' });
    await expect(manager.getByRole('heading', { name: 'Bound identities' })).toBeVisible();

    // Manual creation is deliberately assisted, yet remains available for a
    // subject independently verified from a provider token.
    const manualSubject = `manual-${process.env.E2E_APPLICATION_CODE}`;
    const editedSubject = `${manualSubject}-edited`;
    await manager.getByRole('button', { name: 'Add identity binding' }).click();
    const editor = manager.locator('.oidc-binding-editor');
    await expect(editor).toContainText('exact sub');
    await expect(editor).toContainText('federation and subject-mode mappings');
    await editor.locator('input[type="text"]').fill(manualSubject);
    await editor.locator('select').selectOption({ label: process.env.E2E_TEST_USERNAME });
    await editor.getByRole('button', { name: 'Save binding' }).click();
    let manualRow = manager.locator('tbody tr').filter({ hasText: manualSubject });
    await expect(manualRow).toHaveCount(1);
    await manualRow.getByRole('button', { name: 'Edit' }).click();
    await manager.locator('.oidc-binding-editor input[type="text"]').fill(editedSubject);
    await manager.locator('.oidc-binding-editor').getByRole('button', { name: 'Save binding' }).click();
    manualRow = manager.locator('tbody tr').filter({ hasText: editedSubject });
    await expect(manualRow).toHaveCount(1);
    await manualRow.getByRole('button', { name: 'Remove' }).click();
    const removeDialog = page.getByRole('dialog', { name: 'Remove identity binding' });
    await removeDialog.getByRole('button', { name: 'OK' }).click();
    await expect(manager.locator('tbody tr').filter({ hasText: editedSubject })).toHaveCount(0);

    // The only remaining record is the identity established by the earlier
    // real login. Removing it makes the following sign-in enter the queue.
    const established = manager.locator('tbody tr');
    await expect(established).toHaveCount(1);
    await established.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('dialog', { name: 'Remove identity binding' })
      .getByRole('button', { name: 'OK' }).click();
    await expect(manager).toContainText('No identity is currently bound to a local account.');
    await manager.getByRole('button', { name: 'Done' }).click();
    await expect(manager).toBeHidden();
  });
  const approvalCallbackPromise = userPage.waitForResponse(response => (
    new URL(response.url()).pathname === callbackPath
  ));
  await userPage.goto(origin);
  await userPage.getByRole('link', { name: `Login using ${process.env.E2E_SERVER_NAME}` }).click();
  const providerUsername = userPage.getByRole('textbox', { name: 'Username' });
  const approvalRequired = userPage.getByRole('heading', { name: 'Administrator approval required' });
  await expect(providerUsername.or(approvalRequired))
    .toBeVisible();
  if (await providerUsername.isVisible()) {
    await providerUsername.fill(process.env.E2E_TEST_USERNAME);
    await userPage.getByRole('textbox', { name: 'Password' }).fill(process.env.E2E_TEST_PASSWORD);
    await userPage.getByRole('button', { name: 'Sign In' }).click();
  }
  await expect(approvalRequired).toBeVisible();
  const approvalCallbackResponse = await approvalCallbackPromise;
  expectStandaloneHtmlHeaders(approvalCallbackResponse);
  await expect(userPage.locator('.oidc-approval-required')).toContainText('No WebGUI session was created.');
  await expect(userPage.locator('.oidc-approval-required .reference code')).toHaveText(/^[a-f0-9]{20}$/);

  await adminPage.goto(`${origin}/system_authservers.php`);
  await adminPage.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await adminPage.getByRole('button', { name: 'Manage identities' }).click();
  const approvalDialog = adminPage.getByRole('dialog', { name: 'Manage identities' });
  await expect(approvalDialog.locator('.oidc-approval-card')).toHaveCount(1);
  await expect(approvalDialog).toContainText(issuer);
  await expect(approvalDialog).toContainText(process.env.E2E_TEST_USERNAME);
  await approvalDialog.locator('.oidc-approval-card select').selectOption({
    label: process.env.E2E_TEST_USERNAME,
  });
  await approvalDialog.getByRole('button', { name: 'Approve and bind' }).click();
  await expect(approvalDialog).toContainText('There are no pending identities for this provider.');
  await approvalDialog.getByRole('button', { name: 'Done' }).click();
  await expect(approvalDialog).toBeHidden();

  await providerLogin(userPage, { formPost: true });
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);

  // Authentication and identity admission are not enough on their own. Once
  // every local group privilege is removed, the callback must explain the
  // authorization denial without creating the session/logout loop core would
  // otherwise produce through index.php?logout.
  await removeLocalPrivileges();
  const deniedCallback = userPage.waitForResponse(response => (
    new URL(response.url()).pathname === callbackPath
  ));
  await userPage.goto(origin);
  await userPage.getByRole('link', { name: `Login using ${process.env.E2E_SERVER_NAME}` }).click();
  const deniedProviderUsername = userPage.getByRole('textbox', { name: 'Username' });
  const accessDenied = userPage.getByRole('heading', { name: 'WebGUI access denied' });
  await expect(deniedProviderUsername.or(accessDenied)).toBeVisible();
  if (await deniedProviderUsername.isVisible()) {
    await deniedProviderUsername.fill(process.env.E2E_TEST_USERNAME);
    await userPage.getByRole('textbox', { name: 'Password' }).fill(process.env.E2E_TEST_PASSWORD);
    await userPage.getByRole('button', { name: 'Sign In' }).click();
  }
  const deniedCallbackResponse = await deniedCallback;
  expect(deniedCallbackResponse.status()).toBe(403);
  expectStandaloneHtmlHeaders(deniedCallbackResponse);
  await expect(accessDenied).toBeVisible();
  await expect(userPage.locator('.oidc-access-denied')).toContainText(
    'The identity provider authenticated you successfully'
  );
  await expect(userPage.locator('.oidc-access-denied')).toContainText('No WebGUI session was created.');
  await userPage.getByRole('link', { name: 'Return to login' }).click();
  await expect(userPage).toHaveTitle(/Login/);

  await user.close();
  await admin.close();
});
