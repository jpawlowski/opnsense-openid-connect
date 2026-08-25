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
  'E2E_TEST_USERNAME', 'E2E_TEST_PASSWORD',
  'E2E_SERVER_NAME', 'E2E_APPLICATION_CODE', 'E2E_BACKCHANNEL_URL', 'E2E_ZAP_PROXY',
];
for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`${name} is required; start this test through tests/e2e/run.sh`);
  }
}

const opnsense = new URL(process.env.E2E_OPNSENSE_URL);
const keycloak = new URL(process.env.E2E_KEYCLOAK_URL);
const keycloakApiOrigin = process.env.E2E_PROVIDER_BROWSER_IP
  ? keycloak.origin.replace(keycloak.hostname, process.env.E2E_PROVIDER_BROWSER_IP)
  : keycloak.origin;
const origin = opnsense.origin;
const issuer = `${keycloak.origin}/realms/${process.env.E2E_KEYCLOAK_REALM}`;
const callbackPath = `/api/openidconnect/auth/callback/${process.env.E2E_APPLICATION_CODE}`;
const runCommand = promisify(execFile);
let keycloakClientSecret = '';

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

async function selectNative(locator, value) {
  // OPNsense's Bootstrap picker intentionally hides the authoritative select.
  await locator.selectOption(value, { force: true });
}

function selectPickerButton(locator) {
  return locator.locator(
    'xpath=ancestor::*[contains(concat(" ", normalize-space(@class), " "), " bootstrap-select ")][1]/button'
  );
}

async function configureServer(page) {
  let discoveryRequests = 0;
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/openidconnect/discovery/probe') {
      discoveryRequests += 1;
    }
  });
  await page.goto(`${origin}/system_authservers.php?act=new`);
  await selectNative(page.locator('select[name="type"]'), 'openidconnect');
  const newServerRevert = page.getByRole('button', { name: 'Revert changes' });
  await expect(newServerRevert).toBeVisible();
  await newServerRevert.click();
  await expect(page).toHaveURL(/system_authservers\.php\?act=new$/);
  await expect(page.locator('select[name="type"]')).toHaveValue('ldap');
  await expect(newServerRevert).toBeHidden();
  await selectNative(page.locator('select[name="type"]'), 'openidconnect');
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connection health' })).toBeDisabled();
  await expect(page.locator('[data-oidc-action-section="diagnostics"]')).toBeVisible();
  await expect(page.locator('[data-oidc-action-section="identities"]')).toBeVisible();
  await expect(page.locator('[data-oidc-action-section="provider-setup"]')).toBeHidden();
  expect(await page.evaluate(() => {
    const sections = document.querySelector('.oidc-action-sections');
    const save = document.querySelector('#submit');
    return Boolean(sections && save
      && (sections.compareDocumentPosition(save) & Node.DOCUMENT_POSITION_FOLLOWING));
  })).toBe(true);
  const diagnosticButtons = page.locator('[data-oidc-action-section="diagnostics"] button:visible');
  await expect(diagnosticButtons).toHaveCount(3);
  expect(new Set((await diagnosticButtons.evaluateAll(buttons => (
    buttons.map(button => Math.round(button.getBoundingClientRect().top))
  )))).size).toBe(1);
  await expect(page.locator('.oidc-endpoints')).toBeVisible({ timeout: 15_000 });
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
  const admissionPolicy = page.locator('select[name="openidconnect_bootstrap_mode"]');
  const requiredAuthentication = page.locator('select[name="openidconnect_required_authentication"]');
  const createUsers = page.locator('input[name="openidconnect_create_users"]');
  const buttonProviderLabel = page.locator('input[name="openidconnect_button_provider_label"]');
  const customButtonText = page.locator('input[name="openidconnect_button_custom_text"]');
  await expect(iconField).toHaveValue('/api/openidconnect/auth/builtinicon/general');
  await expect(buttonTextMode).toHaveValue('localized');
  await expect(buttonTextMode.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(customButtonText.locator('xpath=ancestor::tr')).toBeHidden();
  await selectNative(providerProfile, 'apple');
  await expect(issuerField).toHaveValue('https://appleid.apple.com');
  await expect(issuerField).toHaveAttribute('readonly', 'readonly');
  await expect(page.locator('select[name="openidconnect_token_auth"]')).toBeDisabled();
  await expect(selectPickerButton(page.locator('select[name="openidconnect_token_auth"]'))).toBeDisabled();
  await expect(page.locator('input[data-oidc-profile-shadow="openidconnect_token_auth"]'))
    .toHaveValue('client_secret_post');
  await expect(page.locator('select[name="openidconnect_claims_source"]')).toBeDisabled();
  await expect(page.locator('select[name="openidconnect_response_mode"]')).toBeDisabled();
  await expect(admissionPolicy).toHaveValue('approval');
  await expect(admissionPolicy.locator('option[value="username"]')).toBeDisabled();
  await expect(admissionPolicy.locator('option[value="verified_email"]')).toBeDisabled();
  await expect(createUsers).not.toBeChecked();
  await expect(createUsers).toBeDisabled();
  await expect(createUsers.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(page.locator('.oidc-public-admission-boundary')).toBeVisible();
  await expect(page.locator('.oidc-public-creation-boundary')).toBeVisible();
  await expect(requiredAuthentication.locator('option[value="multi-factor"]')).toBeDisabled();
  await expect(requiredAuthentication.locator('option[value="phishing-resistant"]')).toBeDisabled();
  await expect(requiredAuthentication).toBeDisabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeDisabled();
  await expect(page.locator('.oidc-authentication-requirement-boundary')).toBeVisible();
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
  await selectNative(providerProfile, 'orcid');
  await expect(issuerField).toHaveValue('https://orcid.org');
  await expect(page.locator('input[name="openidconnect_scopes"]')).toHaveValue('openid');
  await selectNative(providerProfile, 'auth0');
  await expect(requiredAuthentication).toBeEnabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeEnabled();
  await expect(requiredAuthentication.locator('option[value="multi-factor"]')).toBeEnabled();
  await expect(requiredAuthentication.locator('option[value="phishing-resistant"]')).toBeDisabled();
  await selectNative(requiredAuthentication, 'multi-factor');
  await expect(selectPickerButton(requiredAuthentication)).toContainText('Multi-factor authentication');
  await expect(page.locator('select[name="openidconnect_acr_request"]')).toHaveValue('acr_values');
  await expect(selectPickerButton(page.locator('select[name="openidconnect_acr_request"]')))
    .toContainText('acr_values authorization parameter');
  await selectNative(providerProfile, 'keycloak');
  await expect(requiredAuthentication).toBeEnabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeEnabled();
  await expect(requiredAuthentication.locator('option[value="multi-factor"]')).toBeEnabled();
  await expect(requiredAuthentication.locator('option[value="phishing-resistant"]')).toBeEnabled();
  await expect(page.locator('.oidc-authentication-requirement-boundary')).toContainText(
    'provider-side flow'
  );
  await expect(admissionPolicy.locator('option[value="username"]')).toBeEnabled();
  await selectNative(admissionPolicy, 'username');
  await expect(createUsers).toBeEnabled();
  await expect(createUsers.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(iconField).toHaveValue('/api/openidconnect/auth/builtinicon/keycloak');
  await expect(buttonTextMode).toBeEnabled();
  await expect(buttonTextMode).toHaveValue('localized');
  await expect(buttonTextMode.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeVisible();
  await buttonProviderLabel.fill('Company identity');
  await selectNative(buttonTextMode, 'custom');
  await expect(buttonProviderLabel.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(customButtonText.locator('xpath=ancestor::tr')).toBeVisible();
  await customButtonText.fill('Continue through Company identity');
  await selectNative(buttonTextMode, 'localized');
  await buttonProviderLabel.fill('');
  await expect(issuerField).not.toHaveAttribute('readonly');
  await expect(page.locator('select[name="openidconnect_token_auth"]')).toBeEnabled();
  await expect(issuerField).toHaveAttribute('placeholder', 'https://id.example.com/realms/opnsense');
  await selectNative(providerProfile, 'authentik');
  await expect(requiredAuthentication.locator('option[value="multi-factor"]')).toBeDisabled();
  await expect(requiredAuthentication.locator('option[value="phishing-resistant"]')).toBeDisabled();
  await expect(requiredAuthentication).toHaveValue('');
  await expect(requiredAuthentication).toBeDisabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeDisabled();
  await issuerField.fill(
    'https://auth.example.com/application/o/firewall/.well-known/openid-configuration'
  );
  await issuerField.blur();
  await expect(issuerField).toHaveValue('https://auth.example.com/application/o/firewall/');
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'entra');
  const microsoftAudience = page.locator('select[name="openidconnect_microsoft_audience"]');
  await expect(microsoftAudience.locator('xpath=ancestor::tr')).toBeVisible();
  await expect(microsoftAudience.locator('option')).toHaveCount(4);
  await expect(requiredAuthentication).toBeEnabled();
  await selectNative(requiredAuthentication, 'multi-factor');
  const microsoftContext = page.locator('select[name="openidconnect_entra_auth_context"]');
  await expect(microsoftContext.locator('xpath=ancestor::tr')).toBeVisible();
  await selectNative(microsoftAudience, 'common');
  await expect(requiredAuthentication).toHaveValue('');
  await expect(requiredAuthentication).toBeDisabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeDisabled();
  await expect(page.locator('.oidc-authentication-requirement-boundary'))
    .toContainText('one specific Entra tenant');
  await expect(microsoftContext.locator('xpath=ancestor::tr')).toBeHidden();
  await expect(page.locator('input[name="openidconnect_provider_url"]'))
    .toHaveValue('https://login.microsoftonline.com/common/v2.0');
  await expect(page.locator('input[name="openidconnect_provider_url"]'))
    .toHaveAttribute('readonly', 'readonly');
  await selectNative(microsoftAudience, 'tenant');
  await expect(requiredAuthentication).toBeEnabled();
  await expect(selectPickerButton(requiredAuthentication)).toBeEnabled();
  await selectNative(microsoftAudience, 'common');
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'keycloak');
  await expect(microsoftAudience.locator('xpath=ancestor::tr')).toBeHidden();
  const providerSetupSection = page.locator('[data-oidc-action-section="provider-setup"]');
  await expect(providerSetupSection).toBeVisible();
  const setupChannel = providerSetupSection.locator('select');
  expect(await setupChannel.evaluate(element => element.getBoundingClientRect().height)).toBeGreaterThan(35);
  const logoutNotifications = page.locator('select[name="openidconnect_logout_notifications"]');
  await expect(logoutNotifications).toHaveValue('backchannel');
  await selectNative(setupChannel, 'frontchannel');
  await expect(logoutNotifications).toHaveValue('frontchannel');
  await expect(selectPickerButton(logoutNotifications)).toContainText('Front-channel');
  await selectNative(setupChannel, 'backchannel');
  await expect(logoutNotifications).toHaveValue('backchannel');
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue('');
  await expect(page.locator('select[name="openidconnect_origin_policy"]')).toHaveValue('opnsense');
  await expect(page.locator('input[name="openidconnect_redirect_urls"]').locator('xpath=ancestor::tr')).toBeVisible();
  await selectNative(page.locator('select[name="openidconnect_origin_policy"]'), 'custom');
  await setFlatList(page, 'openidconnect_redirect_urls', [origin]);
  await page.locator('input[name="name"]').fill(process.env.E2E_SERVER_NAME);
  await page.locator('input[name="openidconnect_app_code"]').fill(process.env.E2E_APPLICATION_CODE);
  await expect(page.locator('.oidc-endpoints code').first()).toHaveText(`${origin}${callbackPath}`);
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'keycloak');
  await selectNative(page.locator('select[name="openidconnect_bootstrap_mode"]'), 'username');
  await page.locator('input[name="openidconnect_username_claim"]').fill('preferred_username');
  await selectNative(page.locator('select[name="openidconnect_claims_source"]'), 'userinfo');
  await selectNative(page.locator('select[name="openidconnect_response_mode"]'), 'query');
  await setFlatList(page, 'openidconnect_scopes', ['openid', 'email', 'profile']);
  await page.locator('input[name="openidconnect_create_users"]').check();
  await setGroupList(page, 'openidconnect_default_groups', ['admins']);
  await page.locator('input[name="openidconnect_logout_menu"]').check();
  await page.locator('input[name="openidconnect_logout_redirect"]').check();
  // The Keycloak preset deliberately recommends back-channel only. This broad
  // interoperability test opts into both so it can exercise the alternative
  // front-channel notification later without weakening the preset itself.
  await selectNative(logoutNotifications, 'both');
  await page.locator('input[name="openidconnect_debug"]').check();

  // The current unsaved form is sufficient to produce a no-secret provider import.
  const setupResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/setup/generate'
  ));
  const setupRequestPromise = page.waitForRequest(request => (
    new URL(request.url()).pathname === '/api/openidconnect/setup/generate'
  ));
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download provider setup' }).click();
  expectPrivateResponseHeaders(await setupResponsePromise);
  const setupRequest = await setupRequestPromise;
  expect(new URLSearchParams(setupRequest.postData() || '').get('preferred_origin')).toBe(origin);
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
  expect(generatedClient.rootUrl).toBe(origin);
  expect(generatedClient.baseUrl).toBe(
    `${origin}/api/openidconnect/auth/login?provider=${encodeURIComponent(process.env.E2E_SERVER_NAME)}`
  );
  expect(generatedClient.alwaysDisplayInConsole).toBe(true);
  expect(generatedClient.redirectUris.every(uri => uri.endsWith(callbackPath))).toBeTruthy();
  await importGeneratedKeycloakClient(setup);
  const keycloakSetupDialog = page.getByRole('dialog');
  const keycloakSetupResult = keycloakSetupDialog.locator(
    '.oidc-setup-result[data-provider="keycloak"]'
  );
  await expect(keycloakSetupResult.locator('.alert-success')).toBeVisible();
  await expect(keycloakSetupResult.locator('.oidc-setup-file code')).toHaveText(download.suggestedFilename());
  await expect(keycloakSetupResult.locator('.oidc-setup-progress-label')).toHaveText('Step 1 of 3');
  await expect(keycloakSetupResult.locator('[data-step="download"]')).toBeVisible();
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click({ force: true });
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
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click({ force: true });
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
  await keycloakSetupResult.getByRole('button', { name: 'Previous' }).click({ force: true });
  await expect(keycloakSetupResult.locator('[data-step="import"]')).toBeVisible();
  await keycloakSetupResult.getByRole('button', { name: 'Next' }).click({ force: true });
  await keycloakSetupResult.getByRole('button', { name: 'Done' }).click({ force: true });
  await expect(keycloakSetupDialog).toBeHidden();

  // Each supported profile receives concrete instructions for its own import UI.
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'authentik');
  const authentikDownloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download provider setup' }).click();
  const authentikDownload = await authentikDownloadPromise;
  expect(authentikDownload.suggestedFilename()).toMatch(/-authentik-blueprint\.yaml$/);
  const authentikBlueprint = await readFile(await authentikDownload.path(), 'utf8');
  expect(authentikBlueprint).toContain(
    `meta_launch_url: '${origin}/api/openidconnect/auth/login?provider=`
      + `${encodeURIComponent(process.env.E2E_SERVER_NAME)}'`
  );
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
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'keycloak');
  // Selecting a named profile deliberately restores its complete safe starting point.
  // Apply this test's less restrictive JIT policy only after the final profile choice.
  await selectNative(page.locator('select[name="openidconnect_bootstrap_mode"]'), 'username');
  await page.locator('input[name="openidconnect_create_users"]').check();
  await page.locator('input[name="openidconnect_logout_menu"]').check();
  await page.locator('input[name="openidconnect_logout_redirect"]').check();
  await selectNative(page.locator('select[name="openidconnect_logout_notifications"]'), 'both');

  // Saving a disabled draft needs no provider-side values and never contacts Discovery.
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
  expect(discoveryRequests).toBe(0);
  const serverRow = page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) });
  await expect(serverRow).toBeVisible();

  // Callback routing is unambiguous only while every OIDC application code is unique.
  await page.goto(`${origin}/system_authservers.php?act=new`);
  await selectNative(page.locator('select[name="type"]'), 'openidconnect');
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
  const signInTestHelp = page.locator('.oidc-signin-test-help');
  const revertChanges = page.getByRole('button', { name: 'Revert changes' });
  await expect(signInTestButton).toBeDisabled();
  await expect(signInTestHelp).toHaveAttribute('aria-label', /Complete and save.*Client ID/);
  await expect(revertChanges).toBeHidden();
  await signInTestHelp.hover();
  await expect(page.locator('.tooltip')).toBeVisible();
  await expect(page.locator('.tooltip')).toContainText('Complete and save');
  await signInTestHelp.focus();
  await expect(page.locator('.tooltip')).toContainText('Complete and save');

  await page.locator('input[name="openidconnect_provider_url"]')
    .fill(`${issuer}/.well-known/openid-configuration`);
  await expect(signInTestButton).toBeDisabled();
  await expect(signInTestButton).toHaveAttribute('title', /Complete and save.*Client ID/);
  await expect(signInTestHelp).toHaveAttribute('aria-label', /Complete and save.*Client ID/);
  await expect(revertChanges).toBeVisible();
  await revertChanges.click();
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue('');
  await expect(revertChanges).toBeHidden();
  await page.locator('input[name="openidconnect_provider_url"]')
    .fill(`${issuer}/.well-known/openid-configuration`);
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

  // Public Discovery and signing material can be checked before client registration is complete.
  const draftDiscoveryResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/discovery/probe'
  ));
  await page.getByRole('button', { name: 'Test discovery' }).click();
  expectPrivateResponseHeaders(await draftDiscoveryResponsePromise);
  let dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('Enter Client ID and Client Secret');
  await expect(dialog.locator('.oidc-probe-check[data-verification="not-tested"]').first()).toBeVisible();
  const diagnosticColumns = await dialog.locator('.oidc-probe-check-actions').evaluateAll(actions => actions.map(action => ({
    statusLeft: action.querySelector('.label')?.getBoundingClientRect().left,
    infoLeft: action.querySelector('.oidc-probe-info').getBoundingClientRect().left,
  })).filter(position => Number.isFinite(position.statusLeft)));
  expect(new Set(diagnosticColumns.map(position => Math.round(position.statusLeft))).size).toBe(1);
  expect(new Set(diagnosticColumns.map(position => Math.round(position.infoLeft))).size).toBe(1);
  await dialog.getByRole('button', { name: '×' }).click();

  await page.locator('input[name="openidconnect_client_id"]').fill(process.env.E2E_KEYCLOAK_CLIENT_ID);
  await expect(signInTestButton).toBeDisabled();
  expect(keycloakClientSecret).not.toBe('');
  await page.locator('input[name="openidconnect_client_secret"]').fill(keycloakClientSecret);
  // All three current fields are populated, but the sign-in test uses saved values only.
  await expect(signInTestButton).toBeDisabled();

  const healthButton = page.getByRole('button', { name: 'Connection health' });
  await expect(healthButton).toBeEnabled();
  const healthRequestPromise = page.waitForRequest(request => (
    new URL(request.url()).pathname === '/api/openidconnect/health/probe'
  ));
  const healthResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/health/probe'
  ));
  await healthButton.focus();
  await expect(healthButton).toBeFocused();
  await page.keyboard.press('Enter');
  const healthRequest = await healthRequestPromise;
  expect(healthRequest.method()).toBe('POST');
  const healthForm = new URLSearchParams(healthRequest.postData() || '');
  expect(healthForm.get('openidconnect_provider_url')).toContain(issuer);
  expect(healthForm.get('openidconnect_client_id')).toBe(process.env.E2E_KEYCLOAK_CLIENT_ID);
  const healthResponse = await healthResponsePromise;
  expectPrivateResponseHeaders(healthResponse);
  const healthAnswer = await healthResponse.json();
  expect(healthAnswer.status).toBe('ok');
  expect(JSON.stringify(healthAnswer)).not.toContain(keycloakClientSecret);
  dialog = page.getByRole('dialog');
  await expect(dialog.locator('.oidc-discovery-results')).toBeVisible();
  await expect(dialog).toContainText('Client configuration');
  await expect(dialog).toContainText('WebGUI transport');
  await expect(dialog).toContainText('Client credentials');
  await expect(dialog.locator('.oidc-probe-check[data-verification="live"]').first()).toBeVisible();
  await expect(dialog.locator('.oidc-probe-check[data-verification="metadata"]').first()).toBeVisible();
  await expect(dialog.locator('.oidc-probe-check[data-verification="configuration"]').first()).toBeVisible();
  await expect(dialog.locator('.oidc-probe-check[data-verification="not-tested"]').first()).toBeVisible();
  await dialog.getByRole('button', { name: '×' }).click();

  const discoveryResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/discovery/probe'
  ));
  await page.getByRole('button', { name: 'Test discovery' }).click();
  expectPrivateResponseHeaders(await discoveryResponsePromise);
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue(issuer);
  dialog = page.getByRole('dialog');
  await expect(dialog.locator('.oidc-probe-summary .label-success')).toBeVisible();
  await expect(dialog.locator('.oidc-discovery-results')).toBeVisible();
  await expect(dialog.locator('.oidc-probe-check')).toHaveCount(17);
  await expect(dialog.locator('.oidc-check-flow')).toHaveCount(17);
  await expect(dialog.locator('.oidc-check-flow[aria-label]')).toHaveCount(17);
  await expect(dialog.locator('.oidc-check-actor')).not.toHaveCount(0);
  await expect(dialog.locator('.oidc-check-actor i[aria-hidden="true"]')).not.toHaveCount(0);
  await expect(dialog.locator('th').filter({ hasText: /(?:OPNsense|Browser|IdP)/ }))
    .toHaveCount(0);
  const resultSemantics = await dialog.locator('.oidc-probe-check').evaluateAll(rows => (
    Object.fromEntries(rows.map(row => [
      row.querySelector('h4').textContent.trim(),
      [row.querySelector('.oidc-check-flow').dataset.actors, row.dataset.verification],
    ]))
  ));
  expect(resultSemantics).toEqual({
    Discovery: ['opnsense,idp', 'live'],
    'Provider profile': ['opnsense', 'configuration'],
    'Authorization endpoint': ['browser,idp', 'not-tested'],
    'Token endpoint': ['opnsense,idp', 'not-tested'],
    'UserInfo endpoint': ['opnsense,idp', 'not-tested'],
    'ID Token signatures': ['opnsense', 'metadata'],
    'Client authentication': ['opnsense', 'metadata'],
    PKCE: ['opnsense', 'metadata'],
    'DPoP sender constraint': ['opnsense', 'metadata'],
    'Authorization response mode': ['idp,browser,opnsense', 'metadata'],
    'Selected authentication method': ['opnsense', 'metadata'],
    'Authorization response issuer': ['idp,browser,opnsense', 'metadata'],
    'Provider sign-out': ['browser,idp', 'not-tested'],
    'Token revocation': ['opnsense,idp', 'not-tested'],
    'Signing keys': ['opnsense,idp', 'live'],
    'JWT-secured authorization request': ['opnsense', 'configuration'],
    'PAR endpoint': ['opnsense,idp', 'live'],
  });
  await expect(dialog.locator('.oidc-probe-check[data-status="success"]').first()).toBeVisible();
  await expect(dialog.locator('.oidc-probe-check[data-status="info"]')).toHaveCount(0);
  const dpopDiscoveryRow = dialog.locator('.oidc-probe-check')
    .filter({ hasText: 'DPoP sender constraint' });
  await expect(dpopDiscoveryRow).toHaveCount(1);
  await expect(dpopDiscoveryRow).toHaveAttribute('data-status', 'success');
  await expect(dpopDiscoveryRow).toContainText('ES256');
  await expect(dialog).toContainText(issuer);
  await expect(dialog).toContainText('RS256');
  await expect(dialog).toContainText('client_secret_post');
  await expect(dialog.getByText(/PAR will be used automatically/)).toBeHidden();
  const authorizationRow = dialog.locator('.oidc-probe-check').filter({ hasText: 'Authorization endpoint' });
  await expect(authorizationRow.locator('.oidc-probe-check-details')).toBeHidden();
  await authorizationRow.locator('.oidc-probe-info').click();
  await expect(authorizationRow.locator('.oidc-probe-check-details')).toContainText('Live Discovery document');
  await expect(authorizationRow.locator('.oidc-probe-check-details')).toContainText(
    'The endpoint was not called because it needs an interactive browser sign-in'
  );
  await dialog.getByRole('button', { name: '×' }).click();

  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
  expect(discoveryRequests).toBe(2);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await expect(page.locator('input[name="openidconnect_provider_url"]')).toHaveValue(issuer);
  await expect(page.locator('select[name="openidconnect_bootstrap_mode"]')).toHaveValue('username');
  await expect(page.locator('input[name="openidconnect_create_users"]')).toBeChecked();
  await expect(page.locator('input[name="openidconnect_logout_menu"]')).toBeChecked();
  await expect(page.locator('input[name="openidconnect_logout_redirect"]')).toBeChecked();
  await expect(page.locator('select[name="openidconnect_logout_notifications"]')).toHaveValue('both');
  const savedSignInTest = page.getByRole('button', { name: 'Test sign-in' });
  const savedSignInHelp = page.locator('.oidc-signin-test-help');
  const savedRevertChanges = page.getByRole('button', { name: 'Revert changes' });
  await expect(savedSignInTest).toBeEnabled();
  await expect(savedRevertChanges).toBeHidden();

  const maxAge = page.locator('input[name="openidconnect_max_age"]');
  const savedMaxAge = await maxAge.inputValue();
  await maxAge.fill('60');
  await expect(savedSignInTest).toBeDisabled();
  await expect(savedSignInTest).toHaveAttribute('title', /Save or revert your changes/);
  await expect(savedSignInHelp).toHaveAttribute('aria-label', /Save or revert your changes/);
  await expect(savedRevertChanges).toBeVisible();
  await savedSignInHelp.hover();
  await expect(page.locator('.tooltip')).toContainText('Save or revert your changes');
  await maxAge.fill(savedMaxAge);
  await expect(savedSignInTest).toBeEnabled();
  await expect(savedRevertChanges).toBeHidden();

  const selectAccount = page.locator('input[name="openidconnect_select_account"]');
  await selectAccount.check();
  await expect(savedSignInTest).toBeDisabled();
  await selectAccount.uncheck();
  await expect(savedSignInTest).toBeEnabled();

  await setFlatList(page, 'openidconnect_scopes', ['openid', 'email']);
  await expect(savedSignInTest).toBeDisabled();
  await setFlatList(page, 'openidconnect_scopes', ['openid', 'email', 'profile']);
  await expect(savedSignInTest).toBeEnabled();

  const secretField = page.locator('input[name="openidconnect_client_secret"]');
  await secretField.fill(`${keycloakClientSecret}-changed`);
  await expect(savedSignInTest).toBeDisabled();
  await secretField.fill(keycloakClientSecret);
  await expect(savedSignInTest).toBeEnabled();

  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), 'authentik');
  await expect(savedSignInTest).toBeDisabled();
  await page.reload();
  await expect(page.getByRole('button', { name: 'Test sign-in' })).toBeEnabled();

  await page.locator('input[name="openidconnect_provider_url"]').fill('not-an-issuer');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.locator('body')).toContainText('Exact issuer URL');
  await expect(page.getByRole('button', { name: 'Test sign-in' })).toBeDisabled();
}

async function editServer(page, change) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await change(page);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
}

async function testSignIn(page, {
  expectNoLocalAccount = false,
  expectedEmailVerification = 'true',
} = {}) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  const serverEditUrl = page.url();
  const startResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/test/start'
  ));
  const callbackResponsePromise = page.waitForResponse(response => (
    new URL(response.url()).pathname === callbackPath
  ));
  await page.getByRole('button', { name: 'Test sign-in' }).click();
  const startResponse = await startResponsePromise;
  expectPrivateResponseHeaders(startResponse);

  let arrival = 'waiting';
  await expect.poll(async () => {
    if (keycloak.origin === new URL(page.url()).origin) {
      arrival = 'provider';
    } else if (await page.getByRole('heading', { name: 'Sign-in test succeeded' }).count()) {
      arrival = 'result';
    } else if (await page.getByRole('dialog').filter({ hasText: 'Test sign-in' }).count()) {
      arrival = 'error';
    }
    return arrival;
  }).not.toBe('waiting');
  if (arrival === 'error') {
    throw new Error(`Test sign-in start failed: ${await page.getByRole('dialog').innerText()}`);
  }

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
  await expect(page.locator('.oidc-signin-results tr')).toHaveCount(7);
  await expect(page.getByRole('row', { name: /E-mail verification claim/ }))
    .toContainText(expectedEmailVerification);
  await expect(page.locator('body')).toContainText('PKCE binding');
  await expect(page.locator('body')).toContainText(process.env.E2E_TEST_USERNAME);
  await expect(page.locator('body')).toContainText(
    'No login session, local account, subject binding or group membership was changed.'
  );
  await page.getByRole('link', { name: 'Return to authentication servers' }).click();
  await expect(page).toHaveURL(serverEditUrl);
  await expect(page.locator('input[name="name"]')).toHaveValue(process.env.E2E_SERVER_NAME);

  if (expectNoLocalAccount) {
    await page.goto(`${origin}/ui/auth/user`);
    await expect(page.getByRole('row', { name: new RegExp(process.env.E2E_TEST_USERNAME) })).toHaveCount(0);
  }
}

async function providerLogin(page, { responseMode = 'query' } = {}) {
  const formPost = responseMode.startsWith('form_post');
  const jarm = responseMode.endsWith('.jwt');
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
  const requestUri = authorization.searchParams.get('request_uri');
  if (requestUri) {
    expect(authorization.searchParams.get('client_id')).toBe(process.env.E2E_KEYCLOAK_CLIENT_ID);
    expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    expect(authorization.searchParams.get('response_type')).toBeNull();
    expect(authorization.searchParams.get('state')).toBeNull();
    expect(authorization.searchParams.get('nonce')).toBeNull();
  } else {
    expect(authorization.searchParams.get('response_type')).toBe('code');
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorization.searchParams.get('state')).toBeTruthy();
    expect(authorization.searchParams.get('nonce')).toBeTruthy();
    expect(authorization.searchParams.get('response_mode')).toBe(responseMode === 'query' ? null : responseMode);
  }

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
    expect(callback.body).toContain(jarm ? 'response=' : 'code=');
    expect(callback.body.includes('state=')).toBe(!jarm);
  } else {
    expect(callback.method).toBe('GET');
    const callbackUrl = new URL(callback.url);
    expect(callbackUrl.searchParams.has('response')).toBe(jarm);
    expect(callbackUrl.searchParams.has('code')).toBe(!jarm);
    expect(callbackUrl.searchParams.has('state')).toBe(!jarm);
  }
  return callback.url;
}

async function keycloakAdmin() {
  const extraHTTPHeaders = process.env.E2E_PROVIDER_BROWSER_IP ? { Host: keycloak.host } : {};
  const proxy = process.env.E2E_PROVIDER_BROWSER_IP
    ? { server: process.env.E2E_ZAP_PROXY, bypass: process.env.E2E_PROVIDER_BROWSER_IP }
    : undefined;
  const api = await playwrightRequest.newContext({ ignoreHTTPSErrors: true, extraHTTPHeaders, proxy });
  const tokenResponse = await api.post(`${keycloakApiOrigin}/realms/master/protocol/openid-connect/token`, {
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

async function importGeneratedKeycloakClient(setup) {
  const { api, headers } = await keycloakAdmin();
  const realmApi = `${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}`;
  const imported = await api.post(`${realmApi}/partialImport`, { headers, data: setup });
  expect(imported.ok()).toBeTruthy();
  expect((await imported.json()).added).toBeGreaterThanOrEqual(1);

  const list = await api.get(`${realmApi}/clients`, {
    headers,
    params: { clientId: process.env.E2E_KEYCLOAK_CLIENT_ID },
  });
  expect(list.ok()).toBeTruthy();
  const clients = await list.json();
  expect(clients).toHaveLength(1);
  const clientId = clients[0].id;
  const representation = await api.get(`${realmApi}/clients/${clientId}`, { headers });
  expect(representation.ok()).toBeTruthy();
  const client = await representation.json();
  expect(client.redirectUris).toEqual(setup.clients[0].redirectUris);
  expect(client.webOrigins).toEqual(setup.clients[0].webOrigins);
  expect(client.rootUrl).toBe(setup.clients[0].rootUrl);
  expect(client.baseUrl).toBe(setup.clients[0].baseUrl);
  expect(client.alwaysDisplayInConsole).toBe(true);
  expect(client.defaultClientScopes).toEqual(setup.clients[0].defaultClientScopes);
  expect([...client.optionalClientScopes].sort()).toEqual([...setup.clients[0].optionalClientScopes].sort());
  expect(client.attributes['dpop.bound.access.tokens']).toBe('true');
  expect(client.attributes['post.logout.redirect.uris']).toBe(`${origin}/`);
  expect(client.attributes['logout.confirmation.enabled']).toBe('false');

  // The generated public URL is correct for a real deployment. The disposable
  // lab routes provider-initiated HTTPS through its short-lived trusted proxy.
  client.attributes['backchannel.logout.url'] = `${process.env.E2E_BACKCHANNEL_URL}`
    + `/api/openidconnect/auth/backchannel/${process.env.E2E_APPLICATION_CODE}`;
  const update = await api.put(`${realmApi}/clients/${clientId}`, { headers, data: client });
  expect(update.ok()).toBeTruthy();

  const secret = await api.get(`${realmApi}/clients/${clientId}/client-secret`, { headers });
  expect(secret.ok()).toBeTruthy();
  keycloakClientSecret = (await secret.json()).value;
  expect(keycloakClientSecret).toBeTruthy();
  await api.dispose();
}

async function setKeycloakEmailVerification(mode) {
  const { api, headers } = await keycloakAdmin();
  const realmApi = `${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}`;
  const list = await api.get(`${realmApi}/users`, {
    headers,
    params: { username: process.env.E2E_TEST_USERNAME, exact: 'true' },
  });
  expect(list.ok()).toBeTruthy();
  const userId = (await list.json())[0].id;
  const response = await api.get(`${realmApi}/users/${userId}`, { headers });
  expect(response.ok()).toBeTruthy();
  const user = await response.json();
  if (mode === 'missing') {
    user.email = null;
    user.emailVerified = false;
  } else {
    user.email = `${process.env.E2E_TEST_USERNAME}@example.com`;
    user.emailVerified = mode === 'true';
  }
  const update = await api.put(`${realmApi}/users/${userId}`, { headers, data: user });
  expect(update.ok()).toBeTruthy();
  await api.dispose();
}

async function setFrontChannel(enabled) {
  const { api, headers } = await keycloakAdmin();
  const list = await api.get(`${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients`, {
    headers,
    params: { clientId: process.env.E2E_KEYCLOAK_CLIENT_ID },
  });
  const clientId = (await list.json())[0].id;
  const response = await api.get(
    `${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients/${clientId}`,
    { headers }
  );
  const client = await response.json();
  client.frontchannelLogout = enabled;
  const update = await api.put(
    `${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/clients/${clientId}`,
    { headers, data: client }
  );
  expect(update.ok()).toBeTruthy();
  await api.dispose();
}

async function terminateProviderSession() {
  const { api, headers } = await keycloakAdmin();
  const list = await api.get(`${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/users`, {
    headers,
    params: { username: process.env.E2E_TEST_USERNAME, exact: 'true' },
  });
  const userId = (await list.json())[0].id;
  const logout = await api.post(
    `${keycloakApiOrigin}/admin/realms/${process.env.E2E_KEYCLOAK_REALM}/users/${userId}/logout`,
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
  const sshArguments = process.env.E2E_OPNSENSE_SSH_CONFIG
    ? ['-F', process.env.E2E_OPNSENSE_SSH_CONFIG, 'opnsense-e2e', remoteCommand]
    : ['-o', 'BatchMode=yes', process.env.E2E_OPNSENSE_SSH, remoteCommand];
  await runCommand('ssh', sshArguments);
}

test('real OPNsense login, session binding and logout interoperability', async ({ browser }) => {
  const unauthenticated = await playwrightRequest.newContext(opnsenseRequestContextOptions());
  const formScript = await unauthenticated.get(
    `${origin}/api/openidconnect/auth/formscript`,
    { maxRedirects: 0 }
  );
  expect(formScript.status()).toBe(200);
  expect(formScript.headers()['content-type']).toContain('javascript');
  expect(formScript.headers()['cache-control']).toContain('public');
  expect(formScript.headers()['x-content-type-options']).toBe('nosniff');
  expect(await formScript.text()).toContain('window.__oidcForm');
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
  const deniedHealth = await unauthenticated.post(`${origin}/api/openidconnect/health/probe`, {
    form: {
      openidconnect_provider_url: issuer,
      openidconnect_client_id: process.env.E2E_KEYCLOAK_CLIENT_ID,
      openidconnect_client_secret: 'not-a-real-secret',
    },
    maxRedirects: 0,
  });
  expect(deniedHealth.status()).toBe(302);
  expect(deniedHealth.headers().location).toBe('/?url=/api/openidconnect/health/probe');
  expectPrivateResponseHeaders(deniedHealth);
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
  await setKeycloakEmailVerification('false');
  await testSignIn(adminPage, {
    expectNoLocalAccount: true,
    expectedEmailVerification: 'false',
  });
  await setKeycloakEmailVerification('missing');
  await testSignIn(adminPage, {
    expectNoLocalAccount: true,
    expectedEmailVerification: 'false',
  });
  await setKeycloakEmailVerification('true');
  await editServer(adminPage, async page => {
    await page.locator('input[name="openidconnect_enabled"]').check();
  });

  const localFallback = await browser.newContext();
  const localPage = await localFallback.newPage();
  await localLogin(localPage);
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
  await expect(accountRow).toContainText('admins', { timeout: 15_000 });

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
    await selectNative(page.locator('select[name="openidconnect_response_mode"]'), 'query.jwt');
  });
  await testSignIn(adminPage);
  await providerLogin(userPage, { responseMode: 'query.jwt' });
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);

  await editServer(adminPage, async page => {
    await selectNative(page.locator('select[name="openidconnect_response_mode"]'), 'form_post.jwt');
  });
  await testSignIn(adminPage);
  await providerLogin(userPage, { responseMode: 'form_post.jwt' });
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);

  await editServer(adminPage, async page => {
    await selectNative(page.locator('select[name="openidconnect_token_auth"]'), 'client_secret_post');
    await selectNative(page.locator('select[name="openidconnect_response_mode"]'), 'form_post');
  });
  await testSignIn(adminPage);
  await providerLogin(userPage, { responseMode: 'form_post' });
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);

  // Removing the established binding under the Approval policy must queue the
  // identity without granting a session, then require an explicit local-UID choice.
  await editServer(adminPage, async page => {
    await selectNative(page.locator('select[name="openidconnect_bootstrap_mode"]'), 'approval');
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
    const manager = page.getByRole('dialog');
    await expect(manager.getByRole('heading', { name: 'Bound identities' })).toBeVisible();

    // Manual creation is deliberately assisted, yet remains available for a
    // subject independently verified from a provider token.
    const manualSubject = `manual-${process.env.E2E_APPLICATION_CODE}`;
    const editedSubject = `${manualSubject}-edited`;
    const inlineUsername = `${process.env.E2E_TEST_USERNAME}-inline`;
    await manager.getByRole('button', { name: 'Add identity binding' }).click();
    await expect(manager).toHaveAccessibleName('Add an identity');
    const editor = manager.locator('.oidc-binding-editor');
    await expect(editor).toContainText('exact sub');
    await expect(editor).toContainText('federation and subject-mode mappings');
    await editor.getByRole('textbox', { name: 'Paste the exact sub claim' }).fill(manualSubject);
    await expect(editor.locator('select option', { hasText: process.env.E2E_TEST_USERNAME }))
      .toHaveCount(0);
    await editor.locator('select').selectOption({ label: 'Create a new local account…' });
    await editor.locator('.oidc-account-creation input').fill(inlineUsername);
    await editor.getByRole('button', { name: 'Save binding' }).click();
    await expect(manager).toHaveAccessibleName('Manage identities');
    let manualRow = manager.locator('tbody tr').filter({ hasText: manualSubject });
    await expect(manualRow).toHaveCount(1);
    await expect(manualRow).toContainText(inlineUsername);
    await manualRow.getByRole('button', { name: 'Edit' }).click();
    await expect(manager).toHaveAccessibleName('Edit identity binding');
    await manager.locator('.oidc-binding-editor')
      .getByRole('textbox', { name: 'Paste the exact sub claim' }).fill(editedSubject);
    await expect(manager.locator('.oidc-binding-editor select')).toHaveValue(/\d+/);
    await manager.locator('.oidc-binding-editor').getByRole('button', { name: 'Save binding' }).click();
    await expect(manager).toHaveAccessibleName('Manage identities');
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
  const genericRefusal = userPage.getByText('There is no local account for this user, or it may not be used.');
  await expect(providerUsername.or(genericRefusal))
    .toBeVisible();
  if (await providerUsername.isVisible()) {
    await providerUsername.fill(process.env.E2E_TEST_USERNAME);
    await userPage.getByRole('textbox', { name: 'Password' }).fill(process.env.E2E_TEST_PASSWORD);
    await userPage.getByRole('button', { name: 'Sign In' }).click();
  }
  await expect(genericRefusal).toBeVisible();
  const approvalCallbackResponse = await approvalCallbackPromise;
  expect(approvalCallbackResponse.status()).toBe(403);
  await expect(userPage.locator('body')).not.toContainText('Administrator approval required');
  await expect(userPage.locator('body')).not.toContainText(/Approval request|[a-f0-9]{20}/);

  await adminPage.goto(`${origin}/system_authservers.php`);
  await adminPage.getByRole('row', { name: new RegExp(process.env.E2E_SERVER_NAME) })
    .getByRole('link', { name: 'Edit' }).click();
  await adminPage.getByRole('button', { name: 'Manage identities' }).click();
  const approvalDialog = adminPage.getByRole('dialog');
  await approvalDialog.getByRole('button', { name: /Pending administrator approvals/ }).click();
  await expect(approvalDialog).toHaveAccessibleName('Pending administrator approvals');
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

  await providerLogin(userPage, { responseMode: 'form_post' });
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
