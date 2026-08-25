/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { expect, request as playwrightRequest, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

for (const name of [
  'E2E_PROVIDER_STATE_FILE', 'E2E_OPNSENSE_URL', 'E2E_OPNSENSE_USERNAME', 'E2E_OPNSENSE_PASSWORD',
]) {
  if (!process.env[name]) throw new Error(`${name} is required; start through tests/e2e/run.sh`);
}

const state = JSON.parse(await readFile(process.env.E2E_PROVIDER_STATE_FILE, 'utf8'));
const origin = new URL(process.env.E2E_OPNSENSE_URL).origin;
const providerOrigin = new URL(state.url).origin;
const providerApiOrigin = process.env.E2E_PROVIDER_BROWSER_IP
  ? providerOrigin.replace(new URL(providerOrigin).hostname, process.env.E2E_PROVIDER_BROWSER_IP)
  : providerOrigin;
const callbackPath = `/api/openidconnect/auth/callback/${state.application_code}`;

async function localLogin(page) {
  await page.goto(origin);
  await page.getByRole('textbox', { name: 'Username:' }).fill(process.env.E2E_OPNSENSE_USERNAME);
  await page.getByRole('textbox', { name: 'Password:' }).fill(process.env.E2E_OPNSENSE_PASSWORD);
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page).toHaveURL(/\/ui\/core\/dashboard/);
}

async function setFlatList(page, name, values) {
  await page.locator(`input[name="${name}"]`).evaluate((element, entries) => {
    element.value = entries.join(',');
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
  if (await picker.count()) await picker.selectOption(values, { force: true });
}

async function selectNative(locator, value) {
  // OPNsense's Bootstrap picker intentionally hides the authoritative select.
  await locator.selectOption(value, { force: true });
}

async function apiContext(extraHTTPHeaders = {}) {
  const localHostHeader = process.env.E2E_PROVIDER_BROWSER_IP ? { Host: state.authority } : {};
  return playwrightRequest.newContext({
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { ...localHostHeader, ...extraHTTPHeaders },
  });
}

async function checkedJson(response, description) {
  if (!response.ok()) throw new Error(`${description} failed (${response.status()}): ${await response.text()}`);
  return response.json();
}

async function checked(response, description) {
  if (!response.ok()) throw new Error(`${description} failed (${response.status()}): ${await response.text()}`);
}

async function provisionAuthentik(blueprintPath) {
  const api = await apiContext({ Authorization: `Bearer ${state.admin_token}` });
  const user = await checkedJson(await api.post(`${providerApiOrigin}/api/v3/core/users/`, {
    data: {
      username: state.username, name: 'OIDC E2E', email: `${state.username}@example.com`,
      attributes: { email_verified: true }, is_active: true, type: 'internal', path: 'users',
    },
  }), 'authentik user creation');
  state.user_pk = user.pk;
  await checked(await api.post(`${providerApiOrigin}/api/v3/core/users/${user.pk}/set_password/`, {
    data: { password: state.password },
  }), 'authentik password creation');
  const blueprint = await readFile(blueprintPath);
  const imported = await api.post(`${providerApiOrigin}/api/v3/managed/blueprints/import/`, {
    multipart: { file: { name: 'opnsense-authentik-blueprint.yaml', mimeType: 'application/yaml', buffer: blueprint } },
  });
  const importResult = await checkedJson(imported, 'authentik Blueprint import');
  if (!importResult.success) {
    throw new Error(`authentik Blueprint validation failed: ${JSON.stringify(importResult.logs)}`);
  }
  const list = await checkedJson(await api.get(`${providerApiOrigin}/api/v3/providers/oauth2/`, {
    params: { search: `opnsense-${state.application_code}` },
  }), 'authentik provider lookup');
  const provider = list.results.find(candidate => candidate.name.includes(state.application_code));
  expect(provider).toBeTruthy();
  state.client_id = provider.client_id;
  state.client_secret = provider.client_secret;
  state.issuer = `${providerOrigin}/application/o/opnsense-${state.application_code}/`;
  await api.dispose();
}

async function provisionPocketId() {
  const headers = { 'X-API-KEY': state.admin_token };
  const api = await apiContext(headers);
  const group = await checkedJson(await api.post(`${providerApiOrigin}/api/user-groups`, {
    data: { name: `e2e-${state.run_id}`, friendlyName: 'OPNsense E2E' },
  }), 'Pocket ID group creation');
  const client = await checkedJson(await api.post(`${providerApiOrigin}/api/oidc/clients`, {
    data: {
      id: state.client_id, name: state.server_name, description: 'Disposable OPNsense browser E2E',
      callbackURLs: [`${origin}${callbackPath}`], logoutCallbackURLs: [`${origin}/`],
      isPublic: false, pkceEnabled: true, requiresReauthentication: false,
      requiresPushedAuthorizationRequests: false, skipConsent: true, credentials: {},
      isGroupRestricted: true, accessTokenDurationMinutes: 5, refreshTokenDurationMinutes: 60,
    },
  }), 'Pocket ID client creation');
  await checkedJson(await api.post(`${providerApiOrigin}/api/oidc/clients/${client.id}/secrets`, {
    data: { secret: state.client_secret },
  }), 'Pocket ID client secret creation');
  await checkedJson(await api.put(`${providerApiOrigin}/api/oidc/clients/${client.id}/allowed-user-groups`, {
    data: { userGroupIds: [group.id] },
  }), 'Pocket ID group restriction');
  const signup = await checkedJson(await api.post(`${providerApiOrigin}/api/signup-tokens`, {
    data: { ttl: '1h', usageLimit: 1, userGroupIds: [group.id] },
  }), 'Pocket ID signup token creation');
  state.signup_token = signup.token;
  await api.dispose();
}

async function provisionEntra() {
  const api = await apiContext();
  const user = await checkedJson(await api.post(`${providerApiOrigin}/admin/api/users`, {
    data: {
      userPrincipalName: state.username,
      displayName: 'OIDC E2E',
      givenName: 'OIDC',
      surname: 'E2E',
      mail: `${state.username}@example.com`,
      accountEnabled: true,
      password: state.password,
    },
  }), 'Entra Local user creation');
  expect(user.userPrincipalName).toBe(state.username);
  const app = await checkedJson(await api.post(`${providerApiOrigin}/admin/api/apps`, {
    data: {
      displayName: state.server_name,
      isConfidential: true,
      redirectUris: [{ uri: `${origin}${callbackPath}`, type: 'web' }],
    },
  }), 'Entra Local app creation');
  await checkedJson(await api.patch(`${providerApiOrigin}/admin/api/apps/${app.id}`, {
    data: {
      optionalClaims: {
        idToken: [
          { name: 'email', essential: false },
          { name: 'preferred_username', essential: false },
          { name: 'auth_time', essential: true },
        ],
        accessToken: [],
      },
    },
  }), 'Entra Local optional claim configuration');
  const secret = await checkedJson(await api.post(`${providerApiOrigin}/admin/api/apps/${app.id}/secrets`, {
    data: { displayName: 'Disposable OPNsense E2E' },
  }), 'Entra Local client secret creation');
  state.client_id = app.id;
  state.client_secret = secret.secretText;
  await api.dispose();
}

async function enrollPocketIdPasskey(browser) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  await page.goto(`${providerOrigin}/signup?token=${encodeURIComponent(state.signup_token)}`);
  await page.getByRole('textbox', { name: /username/i }).fill(state.username);
  const email = page.getByRole('textbox', { name: /email/i });
  if (await email.count()) await email.fill(`${state.username}@example.com`);
  const first = page.getByRole('textbox', { name: /first name/i });
  if (await first.count()) await first.fill('OIDC');
  const last = page.getByRole('textbox', { name: /last name/i });
  if (await last.count()) await last.fill('E2E');
  await page.getByRole('button', { name: /sign up|continue|create/i }).click();
  const addPasskey = page.getByRole('button', { name: /add passkey|create passkey|continue/i });
  await expect(addPasskey).toBeVisible();
  await addPasskey.click();
  await expect.poll(async () => (
    await cdp.send('WebAuthn.getCredentials', { authenticatorId })
  ).credentials.length, { timeout: 30_000 }).toBeGreaterThan(0);
  return { context, page, cdp };
}

async function configureServer(page) {
  await page.goto(`${origin}/system_authservers.php?act=new`);
  await selectNative(page.locator('select[name="type"]'), 'openidconnect');
  await page.locator('input[name="name"]').fill(state.server_name);
  await page.locator('input[name="openidconnect_app_code"]').fill(state.application_code);
  await selectNative(page.locator('select[name="openidconnect_provider_profile"]'), state.profile);
  // The local VM forwards a random Mac port to the guest's HTTPS port. That
  // externally visible origin therefore cannot be inferred from OPNsense's
  // own listen address and must be registered exactly like a reverse proxy.
  await selectNative(page.locator('select[name="openidconnect_origin_policy"]'), 'custom');
  await setFlatList(page, 'openidconnect_redirect_urls', [origin]);
  if (state.provider === 'apple') {
    await selectNative(page.locator('select[name="openidconnect_bootstrap_mode"]'), 'approval');
  } else {
    await selectNative(page.locator('select[name="openidconnect_bootstrap_mode"]'), 'username');
    await page.locator('input[name="openidconnect_create_users"]').check();
    await setGroupList(page, 'openidconnect_default_groups', ['admins']);
  }
  await page.locator('input[name="openidconnect_logout_menu"]').check();
  await page.locator('input[name="openidconnect_logout_redirect"]').check();
  await setFlatList(page, 'openidconnect_scopes', state.scopes);
  if (state.provider === 'apple' || state.provider === 'okta') {
    await selectNative(page.locator('select[name="openidconnect_response_mode"]'), 'form_post');
  }

  if (state.provider === 'authentik') {
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download provider setup' }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/-authentik-blueprint\.yaml$/);
    await provisionAuthentik(await download.path());
    const setup = page.getByRole('dialog').locator('.oidc-setup-result[data-provider="authentik"]');
    await setup.getByRole('button', { name: 'Next' }).click();
    await setup.getByRole('button', { name: 'Next' }).click();
    await setup.getByRole('button', { name: 'Done' }).click();
  }
  const issuer = page.locator('input[name="openidconnect_provider_url"]');
  if (await issuer.isEditable()) {
    await issuer.fill(state.issuer);
  } else {
    await expect(issuer).toHaveValue(state.issuer);
  }
  await page.locator('input[name="openidconnect_client_id"]').fill(state.client_id);
  await page.locator('input[name="openidconnect_client_secret"]').fill(state.client_secret);
  const discovery = page.waitForResponse(response => (
    new URL(response.url()).pathname === '/api/openidconnect/discovery/probe'
  ));
  await page.getByRole('button', { name: 'Test discovery' }).click();
  expect((await discovery).ok()).toBeTruthy();
  const discoveryDialog = page.getByRole('dialog');
  await expect(discoveryDialog).toBeVisible();
  await expect(discoveryDialog.locator('.label-danger')).toHaveCount(0);
  await discoveryDialog.getByRole('button', { name: '×' }).click();
  await page.locator('input[name="openidconnect_enabled"]').check();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page).toHaveURL(/\/system_authservers\.php$/);
}

async function passwordLogin(page) {
  const username = page.getByRole('textbox', { name: /username|email address|username or email/i }).first();
  await expect(username).toBeVisible();
  await username.fill(state.username);
  const action = page.getByRole('button', { name: /continue|next|sign in|log in|login/i });
  // authentik's identification page includes a password-shaped control, but
  // the actual password stage is rendered only after submitting the username.
  if (state.provider === 'authentik') {
    await action.click();
    await expect(username).toBeHidden();
  }
  const password = page.getByRole('textbox', { name: /password/i }).or(page.locator('input[type="password"]')).first();
  await expect(password).toBeVisible();
  await password.fill(state.password);
  await action.click();
}

async function liveProviderInteraction(page) {
  if (state.interaction === 'manual') {
    console.log(`Complete the ${state.provider} sign-in in the visible browser; secrets are not printed.`);
    return;
  }
  try {
    if (state.provider === 'entra') {
      await page.getByRole('textbox', { name: /email|account|sign in/i }).fill(state.username);
      await page.getByRole('button', { name: /next|continue/i }).click();
      await page.getByRole('textbox', { name: /password/i })
        .or(page.locator('input[type="password"]')).first().fill(state.password);
      await page.getByRole('button', { name: /sign in|continue/i }).click();
      return;
    }
    await page.getByRole('textbox', { name: /username|email/i }).fill(state.username);
    await page.getByRole('textbox', { name: /password/i })
      .or(page.locator('input[type="password"]')).first().fill(state.password);
    await page.getByRole('button', { name: /sign in|continue/i }).click();
  } catch {
    console.log(`Automatic ${state.provider} handoff stopped at MFA or consent; continue in the visible browser.`);
  }
}

async function setAuthentikEmailVerification(mode) {
  const api = await apiContext({ Authorization: `Bearer ${state.admin_token}` });
  const attributes = mode === 'missing' ? {} : { email_verified: mode === 'true' };
  await checked(await api.patch(`${providerApiOrigin}/api/v3/core/users/${state.user_pk}/`, {
    data: { attributes },
  }), `authentik e-mail verification update (${mode})`);
  await api.dispose();
}

async function testAuthentikEmailVerification(page, expected) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(state.server_name) })
    .getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Test sign-in' }).click();
  let arrival = 'waiting';
  await expect.poll(async () => {
    if (await page.getByRole('heading', { name: 'Sign-in test succeeded' }).count()) {
      arrival = 'result';
    } else if (new URL(page.url()).origin === providerOrigin) {
      arrival = 'provider';
    } else if (new URL(page.url()).pathname === callbackPath
      && await page.locator('body').getByText(/OpenID Connect could not complete this request/).count()) {
      arrival = 'error';
    }
    return arrival;
  }).not.toBe('waiting');
  if (arrival === 'error') {
    throw new Error(`Test sign-in callback failed: ${await page.locator('body').innerText()}`);
  }
  if (arrival === 'provider') {
    await passwordLogin(page);
    await expect.poll(async () => {
      if (await page.getByRole('heading', { name: 'Sign-in test succeeded' }).count()) return 'result';
      if (new URL(page.url()).pathname === callbackPath
        && await page.locator('body').getByText(/OpenID Connect could not complete this request/).count()) {
        return 'error';
      }
      return 'waiting';
    }).not.toBe('waiting');
    if (await page.locator('body').getByText(/OpenID Connect could not complete this request/).count()) {
      throw new Error(`Test sign-in callback failed: ${await page.locator('body').innerText()}`);
    }
  }
  await expect(page.getByRole('heading', { name: 'Sign-in test succeeded' })).toBeVisible();
  await expect(page.getByRole('row', { name: /E-mail verification claim/ })).toContainText(expected);
  await page.getByRole('link', { name: 'Return to authentication servers' }).click();
  await expect(page.locator('input[name="name"]')).toHaveValue(state.server_name);
}

async function providerLogin(page) {
  await page.goto(origin);
  const before = (await page.context().cookies(origin)).find(cookie => cookie.name === 'PHPSESSID')?.value;
  let authorization;
  page.on('request', request => {
    if (new URL(request.url()).origin === providerOrigin && new URL(request.url()).searchParams.has('code_challenge')) {
      authorization = new URL(request.url());
    }
  });
  await page.getByRole('link', { name: `Login using ${state.server_name}` }).click();
  if (state.login_mode === 'picker') {
    await page.getByRole('button', { name: new RegExp(state.username, 'i') }).click();
  } else if (state.provider !== 'pocketid') {
    await passwordLogin(page);
    if (state.provider === 'authelia') {
      await page.getByRole('button', { name: 'Accept' }).click();
    }
  } else {
    const passkey = page.getByRole('button', { name: /passkey|sign in|log in/i }).first();
    if (await passkey.count()) await passkey.click();
  }
  await expect(page).toHaveURL(/\/ui\/core\/dashboard/, { timeout: 45_000 });
  const after = (await page.context().cookies(origin)).find(cookie => cookie.name === 'PHPSESSID')?.value;
  expect(authorization).toBeTruthy();
  expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorization.searchParams.get('state')).toBeTruthy();
  expect(authorization.searchParams.get('nonce')).toBeTruthy();
  expect(after).toBeTruthy();
  expect(after).not.toBe(before);
}

async function testProviderSignIn(page) {
  await page.goto(`${origin}/system_authservers.php`);
  await page.getByRole('row', { name: new RegExp(state.server_name) })
    .getByRole('link', { name: 'Edit' }).click();
  const callback = page.waitForRequest(request => new URL(request.url()).pathname === callbackPath);
  await page.getByRole('button', { name: 'Test sign-in' }).click();
  await expect.poll(async () => {
    if (await page.getByRole('heading', { name: 'Sign-in test succeeded' }).count()) return 'result';
    if (new URL(page.url()).origin !== origin) return 'provider';
    return 'waiting';
  }).not.toBe('waiting');
  if (new URL(page.url()).origin !== origin) {
    if (state.source === 'live') {
      await liveProviderInteraction(page);
    } else if (state.login_mode === 'picker') {
      await page.getByRole('button', { name: new RegExp(state.username, 'i') }).click();
    } else {
      await passwordLogin(page);
    }
  }
  const callbackRequest = await callback;
  if (state.provider === 'apple' || state.provider === 'okta') {
    expect(callbackRequest.method()).toBe('POST');
    const form = new URLSearchParams(callbackRequest.postData());
    expect(form.get('code')).toBeTruthy();
    expect(form.get('state')).toBeTruthy();
    if (state.provider === 'apple') {
      const firstLoginData = form.get('user');
      if (state.source === 'emulated') {
        const firstLogin = JSON.parse(firstLoginData);
        expect(firstLogin.email).toBe(state.email);
        expect(firstLogin.email.endsWith('@privaterelay.appleid.com')).toBeTruthy();
        expect(firstLogin.name).toBeTruthy();
      } else if (firstLoginData) {
        // Apple sends this object only on the first authorization. A reused live
        // test account must still prove Form Post without manufacturing it.
        expect(JSON.parse(firstLoginData)).toBeTruthy();
      }
    }
  }
  await expect(page.getByRole('heading', { name: 'Sign-in test succeeded' })).toBeVisible();
  await expect(page.locator('body')).toContainText('PKCE binding');
  if (state.provider === 'apple') {
    await expect(page.getByRole('row', { name: /E-mail verification claim/ })).toContainText('true');
  } else if (state.source !== 'live') {
    await expect(page.locator('body')).toContainText(state.username);
  }
}

test(`OPNsense provider flow through ${state.provider}`, async ({ browser }) => {
  if (state.provider === 'pocketid') await provisionPocketId();
  if (state.provider === 'entra' && state.source === 'emulated') await provisionEntra();
  const admin = await browser.newContext({ ignoreHTTPSErrors: true });
  const adminPage = await admin.newPage();
  await localLogin(adminPage);
  await configureServer(adminPage);
  if (state.provider === 'authentik') {
    await testAuthentikEmailVerification(adminPage, 'true');
    await setAuthentikEmailVerification('false');
    await testAuthentikEmailVerification(adminPage, 'false');
    await setAuthentikEmailVerification('missing');
    await testAuthentikEmailVerification(adminPage, 'false');
    await setAuthentikEmailVerification('true');
  }

  if (state.source === 'live' || state.source === 'emulated') {
    await testProviderSignIn(adminPage);
    await admin.close();
    return;
  }

  const localFallback = await browser.newContext({ ignoreHTTPSErrors: true });
  await localLogin(await localFallback.newPage());
  await localFallback.close();

  let pocket;
  let user;
  if (state.provider === 'pocketid') {
    pocket = await enrollPocketIdPasskey(browser);
    user = pocket.context;
  } else {
    user = await browser.newContext({ ignoreHTTPSErrors: true });
  }
  const userPage = state.provider === 'pocketid' ? pocket.page : await user.newPage();
  if (state.provider === 'pocketid') await userPage.goto(`${providerOrigin}/logout`);
  await providerLogin(userPage);
  await expect(userPage.locator('body')).toContainText(state.username);
  await userPage.getByRole('link', { name: /Logout/ }).click();
  await expect(userPage).toHaveTitle(/Login/);
  await user.close();
  await admin.close();
});
