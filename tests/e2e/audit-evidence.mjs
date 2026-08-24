/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { createHash } from 'node:crypto';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const required = [
  'E2E_AUDIT_EVIDENCE',
  'E2E_AUDIT_EXECUTION_STARTED_AT',
  'E2E_AUDIT_SOURCE_REVISION',
  'E2E_AUDIT_SOURCE_DIRTY',
  'E2E_AUDIT_PACKAGE_SHA256',
  'E2E_AUDIT_PACKAGE_NAME',
  'E2E_AUDIT_PACKAGE_VERSION',
  'E2E_AUDIT_OPNSENSE_VERSION',
  'E2E_AUDIT_KEYCLOAK_IMAGE',
  'E2E_AUDIT_ZAP_IMAGE',
  'E2E_AUDIT_PLAYWRIGHT_VERSION',
  'E2E_PLAYWRIGHT_AUDIT_RESULT',
  'E2E_ZAP_REPORT',
];
for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`${name} is required; start this check through tests/e2e/run-keycloak.sh`);
  }
}

function requireMatch(name, pattern) {
  const value = process.env[name];
  if (!pattern.test(value)) {
    throw new Error(`${name} has an invalid value`);
  }
  return value;
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
}

async function testSuiteDigest() {
  const base = dirname(fileURLToPath(import.meta.url));
  const files = [
    'audit-evidence.mjs',
    'audit-reporter.mjs',
    'oidc.spec.mjs',
    'playwright.config.mjs',
    'run-keycloak.sh',
    'zap-report.mjs',
  ];
  const hash = createHash('sha256');
  for (const name of files) {
    hash.update(name);
    hash.update('\0');
    hash.update(await readFile(join(base, name)));
    hash.update('\0');
  }
  return hash.digest('hex');
}

const output = process.env.E2E_AUDIT_EVIDENCE;
if (!isAbsolute(output)) {
  throw new Error('E2E_AUDIT_EVIDENCE must be an absolute caller-supplied path');
}
const revision = requireMatch('E2E_AUDIT_SOURCE_REVISION', /^[0-9a-f]{40,64}$/);
const packageSha256 = requireMatch('E2E_AUDIT_PACKAGE_SHA256', /^[0-9a-f]{64}$/);
const sourceDirty = requireMatch('E2E_AUDIT_SOURCE_DIRTY', /^(?:true|false)$/) === 'true';
const packageName = requireMatch('E2E_AUDIT_PACKAGE_NAME', /^[a-z0-9][a-z0-9-]{0,63}$/);
const packageVersion = requireMatch('E2E_AUDIT_PACKAGE_VERSION', /^[0-9A-Za-z][0-9A-Za-z.]{0,63}$/);
const opnsenseVersion = requireMatch('E2E_AUDIT_OPNSENSE_VERSION', /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}$/);
const playwrightVersion = requireMatch('E2E_AUDIT_PLAYWRIGHT_VERSION', /^[0-9]+(?:\.[0-9]+){2}$/);
const imagePattern = /^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$/;
const keycloakImage = requireMatch('E2E_AUDIT_KEYCLOAK_IMAGE', imagePattern);
const zapImage = requireMatch('E2E_AUDIT_ZAP_IMAGE', imagePattern);
const startedAt = requireMatch(
  'E2E_AUDIT_EXECUTION_STARTED_AT',
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
);

const playwright = await readJson(process.env.E2E_PLAYWRIGHT_AUDIT_RESULT, 'Playwright audit result');
if (playwright.status !== 'passed' || playwright.total < 1 || playwright.passed !== playwright.total
    || playwright.failed !== 0 || playwright.skipped !== 0) {
  throw new Error('Playwright did not complete every browser audit check successfully');
}
const zap = await readJson(process.env.E2E_ZAP_REPORT, 'ZAP audit result');
if (!Array.isArray(zap.validatedResponseClasses) || zap.validatedResponseClasses.length < 1
    || zap.validatedResponseClasses.length !== zap.requiredResponseClasses
    || !Array.isArray(zap.missingResponseClasses) || zap.missingResponseClasses.length !== 0
    || !Array.isArray(zap.blockingFindings) || zap.blockingFindings.length !== 0) {
  throw new Error('ZAP did not validate every required response class without blocking findings');
}
if (!/^[0-9]+(?:\.[0-9]+){1,3}$/.test(zap.zapVersion || '')) {
  throw new Error('ZAP did not report a valid scanner version');
}

const capabilities = [
  ['browser-authorization-code-flow',
    'Authorization Code login uses state, nonce and PKCE S256 through a real provider and OPNsense WebGUI.'],
  ['browser-session-rotation',
    'Successful session elevation replaces the pre-authentication PHP session identifier.'],
  ['browser-local-group-assignment',
    'A configured default local group is present on the account created by the real login.'],
  ['browser-local-password-fallback',
    'The native local-password login remains usable independently of the provider flow.'],
  ['browser-form-post',
    'A form_post authorization response reaches the bound callback as a URL-encoded POST.'],
  ['browser-jarm',
    'Signed query and Form POST JARM responses complete through a real provider and OPNsense WebGUI.'],
  ['browser-rp-logout',
    'RP-initiated logout ends both the local WebGUI session and the provider browser session.'],
  ['browser-backchannel-logout',
    'A provider back-channel logout event invalidates the bound local WebGUI session.'],
  ['browser-frontchannel-logout',
    'A provider front-channel logout iframe invalidates the bound local WebGUI session.'],
  ['browser-generic-refusals',
    'Callback replay is refused generically, while approval and WebGUI ACL refusals create no session.'],
  ['browser-provider-setup',
    'Provider setup downloads are generated from an unsaved form without embedding a client secret.'],
  ['browser-profile-ui',
    'Named provider profiles, fixed fields, defaults, conditional fields and restoration work in the real form.'],
  ['browser-response-headers',
    'Browser and API assertions validate endpoint-specific caching, MIME, referrer and CSP policy.'],
  ['passive-zap-response-headers',
    'Passive ZAP validation observed every required plugin response class without a blocking header finding.'],
];

const completedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const suiteSha256 = await testSuiteDigest();
const evidence = {
  schema: 'opnsense-openid-connect.audit-evidence/v1',
  tier: 'browser-e2e',
  subject: {
    source: {
      revision,
      dirty: sourceDirty,
      tested_package_sha256: packageSha256,
      test_suite_sha256: suiteSha256,
    },
    package: {
      name: packageName,
      version: packageVersion,
      sha256: packageSha256,
    },
    opnsense: { version: opnsenseVersion },
    keycloak: { image: keycloakImage },
    zap: { image: zapImage, version: zap.zapVersion },
  },
  execution: {
    status: 'passed',
    started_at: startedAt,
    completed_at: completedAt,
    checks_passed: playwright.passed + 1,
    checks_failed: 0,
    checks_skipped: 0,
    playwright_version: playwrightVersion,
    zap_response_classes: zap.validatedResponseClasses,
  },
  capabilities: capabilities.map(([id, validation]) => ({
    id,
    status: 'passed',
    validation,
  })),
};

const temporary = `${dirname(output)}/.${output.split('/').pop()}.${process.pid}.tmp`;
await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
await chmod(temporary, 0o600);
await rename(temporary, output);
console.log('Wrote sanitized browser audit evidence.');
