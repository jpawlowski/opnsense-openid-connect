/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';

for (const name of ['E2E_ZAP_API', 'E2E_OPNSENSE_URL', 'E2E_APPLICATION_CODE']) {
  if (!process.env[name]) {
    throw new Error(`${name} is required; start this check through tests/e2e/run.sh`);
  }
}

const api = new URL(process.env.E2E_ZAP_API);
const origin = new URL(process.env.E2E_OPNSENSE_URL).origin;
const applicationCode = encodeURIComponent(process.env.E2E_APPLICATION_CODE);
const pluginRoot = '/api/openidconnect/';
const apiOnlyRoots = [
  `${pluginRoot}approval/`,
  `${pluginRoot}discovery/`,
  `${pluginRoot}health/`,
  `${pluginRoot}setup/`,
  `${pluginRoot}test/`,
];
const headerRuleIds = new Set(['10015', '10019', '10020', '10021', '10035', '10038', '10055', '100016']);

async function query(path, parameters = {}) {
  const url = new URL(path, api);
  for (const [name, value] of Object.entries(parameters)) {
    url.searchParams.set(name, value);
  }
  return new Promise((resolve, reject) => {
    const apiRequest = request(url, {
      headers: { Host: process.env.E2E_ZAP_API_HOST || '127.0.0.1:8080' },
      timeout: 10_000,
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`ZAP API ${path} answered with HTTP ${response.statusCode}`));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(new Error(`ZAP API ${path} returned invalid JSON`, { cause: error }));
        }
      });
    });
    apiRequest.on('timeout', () => apiRequest.destroy(new Error(`ZAP API ${path} timed out`)));
    apiRequest.on('error', reject);
    apiRequest.end();
  });
}

async function waitForPassiveScan() {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const pending = Number.parseInt((await query('/JSON/pscan/view/recordsToScan/')).recordsToScan, 10);
    if (pending === 0) {
      return;
    }
    await delay(500);
  }
  throw new Error('ZAP passive scanning did not finish within two minutes');
}

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

function isApiOnly(path) {
  return apiOnlyRoots.some(root => path.startsWith(root));
}

async function responseFactsOf(alert) {
  const messageId = String(alert.messageId || '');
  if (!/^\d+$/.test(messageId)) {
    return {};
  }
  const message = (await query('/JSON/core/view/message/', { id: messageId })).message || {};
  const headers = String(message.responseHeader || '');
  const status = headers.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/m);
  const value = name => {
    const match = headers.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'));
    return match ? match[1].trim() : '';
  };
  return {
    status: status ? Number.parseInt(status[1], 10) : null,
    contentType: value('Content-Type').toLowerCase(),
    cacheControl: value('Cache-Control').toLowerCase(),
    contentSecurityPolicy: value('Content-Security-Policy').toLowerCase(),
  };
}

function classify(alert, response) {
  const id = String(alert.pluginId || '');
  const reference = String(alert.alertRef || id);
  const path = pathOf(alert.url);

  if (id === '10035') {
    return ['expected', 'HSTS is owned by the WebGUI TLS listener or terminating proxy'];
  }
  if ((id === '10038' || id === '10020') && isApiOnly(path)) {
    return ['expected', 'non-HTML API response'];
  }
  if (id === '10019' && isApiOnly(path)
      && response.status >= 300 && response.status < 400) {
    return ['expected', 'core authentication redirect without a response media type'];
  }
  if (id === '10020' && response.contentType !== ''
      && !response.contentType.includes('text/html')) {
    return ['expected', 'anti-clickjacking headers do not apply to this non-HTML response'];
  }
  if (id === '10020' && response.contentSecurityPolicy.includes("frame-ancestors 'none'")) {
    return ['expected', 'the response is protected by CSP frame-ancestors'];
  }
  if (id === '10020' && path.includes('/auth/frontchannel/')) {
    return ['expected', 'front-channel logout must be frameable by the provider'];
  }
  if (id === '10015' && response.cacheControl.includes('public')
      && (path.includes('/auth/icon') || path.includes('/auth/builtinicon/'))) {
    return ['expected', 'validated login icons are deliberately cacheable'];
  }
  if (id === '10015' && response.cacheControl.includes('no-store')) {
    return ['expected', 'the private response explicitly forbids storage'];
  }
  if (reference === '10055-4' && path.includes('/auth/frontchannel/')) {
    return ['expected', 'front-channel logout deliberately uses frame-ancestors *'];
  }
  if (reference === '10055-6'
      && (path.includes('/auth/callback/') || path.includes('/auth/icon')
        || path.includes('/auth/builtinicon/'))) {
    return ['expected', 'self-contained result pages and SVG icons use reviewed inline styling'];
  }
  if (reference === '10055-13'
      && (path.includes('/auth/frontchannel/') || path.includes('/auth/icon')
        || path.includes('/auth/builtinicon/'))) {
    return ['expected', 'empty logout and image responses are not navigable HTML documents'];
  }

  if (['10015', '10019', '10020', '10021'].includes(id)) {
    return ['blocking', 'required response protection is missing or invalid'];
  }
  if (id === '10038' && ['10038', '10038-1', '10038-2', '10038-3'].includes(reference)) {
    return ['blocking', 'an enforceable CSP is required for plugin-rendered content'];
  }
  if (id === '10055' && [
    '10055-1', '10055-2', '10055-4', '10055-5', '10055-7', '10055-8',
    '10055-9', '10055-10', '10055-11', '10055-12', '10055-13',
  ].includes(reference)) {
    return ['blocking', 'CSP is obsolete, unsafe, malformed or incomplete'];
  }

  return ['advisory', 'external scanner observation outside the curated failure policy'];
}

await waitForPassiveScan();
const zapVersion = String((await query('/JSON/core/view/version/')).version || '');

const observedUrls = (await query('/JSON/core/view/urls/', { baseurl: origin })).urls || [];
const observedPaths = new Set(observedUrls.map(pathOf).filter(path => path.startsWith(pluginRoot)));
const requiredClasses = [
  ['login start', path => path === `${pluginRoot}auth/login`],
  ['callback outcomes', path => path === `${pluginRoot}auth/callback/${applicationCode}`],
  ['RP-initiated logout', path => path === `${pluginRoot}auth/logout`],
  ['front-channel logout', path => path === `${pluginRoot}auth/frontchannel/${applicationCode}`],
  ['back-channel logout', path => path === `${pluginRoot}auth/backchannel/${applicationCode}`],
  ['cacheable icon', path => path === `${pluginRoot}auth/builtinicon/keycloak`],
  ['icon refusal', path => path === `${pluginRoot}auth/builtinicon/unknown`
    || path === `${pluginRoot}auth/icon`],
  ['Discovery API', path => path === `${pluginRoot}discovery/probe`],
  ['connection-health API', path => path === `${pluginRoot}health/probe`],
  ['sign-in-test API', path => path === `${pluginRoot}test/start`],
  ['provider-setup API', path => path === `${pluginRoot}setup/generate`],
  ['identity-approval API', path => path.startsWith(`${pluginRoot}approval/`)],
];
const missingClasses = requiredClasses
  .filter(([, matches]) => ![...observedPaths].some(matches))
  .map(([name]) => name);

const alerts = (await query('/JSON/core/view/alerts/', {
  baseurl: origin,
  start: '0',
  count: '5000',
})).alerts || [];
const relevantAlerts = alerts
  .filter(alert => pathOf(alert.url).startsWith(pluginRoot))
  .filter(alert => headerRuleIds.has(String(alert.pluginId || '')));
const findings = await Promise.all(relevantAlerts.map(async alert => {
  const response = await responseFactsOf(alert);
  const [outcome, reason] = classify(alert, response);
  return {
    outcome,
    rule: String(alert.alertRef || alert.pluginId || ''),
    name: String(alert.name || alert.alert || 'ZAP finding'),
    method: String(alert.method || 'GET'),
    path: pathOf(alert.url),
    reason,
  };
}));

const blocking = findings.filter(finding => finding.outcome === 'blocking');
const summary = {
  zapVersion,
  observedPluginPaths: observedPaths.size,
  requiredResponseClasses: requiredClasses.length,
  validatedResponseClasses: requiredClasses
    .filter(([, matches]) => [...observedPaths].some(matches))
    .map(([name]) => name),
  missingResponseClasses: missingClasses,
  blockingFindings: blocking,
  expectedExceptions: findings.filter(finding => finding.outcome === 'expected'),
  advisoryFindings: findings.filter(finding => finding.outcome === 'advisory'),
};

if (process.env.E2E_ZAP_REPORT) {
  await writeFile(process.env.E2E_ZAP_REPORT, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
}

console.log(`ZAP observed ${observedPaths.size} OpenID Connect paths across ${requiredClasses.length} required response classes.`);
if (summary.expectedExceptions.length > 0) {
  console.log(`ZAP classified ${summary.expectedExceptions.length} finding(s) as documented endpoint exceptions.`);
}
if (summary.advisoryFindings.length > 0) {
  console.log(`ZAP retained ${summary.advisoryFindings.length} non-blocking finding(s) for review.`);
}

if (missingClasses.length > 0) {
  throw new Error(`ZAP did not observe required response classes: ${missingClasses.join(', ')}`);
}
if (blocking.length > 0) {
  const descriptions = blocking.map(finding => (
    `${finding.rule} ${finding.method} ${finding.path}: ${finding.name}`
  ));
  throw new Error(`ZAP found blocking response-header regressions:\n${descriptions.join('\n')}`);
}

console.log('ZAP found no blocking response-header regressions.');
