import { defineConfig } from '@playwright/test';

const browserIp = process.env.E2E_PROVIDER_BROWSER_IP;
const providerHost = process.env.E2E_PROVIDER_HOST;
const live = process.env.E2E_SOURCE === 'live';
const liveHandoffs = process.env.E2E_CLUSTER === 'direct' ? 2 : 1;
const liveHandoffTimeout = Number(process.env.E2E_LIVE_TIMEOUT || 300_000);
const resolverRules = [];
if (browserIp && providerHost) resolverRules.push(`MAP ${providerHost} ${browserIp}`);
if (process.env.E2E_OPNSENSE_BROWSER_IP && process.env.E2E_OPNSENSE_URL) {
  const opnsenseHost = new URL(process.env.E2E_OPNSENSE_URL).hostname;
  resolverRules.push(`MAP ${opnsenseHost} ${process.env.E2E_OPNSENSE_BROWSER_IP}`);
}

export default defineConfig({
  testDir: '.',
  testMatch: 'provider.spec.mjs',
  // A direct live run deliberately performs both the diagnostic callback and
  // a separate WebGUI login. Each manual handoff receives the configured
  // budget, while setup and local assertions keep a bounded margin of their own.
  timeout: live ? liveHandoffTimeout * liveHandoffs + 120_000 : 300_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  outputDir: live ? process.env.E2E_LIVE_ARTIFACT_DIR : undefined,
  reporter: live ? [['list']] : [['list'], ['html', { open: 'never' }]],
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    trace: live ? 'off' : 'retain-on-failure',
    screenshot: live ? 'off' : 'only-on-failure',
    video: 'off',
    actionTimeout: 15_000,
    navigationTimeout: 45_000,
    launchOptions: resolverRules.length ? {
      args: [`--host-resolver-rules=${resolverRules.join(',')}`],
    } : {},
  },
});
