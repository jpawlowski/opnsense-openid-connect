import { defineConfig } from '@playwright/test';

const browserIp = process.env.E2E_PROVIDER_BROWSER_IP;
const providerHost = process.env.E2E_PROVIDER_HOST;
const resolverRules = [];
if (browserIp && providerHost) resolverRules.push(`MAP ${providerHost} ${browserIp}`);
if (process.env.E2E_OPNSENSE_BROWSER_IP && process.env.E2E_OPNSENSE_URL) {
  const opnsenseHost = new URL(process.env.E2E_OPNSENSE_URL).hostname;
  resolverRules.push(`MAP ${opnsenseHost} ${process.env.E2E_OPNSENSE_BROWSER_IP}`);
}

export default defineConfig({
  testDir: '.',
  testMatch: 'provider.spec.mjs',
  timeout: 300_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 1000 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    actionTimeout: 15_000,
    navigationTimeout: 45_000,
    launchOptions: resolverRules.length ? {
      args: [`--host-resolver-rules=${resolverRules.join(',')}`],
    } : {},
  },
});
