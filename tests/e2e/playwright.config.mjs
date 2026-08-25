import { defineConfig } from '@playwright/test';

const use = {
  headless: true,
  ignoreHTTPSErrors: true,
  viewport: { width: 1440, height: 1000 },
  trace: 'retain-on-failure',
  screenshot: 'only-on-failure',
  actionTimeout: 10_000,
  navigationTimeout: 30_000,
};

const resolverRules = [];
if (process.env.E2E_PROVIDER_BROWSER_IP && process.env.E2E_PROVIDER_HOST) {
  resolverRules.push(`MAP ${process.env.E2E_PROVIDER_HOST} ${process.env.E2E_PROVIDER_BROWSER_IP}`);
}
if (process.env.E2E_OPNSENSE_BROWSER_IP && process.env.E2E_OPNSENSE_URL) {
  resolverRules.push(`MAP ${new URL(process.env.E2E_OPNSENSE_URL).hostname} ${process.env.E2E_OPNSENSE_BROWSER_IP}`);
}
if (resolverRules.length) {
  use.launchOptions = {
    args: [`--host-resolver-rules=${resolverRules.join(',')}`],
  };
}

if (process.env.E2E_ZAP_PROXY) {
  use.proxy = {
    server: process.env.E2E_ZAP_PROXY,
    // Only OPNsense is in scope. Provider traffic remains direct so ZAP cannot
    // turn findings in the disposable IdP into plugin failures.
    bypass: new URL(process.env.E2E_KEYCLOAK_URL).hostname,
  };
}

const reporter = [['list'], ['html', { open: 'never' }]];
if (process.env.E2E_PLAYWRIGHT_AUDIT_RESULT) {
  reporter.push(['./audit-reporter.mjs', { outputFile: process.env.E2E_PLAYWRIGHT_AUDIT_RESULT }]);
}

export default defineConfig({
  testDir: '.',
  testMatch: 'oidc.spec.mjs',
  timeout: 180_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter,
  use,
});
