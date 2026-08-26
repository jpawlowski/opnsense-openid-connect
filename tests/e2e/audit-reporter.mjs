import { writeFile } from 'node:fs/promises';

export default class AuditReporter {
  constructor(options = {}) {
    this.outputFile = options.outputFile || process.env.E2E_PLAYWRIGHT_AUDIT_RESULT;
    this.total = 0;
    this.results = [];
  }

  onBegin(_config, suite) {
    this.total = suite.allTests().length;
  }

  onTestEnd(test, result) {
    this.results.push({
      title: test.title,
      status: result.status,
      expectedStatus: test.expectedStatus,
    });
  }

  async onEnd(result) {
    if (!this.outputFile) {
      return;
    }
    const counts = {
      passed: this.results.filter(item => item.status === 'passed'
        && item.expectedStatus === 'passed').length,
      failed: this.results.filter(item => item.status !== item.expectedStatus).length,
      skipped: this.results.filter(item => item.status === 'skipped').length,
    };
    const summary = {
      status: result.status,
      total: this.total,
      ...counts,
      tests: this.results.map(item => ({ title: item.title, status: item.status })),
    };
    await writeFile(this.outputFile, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o600 });
  }
}
