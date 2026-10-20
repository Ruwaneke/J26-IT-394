// @ts-check
/**
 * `npm run test:report`: turns the Surefire XML of the last `mvn test` into
 * backend/target/quality-report.json and prints a summary (TASKS P1-5).
 * It does not run the tests. Exit code: 0 passed, 1 failures or errors, 2 no reports.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSurefireReports } from './surefireReport.mjs';

const backendDir = resolve(dirname(fileURLToPath(import.meta.url)), '../../backend');
const reportsDir = join(backendDir, 'target', 'surefire-reports');
const output = join(backendDir, 'target', 'quality-report.json');

const report = await readSurefireReports(reportsDir);
if (!report) {
  console.error('No Surefire reports found in backend/target/surefire-reports.');
  console.error('Run the tests first:  cd ../backend && mvn test');
  process.exit(2);
}

await mkdir(dirname(output), { recursive: true });
await writeFile(output, JSON.stringify(report, null, 2));

const { totals } = report;
console.log(`${report.status}: ${totals.tests} tests in ${totals.classes} classes, ${totals.passed} passed, `
  + `${totals.failed} failed, ${totals.errors} errors, ${totals.skipped} skipped (${totals.durationSeconds.toFixed(1)} s)`);
for (const category of report.categories) {
  console.log(`  ${category.label.padEnd(32)} ${String(category.passed).padStart(4)} / ${category.tests}`);
}
for (const testCase of report.testCases.filter(t => t.status === 'FAIL' || t.status === 'ERROR')) {
  console.log(`  ${testCase.status}  ${testCase.simpleClassName}.${testCase.name}: ${testCase.failure?.message ?? ''}`);
}
console.log(`Report written to backend/target/quality-report.json (executed ${report.executedAt ?? 'unknown'})`);
process.exit(report.status === 'PASSED' ? 0 : 1);
