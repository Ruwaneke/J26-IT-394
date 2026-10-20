// @ts-check
/**
 * Builds the Component 2 test report (TASKS P1-5) from Maven Surefire's XML files in
 * backend/target/surefire-reports. Used by the dev-server plugin (qualityPlugin.mjs) and by
 * `npm run test:report`. Plain Node, no dependencies.
 *
 * Only test names, counts, durations and failure details are read. Surefire's <properties>
 * (JVM system properties) and captured stdout/stderr are never copied into the report.
 */
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

export const REPORT_SCHEMA_VERSION = 1;

/** Lines of a stack trace kept in the report. */
const STACK_TRACE_LINES = 25;

/** @typedef {'api-contract' | 'auth' | 'lifecycle' | 'hash-chain' | 'database' | 'regression'} CategoryId */

/** @type {{ id: CategoryId, label: string, description: string }[]} */
export const CATEGORIES = [
  {
    id: 'api-contract',
    label: 'API contract',
    description: 'Request validation, status codes, response shapes and the error format of every endpoint',
  },
  {
    id: 'auth',
    label: 'Authentication & authorization',
    description: 'GitHub sign-in with GitHub mocked, identity taken only from GitHub, event ownership (403)',
  },
  {
    id: 'lifecycle',
    label: 'Lifecycle transitions',
    description: 'Every status × action pair, same-status actions (P1-1) and the history row of each change',
  },
  {
    id: 'hash-chain',
    label: 'Hash-chain integrity',
    description: 'Tamper evidence of the lifecycle history (P2-9): VALID, BROKEN and UNCHAINED cases',
  },
  {
    id: 'database',
    label: 'Database consistency',
    description: 'Repository queries, rollback on failed writes, concurrent actions, schema.sql against the entities',
  },
  {
    id: 'regression',
    label: 'Regression',
    description: 'Unit tests of services and behaviour analysis that guard existing behaviour',
  },
];

/** Test class (simple name, without nested-class suffix) → category. Unlisted classes are regression tests. */
const CLASS_CATEGORY = /** @type {Record<string, CategoryId>} */ ({
  SecurityEventApiContractTest: 'api-contract',
  DeveloperInteractionApiContractTest: 'api-contract',
  DeveloperApiContractTest: 'api-contract',
  LifecycleAndBehaviourApiContractTest: 'api-contract',
  SecurityEventControllerTest: 'api-contract',
  DeveloperInteractionControllerTest: 'api-contract',
  DeveloperBehaviourControllerTest: 'api-contract',

  GitHubAuthApiContractTest: 'auth',
  GitHubAuthServiceTest: 'auth',

  LifecycleTransitionIntegrationTest: 'lifecycle',
  SecurityEventStatusTest: 'lifecycle',
  DeveloperInteractionFlowIntegrationTest: 'lifecycle',
  DeveloperInteractionServiceTest: 'lifecycle',
  DeveloperInteractionServiceRulesTest: 'lifecycle',
  FixVerificationRulesTest: 'lifecycle',
  FixVerificationIntegrationTest: 'lifecycle',

  LifecycleHashChainTest: 'hash-chain',
  LifecycleHistoryVerificationIntegrationTest: 'hash-chain',
  LifecycleHashChainEdgeCaseIntegrationTest: 'hash-chain',
  VulnerabilityLifecycleHistoryServiceTest: 'hash-chain',

  WriteFailureRollbackIntegrationTest: 'database',
  ConcurrentInteractionIntegrationTest: 'database',
  SchemaCompatibilityTest: 'database',
  BehaviourLogRepositoryTest: 'database',
  DeveloperRepositoryTest: 'database',
  SecurityEventRepositoryPhase02Test: 'database',
  VulnerabilityLifecycleHistoryRepositoryTest: 'database',
});

/** Ownership tests inside other classes count as authorization tests. */
const AUTH_METHOD_PATTERN = /otherDeveloper|403|Forbidden|intruder/i;

/**
 * @param {string} className fully qualified, possibly with a `$Nested` suffix
 * @param {string} methodName
 * @returns {CategoryId}
 */
export function categoryOf(className, methodName) {
  if (AUTH_METHOD_PATTERN.test(methodName)) return 'auth';
  const simple = className.slice(className.lastIndexOf('.') + 1).split('$')[0];
  return CLASS_CATEGORY[simple] ?? 'regression';
}

// ── XML reading ──────────────────────────────────────────────────────────────

/** @param {string} text */
export function decodeXml(text) {
  return text
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** @param {string} source */
function attributes(source) {
  /** @type {Record<string, string>} */
  const attrs = {};
  for (const match of source.matchAll(/([\w:.-]+)\s*=\s*"([^"]*)"/g)) {
    attrs[match[1]] = decodeXml(match[2]);
  }
  return attrs;
}

/**
 * @typedef {'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED'} TestStatus
 * @typedef {{ type: string | null, message: string | null, stackTrace: string | null }} FailureDetail
 * @typedef {{
 *   id: string, className: string, simpleClassName: string, name: string, category: CategoryId,
 *   status: TestStatus, durationSeconds: number, failure: FailureDetail | null
 * }} TestCaseResult
 */

/**
 * Parses one Surefire XML file into test cases.
 * @param {string} xml
 * @returns {TestCaseResult[]}
 */
export function parseSurefireXml(xml) {
  /** @type {TestCaseResult[]} */
  const cases = [];
  // Drop the <properties> block (JVM system properties) before anything else is read
  const body = xml.replace(/<properties>[\s\S]*?<\/properties>/g, '');
  const testcase = /<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g;
  for (const match of body.matchAll(testcase)) {
    const attrs = attributes(match[1]);
    const inner = match[2] ?? '';
    const className = attrs.classname ?? '';
    const name = attrs.name ?? '';

    /** @type {TestStatus} */
    let status = 'PASS';
    /** @type {FailureDetail | null} */
    let failure = null;
    const problem = /<(failure|error)\b([^>]*?)(?:\/>|>([\s\S]*?)<\/\1>)/.exec(inner);
    if (problem) {
      status = problem[1] === 'failure' ? 'FAIL' : 'ERROR';
      const problemAttrs = attributes(problem[2]);
      failure = {
        type: problemAttrs.type ?? null,
        message: problemAttrs.message ?? null,
        stackTrace: problem[3] ? excerpt(decodeXml(problem[3])) : null,
      };
    } else {
      const skipped = /<skipped\b([^>]*?)\/?>/.exec(inner);
      if (skipped) {
        status = 'SKIPPED';
        const skippedAttrs = attributes(skipped[1]);
        failure = skippedAttrs.message ? { type: null, message: skippedAttrs.message, stackTrace: null } : null;
      }
    }

    const duration = Number.parseFloat((attrs.time ?? '0').replace(/,/g, ''));
    cases.push({
      id: `${className}#${name}`,
      className,
      simpleClassName: className.slice(className.lastIndexOf('.') + 1).replace(/\$/g, ' › '),
      name,
      category: categoryOf(className, name),
      status,
      durationSeconds: Number.isFinite(duration) ? duration : 0,
      failure,
    });
  }
  return cases;
}

/** @param {string} stackTrace */
function excerpt(stackTrace) {
  const lines = stackTrace.trim().split(/\r?\n/);
  return lines.length <= STACK_TRACE_LINES
    ? lines.join('\n')
    : [...lines.slice(0, STACK_TRACE_LINES), `\t… ${lines.length - STACK_TRACE_LINES} more lines`].join('\n');
}

// ── Report ───────────────────────────────────────────────────────────────────

/**
 * @typedef {{ tests: number, passed: number, failed: number, errors: number, skipped: number }} Counts
 * @typedef {{
 *   schemaVersion: number, generatedAt: string, executedAt: string | null, source: string,
 *   status: 'PASSED' | 'FAILED' | 'NO_TESTS',
 *   totals: Counts & { durationSeconds: number, classes: number },
 *   categories: ({ id: CategoryId, label: string, description: string } & Counts)[],
 *   testCases: TestCaseResult[]
 * }} TestReport
 */

/** @returns {Counts} */
function emptyCounts() {
  return { tests: 0, passed: 0, failed: 0, errors: 0, skipped: 0 };
}

/**
 * @param {Counts} counts
 * @param {TestStatus} status
 */
function add(counts, status) {
  counts.tests++;
  if (status === 'PASS') counts.passed++;
  else if (status === 'FAIL') counts.failed++;
  else if (status === 'ERROR') counts.errors++;
  else counts.skipped++;
}

/**
 * Builds a report from parsed test cases.
 * @param {TestCaseResult[]} testCases
 * @param {{ executedAt?: Date | null, now?: Date }} [options]
 * @returns {TestReport}
 */
export function buildReport(testCases, options = {}) {
  const totals = { ...emptyCounts(), durationSeconds: 0, classes: 0 };
  const byCategory = new Map(CATEGORIES.map(c => [c.id, emptyCounts()]));
  const classes = new Set();
  for (const testCase of testCases) {
    add(totals, testCase.status);
    add(/** @type {Counts} */ (byCategory.get(testCase.category)), testCase.status);
    totals.durationSeconds += testCase.durationSeconds;
    classes.add(testCase.className.split('$')[0]);
  }
  totals.durationSeconds = Math.round(totals.durationSeconds * 1000) / 1000;
  totals.classes = classes.size;

  const order = { ERROR: 0, FAIL: 1, SKIPPED: 2, PASS: 3 };
  const sorted = [...testCases].sort(
    (a, b) => order[a.status] - order[b.status] || a.className.localeCompare(b.className) || a.name.localeCompare(b.name)
  );

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: (options.now ?? new Date()).toISOString(),
    executedAt: options.executedAt ? options.executedAt.toISOString() : null,
    source: 'maven-surefire',
    status: totals.tests === 0 ? 'NO_TESTS' : totals.failed + totals.errors > 0 ? 'FAILED' : 'PASSED',
    totals,
    categories: CATEGORIES.map(c => ({ ...c, .../** @type {Counts} */ (byCategory.get(c.id)) })),
    testCases: sorted,
  };
}

/**
 * Reads every TEST-*.xml file in a Surefire reports directory. Returns null when the directory
 * does not exist or holds no reports (no test run yet).
 * @param {string} reportsDir
 * @returns {Promise<TestReport | null>}
 */
export async function readSurefireReports(reportsDir) {
  let files;
  try {
    files = (await readdir(reportsDir)).filter(f => /^TEST-.*\.xml$/.test(f));
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return null;
    throw err;
  }
  if (files.length === 0) return null;

  /** @type {TestCaseResult[]} */
  const testCases = [];
  let newest = 0;
  for (const file of files) {
    const path = join(reportsDir, file);
    const [xml, info] = await Promise.all([readFile(path, 'utf8'), stat(path)]);
    testCases.push(...parseSurefireXml(xml));
    newest = Math.max(newest, info.mtimeMs);
  }
  return buildReport(testCases, { executedAt: new Date(newest) });
}
