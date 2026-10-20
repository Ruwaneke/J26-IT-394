// @ts-check
/**
 * Vite dev-server plugin for the Quality & Regression Tests page (TASKS P1-5).
 *
 *   GET  /__c2-quality/report  latest Surefire results as JSON, plus the state of the last run
 *   POST /__c2-quality/run     starts the backend test suite
 *
 * It exists only in `npm run dev` (apply: 'serve'). The production build and `vite preview`
 * have no such routes, and the Spring Boot backend has no endpoint that runs tests.
 *
 * The runner is deliberately narrow:
 * - one fixed command, `mvn -B -ntp test -Dspring.profiles.active=test`, in the backend folder;
 *   nothing from the request is used (no arguments, paths or shell);
 * - the test profile uses the in-memory H2 database; database credentials and other secrets in
 *   the environment are not passed on (only an allow-list of variables);
 * - loopback clients only, same-origin requests only, and a custom header is required;
 * - one run at a time, killed after a timeout;
 * - only the last lines of Maven's output are kept, with obvious secrets redacted.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSurefireReports } from './surefireReport.mjs';

const BACKEND_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../backend');
const REPORTS_DIR = join(BACKEND_DIR, 'target', 'surefire-reports');
const JSON_REPORT = join(BACKEND_DIR, 'target', 'quality-report.json');

const ROUTE = '/__c2-quality';
const REQUIRED_HEADER = 'x-c2-quality';
const MAVEN_ARGS = ['-B', '-ntp', 'test', '-Dspring.profiles.active=test'];
const TIMEOUT_MS = 10 * 60 * 1000;
const OUTPUT_LINES = 60;

/** Environment variables passed to Maven. Everything else (DB_PASSWORD, tokens, …) is dropped. */
const ENV_ALLOW_LIST = [
  'PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP', 'JAVA_HOME', 'M2_HOME', 'MAVEN_HOME',
  'SystemRoot', 'ComSpec', 'PATHEXT', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'ProgramData',
];

/**
 * @typedef {{
 *   state: 'idle' | 'running' | 'passed' | 'failed' | 'runner-error',
 *   reason: 'maven-not-found' | 'spawn-failed' | 'timeout' | 'no-test-results' | null,
 *   message: string | null, startedAt: string | null, finishedAt: string | null,
 *   exitCode: number | null, outputTail: string[]
 * }} RunState
 */

/** @type {RunState} */
let run = idleState();
/** @type {import('node:child_process').ChildProcess | null} */
let child = null;

/** @returns {RunState} */
function idleState() {
  return { state: 'idle', reason: null, message: null, startedAt: null, finishedAt: null, exitCode: null, outputTail: [] };
}

/** @returns {import('vite').Plugin} */
export function qualityReportPlugin() {
  return {
    name: 'c2-quality-report',
    apply: 'serve',
    configureServer(server) {
      // A run must not outlive the dev server
      server.httpServer?.once('close', () => {
        if (child) killTree(child);
      });
      server.middlewares.use(ROUTE, (req, res) => {
        handle(req, res).catch(err => {
          server.config.logger.error(`[c2-quality] ${err instanceof Error ? err.message : String(err)}`);
          send(res, 500, { message: 'Could not read the test reports.' });
        });
      });
    },
  };
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 */
async function handle(req, res) {
  if (!isLoopback(req.socket.remoteAddress)) {
    return send(res, 403, { message: 'The test runner only accepts requests from this computer.' });
  }
  const path = (req.url ?? '/').split('?')[0];

  if (req.method === 'GET' && (path === '/report' || path === '/report/')) {
    const report = await readSurefireReports(REPORTS_DIR);
    return send(res, 200, { runnerAvailable: true, run, report });
  }

  if (req.method === 'POST' && (path === '/run' || path === '/run/')) {
    if (req.headers[REQUIRED_HEADER] !== '1' || !isSameOrigin(req)) {
      return send(res, 403, { message: 'Test runs can only be started from the dashboard.' });
    }
    if (run.state === 'running') {
      return send(res, 409, { message: 'A test run is already in progress.', run });
    }
    startRun();
    return send(res, 202, { run });
  }

  res.setHeader('Allow', path.startsWith('/run') ? 'POST' : 'GET');
  return send(res, path === '/report' || path === '/run' ? 405 : 404, { message: 'Not found.' });
}

function startRun() {
  const startedAt = new Date();
  run = { ...idleState(), state: 'running', startedAt: startedAt.toISOString(), message: 'Running mvn test…' };

  if (!existsSync(join(BACKEND_DIR, 'pom.xml'))) {
    finish('runner-error', 'spawn-failed', 'The backend folder (with pom.xml) was not found next to the frontend.', null);
    return;
  }

  const windows = process.platform === 'win32';
  /** @type {NodeJS.ProcessEnv} */
  const env = {};
  for (const key of ENV_ALLOW_LIST) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }

  // Fixed executable and arguments, no shell. On Windows, mvn is a .cmd script that needs cmd.exe.
  const proc = windows
    ? spawn(process.env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', 'mvn.cmd', ...MAVEN_ARGS], {
        cwd: BACKEND_DIR, env, windowsHide: true,
      })
    : spawn('mvn', MAVEN_ARGS, { cwd: BACKEND_DIR, env });
  child = proc;

  const timer = setTimeout(() => {
    appendOutput(`Stopped after ${TIMEOUT_MS / 60000} minutes.`);
    finish('runner-error', 'timeout', `The test run took longer than ${TIMEOUT_MS / 60000} minutes and was stopped.`, null);
    killTree(proc);
  }, TIMEOUT_MS);

  proc.once('spawn', () => {
    // Old results are removed only once Maven has started, so a failed start keeps them
    rm(REPORTS_DIR, { recursive: true, force: true }).catch(() => {});
  });
  proc.stdout?.on('data', chunk => appendOutput(String(chunk)));
  proc.stderr?.on('data', chunk => appendOutput(String(chunk)));

  proc.once('error', err => {
    clearTimeout(timer);
    const notFound = /** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT';
    finish('runner-error', notFound ? 'maven-not-found' : 'spawn-failed',
      notFound
        ? 'Maven (mvn) was not found on the PATH of the dev server. Install Maven and Java 17, or run the tests from a terminal.'
        : `The test runner could not start: ${redact(err.message)}`,
      null);
  });

  proc.once('close', async code => {
    clearTimeout(timer);
    if (run.state !== 'running' || child !== proc) return;
    const report = await readSurefireReports(REPORTS_DIR).catch(() => null);
    if (!report) {
      finish('runner-error', 'no-test-results',
        'Maven finished without test results, so the build failed before the tests ran (for example a compile error). See the output below.',
        code);
      return;
    }
    await writeJsonReport(report);
    finish(report.status === 'PASSED' ? 'passed' : 'failed', null,
      report.status === 'PASSED' ? 'All tests passed.' : `${report.totals.failed + report.totals.errors} test(s) did not pass.`,
      code);
  });
}

/**
 * @param {RunState['state']} state
 * @param {RunState['reason']} reason
 * @param {string} message
 * @param {number | null} exitCode
 */
function finish(state, reason, message, exitCode) {
  if (run.state !== 'running') return;
  run = { ...run, state, reason, message, exitCode, finishedAt: new Date().toISOString() };
  child = null;
}

/** @param {import('node:child_process').ChildProcess} proc */
function killTree(proc) {
  if (proc.pid === undefined) return;
  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { windowsHide: true });
    } else {
      // Surefire's forked test JVM exits by itself once Maven has gone
      proc.kill('SIGTERM');
    }
  } catch {
    proc.kill('SIGKILL');
  }
}

/** @param {import('./surefireReport.mjs').TestReport} report */
async function writeJsonReport(report) {
  try {
    await mkdir(dirname(JSON_REPORT), { recursive: true });
    await writeFile(JSON_REPORT, JSON.stringify(report, null, 2));
  } catch {
    // The JSON file is a convenience copy; the page reads the XML reports directly
  }
}

/** @param {string} text */
function appendOutput(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim() !== '').map(redact);
  run.outputTail = [...run.outputTail, ...lines].slice(-OUTPUT_LINES);
}

const HOME = homedir();
// Also matches prefixed names such as DB_PASSWORD or GITHUB_TOKEN
const SECRET_ASSIGNMENT = /\b([\w.-]*?(?:password|passwd|pwd|secret|token|authorization|api[_-]?key|credentials?))(\s*[=:]\s*)(\S+)/gi;
const GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;

/** Removes obvious secrets and the home folder from a line of output. */
export function redact(line) {
  // Token patterns first: "Authorization: Bearer x" must lose x, not only the word Bearer
  let out = line
    .replace(BEARER, 'Bearer [REDACTED]')
    .replace(GITHUB_TOKEN, '[REDACTED]')
    .replace(SECRET_ASSIGNMENT, '$1$2[REDACTED]');
  if (HOME && HOME.length > 1) out = out.split(HOME).join('~');
  return out;
}

/** @param {string | undefined} address */
export function isLoopback(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

/**
 * Browsers send Origin on POST; it must be this dev server. Sec-Fetch-Site, when present,
 * must say same-origin.
 * @param {import('node:http').IncomingMessage} req
 */
export function isSameOrigin(req) {
  const site = req.headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin') return false;
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}
