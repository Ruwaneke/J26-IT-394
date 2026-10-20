import React, { useCallback, useEffect, useId, useMemo, useState } from 'react';
import { qualityApi, QualityUnavailableError, normalizeError } from '../api/client';
import {
  PageHeader,
  Card,
  StatTile,
  LoadingState,
  ErrorState,
  EmptyState,
  formatDateTime,
  formatNumber,
} from '../components/Cards';
import { Badge } from '../components/Badges';
import { Icon } from '../components/Icon';
import {
  QualityStatus,
  TestCaseResult,
  TestCaseStatus,
  TestCategoryId,
  TestReport,
  TestRunState,
} from '../types';
import './QualityTests.css';

/**
 * Quality & Regression Tests (TASKS P1-5): the latest real `mvn test` results of the backend,
 * read from Surefire's reports by the Vite dev-server plugin (frontend/dev/qualityPlugin.mjs).
 * Nothing on this page is sample data; without a report it says so.
 */

const POLL_MS = 2000;

const STATUS_CONFIG: Record<TestCaseStatus, { label: string; tone: string; icon: string }> = {
  PASS: { label: 'Pass', tone: 'good', icon: 'check' },
  FAIL: { label: 'Fail', tone: 'critical', icon: 'dismiss' },
  ERROR: { label: 'Error', tone: 'serious', icon: 'error' },
  SKIPPED: { label: 'Skipped', tone: 'neutral', icon: 'eyeOff' },
};

const STATUS_KEYS: TestCaseStatus[] = ['FAIL', 'ERROR', 'SKIPPED', 'PASS'];

const RUNNER_REASON: Record<NonNullable<TestRunState['reason']>, string> = {
  'maven-not-found': 'Maven not found',
  'spawn-failed': 'Runner could not start',
  timeout: 'Run timed out',
  'no-test-results': 'Build failed before the tests ran',
};

export const QualityTests: React.FC = () => {
  const [status, setStatus] = useState<QualityStatus>();
  const [error, setError] = useState<Error>();
  const [refreshing, setRefreshing] = useState(false);
  const [starting, setStarting] = useState(false);
  const [runError, setRunError] = useState<Error>();

  const load = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const next = await qualityApi.getStatus(signal);
      if (!signal?.aborted) {
        setStatus(next);
        setError(undefined);
      }
    } catch (err) {
      if (!signal?.aborted) {
        setError(err instanceof QualityUnavailableError ? err : normalizeError(err));
      }
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  // Poll while a run is in progress
  const running = status?.run.state === 'running';
  useEffect(() => {
    if (!running) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => load(controller.signal), POLL_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [running, status, load]);

  const startRun = async () => {
    setStarting(true);
    setRunError(undefined);
    try {
      const run = await qualityApi.startRun();
      setStatus(prev => (prev ? { ...prev, run } : prev));
    } catch (err) {
      setRunError(err instanceof Error ? err : new Error('Could not start the test run.'));
    } finally {
      setStarting(false);
    }
  };

  const header = (
    <PageHeader
      title="Quality & Regression Tests"
      description="Results of the backend’s automated test suite: API contracts, authentication and ownership, lifecycle transitions, hash-chain integrity and database consistency. Every number comes from the last real mvn test run; nothing here is sample data."
      endpoints={['/__c2-quality/report (local dev server)']}
    />
  );

  if (error instanceof QualityUnavailableError) {
    return (
      <>
        {header}
        <EmptyState title="Test reports are not available here">
          This page reads the backend’s test reports through the local development server, so it works
          only with <code>npm run dev</code>. Run the tests from a terminal instead:
        </EmptyState>
        <TerminalInstructions />
      </>
    );
  }

  if (error && !status) {
    return (
      <>
        {header}
        <ErrorState error={error} onRetry={() => load()} />
      </>
    );
  }

  if (!status) {
    return (
      <>
        {header}
        <LoadingState />
      </>
    );
  }

  const { report, run } = status;

  return (
    <>
      {header}
      <div className={`stack quality${refreshing && !running ? ' is-refreshing' : ''}`}>
        <RunBanner
          report={report}
          run={run}
          starting={starting}
          onRun={startRun}
          onRefresh={() => load()}
        />

        {runError && <ErrorState error={runError} />}
        {error && <ErrorState error={error} onRetry={() => load()} />}

        {run.state === 'runner-error' && run.outputTail.length > 0 && (
          <Card
            title="Runner output"
            description="The last lines Maven printed. Secrets and your home folder are masked."
          >
            <pre className="quality-pre">{run.outputTail.join('\n')}</pre>
          </Card>
        )}

        {report ? (
          <ReportView report={report} />
        ) : (
          <EmptyState title="No test report yet">
            No Surefire reports were found in <code>backend/target/surefire-reports</code>. Select{' '}
            <strong>Run test suite</strong> above, or run <code>mvn test</code> in the backend folder and refresh.
          </EmptyState>
        )}

        <TerminalInstructions />
      </div>
    </>
  );
};

// ── Run banner ────────────────────────────────────────────────────────────────

const RunBanner: React.FC<{
  report: TestReport | null;
  run: TestRunState;
  starting: boolean;
  onRun: () => void;
  onRefresh: () => void;
}> = ({ report, run, starting, onRun, onRefresh }) => {
  let tone = 'neutral';
  let icon = 'info';
  let label = 'No test report yet';
  let summary = 'Run the suite to produce a report.';

  if (run.state === 'running') {
    tone = 'info';
    icon = 'clock';
    label = 'Test run in progress';
    summary = `Started ${formatDateTime(stripZone(run.startedAt))}. Results refresh automatically; a full run takes about a minute.`;
  } else if (run.state === 'runner-error') {
    tone = 'serious';
    icon = 'error';
    label = run.reason ? RUNNER_REASON[run.reason] : 'Test runner error';
    summary = `${run.message ?? 'The test runner did not finish.'} This is not a test failure: the tests did not run to completion.`;
  } else if (report?.status === 'PASSED') {
    tone = 'good';
    icon = 'shieldCheck';
    label = 'All tests passed';
    summary = `${formatNumber(report.totals.tests)} tests in ${report.totals.classes} classes passed.`;
  } else if (report?.status === 'FAILED') {
    const broken = report.totals.failed + report.totals.errors;
    tone = 'critical';
    icon = 'shieldAlert';
    label = `${formatNumber(broken)} ${broken === 1 ? 'test' : 'tests'} not passing`;
    summary = `${formatNumber(report.totals.failed)} failed and ${formatNumber(report.totals.errors)} errored out of ${formatNumber(report.totals.tests)}. Expand a row below for the failure message.`;
  } else if (report?.status === 'NO_TESTS') {
    label = 'The report contains no tests';
  }

  return (
    <section className={`hero tone-${tone}`} aria-labelledby="run-status-heading" aria-live="polite">
      <span className="hero-icon">
        {run.state === 'running' ? <span className="spinner quality-spinner" /> : <Icon name={icon} size={30} />}
      </span>
      <div className="quality-hero-body">
        <p className="eyebrow">Overall test-run status</p>
        <h2 id="run-status-heading" className="hero-label">
          {label}
        </h2>
        <p className="hero-summary">{summary}</p>
        <div className="quality-actions">
          <button
            type="button"
            className="button button-primary"
            onClick={onRun}
            disabled={run.state === 'running' || starting}
          >
            <Icon name="activity" size={14} />
            {run.state === 'running' ? 'Running…' : 'Run test suite'}
          </button>
          <button type="button" className="button" onClick={onRefresh}>
            <Icon name="refresh" size={14} />
            Refresh results
          </button>
          {report && (
            <button type="button" className="button" onClick={() => downloadReport(report)}>
              <Icon name="file" size={14} />
              Export JSON
            </button>
          )}
        </div>
        <p className="quality-note">
          Runs <code>mvn -B -ntp test -Dspring.profiles.active=test</code> in <code>backend/</code> on the
          in-memory H2 test database. Only available on the local dev server.
        </p>
      </div>
    </section>
  );
};

// ── Report ────────────────────────────────────────────────────────────────────

const ReportView: React.FC<{ report: TestReport }> = ({ report }) => {
  const [statusFilter, setStatusFilter] = useState<'ALL' | TestCaseStatus>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | TestCategoryId>('ALL');
  const [query, setQuery] = useState('');
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const searchId = useId();
  const categoryId = useId();
  const { totals } = report;
  const notPassing = totals.failed + totals.errors;

  const statusCounts = useMemo(() => {
    const counts = new Map<TestCaseStatus, number>();
    for (const t of report.testCases) counts.set(t.status, (counts.get(t.status) ?? 0) + 1);
    return counts;
  }, [report]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return report.testCases.filter(
      t =>
        (statusFilter === 'ALL' || t.status === statusFilter) &&
        (categoryFilter === 'ALL' || t.category === categoryFilter) &&
        (q === '' || `${t.simpleClassName} ${t.name} ${t.className}`.toLowerCase().includes(q))
    );
  }, [report, statusFilter, categoryFilter, query]);

  const categoryLabel = (id: TestCategoryId) => report.categories.find(c => c.id === id)?.label ?? id;

  const toggle = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const clearFilters = () => {
    setStatusFilter('ALL');
    setCategoryFilter('ALL');
    setQuery('');
  };

  return (
    <>
      <div className="grid grid-tiles">
        <StatTile label="Total tests" icon="list" value={formatNumber(totals.tests)} detail={`${totals.classes} test classes`} />
        <StatTile
          label="Passed"
          icon="check"
          value={formatNumber(totals.passed)}
          detail={totals.tests ? `${((totals.passed / totals.tests) * 100).toFixed(1)}% of all tests` : '—'}
        />
        <StatTile label="Failed" icon="dismiss" value={formatNumber(totals.failed)} detail="Assertions that did not hold" />
        <StatTile label="Errors" icon="error" value={formatNumber(totals.errors)} detail="Unexpected exceptions" />
        <StatTile label="Skipped" icon="eyeOff" value={formatNumber(totals.skipped)} detail="Disabled or assumption not met" />
        <StatTile
          label="Last execution"
          icon="clock"
          value={<span className="quality-time">{formatDateTime(stripZone(report.executedAt))}</span>}
          detail={`Test time ${totals.durationSeconds.toFixed(1)} s (sum over tests)`}
        />
      </div>

      <h2 className="section-title">Test categories</h2>
      <div className="grid quality-categories">
        {report.categories.map(c => {
          const broken = c.failed + c.errors;
          const share = c.tests ? (c.passed / c.tests) * 100 : 0;
          const selected = categoryFilter === c.id;
          return (
            <button
              key={c.id}
              type="button"
              className={`card quality-category tone-${c.tests === 0 ? 'neutral' : broken > 0 ? 'critical' : 'good'}`}
              aria-pressed={selected}
              onClick={() => setCategoryFilter(selected ? 'ALL' : c.id)}
              title={selected ? 'Show all categories' : `Show only ${c.label}`}
            >
              <span className="quality-category-head">
                <strong>{c.label}</strong>
                <span className="quality-category-count">
                  {formatNumber(c.passed)}/{formatNumber(c.tests)}
                </span>
              </span>
              <span className="quality-category-text">{c.description}</span>
              <span className="meter-track" aria-hidden="true">
                {share > 0 && <span className="meter-fill quality-fill" style={{ width: `${share}%` }} />}
              </span>
              <span className="quality-category-foot">
                {c.tests === 0
                  ? 'No tests in this report'
                  : broken > 0
                    ? `${broken} not passing${c.skipped ? `, ${c.skipped} skipped` : ''}`
                    : `All passing${c.skipped ? `, ${c.skipped} skipped` : ''}`}
              </span>
            </button>
          );
        })}
      </div>

      <Card
        title={`Test results (${formatNumber(filtered.length)} of ${formatNumber(report.testCases.length)})`}
        description="Failures and errors are listed first. Select a row to see the failure message and stack-trace excerpt."
        actions={
          notPassing > 0 && (
            <button
              type="button"
              className="button"
              onClick={() => {
                setStatusFilter(statusFilter === 'FAIL' ? 'ALL' : 'FAIL');
                setCategoryFilter('ALL');
              }}
            >
              <Icon name="alert" size={14} />
              {statusFilter === 'FAIL' ? 'Show all tests' : `View failed tests (${formatNumber(totals.failed)})`}
            </button>
          )
        }
      >
        <div className="toolbar">
          <div className="segmented" role="group" aria-label="Filter by result">
            <button type="button" className="chip" aria-pressed={statusFilter === 'ALL'} onClick={() => setStatusFilter('ALL')}>
              All results <span className="chip-count">{report.testCases.length}</span>
            </button>
            {STATUS_KEYS.filter(s => statusCounts.has(s)).map(s => (
              <button
                key={s}
                type="button"
                className={`chip tone-${STATUS_CONFIG[s].tone}`}
                aria-pressed={statusFilter === s}
                onClick={() => setStatusFilter(s)}
              >
                <Icon name={STATUS_CONFIG[s].icon} size={14} className="badge-icon" />
                {STATUS_CONFIG[s].label}
                <span className="chip-count">{statusCounts.get(s)}</span>
              </button>
            ))}
          </div>
          <div className="quality-filters">
            <div className="select-field">
              <label htmlFor={categoryId}>Category</label>
              <select
                id={categoryId}
                className="select"
                value={categoryFilter}
                onChange={e => setCategoryFilter(e.target.value as 'ALL' | TestCategoryId)}
              >
                <option value="ALL">All categories</option>
                {report.categories.map(c => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="select-field">
              <label htmlFor={searchId}>Search</label>
              <input
                id={searchId}
                type="search"
                className="input quality-search"
                placeholder="Class or test name"
                value={query}
                onChange={e => setQuery(e.target.value)}
              />
            </div>
          </div>
        </div>

        {filtered.length === 0 ? (
          <EmptyState title="No tests match these filters">
            <button type="button" className="button" onClick={clearFilters}>
              Clear filters
            </button>
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="data-table quality-table">
              <thead>
                <tr>
                  <th scope="col">Result</th>
                  <th scope="col">Test</th>
                  <th scope="col">Category</th>
                  <th scope="col" className="num">
                    Duration
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(t => (
                  <TestRow
                    key={t.id}
                    test={t}
                    categoryLabel={categoryLabel(t.category)}
                    open={expanded.has(t.id)}
                    onToggle={() => toggle(t.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
};

const TestRow: React.FC<{
  test: TestCaseResult;
  categoryLabel: string;
  open: boolean;
  onToggle: () => void;
}> = ({ test, categoryLabel, open, onToggle }) => {
  const conf = STATUS_CONFIG[test.status];
  const detailId = useId();
  return (
    <>
      <tr className={open ? 'is-open' : undefined}>
        <td>
          <Badge tone={conf.tone} icon={conf.icon} label={conf.label} />
        </td>
        <td>
          <button
            type="button"
            className="quality-row-toggle"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={onToggle}
          >
            <Icon name={open ? 'sortDown' : 'arrowRight'} size={14} />
            <span>
              <span className="cell-title mono break">{test.name}</span>
              <span className="cell-sub mono">{test.simpleClassName}</span>
            </span>
          </button>
        </td>
        <td className="nowrap">{categoryLabel}</td>
        <td className="num nowrap">{formatSeconds(test.durationSeconds)}</td>
      </tr>
      {open && (
        <tr id={detailId} className="quality-detail">
          <td colSpan={4}>
            <dl className="facts">
              <div>
                <dt>Test class</dt>
                <dd className="mono">{test.className}</dd>
              </div>
              <div>
                <dt>Result</dt>
                <dd>{conf.label}</dd>
              </div>
              {test.failure?.type && (
                <div>
                  <dt>Exception</dt>
                  <dd className="mono">{test.failure.type}</dd>
                </div>
              )}
            </dl>
            {test.failure?.message && (
              <>
                <p className="quality-detail-label">Message</p>
                <pre className="quality-pre">{test.failure.message}</pre>
              </>
            )}
            {test.failure?.stackTrace && (
              <>
                <p className="quality-detail-label">Stack trace (excerpt)</p>
                <pre className="quality-pre">{test.failure.stackTrace}</pre>
              </>
            )}
            {!test.failure && <p className="muted">Passed. No failure details are recorded for passing tests.</p>}
          </td>
        </tr>
      )}
    </>
  );
};

// ── Terminal instructions ─────────────────────────────────────────────────────

const TerminalInstructions: React.FC = () => (
  <Card
    title="Run the tests from a terminal"
    description="The same suite, without the dashboard. Uses the in-memory H2 database; no PostgreSQL and no GitHub account are needed."
  >
    <pre className="quality-pre quality-terminal">
      {[
        '# 1. Run the backend test suite (Java 17 and Maven)',
        'cd component-2-behaviour-tracker/backend',
        'mvn test',
        '',
        '# Only one class or one category of classes',
        "mvn test -Dtest=LifecycleTransitionIntegrationTest",
        "mvn test -Dtest='*ApiContractTest'",
        '',
        '# 2. Write backend/target/quality-report.json and print a summary',
        'cd ../frontend',
        'npm run test:report',
        '',
        '# 3. See the results on this page',
        'npm run dev        # then open http://localhost:5173/quality',
      ].join('\n')}
    </pre>
    <p className="card-foot">
      Raw results: <code>backend/target/surefire-reports/</code>. Troubleshooting is in{' '}
      <code>backend/README.md</code> under “Tests and test reports”.
    </p>
  </Card>
);

// ── Helpers ───────────────────────────────────────────────────────────────────

/** The plugin sends UTC ISO strings; show them in local time like the rest of the dashboard. */
function stripZone(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function formatSeconds(seconds: number): string {
  if (seconds < 0.001) return '<1 ms';
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  return `${seconds.toFixed(2)} s`;
}

function downloadReport(report: TestReport): void {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const stamp = (report.executedAt ?? report.generatedAt).replace(/[:.]/g, '-');
  link.href = url;
  link.download = `c2-test-report-${stamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
