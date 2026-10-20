// Tests for the report reader and the runner's request guards (TASKS P1-5). Run: npm test
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { buildReport, categoryOf, decodeXml, parseSurefireXml, readSurefireReports } from './surefireReport.mjs';
import { isLoopback, isSameOrigin, redact } from './qualityPlugin.mjs';

const XML = `<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="com.sentinel.tracker.controller.SecurityEventApiContractTest" time="1.5" tests="4" errors="1" skipped="1" failures="1">
  <properties>
    <property name="DB_PASSWORD" value="must-not-appear"/>
    <property name="user.home" value="/Users/someone"/>
  </properties>
  <testcase name="create_ok" classname="com.sentinel.tracker.controller.SecurityEventApiContractTest" time="0.250"/>
  <testcase name="create_bad(String)[1]" classname="com.sentinel.tracker.controller.SecurityEventApiContractTest" time="1,000.5">
    <failure message="Status expected:&lt;400&gt; but was:&lt;201&gt;" type="java.lang.AssertionError">java.lang.AssertionError: Status expected:&lt;400&gt; but was:&lt;201&gt;
	at org.springframework.test.util.AssertionErrors.fail(AssertionErrors.java:59)</failure>
    <system-out>secret log output</system-out>
  </testcase>
  <testcase name="create_otherDevelopersEvent_shouldReturn403" classname="com.sentinel.tracker.controller.SecurityEventApiContractTest" time="0.1">
    <error message="boom &amp; more" type="java.lang.IllegalStateException"/>
  </testcase>
  <testcase name="skipped_one" classname="com.sentinel.tracker.service.SecurityEventServicePhase02Test$CreateSecurityEvent" time="0">
    <skipped message="not today"/>
  </testcase>
</testsuite>`;

test('parseSurefireXml reads status, duration, category and failure details', () => {
  const cases = parseSurefireXml(XML);
  assert.equal(cases.length, 4);

  const [ok, bad, forbidden, skipped] = cases;
  assert.equal(ok.status, 'PASS');
  assert.equal(ok.durationSeconds, 0.25);
  assert.equal(ok.category, 'api-contract');
  assert.equal(ok.failure, null);

  assert.equal(bad.status, 'FAIL');
  assert.equal(bad.durationSeconds, 1000.5);
  assert.equal(bad.failure.type, 'java.lang.AssertionError');
  assert.equal(bad.failure.message, 'Status expected:<400> but was:<201>');
  assert.match(bad.failure.stackTrace, /AssertionErrors\.fail/);

  assert.equal(forbidden.status, 'ERROR');
  assert.equal(forbidden.category, 'auth');
  assert.equal(forbidden.failure.message, 'boom & more');
  assert.equal(forbidden.failure.stackTrace, null);

  assert.equal(skipped.status, 'SKIPPED');
  assert.equal(skipped.simpleClassName, 'SecurityEventServicePhase02Test › CreateSecurityEvent');
  assert.equal(skipped.category, 'regression');
  assert.equal(skipped.failure.message, 'not today');
});

test('parseSurefireXml never copies properties or captured output', () => {
  const json = JSON.stringify(parseSurefireXml(XML));
  assert.doesNotMatch(json, /must-not-appear|\/Users\/someone|secret log output/);
});

test('long stack traces are cut to an excerpt', () => {
  const trace = Array.from({ length: 60 }, (_, i) => `\tat Frame${i}`).join('\n');
  const [testCase] = parseSurefireXml(
    `<testcase name="t" classname="a.B" time="0"><failure message="m" type="T">${trace}</failure></testcase>`);
  const lines = testCase.failure.stackTrace.split('\n');
  assert.equal(lines.length, 26);
  assert.match(lines[25], /35 more lines/);
});

test('buildReport counts totals and categories and orders problems first', () => {
  const report = buildReport(parseSurefireXml(XML), { now: new Date('2026-10-20T10:00:00Z') });
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.status, 'FAILED');
  assert.deepEqual(
    { tests: report.totals.tests, passed: report.totals.passed, failed: report.totals.failed,
      errors: report.totals.errors, skipped: report.totals.skipped, classes: report.totals.classes },
    { tests: 4, passed: 1, failed: 1, errors: 1, skipped: 1, classes: 2 });
  assert.deepEqual(report.testCases.map(t => t.status), ['ERROR', 'FAIL', 'SKIPPED', 'PASS']);
  assert.equal(report.categories.length, 6);
  assert.equal(report.categories.find(c => c.id === 'auth').errors, 1);
  assert.equal(report.categories.reduce((n, c) => n + c.tests, 0), 4);
});

test('buildReport status is PASSED or NO_TESTS', () => {
  assert.equal(buildReport(parseSurefireXml('<testcase name="a" classname="x.Y" time="0"/>')).status, 'PASSED');
  assert.equal(buildReport([]).status, 'NO_TESTS');
});

test('readSurefireReports returns null without reports and reads TEST-*.xml files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'c2-quality-'));
  try {
    assert.equal(await readSurefireReports(join(dir, 'missing')), null);
    assert.equal(await readSurefireReports(dir), null);
    await writeFile(join(dir, 'TEST-a.xml'), XML);
    await writeFile(join(dir, 'a.txt'), 'ignored');
    const report = await readSurefireReports(dir);
    assert.equal(report.totals.tests, 4);
    assert.ok(report.executedAt);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('categoryOf maps known classes and falls back to regression', () => {
  assert.equal(categoryOf('com.sentinel.tracker.controller.LifecycleTransitionIntegrationTest', 'x'), 'lifecycle');
  assert.equal(categoryOf('com.sentinel.tracker.analysis.LifecycleHashChainTest', 'x'), 'hash-chain');
  assert.equal(categoryOf('com.sentinel.tracker.repository.SchemaCompatibilityTest', 'x'), 'database');
  assert.equal(categoryOf('com.sentinel.tracker.service.GitHubAuthServiceTest', 'x'), 'auth');
  assert.equal(categoryOf('com.sentinel.tracker.service.SomethingNewTest', 'x'), 'regression');
});

test('decodeXml decodes entities once', () => {
  assert.equal(decodeXml('&amp;lt; &lt;b&gt; &#65;&#x42;'), '&lt; <b> AB');
});

test('redact hides secrets in runner output', () => {
  assert.equal(redact('DB_PASSWORD=hunter2 ok'), 'DB_PASSWORD=[REDACTED] ok');
  assert.equal(redact('password: hunter2'), 'password: [REDACTED]');
  assert.equal(redact('spring.datasource.password=hunter2'), 'spring.datasource.password=[REDACTED]');
  assert.equal(redact('GITHUB_TOKEN=abc'), 'GITHUB_TOKEN=[REDACTED]');
  assert.doesNotMatch(redact('Authorization: Bearer abc.def'), /abc\.def/);
  assert.doesNotMatch(redact('token ghp_abcdefghijklmnopqrstuvwxyz0123'), /ghp_/);
  assert.doesNotMatch(redact('header Bearer gho_secretvalue1234567890'), /secretvalue/);
  assert.equal(redact('Tests run: 5, Failures: 0'), 'Tests run: 5, Failures: 0');
});

test('only loopback clients and same-origin requests are accepted', () => {
  assert.ok(isLoopback('127.0.0.1'));
  assert.ok(isLoopback('::1'));
  assert.ok(isLoopback('::ffff:127.0.0.1'));
  assert.ok(!isLoopback('192.168.1.20'));
  assert.ok(!isLoopback(undefined));

  const req = headers => ({ headers: { host: 'localhost:5173', ...headers } });
  assert.ok(isSameOrigin(req({})));
  assert.ok(isSameOrigin(req({ origin: 'http://localhost:5173', 'sec-fetch-site': 'same-origin' })));
  assert.ok(!isSameOrigin(req({ origin: 'http://evil.example' })));
  assert.ok(!isSameOrigin(req({ origin: 'http://localhost:5173', 'sec-fetch-site': 'cross-site' })));
  assert.ok(!isSameOrigin(req({ origin: 'null' })));
});
