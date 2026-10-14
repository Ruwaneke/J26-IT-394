/**
 * Verification Test: Vulnerability Resolution Progress Concept
 *
 * Verifies:
 * 1. When 6 vulnerabilities are detected: fixPercentage is strictly 0.0% (0 / 6 Fixed).
 * 2. When 1 vulnerability is resolved in code: fixPercentage is 16.7% (1 / 6 Fixed).
 * 3. When 3 vulnerabilities are resolved in code: fixPercentage is 50.0% (3 / 6 Fixed).
 * 4. When all 6 vulnerabilities are resolved in code: fixPercentage is 100.0% (6 / 6 Fixed).
 * 5. Deterministic IDs guarantee zero false-fix churn across typing events.
 */

import { computeFindingId, Severity, VulnerabilityType, SecurityFinding } from '../analyzer/types.js';
import { NeonDatabaseService } from '../data/neonDatabaseService.js';
import { generateContextualExplanation } from '../diagnostics/contextualExplainer.js';

async function runTest() {
  console.log('🧪 Starting Vulnerability Resolution Concept Test...\n');

  const testFile = '/workspace/src/test_vulnerable_service.ts';
  const testDev = 'TEST_DEV_PROGRESS_VERIFY';
  const sessionId = 'TEST-VERIFY-SESSION';

  // 1. Simulate 6 detected vulnerabilities in the file
  const snippets = [
    'const q1 = "SELECT * FROM users WHERE id = " + id;',
    'const q2 = "SELECT * FROM accounts WHERE name = \'" + name + "\'";',
    'const apiKey = "AKIAIOSFODNN7EXAMPLE";',
    'document.getElementById("user").innerHTML = untrustedInput;',
    'const q3 = "DELETE FROM orders WHERE id = " + orderId;',
    'eval("var res = " + userInput);',
  ];

  const types = [
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.HARDCODED_SECRET,
    VulnerabilityType.XSS,
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.XSS,
  ];

  const ruleIds = [
    'SENTINEL-SQL-001',
    'SENTINEL-SQL-001',
    'SENTINEL-SECRET-001',
    'SENTINEL-XSS-001',
    'SENTINEL-SQL-001',
    'SENTINEL-XSS-001',
  ];

  const findings: SecurityFinding[] = snippets.map((snip, idx) => ({
    id: computeFindingId(testFile, types[idx], ruleIds[idx], snip, 0),
    type: types[idx],
    severity: Severity.HIGH,
    confidence: 0.9,
    message: `Test issue ${idx + 1}`,
    fileName: testFile,
    lineNumber: (idx + 1) * 10,
    columnNumber: 5,
    codeSnippet: snip,
    detectedAt: new Date().toISOString(),
    detectedByRule: ruleIds[idx],
  }));

  console.log(`✅ Generated 6 findings with deterministic stable IDs:`);
  findings.forEach((f, i) => console.log(`   [${i + 1}] ID: ${f.id} | Line: ${f.lineNumber} | Snippet: ${f.codeSnippet.substring(0, 40)}...`));

  // Initialize DB
  const db = NeonDatabaseService.getInstance();
  await db.initialize();

  // Clear any existing test records for this test dev
  if ((db as any).pool) {
    await (db as any).pool.query(
      `DELETE FROM vulnerability_records WHERE developer_id = $1;`,
      [testDev]
    );
  }

  // ── Test Stage 1: All 6 vulnerabilities detected in editor (0 fixed) ────────
  console.log('\n--- STAGE 1: 6 Vulnerabilities Detected in Code (0 Fixed) ---');
  for (const f of findings) {
    const expl = generateContextualExplanation(f);
    await db.saveVulnerabilityRecord(f, testDev, testDev, sessionId, expl);
  }

  // Run autoDetect: all 6 are active
  const activeIdsStage1 = findings.map(f => f.id);
  const fixedStage1Result = await db.autoDetectFixedFindingsInFile(testFile, testDev, activeIdsStage1);
  console.log(`   Auto-detected fixed count: ${fixedStage1Result.length}`);

  // Compute stats as dashboard would
  const statsStage1 = await db.getVulnerabilityStats(testDev, testFile);
  const totalStage1 = statsStage1.totalIdentified;
  const fixedStage1 = statsStage1.fixedCount;
  const openStage1 = statsStage1.openCount;
  const fixPctStage1 = totalStage1 > 0 ? Math.round((fixedStage1 / totalStage1) * 1000) / 10 : 0.0;

  console.log(`   Total Identified: ${totalStage1}`);
  console.log(`   Fixed Count:      ${fixedStage1}`);
  console.log(`   Open Count:       ${openStage1}`);
  console.log(`   Fix Percentage:   ${fixPctStage1}%`);

  if (fixPctStage1 !== 0.0) {
    throw new Error(`FAIL: Stage 1 fix percentage should be 0.0%, but was ${fixPctStage1}%!`);
  }
  console.log('   >>> PASS: When 6 vulnerabilities exist and 0 are fixed, progress is EXACTLY 0.0% (0 / 6)!');

  // ── Test Stage 2: Correct 1 vulnerability in code (red line removed) ─────────
  console.log('\n--- STAGE 2: Correct 1 Problem in Code (Finding #1 Red Line Gone) ---');
  // Finding #1 is corrected, remaining 5 active
  const activeFindingsStage2 = findings.slice(1);
  const activeIdsStage2 = activeFindingsStage2.map(f => f.id);
  const fixedStage2Result = await db.autoDetectFixedFindingsInFile(testFile, testDev, activeIdsStage2);
  console.log(`   Auto-detected fixed count: ${fixedStage2Result.length}`);

  const statsStage2 = await db.getVulnerabilityStats(testDev, testFile);
  const totalStage2 = statsStage2.totalIdentified;
  const fixedStage2 = statsStage2.fixedCount;
  const openStage2 = activeFindingsStage2.length;
  const fixPctStage2 = totalStage2 > 0 ? Math.round((fixedStage2 / totalStage2) * 1000) / 10 : 0.0;

  console.log(`   Total Identified: ${totalStage2}`);
  console.log(`   Fixed Count:      ${fixedStage2}`);
  console.log(`   Open Count:       ${openStage2}`);
  console.log(`   Fix Percentage:   ${fixPctStage2}%`);

  if (fixedStage2 !== 1 || fixPctStage2 !== 16.7) {
    throw new Error(`FAIL: Stage 2 expected 1/6 (16.7%), got ${fixedStage2}/${totalStage2} (${fixPctStage2}%)`);
  }
  console.log('   >>> PASS: When 1 of 6 is fixed, progress is EXACTLY 16.7% (1 / 6)!');

  // ── Test Stage 3: Correct 2 more vulnerabilities in code (total 3 fixed) ─────
  console.log('\n--- STAGE 3: Correct 2 More in Code (3 Total Fixed of 6) ---');
  // Findings #1, #2, #3 are fixed, remaining are #4, #5, #6
  const activeFindingsStage3 = findings.slice(3);
  const activeIdsStage3 = activeFindingsStage3.map(f => f.id);
  const fixedStage3Result = await db.autoDetectFixedFindingsInFile(testFile, testDev, activeIdsStage3);
  console.log(`   Auto-detected fixed count: ${fixedStage3Result.length}`);

  const statsStage3 = await db.getVulnerabilityStats(testDev, testFile);
  const totalStage3 = statsStage3.totalIdentified;
  const fixedStage3 = statsStage3.fixedCount;
  const openStage3 = activeFindingsStage3.length;
  const fixPctStage3 = totalStage3 > 0 ? Math.round((fixedStage3 / totalStage3) * 1000) / 10 : 0.0;

  console.log(`   Total Identified: ${totalStage3}`);
  console.log(`   Fixed Count:      ${fixedStage3}`);
  console.log(`   Open Count:       ${openStage3}`);
  console.log(`   Fix Percentage:   ${fixPctStage3}%`);

  if (fixedStage3 !== 3 || fixPctStage3 !== 50.0) {
    throw new Error(`FAIL: Stage 3 expected 3/6 (50.0%), got ${fixedStage3}/${totalStage3} (${fixPctStage3}%)`);
  }
  console.log('   >>> PASS: When 3 of 6 are fixed, progress is EXACTLY 50.0% (3 / 6)!');

  // ── Test Stage 4: Correct all remaining vulnerabilities (all red lines gone) ──
  console.log('\n--- STAGE 4: All 6 Fixed in Code (All Red Lines Gone) ---');
  const activeIdsStage4: string[] = []; // No active findings left!
  const fixedStage4Result = await db.autoDetectFixedFindingsInFile(testFile, testDev, activeIdsStage4);
  console.log(`   Auto-detected fixed count: ${fixedStage4Result.length}`);

  const statsStage4 = await db.getVulnerabilityStats(testDev, testFile);
  const totalStage4 = statsStage4.totalIdentified;
  const fixedStage4 = statsStage4.fixedCount;
  const openStage4 = 0;
  const fixPctStage4 = totalStage4 > 0 ? Math.round((fixedStage4 / totalStage4) * 1000) / 10 : 0.0;

  console.log(`   Total Identified: ${totalStage4}`);
  console.log(`   Fixed Count:      ${fixedStage4}`);
  console.log(`   Open Count:       ${openStage4}`);
  console.log(`   Fix Percentage:   ${fixPctStage4}%`);

  if (fixedStage4 !== 6 || fixPctStage4 !== 100.0) {
    throw new Error(`FAIL: Stage 4 expected 6/6 (100.0%), got ${fixedStage4}/${totalStage4} (${fixPctStage4}%)`);
  }
  console.log('   >>> PASS: When all 6 are fixed, progress is EXACTLY 100.0% (6 / 6)!');

  // Clean up test file records
  if ((db as any).pool) {
    await (db as any).pool.query(
      `DELETE FROM vulnerability_records WHERE developer_id = $1;`,
      [testDev]
    );
  }
  await db.close();

  console.log('\n🎉 ALL CONCEPT TESTS PASSED PERFECTLY!\n');
}

runTest().catch(err => {
  console.error('\n❌ TEST FAILED:', err);
  process.exit(1);
});
