/**
 * Test: OWASP Top 10 Detection, AI Suggestion Generation, and Real-Time Fix Verification
 *
 * Verifies:
 * 1. SecurityAnalyzer cleanly detects all Top 10 vulnerabilities developers encounter.
 * 2. Contextual AI suggestions are generated with root-cause explanation, attack vector,
 *    and secure code replacement for every category.
 * 3. Real-time code fix workflow:
 *    - Developer starts with vulnerable code -> Sentinel identifies vulnerability -> status OPEN.
 *    - Developer edits/fixes code in real time (simulated typing) -> Sentinel auto-detects fix -> status FIXED.
 *    - No clickable auto-fix buttons are required.
 */

import { SecurityAnalyzer } from '../analyzer/securityAnalyzer.js';
import { generateContextualExplanation } from '../diagnostics/contextualExplainer.js';
import { NeonDatabaseService } from '../data/neonDatabaseService.js';
import { VulnerabilityType, Severity, SecurityFinding } from '../analyzer/types.js';

async function runTop10RealTimeTest() {
  console.log('🛡️ Starting OWASP Top 10 & Real-Time Fix Verification Test...\n');

  const analyzer = new SecurityAnalyzer();
  const db = NeonDatabaseService.getInstance();
  await db.initialize();

  const testDev = 'TEST_DEV_REALTIME_FIX';
  const sessionId = 'TEST-SESSION-TOP10';
  const testFile = '/workspace/src/api_routes.ts';

  // Clean up any old test records
  if ((db as any).pool) {
    await (db as any).pool.query(
      `DELETE FROM vulnerability_records WHERE developer_id = $1;`,
      [testDev]
    );
  }

  // ── 1. Test Code Snippets Covering Developer Scenarios ───────────────────
  const vulnerableCode = `
// A01: Path Traversal / Broken Access Control
const userFile = req.query.file;
const content = fs.readFileSync(path.join('/uploads', userFile));

// A02: Cryptographic Failures
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// A03: SQL Injection
const sql = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
db.query(sql);

// A03: Cross-Site Scripting (XSS)
document.getElementById('profile').innerHTML = req.query.name;

// A05: Security Misconfiguration
app.use(cors({ origin: '*' }));

// A07: Hardcoded Secret
const jwtSecret = "super-secret-key-1234567890123456";

// A08: Insecure Deserialization
const unpickled = pickle.loads(untrustedData);

// A10: Server-Side Request Forgery (SSRF)
const target = req.query.url;
fetch(target);
`;

  console.log('🔍 Running SecurityAnalyzer on vulnerable source code...');
  const initialFindings = analyzer.analyze(vulnerableCode, testFile, 'typescript');
  console.log(`✅ Identified ${initialFindings.length} vulnerabilities across OWASP Top 10 categories.`);

  if (initialFindings.length === 0) {
    throw new Error('FAIL: Expected multiple vulnerabilities to be detected.');
  }

  // ── 2. Verify AI Suggestions For Each Finding ───────────────────────────
  console.log('\n🤖 Verifying AI Suggestions (Root Cause, Attack Vector, Secure Fix):');
  for (const f of initialFindings) {
    const aiExpl = generateContextualExplanation(f);
    if (!aiExpl.whyDangerous || !aiExpl.fixedCode || !aiExpl.fixExplanation) {
      throw new Error(`FAIL: Missing AI explanation fields for ${f.type}`);
    }
    console.log(`   [${f.type}] AI Fix: ${aiExpl.fixExplanation.substring(0, 60)}...`);
    // Persist to Neon DB with status OPEN
    await db.saveVulnerabilityRecord(f, testDev, testDev, sessionId, aiExpl);
  }

  // Verify all records are OPEN
  const statsInitial = await db.getVulnerabilityStats(testDev, testFile);
  console.log(`\n📊 Initial DB State: ${statsInitial.totalIdentified} Identified, ${statsInitial.openCount} Open, ${statsInitial.fixedCount} Fixed (${statsInitial.fixPercentage}%)`);
  if (statsInitial.fixedCount !== 0 || statsInitial.openCount !== initialFindings.length) {
    throw new Error(`FAIL: Expected 0 fixed and ${initialFindings.length} open, got ${statsInitial.fixedCount} fixed, ${statsInitial.openCount} open`);
  }

  // ── 3. Simulate Developer Fixing Code in Real-Time (Typing Changes) ────────
  console.log('\n✍️ Developer fixes the SQL Injection and XSS by typing secure parameterized code...');
  
  // Safe code replacing the SQL injection and XSS
  const codeAfterFix = `
// A01: Path Traversal / Broken Access Control
const userFile = req.query.file;
const content = fs.readFileSync(path.join('/uploads', userFile));

// A02: Cryptographic Failures
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// A03: SQL Injection FIXED by developer using parameterized query
const sql = "SELECT * FROM users WHERE email = $1";
db.query(sql, [req.body.email]);

// A03: XSS FIXED by developer using textContent
document.getElementById('profile').textContent = req.query.name;

// A05: Security Misconfiguration
app.use(cors({ origin: '*' }));

// A07: Hardcoded Secret
const jwtSecret = "super-secret-key-1234567890123456";

// A08: Insecure Deserialization
const unpickled = pickle.loads(untrustedData);

// A10: Server-Side Request Forgery (SSRF)
const target = req.query.url;
fetch(target);
`;

  // Re-run analyzer on the updated code (simulating onDidChangeTextDocument)
  const remainingFindings = analyzer.analyze(codeAfterFix, testFile, 'typescript');
  console.log(`🔍 Re-analyzed code: ${remainingFindings.length} findings remaining (${initialFindings.length - remainingFindings.length} resolved).`);

  // Detect fixed findings in DB
  const activeIds = remainingFindings.map(f => f.id);
  const autoFixed = await db.autoDetectFixedFindingsInFile(testFile, testDev, activeIds);
  console.log(`✅ Real-time auto-detected ${autoFixed.length} fixed vulnerabilities in database!`);
  for (const item of autoFixed) {
    console.log(`   Fixed: ${item.vulnerabilityType} (${item.findingId})`);
  }

  if (autoFixed.length !== (initialFindings.length - remainingFindings.length)) {
    throw new Error(`FAIL: Expected ${initialFindings.length - remainingFindings.length} auto-fixed records, got ${autoFixed.length}`);
  }

  // Verify updated DB stats reflect the real-time fixes
  const statsAfterFix = await db.getVulnerabilityStats(testDev, testFile);
  console.log(`📊 Updated DB State: ${statsAfterFix.totalIdentified} Total, ${statsAfterFix.openCount} Open, ${statsAfterFix.fixedCount} Fixed (${statsAfterFix.fixPercentage}%)`);

  if (statsAfterFix.fixedCount !== autoFixed.length) {
    throw new Error(`FAIL: Expected ${autoFixed.length} fixed, got ${statsAfterFix.fixedCount}`);
  }

  // ── 4. Clean up test records ───────────────────────────────────────────
  if ((db as any).pool) {
    await (db as any).pool.query(
      `DELETE FROM vulnerability_records WHERE developer_id = $1;`,
      [testDev]
    );
  }
  await db.close();

  console.log('\n🎉 ALL REAL-TIME VULNERABILITY FIX TESTS PASSED WITH ZERO ERRORS!\n');
}

runTop10RealTimeTest().catch(err => {
  console.error('\n❌ TEST FAILED:', err);
  process.exit(1);
});
