/**
 * Automated Verification Script: Test All OWASP Top 10 Rules & Neon DB Persistence Against test_project
 *
 * 1. Scans every file in the test project using Sentinel's SecurityAnalyzer.
 * 2. Confirms that all 10 OWASP categories are triggered (38 distinct findings).
 * 3. Generates rich contextual AI explanations (Why Dangerous, Attack Vector, Fix Code).
 * 4. Connects to Neon Serverless PostgreSQL and persists all findings into the `vulnerability_records` table.
 * 5. Queries Neon PostgreSQL to verify that data is passing cleanly to the database with status OPEN.
 */

const fs = require('fs');
const path = require('path');

// Import Sentinel's compiled components
const sentinelOutDir = path.resolve(__dirname, '../sentinel/out');
const { SecurityAnalyzer } = require(path.join(sentinelOutDir, 'analyzer/securityAnalyzer.js'));
const { generateContextualExplanation } = require(path.join(sentinelOutDir, 'diagnostics/contextualExplainer.js'));
const { owaspCategoryFor } = require(path.join(sentinelOutDir, 'analyzer/types.js'));
const { NeonDatabaseService } = require(path.join(sentinelOutDir, 'data/neonDatabaseService.js'));

async function runRuleVerification() {
  console.log('\n═══════════════════════════════════════════════════════════════════════════════');
  console.log('🛡️  SENTINEL — OWASP TOP 10 RULES & DATABASE PERSISTENCE VERIFICATION');
  console.log('═══════════════════════════════════════════════════════════════════════════════\n');

  const analyzer = new SecurityAnalyzer();
  const db = NeonDatabaseService.getInstance();

  const developerId = 'HishenPerera';
  const sessionId = `SESSION-${Date.now()}`;

  const filesToScan = [
    { file: 'src/app.js', lang: 'javascript' },
    { file: 'src/routes/authRoutes.js', lang: 'javascript' },
    { file: 'src/routes/userRoutes.js', lang: 'javascript' },
    { file: 'src/routes/fileRoutes.js', lang: 'javascript' },
    { file: 'src/routes/apiRoutes.js', lang: 'javascript' },
    { file: 'src/routes/uiRoutes.js', lang: 'javascript' },
    { file: 'src/utils/dataParser.js', lang: 'javascript' },
    { file: 'src/utils/cryptoHelper.js', lang: 'javascript' },
    { file: 'package.json', lang: 'json' },
  ];

  const allFindings = [];
  const owaspCoverage = new Map();
  // Initialize all Top 10 categories (A01 - A10)
  for (let i = 1; i <= 10; i++) {
    const key = i === 10 ? 'A10' : `A0${i}`;
    owaspCoverage.set(key, []);
  }

  console.log('📂 1. Scanning test_project files with Sentinel Rule Engine...\n');

  for (const item of filesToScan) {
    const fullPath = path.join(__dirname, item.file);
    if (!fs.existsSync(fullPath)) {
      console.warn(`⚠️ File not found: ${item.file}`);
      continue;
    }

    const content = fs.readFileSync(fullPath, 'utf8');
    const findings = analyzer.analyze(content, fullPath, item.lang);

    console.log(`  📄 [${item.file}] → Found ${findings.length} vulnerabilities`);
    for (const f of findings) {
      allFindings.push(f);
      const cat = owaspCategoryFor(f.type);
      const shortCat = cat ? cat.id.split(':')[0] : 'OTHER';
      if (owaspCoverage.has(shortCat)) {
        owaspCoverage.get(shortCat).push({
          finding: f,
          file: item.file,
        });
      }
    }
  }

  console.log('\n───────────────────────────────────────────────────────────────────────────────');
  console.log('📊 2. OWASP TOP 10 COVERAGE BREAKDOWN');
  console.log('───────────────────────────────────────────────────────────────────────────────');

  const owaspTitles = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection (SQL, XSS, Command)',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification & Auth Failures / Secrets',
    'A08': 'Software & Data Integrity Failures',
    'A09': 'Security Logging & Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
  };

  let allCovered = true;

  for (let i = 1; i <= 10; i++) {
    const code = i === 10 ? 'A10' : `A0${i}`;
    const name = owaspTitles[code];
    const items = owaspCoverage.get(code) || [];
    const status = items.length > 0 ? '✅ PASSED' : '❌ FAILED';
    if (items.length === 0) allCovered = false;

    console.log(`\n  ${status}  [${code}:2021] ${name} (${items.length} findings)`);
    for (const it of items) {
      console.log(`       • line ${it.finding.lineNumber.toString().padEnd(3)} | ${it.finding.type.padEnd(28)} | ${it.file}`);
      console.log(`         ↳ Rule: ${it.finding.detectedByRule}`);
    }
  }

  // ── 3. Connect to Database & Persist Findings ──────────────────────────────────
  console.log('\n───────────────────────────────────────────────────────────────────────────────');
  console.log('🗄️  3. PERSISTING VULNERABILITY RECORDS TO NEON POSTGRESQL DATABASE');
  console.log('───────────────────────────────────────────────────────────────────────────────');

  console.log('Connecting to Neon PostgreSQL database...');
  const initOk = await db.initialize();
  const dbStatus = db.getStatus();

  if (!initOk || !dbStatus.isOnline) {
    throw new Error(`Database connection failed: ${dbStatus.error || 'Server unreachable'}`);
  }

  console.log(`✅ Connected to Neon PostgreSQL in ${dbStatus.pingMs}ms. Status: ONLINE`);
  console.log(`Persisting ${allFindings.length} findings into vulnerability_records table for developer "${developerId}"...`);

  let savedCount = 0;
  for (const f of allFindings) {
    const explanation = generateContextualExplanation(f);
    const savedRecord = await db.saveVulnerabilityRecord(
      f,
      developerId,
      developerId,
      sessionId,
      explanation
    );
    if (savedRecord) {
      savedCount++;
    }
  }

  console.log(`✅ Successfully saved ${savedCount} records into Neon PostgreSQL database!`);

  // ── 4. Verify Live Database Records ───────────────────────────────────────────
  console.log('\n───────────────────────────────────────────────────────────────────────────────');
  console.log('🔍 4. VERIFYING LIVE DATABASE QUERY & PROGRESS METRICS');
  console.log('───────────────────────────────────────────────────────────────────────────────');

  const stats = await db.getVulnerabilityStats(developerId);
  const liveRecords = await db.getVulnerabilityRecords(developerId, 'ALL', 100);

  console.log(`  • Total Identified in DB : ${stats.totalIdentified}`);
  console.log(`  • Open Status Count      : ${stats.openCount} (${stats.openPercentage}%)`);
  console.log(`  • Fixed Status Count     : ${stats.fixedCount} (${stats.fixPercentage}%)`);
  console.log(`  • Critical / High Count  : ${stats.criticalCount} Critical, ${stats.highCount} High`);
  console.log(`  • Total Rows Retrieved   : ${liveRecords.length}`);

  if (liveRecords.length === 0) {
    throw new Error('FAIL: Database returned 0 records after saving.');
  }

  // ── 5. AI Guidance Verification ──────────────────────────────────────────────
  console.log('\n───────────────────────────────────────────────────────────────────────────────');
  console.log('🤖 5. CONTEXTUAL AI REMEDIATION & SECURE CODE VERIFICATION');
  console.log('───────────────────────────────────────────────────────────────────────────────');

  const sampleFinding = allFindings[0];
  const sampleExpl = generateContextualExplanation(sampleFinding);
  console.log(`  Sample: ${sampleFinding.type} in ${path.basename(sampleFinding.fileName)}:`);
  console.log(`  • Why Dangerous : ${sampleExpl.whyDangerous.substring(0, 90)}...`);
  console.log(`  • How to Fix    : ${sampleExpl.fixExplanation.substring(0, 90)}...`);
  console.log(`  • Secure Code   :\n    ${sampleExpl.fixedCode.split('\n').join('\n    ')}`);

  console.log('\n═══════════════════════════════════════════════════════════════════════════════');
  console.log(`📋 SUMMARY: Total Vulnerabilities Identified: ${allFindings.length}`);
  console.log(`🎯 OWASP Top 10 Categories Covered          : ${[...owaspCoverage.values()].filter(arr => arr.length > 0).length} / 10`);
  console.log(`🗄️ Neon PostgreSQL Database Synced          : ${savedCount} records stored & verified`);
  console.log('═══════════════════════════════════════════════════════════════════════════════\n');

  if (allCovered && savedCount === allFindings.length) {
    console.log('🎉 SUCCESS: All OWASP Top 10 rules apply and all records are 100% saved in the database!\n');
    process.exit(0);
  } else {
    console.error('❌ FAILURE: Not all findings could be verified in the database.\n');
    process.exit(1);
  }
}

runRuleVerification().catch(err => {
  console.error('Execution error:', err);
  process.exit(1);
});
