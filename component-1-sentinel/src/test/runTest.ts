/**
 * Sentinel — Automated Test Suite
 *
 * Runs self-contained tests across all OWASP Top 10 (2021) vulnerability detection rules.
 * Executed via `npm test` (`node ./out/test/runTest.js`).
 */

import { SecurityAnalyzer } from '../analyzer/securityAnalyzer.js';
import { VulnerabilityType, owaspCategoryFor } from '../analyzer/types.js';

interface TestCase {
  category: string;
  expectedType: VulnerabilityType;
  fileName: string;
  languageId: string;
  code: string;
  description: string;
}

const testCases: TestCase[] = [
  // ── A01: Broken Access Control ──────────────────────────────────────────────
  {
    category: 'A01:2021 Broken Access Control',
    expectedType: VulnerabilityType.PATH_TRAVERSAL,
    fileName: 'fileServer.js',
    languageId: 'javascript',
    code: `
      const path = req.params.filePath;
      const data = fs.readFileSync('/var/data/' + path);
    `,
    description: 'Path traversal via unsanitized file read',
  },
  {
    category: 'A01:2021 Broken Access Control (Open Redirect)',
    expectedType: VulnerabilityType.BROKEN_ACCESS_CONTROL,
    fileName: 'authRedirect.ts',
    languageId: 'typescript',
    code: `
      const target = req.query.url;
      res.redirect(target);
    `,
    description: 'Open redirect via unvalidated user parameter',
  },

  // ── A02: Cryptographic Failures ─────────────────────────────────────────────
  {
    category: 'A02:2021 Cryptographic Failures (Weak Hash)',
    expectedType: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    fileName: 'hasher.js',
    languageId: 'javascript',
    code: `
      const hash = crypto.createHash('md5').update(password).digest('hex');
    `,
    description: 'Weak cryptographic hash function (MD5)',
  },
  {
    category: 'A02:2021 Cryptographic Failures (Insecure Cipher)',
    expectedType: VulnerabilityType.WEAK_CRYPTOGRAPHY,
    fileName: 'encryptor.py',
    languageId: 'python',
    code: `
      cipher = AES.new(key, AES.MODE_ECB)
    `,
    description: 'ECB cipher mode without IV',
  },

  // ── A03: Injection ──────────────────────────────────────────────────────────
  {
    category: 'A03:2021 Injection (SQL)',
    expectedType: VulnerabilityType.SQL_INJECTION,
    fileName: 'userRepo.ts',
    languageId: 'typescript',
    code: `
      const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
      db.query(query);
    `,
    description: 'Classic SQL injection string concatenation',
  },
  {
    category: 'A03:2021 Injection (XSS)',
    expectedType: VulnerabilityType.XSS,
    fileName: 'profileView.js',
    languageId: 'javascript',
    code: `
      document.getElementById('bio').innerHTML = req.body.bio;
    `,
    description: 'Reflected DOM XSS via innerHTML',
  },
  {
    category: 'A03:2021 Injection (Command)',
    expectedType: VulnerabilityType.COMMAND_INJECTION,
    fileName: 'diagnostics.py',
    languageId: 'python',
    code: `
      os.system("ping -c 4 " + target_host)
    `,
    description: 'OS command injection via os.system',
  },
  {
    category: 'A03:2021 Injection (NoSQL)',
    expectedType: VulnerabilityType.NOSQL_INJECTION,
    fileName: 'userModel.js',
    languageId: 'javascript',
    code: `
      User.find({ username: req.body.username, password: req.body.password });
    `,
    description: 'NoSQL object injection passing req.body directly to query',
  },

  // ── A04: Insecure Design ───────────────────────────────────────────────────
  {
    category: 'A04:2021 Insecure Design',
    expectedType: VulnerabilityType.INSECURE_DESIGN,
    fileName: 'routes.py',
    languageId: 'python',
    code: `
      @app.route('/api/v1/auth/login')
      def login():
          return "Logged in"
    `,
    description: 'Unthrottled authentication endpoint without rate-limiting',
  },
  {
    category: 'A04:2021 Insecure Design (Client-trusted Price)',
    expectedType: VulnerabilityType.INSECURE_DESIGN,
    fileName: 'checkout.js',
    languageId: 'javascript',
    code: `
      const price = req.body.price;
      order.total = price;
    `,
    description: 'Critical business values trusted directly from client',
  },

  // ── A05: Security Misconfiguration ──────────────────────────────────────────
  {
    category: 'A05:2021 Security Misconfiguration',
    expectedType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    fileName: 'settings.py',
    languageId: 'python',
    code: `
      DEBUG = True
      ALLOWED_HOSTS = ['*']
    `,
    description: 'Production debug mode enabled in Django settings',
  },
  {
    category: 'A05:2021 Security Misconfiguration (XXE)',
    expectedType: VulnerabilityType.SECURITY_MISCONFIGURATION,
    fileName: 'XmlProcessor.java',
    languageId: 'java',
    code: `
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.parse(inputStream);
    `,
    description: 'XML parser with external entities enabled (XXE)',
  },

  // ── A06: Vulnerable and Outdated Components ─────────────────────────────────
  {
    category: 'A06:2021 Vulnerable Components',
    expectedType: VulnerabilityType.VULNERABLE_COMPONENT,
    fileName: 'package.json',
    languageId: 'json',
    code: JSON.stringify({
      name: 'demo-app',
      dependencies: {
        'lodash': '4.17.20',
        'jsonwebtoken': '8.5.1'
      }
    }, null, 2),
    description: 'Manifest referencing known vulnerable dependency version',
  },

  // ── A07: Identification and Authentication Failures ─────────────────────────
  {
    category: 'A07:2021 Identification & Auth Failures (Hardcoded Secret)',
    expectedType: VulnerabilityType.HARDCODED_SECRET,
    fileName: 'config.ts',
    languageId: 'typescript',
    code: `
      const API_SECRET = process.env.API_SECRET || "demo-placeholder";
    `,
    description: 'Production API key hardcoded in source file',
  },
  {
    category: 'A07:2021 Identification & Auth Failures (None Algorithm)',
    expectedType: VulnerabilityType.INSECURE_AUTH,
    fileName: 'tokenValidator.js',
    languageId: 'javascript',
    code: `
      jwt.verify(token, secret, { algorithms: ['none'] });
    `,
    description: 'JWT verification accepting "none" algorithm',
  },

  // ── A08: Software and Data Integrity Failures ───────────────────────────────
  {
    category: 'A08:2021 Software & Data Integrity Failures',
    expectedType: VulnerabilityType.UNSAFE_DESERIALIZATION,
    fileName: 'sessionDeserializer.py',
    languageId: 'python',
    code: `
      user_obj = pickle.loads(raw_data)
    `,
    description: 'Unsafe deserialization using Python pickle',
  },
  {
    category: 'A08:2021 Software & Data Integrity Failures (Java)',
    expectedType: VulnerabilityType.UNSAFE_DESERIALIZATION,
    fileName: 'PayloadReceiver.java',
    languageId: 'java',
    code: `
      ObjectInputStream ois = new ObjectInputStream(inputStream);
      Object obj = ois.readObject();
    `,
    description: 'Java ObjectInputStream.readObject on untrusted input',
  },

  // ── A09: Security Logging and Monitoring Failures ───────────────────────────
  {
    category: 'A09:2021 Security Logging Failures',
    expectedType: VulnerabilityType.INSUFFICIENT_LOGGING,
    fileName: 'loginHandler.ts',
    languageId: 'typescript',
    code: `
      console.log("Authentication attempt for user:", username, password);
    `,
    description: 'Sensitive credentials logged to console/logger',
  },
  {
    category: 'A09:2021 Security Logging Failures (Swallowed Exception)',
    expectedType: VulnerabilityType.INSUFFICIENT_LOGGING,
    fileName: 'authService.ts',
    languageId: 'typescript',
    code: `
      try {
        validateSecurityToken(token);
      } catch (err) {
        // do nothing
      }
    `,
    description: 'Security exception caught and silently ignored without logging',
  },

  // ── A10: Server-Side Request Forgery (SSRF) ─────────────────────────────────
  {
    category: 'A10:2021 Server-Side Request Forgery',
    expectedType: VulnerabilityType.SSRF,
    fileName: 'webhookProxy.ts',
    languageId: 'typescript',
    code: `
      const targetUrl = req.query.url;
      const response = await fetch(targetUrl);
    `,
    description: 'Direct outbound HTTP request to client-supplied URL',
  },
  {
    category: 'A10:2021 Server-Side Request Forgery (Cloud Metadata)',
    expectedType: VulnerabilityType.SSRF,
    fileName: 'cloudFetcher.py',
    languageId: 'python',
    code: `
      requests.get("http://169.254.169.254/latest/meta-data/")
    `,
    description: 'Outbound HTTP request targeting cloud metadata service IP',
  },
];

export function runAllTests(): boolean {
  console.log('================================================================');
  console.log('  SENTINEL — REAL-TIME OWASP TOP 10 (2021) TEST SUITE');
  console.log('================================================================\n');

  const analyzer = new SecurityAnalyzer();
  const rules = analyzer.getRules();

  console.log(`[Setup] Registered Rule Count: ${rules.length}`);
  for (const rule of rules) {
    console.log(`  • [${rule.ruleId}] ${rule.ruleName} (${rule.vulnerabilityType})`);
  }
  console.log('');

  let passedCount = 0;
  let failedCount = 0;

  for (const [index, tc] of testCases.entries()) {
    const testNum = index + 1;
    const findings = analyzer.analyze(tc.code, tc.fileName, tc.languageId);

    const match = findings.find(
      (f) =>
        f.type === tc.expectedType ||
        owaspCategoryFor(f.type)?.id === owaspCategoryFor(tc.expectedType)?.id
    );

    if (match) {
      passedCount++;
      const owasp = owaspCategoryFor(match.type);
      console.log(
        `[PASS] #${testNum.toString().padStart(2, '0')} ${tc.category}`
      );
      console.log(
        `       File: ${tc.fileName} | Detected: ${match.type} [${owasp?.id || 'N/A'}] (Severity: ${match.severity}, Conf: ${Math.round(match.confidence * 100)}%)`
      );
    } else {
      failedCount++;
      console.error(
        `[FAIL] #${testNum.toString().padStart(2, '0')} ${tc.category}`
      );
      console.error(
        `       File: ${tc.fileName} | Expected: ${tc.expectedType} | Actual: [${findings.map((f) => f.type).join(', ') || 'NONE'}]`
      );
    }
  }

  console.log('\n----------------------------------------------------------------');
  console.log(`Total Tests : ${testCases.length}`);
  console.log(`Passed      : ${passedCount}`);
  console.log(`Failed      : ${failedCount}`);
  console.log(`Success Rate: ${Math.round((passedCount / testCases.length) * 100)}%`);
  console.log('----------------------------------------------------------------');

  return failedCount === 0;
}

// When executed directly via node
if (require.main === module) {
  const success = runAllTests();
  process.exit(success ? 0 : 1);
}
