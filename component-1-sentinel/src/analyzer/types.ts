/**
 * Sentinel — Security Finding Types
 * This is the TEAM CONTRACT between Component 1 (Sentinel) and Component 2 (Behaviour Tracker).
 * Do NOT change field names without coordinating with Member 2.
 */

import * as crypto from 'crypto';

// ─── Severity ────────────────────────────────────────────────────────────────

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH     = 'HIGH',
  MEDIUM   = 'MEDIUM',
  LOW      = 'LOW',
  INFO     = 'INFO',
}

// ─── Vulnerability Types ──────────────────────────────────────────────────────

export enum VulnerabilityType {
  SQL_INJECTION          = 'SQL_INJECTION',
  XSS                    = 'XSS',
  HARDCODED_SECRET       = 'HARDCODED_SECRET',
  COMMAND_INJECTION      = 'COMMAND_INJECTION',
  PATH_TRAVERSAL         = 'PATH_TRAVERSAL',
  MISSING_INPUT_VALIDATION = 'MISSING_INPUT_VALIDATION',
  UNSAFE_DESERIALIZATION = 'UNSAFE_DESERIALIZATION',
  WEAK_CRYPTOGRAPHY      = 'WEAK_CRYPTOGRAPHY',
  INSECURE_AUTH          = 'INSECURE_AUTH',
  SENSITIVE_DATA_EXPOSURE = 'SENSITIVE_DATA_EXPOSURE',

  // ── Added for full OWASP Top 10 (2021) coverage ──────────────────────────
  BROKEN_ACCESS_CONTROL      = 'BROKEN_ACCESS_CONTROL',       // A01
  NOSQL_INJECTION            = 'NOSQL_INJECTION',             // A03
  LDAP_INJECTION             = 'LDAP_INJECTION',              // A03
  XPATH_INJECTION            = 'XPATH_INJECTION',             // A03
  INSECURE_DESIGN            = 'INSECURE_DESIGN',             // A04
  SECURITY_MISCONFIGURATION  = 'SECURITY_MISCONFIGURATION',   // A05
  VULNERABLE_COMPONENT       = 'VULNERABLE_COMPONENT',        // A06
  SOFTWARE_INTEGRITY_FAILURE = 'SOFTWARE_INTEGRITY_FAILURE',  // A08
  INSUFFICIENT_LOGGING       = 'INSUFFICIENT_LOGGING',        // A09
  SSRF                       = 'SSRF',                        // A10
}

// ─── OWASP Top 10 (2021) mapping ──────────────────────────────────────────────

export interface OwaspCategory {
  /** e.g. 'A03:2021' */
  id: string;
  /** e.g. 'Injection' */
  name: string;
  /** Link to the official OWASP Top 10 page */
  url: string;
}

export const OWASP_TOP_10_2021: Record<string, OwaspCategory> = {
  A01: { id: 'A01:2021', name: 'Broken Access Control',                       url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
  A02: { id: 'A02:2021', name: 'Cryptographic Failures',                      url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' },
  A03: { id: 'A03:2021', name: 'Injection',                                   url: 'https://owasp.org/Top10/A03_2021-Injection/' },
  A04: { id: 'A04:2021', name: 'Insecure Design',                             url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/' },
  A05: { id: 'A05:2021', name: 'Security Misconfiguration',                   url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' },
  A06: { id: 'A06:2021', name: 'Vulnerable and Outdated Components',          url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' },
  A07: { id: 'A07:2021', name: 'Identification and Authentication Failures',  url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/' },
  A08: { id: 'A08:2021', name: 'Software and Data Integrity Failures',        url: 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/' },
  A09: { id: 'A09:2021', name: 'Security Logging and Monitoring Failures',    url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
  A10: { id: 'A10:2021', name: 'Server-Side Request Forgery (SSRF)',          url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' },
};

/** Which OWASP Top 10 category each vulnerability type belongs to. */
export const VULNERABILITY_TO_OWASP: Record<VulnerabilityType, string> = {
  [VulnerabilityType.BROKEN_ACCESS_CONTROL]:      'A01',
  [VulnerabilityType.PATH_TRAVERSAL]:             'A01',
  [VulnerabilityType.WEAK_CRYPTOGRAPHY]:          'A02',
  [VulnerabilityType.SENSITIVE_DATA_EXPOSURE]:    'A02',
  [VulnerabilityType.SQL_INJECTION]:              'A03',
  [VulnerabilityType.XSS]:                        'A03',
  [VulnerabilityType.COMMAND_INJECTION]:          'A03',
  [VulnerabilityType.NOSQL_INJECTION]:            'A03',
  [VulnerabilityType.LDAP_INJECTION]:             'A03',
  [VulnerabilityType.XPATH_INJECTION]:            'A03',
  [VulnerabilityType.INSECURE_DESIGN]:            'A04',
  [VulnerabilityType.MISSING_INPUT_VALIDATION]:   'A04',
  [VulnerabilityType.SECURITY_MISCONFIGURATION]:  'A05',
  [VulnerabilityType.VULNERABLE_COMPONENT]:       'A06',
  [VulnerabilityType.INSECURE_AUTH]:              'A07',
  [VulnerabilityType.HARDCODED_SECRET]:           'A07', // CWE-798 is listed under A07
  [VulnerabilityType.UNSAFE_DESERIALIZATION]:     'A08',
  [VulnerabilityType.SOFTWARE_INTEGRITY_FAILURE]: 'A08',
  [VulnerabilityType.INSUFFICIENT_LOGGING]:       'A09',
  [VulnerabilityType.SSRF]:                       'A10',
};

/** Resolve the OWASP Top 10 category for a vulnerability type. */
export function owaspCategoryFor(type: VulnerabilityType): OwaspCategory | undefined {
  const key = VULNERABILITY_TO_OWASP[type];
  return key ? OWASP_TOP_10_2021[key] : undefined;
}

// ─── Security Finding (the core output of Component 1) ───────────────────────

export interface SecurityFinding {
  /** Unique ID for this specific finding instance */
  id: string;
  /** Category of vulnerability */
  type: VulnerabilityType;
  /** How dangerous this is */
  severity: Severity;
  /** Confidence score 0.0–1.0 (e.g. 0.92 = 92% confident) */
  confidence: number;
  /** Human-readable warning message */
  message: string;
  /** Full path of the affected file */
  fileName: string;
  /** 1-indexed line number */
  lineNumber: number;
  /** 0-indexed column number */
  columnNumber: number;
  /** The actual vulnerable code snippet */
  codeSnippet: string;
  /** ISO 8601 timestamp of detection */
  detectedAt: string;
  /** Name of the rule that detected this */
  detectedByRule: string;
  /** Optional: OWASP Top 10 (2021) category id, e.g. 'A03:2021' */
  owaspCategory?: string;
  /** Optional: start offset in the document */
  rangeStart?: number;
  /** Optional: end offset in the document */
  rangeEnd?: number;
}

// ─── Developer Actions (behaviour events) ────────────────────────────────────

export enum DeveloperAction {
  DETECTED            = 'DETECTED',
  WARNING_SHOWN       = 'WARNING_SHOWN',
  EXPLANATION_VIEWED  = 'EXPLANATION_VIEWED',
  SECURE_EXAMPLE_VIEWED = 'SECURE_EXAMPLE_VIEWED',
  FIX_APPLIED         = 'FIX_APPLIED',
  IGNORED             = 'IGNORED',
  MARKED_FALSE_POSITIVE = 'MARKED_FALSE_POSITIVE',
  DISMISSED           = 'DISMISSED',
  FIXED               = 'FIXED',
}

// ─── Security Event (sent to Member 2 backend) ───────────────────────────────

export interface SecurityEvent {
  /** Optional: links action back to original detection */
  eventId?: string;
  /** Developer identifier from config */
  developerId: string;
  /** Session identifier */
  sessionId: string;
  /** The vulnerability type */
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
  confidence: number;
  fileName: string;
  lineNumber: number;
  action: DeveloperAction;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** How long (ms) from detection to action */
  responseTime?: number;
}

// ─── Rule Interface (implemented by each rule file) ──────────────────────────

export interface SecurityRule {
  /** Unique rule identifier */
  readonly ruleId: string;
  /** Human-readable rule name */
  readonly ruleName: string;
  /** What vulnerability this rule detects */
  readonly vulnerabilityType: VulnerabilityType;
  /** Which file languages this rule applies to (e.g. 'csharp', 'javascript') */
  readonly supportedLanguages: string[];
  /**
   * Analyze the document and return all findings.
   * @param text - Full document text
   * @param fileName - Path of the file
   * @param languageId - VS Code language ID
   */
  analyze(text: string, fileName: string, languageId: string): SecurityFinding[];
}

// ─── Vulnerability Metadata (for explanations) ───────────────────────────────

export interface VulnerabilityMetadata {
  type: VulnerabilityType;
  title: string;
  description: string;
  impact: string;
  recommendation: string;
  secureExample: string;
  references: string[];
}

/**
 * Computes a deterministic, stable finding ID across keystrokes and scan passes.
 *
 * This ensures:
 * 1. An open vulnerability maintains the SAME ID across typing events.
 * 2. It is only marked as FIXED when the insecure code is actually removed/corrected
 *    and the diagnostic red underline disappears from the editor.
 * 3. Does not generate duplicate records or churn false fix events.
 */
export function computeFindingId(
  fileName: string,
  type: string,
  ruleId: string,
  snippet: string,
  occurrence: number = 0
): string {
  const normFile = (fileName || '').replace(/\\/g, '/').toLowerCase();
  const normSnippet = (snippet || '').trim().replace(/\s+/g, ' ');
  const raw = `${normFile}:${type}:${ruleId}:${normSnippet}:${occurrence}`;
  return 'FND-' + crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);
}

