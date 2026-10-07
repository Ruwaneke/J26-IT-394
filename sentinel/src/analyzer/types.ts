/**
 * Sentinel — Security Finding Types
 * This is the TEAM CONTRACT between Component 1 (Sentinel) and Component 2 (Behaviour Tracker).
 * Do NOT change field names without coordinating with Member 2.
 */

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
