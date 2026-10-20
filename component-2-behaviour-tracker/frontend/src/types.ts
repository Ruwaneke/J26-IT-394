export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type SecurityEventStatus =
  | 'DETECTED'
  | 'OPENED'
  | 'FIXED'
  | 'IGNORED'
  | 'REOPENED';

export type BehaviourAction =
  | 'OPEN'
  | 'FIX'
  | 'IGNORE'
  | 'DISMISS'
  | 'REOPEN';

/** Set on FIX interactions only. A FIX is a claim; VERIFIED needs a verification source. */
export type FixVerificationStatus = 'CLAIMED' | 'VERIFIED' | 'STILL_VULNERABLE';

export interface Developer {
  id: number;
  developerIdentifier: string;
  githubId: string | null;
  githubUsername: string | null;
  email: string | null;
  createdAt: string;
}

export interface SecurityEvent {
  id: number;
  developerId: number;
  vulnerabilityType: string;
  severity: Severity;
  fileName: string;
  lineNumber: number;
  message: string;
  currentStatus: SecurityEventStatus;
  detectedAt: string;
}

export interface DeveloperInteraction {
  id: number;
  developerId: number;
  securityEventId: number | null;
  action: BehaviourAction;
  actionTimestamp: string;
  timeSinceDetectionSeconds: number | null;
  sessionId?: string | null;
  source?: string | null;
  metadata?: string | null;
  fixVerification?: FixVerificationStatus | null;
}

export interface LifecycleHistory {
  id: number;
  securityEventId: number;
  previousStatus: SecurityEventStatus | null;
  newStatus: SecurityEventStatus;
  changedAt: string;
  changedBy: string | null;
  entryHash?: string | null;
}

export interface DeveloperBehaviourSummary {
  developerId: number;
  totalSecurityEvents: number;
  openedCount: number;
  fixedCount: number;
  ignoredCount: number;
  dismissedCount: number;
  reopenedCount: number;
  fixRate: number | null;
  ignoreRate: number | null;
  reopenRate: number | null;
  highSeverityFixRate: number | null;
  /** Fixes confirmed by a verification source; fixedCount and fixRate count claimed fixes. */
  verifiedFixCount: number;
  verifiedFixRate: number | null;
  averageResponseTimeSeconds: number | null;
  repeatedVulnerabilityCount: number;
  behaviourClassification: string;
}

export interface ClassificationRule {
  code: string;
  label: string;
  tone: 'neutral' | 'good' | 'critical' | 'warning' | 'info';
  icon: string;
  summary: string;
  rule: string;
}

// ── Quality & Regression Tests page (TASKS P1-5) ──────────────────────────────
// Mirrors frontend/dev/surefireReport.mjs and qualityPlugin.mjs, not a backend DTO.

export type TestCategoryId = 'api-contract' | 'auth' | 'lifecycle' | 'hash-chain' | 'database' | 'regression';

export type TestCaseStatus = 'PASS' | 'FAIL' | 'ERROR' | 'SKIPPED';

export interface TestCounts {
  tests: number;
  passed: number;
  failed: number;
  errors: number;
  skipped: number;
}

export interface TestCaseResult {
  id: string;
  className: string;
  simpleClassName: string;
  name: string;
  category: TestCategoryId;
  status: TestCaseStatus;
  durationSeconds: number;
  failure: { type: string | null; message: string | null; stackTrace: string | null } | null;
}

export interface TestReport {
  schemaVersion: number;
  generatedAt: string;
  executedAt: string | null;
  source: string;
  status: 'PASSED' | 'FAILED' | 'NO_TESTS';
  totals: TestCounts & { durationSeconds: number; classes: number };
  categories: (TestCounts & { id: TestCategoryId; label: string; description: string })[];
  testCases: TestCaseResult[];
}

export interface TestRunState {
  state: 'idle' | 'running' | 'passed' | 'failed' | 'runner-error';
  reason: 'maven-not-found' | 'spawn-failed' | 'timeout' | 'no-test-results' | null;
  message: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  exitCode: number | null;
  outputTail: string[];
}

export interface QualityStatus {
  runnerAvailable: boolean;
  run: TestRunState;
  report: TestReport | null;
}
