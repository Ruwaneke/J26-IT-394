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
}

export interface LifecycleHistory {
  id: number;
  securityEventId: number;
  previousStatus: SecurityEventStatus | null;
  newStatus: SecurityEventStatus;
  changedAt: string;
  changedBy: string | null;
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
