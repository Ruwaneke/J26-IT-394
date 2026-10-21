/**
 * Sentinel — Developer Insights
 *
 * Pure computations over Component 1's raw data (live findings, Neon DB
 * vulnerability records, learning profile, activity logs, shift sessions).
 *
 * The same insight object feeds two consumers:
 *   1. The developer dashboard (Detect / Behaviour / Feedback / Analytics / Shift tabs)
 *   2. The Sentinel API server, which exposes it to Component 2 (Behaviour Tracker)
 *
 * Keeping the maths in one place guarantees the dashboard and the API never disagree.
 */

import { SecurityFinding, owaspCategoryFor, VulnerabilityType } from '../analyzer/types.js';
import { DbVulnerabilityRecord, UserActivityLog } from '../data/neonDatabaseService.js';
import { DeveloperLearningProfile } from '../ai/developerLearningStore.js';
import { ShiftSession } from '../data/projectStore.js';
import { VULNERABILITY_METADATA } from '../diagnostics/vulnerabilityMetadata.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TypeFixRate {
  vulnerabilityType: string;
  detected: number;
  fixed: number;
  ignored: number;
  open: number;
  /** fixed / detected, 0–100 with one decimal */
  fixRate: number;
}

export interface DailyTrendPoint {
  /** YYYY-MM-DD */
  date: string;
  detected: number;
  fixed: number;
}

export type BehaviourPattern = 'PROACTIVE_FIXER' | 'STEADY' | 'DISMISSIVE' | 'AT_RISK' | 'NEW';

export interface BehaviourProfile {
  pattern: BehaviourPattern;
  patternLabel: string;
  /** fixed / (fixed + ignored), 0–100 — how often a developer acts on a warning rather than dismissing it */
  responsivenessRate: number;
  /** ignored / total, 0–100 */
  ignoreRate: number;
  /** Mean minutes from detection to fix (null = no fixes yet) */
  meanTimeToFixMinutes: number | null;
  /** Median minutes from detection to fix (null = no fixes yet) */
  medianTimeToFixMinutes: number | null;
  /** Vulnerability types the developer has introduced 3+ times */
  repeatedMistakes: Array<{ vulnerabilityType: string; occurrences: number; fixed: number }>;
  /** Types the AI learning store has suppressed for this developer (high false-positive / ignore rate) */
  suppressedTypes: string[];
  /** Counts of activity-log action types (e.g. VULNERABILITY_FIXED, LOGIN) */
  actionCounts: Record<string, number>;
}

export interface FeedbackItem {
  vulnerabilityType: string;
  title: string;
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  recommendation: string;
  secureExample: string;
  references: string[];
}

export interface FeedbackRating {
  findingId: string | null;
  vulnerabilityType: string | null;
  helpful: boolean;
  comment: string | null;
  ratedAt: string;
}

export interface ShiftInsight {
  sessionsCompleted: number;
  totalShiftMinutes: number;
  findingsPerHour: number;
  averageSecurityScore: number | null;
  latestTrend: 'improving' | 'declining' | 'stable' | null;
}

export interface DeveloperInsights {
  developerId: string;
  generatedAt: string;
  totals: {
    identified: number;
    fixed: number;
    open: number;
    ignored: number;
    liveWarnings: number;
    fixRate: number;
    openRate: number;
  };
  severity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO', number>;
  liveSeverity: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO', number>;
  owasp: Array<{ id: string; name: string; count: number }>;
  fixRateByType: TypeFixRate[];
  trend: DailyTrendPoint[];
  topFiles: Array<{ fileName: string; open: number; total: number }>;
  behaviour: BehaviourProfile;
  feedback: FeedbackItem[];
  feedbackRatings: FeedbackRating[];
  shift: ShiftInsight;
}

export interface InsightInputs {
  developerId: string;
  liveFindings: SecurityFinding[];
  records: DbVulnerabilityRecord[];
  learningProfile: DeveloperLearningProfile | null;
  activities: UserActivityLog[];
  shiftSessions: ShiftSession[];
  trendDays?: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const pct = (num: number, den: number): number =>
  den > 0 ? Math.round((num / den) * 1000) / 10 : 0;

const emptySeverity = () => ({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

function dayKey(iso: string | null | undefined): string | null {
  if (!iso) { return null; }
  const d = new Date(iso);
  return isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10);
}

function median(values: number[]): number | null {
  if (values.length === 0) { return null; }
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

const round1 = (n: number) => Math.round(n * 10) / 10;

// ─── Main entry point ─────────────────────────────────────────────────────────

export function computeDeveloperInsights(input: InsightInputs): DeveloperInsights {
  const { developerId, liveFindings, records, learningProfile, activities, shiftSessions } = input;
  const trendDays = input.trendDays ?? 14;

  // ── Totals ──
  const fixed   = records.filter(r => r.status === 'FIXED').length;
  const ignored = records.filter(r => r.status === 'IGNORED' || r.status === 'FALSE_POSITIVE').length;
  const open    = Math.max(liveFindings.length, records.filter(r => r.status === 'OPEN').length);
  const identified = Math.max(records.length, fixed + ignored + open);

  // ── Severity (historical + live) ──
  const severity = emptySeverity();
  for (const r of records) {
    const k = (r.severity?.toUpperCase() ?? 'INFO') as keyof typeof severity;
    if (k in severity) { severity[k]++; }
  }
  const liveSeverity = emptySeverity();
  for (const f of liveFindings) {
    const k = f.severity as keyof typeof liveSeverity;
    if (k in liveSeverity) { liveSeverity[k]++; }
  }

  // ── OWASP distribution ──
  const owaspMap = new Map<string, { id: string; name: string; count: number }>();
  for (const r of records) {
    const cat = owaspCategoryFor(r.vulnerabilityType as VulnerabilityType);
    const key = cat?.id ?? 'OTHER';
    const entry = owaspMap.get(key) ?? { id: key, name: cat?.name ?? 'Other', count: 0 };
    entry.count++;
    owaspMap.set(key, entry);
  }
  const owasp = [...owaspMap.values()].sort((a, b) => a.id.localeCompare(b.id));

  // ── Fix rate per vulnerability type ──
  const typeMap = new Map<string, TypeFixRate>();
  for (const r of records) {
    const t = typeMap.get(r.vulnerabilityType) ?? {
      vulnerabilityType: r.vulnerabilityType, detected: 0, fixed: 0, ignored: 0, open: 0, fixRate: 0,
    };
    t.detected++;
    if (r.status === 'FIXED') { t.fixed++; }
    else if (r.status === 'OPEN') { t.open++; }
    else { t.ignored++; }
    typeMap.set(r.vulnerabilityType, t);
  }
  const fixRateByType = [...typeMap.values()]
    .map(t => ({ ...t, fixRate: pct(t.fixed, t.detected) }))
    .sort((a, b) => b.detected - a.detected);

  // ── Daily trend (detected vs fixed) ──
  const trendMap = new Map<string, DailyTrendPoint>();
  const today = new Date();
  for (let i = trendDays - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const k = d.toISOString().slice(0, 10);
    trendMap.set(k, { date: k, detected: 0, fixed: 0 });
  }
  for (const r of records) {
    const dk = dayKey(r.detectedAt);
    if (dk && trendMap.has(dk)) { trendMap.get(dk)!.detected++; }
    const fk = r.status === 'FIXED' ? dayKey(r.fixedAt) : null;
    if (fk && trendMap.has(fk)) { trendMap.get(fk)!.fixed++; }
  }
  const trend = [...trendMap.values()];

  // ── Top files ──
  const fileMap = new Map<string, { fileName: string; open: number; total: number }>();
  for (const r of records) {
    const name = (r.fileName || '').replace(/\\/g, '/').split('/').pop() || r.fileName;
    const e = fileMap.get(name) ?? { fileName: name, open: 0, total: 0 };
    e.total++;
    if (r.status === 'OPEN') { e.open++; }
    fileMap.set(name, e);
  }
  const topFiles = [...fileMap.values()].sort((a, b) => b.total - a.total).slice(0, 8);

  // ── Behaviour ──
  const behaviour = computeBehaviour(records, learningProfile, activities, fixed, ignored, identified);

  // ── Feedback (personalised recommendations) ──
  const feedback = computeFeedback(fixRateByType, behaviour, liveFindings);

  // ── Feedback ratings (stored as FEEDBACK_RATED activity logs) ──
  const feedbackRatings: FeedbackRating[] = activities
    .filter(a => a.actionType === 'FEEDBACK_RATED')
    .map(a => {
      const d = typeof a.details === 'string' ? safeJson(a.details) : (a.details ?? {});
      return {
        findingId: a.findingId ?? null,
        vulnerabilityType: a.vulnerabilityType ?? null,
        helpful: !!d.helpful,
        comment: d.comment ?? null,
        ratedAt: a.createdAt,
      };
    });

  // ── Shift ──
  const shift = computeShiftInsight(shiftSessions);

  return {
    developerId,
    generatedAt: new Date().toISOString(),
    totals: {
      identified,
      fixed,
      open,
      ignored,
      liveWarnings: liveFindings.length,
      fixRate: pct(fixed, identified),
      openRate: pct(open, identified),
    },
    severity,
    liveSeverity,
    owasp,
    fixRateByType,
    trend,
    topFiles,
    behaviour,
    feedback,
    feedbackRatings,
    shift,
  };
}

function safeJson(s: string): any {
  try { return JSON.parse(s); } catch { return {}; }
}

function computeBehaviour(
  records: DbVulnerabilityRecord[],
  profile: DeveloperLearningProfile | null,
  activities: UserActivityLog[],
  fixed: number,
  ignored: number,
  identified: number,
): BehaviourProfile {
  const fixMinutes = records
    .filter(r => r.status === 'FIXED' && r.fixedAt && r.detectedAt)
    .map(r => (new Date(r.fixedAt!).getTime() - new Date(r.detectedAt).getTime()) / 60000)
    .filter(m => Number.isFinite(m) && m >= 0);

  const meanTimeToFixMinutes = fixMinutes.length
    ? round1(fixMinutes.reduce((a, b) => a + b, 0) / fixMinutes.length)
    : null;
  const med = median(fixMinutes);

  // Repeated mistakes: prefer the learning profile (counts every detection ever),
  // fall back to DB record counts.
  const repeated = new Map<string, { vulnerabilityType: string; occurrences: number; fixed: number }>();
  if (profile) {
    for (const [type, l] of Object.entries(profile.vulnLearning)) {
      if (l) { repeated.set(type, { vulnerabilityType: type, occurrences: l.totalDetections, fixed: l.totalFixes }); }
    }
  }
  for (const r of records) {
    const e = repeated.get(r.vulnerabilityType);
    if (!e) {
      repeated.set(r.vulnerabilityType, { vulnerabilityType: r.vulnerabilityType, occurrences: 1, fixed: r.status === 'FIXED' ? 1 : 0 });
    } else if (!profile?.vulnLearning[r.vulnerabilityType as VulnerabilityType]) {
      e.occurrences++;
      if (r.status === 'FIXED') { e.fixed++; }
    }
  }
  const repeatedMistakes = [...repeated.values()]
    .filter(r => r.occurrences >= 3)
    .sort((a, b) => b.occurrences - a.occurrences);

  const suppressedTypes = profile
    ? Object.entries(profile.vulnLearning).filter(([, l]) => l?.suppressed).map(([t]) => t)
    : [];

  const actionCounts: Record<string, number> = {};
  for (const a of activities) {
    actionCounts[a.actionType] = (actionCounts[a.actionType] ?? 0) + 1;
  }

  const responsivenessRate = pct(fixed, fixed + ignored);
  const ignoreRate = pct(ignored, identified);

  let pattern: BehaviourPattern;
  let patternLabel: string;
  if (identified < 3) {
    pattern = 'NEW'; patternLabel = 'Building baseline — not enough data yet';
  } else if (ignoreRate >= 40) {
    pattern = 'DISMISSIVE'; patternLabel = 'Frequently dismisses warnings without fixing';
  } else if (repeatedMistakes.some(r => r.occurrences >= 5 && r.fixed / r.occurrences < 0.5)) {
    pattern = 'AT_RISK'; patternLabel = 'Repeats the same vulnerability types';
  } else if (pct(fixed, identified) >= 70 && (med ?? Infinity) <= 30) {
    pattern = 'PROACTIVE_FIXER'; patternLabel = 'Fixes warnings quickly and consistently';
  } else {
    pattern = 'STEADY'; patternLabel = 'Fixes most warnings over time';
  }

  return {
    pattern,
    patternLabel,
    responsivenessRate,
    ignoreRate,
    meanTimeToFixMinutes,
    medianTimeToFixMinutes: med === null ? null : round1(med),
    repeatedMistakes,
    suppressedTypes,
    actionCounts,
  };
}

function computeFeedback(
  byType: TypeFixRate[],
  behaviour: BehaviourProfile,
  liveFindings: SecurityFinding[],
): FeedbackItem[] {
  const items: FeedbackItem[] = [];
  const seen = new Set<string>();
  const liveTypes = new Set(liveFindings.map(f => f.type as string));

  const push = (type: string, priority: FeedbackItem['priority'], reason: string) => {
    if (seen.has(type)) { return; }
    seen.add(type);
    const meta = VULNERABILITY_METADATA[type as VulnerabilityType];
    items.push({
      vulnerabilityType: type,
      title: meta?.title ?? type.replace(/_/g, ' '),
      priority,
      reason,
      recommendation: (meta?.recommendation ?? 'Review the OWASP guidance for this category.').replace(/\*\*/g, ''),
      secureExample: meta?.secureExample ?? '',
      references: meta?.references ?? [],
    });
  };

  // 1. Repeated mistakes — highest value feedback
  for (const r of behaviour.repeatedMistakes) {
    push(r.vulnerabilityType, 'HIGH',
      `You have introduced this ${r.occurrences} times and fixed ${r.fixed}. Building the secure habit below will stop it recurring.`);
  }
  // 2. Types with a low fix rate
  for (const t of byType) {
    if (t.detected >= 2 && t.fixRate < 50) {
      push(t.vulnerabilityType, 'MEDIUM',
        `Only ${t.fixRate}% of these warnings (${t.fixed}/${t.detected}) have been fixed so far.`);
    }
  }
  // 3. Currently open in the editor
  for (const type of liveTypes) {
    push(type, 'LOW', 'Currently open in your editor.');
  }
  return items;
}

function computeShiftInsight(sessions: ShiftSession[]): ShiftInsight {
  const completed = sessions.filter(s => s.endedAt);
  let minutes = 0;
  let findings = 0;
  const scores: number[] = [];
  for (const s of completed) {
    const m = (new Date(s.endedAt!).getTime() - new Date(s.startedAt).getTime()) / 60000;
    if (Number.isFinite(m) && m > 0) { minutes += m; }
    findings += s.findings.length;
    if (s.summary) { scores.push(s.summary.securityScore); }
  }
  const latest = [...completed]
    .sort((a, b) => (b.endedAt ?? '').localeCompare(a.endedAt ?? ''))
    .find(s => s.summary);
  return {
    sessionsCompleted: completed.length,
    totalShiftMinutes: Math.round(minutes),
    findingsPerHour: minutes > 0 ? round1(findings / (minutes / 60)) : 0,
    averageSecurityScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
    latestTrend: latest?.summary?.trend ?? null,
  };
}
