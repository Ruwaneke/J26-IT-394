/**
 * Sentinel — Developer Learning Store
 *
 * Persists per-developer learning data that allows Sentinel to adapt
 * its detection behaviour based on what the developer has historically
 * marked as false-positive, repeatedly ignored, or repeatedly fixed.
 *
 * Data is stored at:
 *   sentinel/src/DATA/<developerId>_learning.json
 *
 * The store is queried by the AI-Enhanced Analyzer to:
 *   1. Suppress high-noise patterns per file/developer
 *   2. Boost confidence for patterns the developer repeatedly missed
 *   3. Provide rich behavioural context to the AI feedback prompt
 */

import * as fs from 'fs';
import * as path from 'path';
import { VulnerabilityType } from '../analyzer/types.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PatternFeedback {
  /** How many times this pattern fired and the developer fixed it (positive signal) */
  fixedCount: number;
  /** How many times this pattern fired and the developer ignored/dismissed it */
  ignoredCount: number;
  /** How many times the developer explicitly marked this as a false positive */
  falsePositiveCount: number;
  /** Running average confidence override (null = use rule default) */
  adjustedConfidence: number | null;
  /** ISO 8601 timestamp of last update */
  lastUpdatedAt: string;
}

export interface VulnTypeLearning {
  /** Total times this type was detected for this developer (ever) */
  totalDetections: number;
  /** Total times the developer fixed this type */
  totalFixes: number;
  /** Total times ignored */
  totalIgnored: number;
  /** Total false-positive markings */
  totalFalsePositives: number;
  /**
   * Per-rule confidence adjustment. Key = ruleId (e.g. 'SENTINEL-SQL-001').
   * Allows fine-grained per-rule tuning without affecting other rules.
   */
  ruleAdjustments: Record<string, PatternFeedback>;
  /** Whether this vuln type is currently suppressed for this developer */
  suppressed: boolean;
  /** ISO 8601 timestamp of first detection */
  firstSeenAt: string;
  /** ISO 8601 timestamp of most recent detection */
  lastSeenAt: string;
}

export interface DeveloperLearningProfile {
  developerId: string;
  /** ISO 8601 timestamp of profile creation */
  createdAt: string;
  /** ISO 8601 timestamp of last update */
  updatedAt: string;
  /**
   * Per-vulnerability-type learning data.
   * Key = VulnerabilityType string.
   */
  vulnLearning: Partial<Record<VulnerabilityType, VulnTypeLearning>>;
  /**
   * Patterns that have been globally suppressed for this developer.
   * Stored as ruleId → suppressed boolean.
   */
  suppressedRules: Record<string, boolean>;
  /**
   * Rolling window of the last 100 snippet hashes marked as false-positive.
   * Used to quickly skip re-detecting the same code on future analyses.
   */
  falsePositiveSnippetHashes: string[];
}

// ─── Learning Events (passed in from the extension action handlers) ────────────

export type LearningEvent =
  | { kind: 'FIXED';          ruleId: string; vulnType: VulnerabilityType; snippetHash: string }
  | { kind: 'IGNORED';        ruleId: string; vulnType: VulnerabilityType; snippetHash: string }
  | { kind: 'FALSE_POSITIVE'; ruleId: string; vulnType: VulnerabilityType; snippetHash: string }
  | { kind: 'DETECTED';       ruleId: string; vulnType: VulnerabilityType; snippetHash: string };

// ─── Store ───────────────────────────────────────────────────────────────────

export class DeveloperLearningStore {
  private readonly dataDir: string;
  /** In-memory cache: developerId → profile */
  private cache: Map<string, DeveloperLearningProfile> = new Map();

  constructor(extensionPath: string) {
    this.dataDir = path.join(extensionPath, 'src', 'data');
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }

  // ─── Public API ──────────────────────────────────────────────────────────

  /**
   * Record a learning event (DETECTED, FIXED, IGNORED, FALSE_POSITIVE).
   * Updates the in-memory profile and flushes to disk.
   */
  recordEvent(developerId: string, event: LearningEvent): void {
    const profile = this.getOrCreate(developerId);
    const now = new Date().toISOString();

    // Ensure the vuln type bucket exists
    if (!profile.vulnLearning[event.vulnType]) {
      profile.vulnLearning[event.vulnType] = {
        totalDetections: 0,
        totalFixes: 0,
        totalIgnored: 0,
        totalFalsePositives: 0,
        ruleAdjustments: {},
        suppressed: false,
        firstSeenAt: now,
        lastSeenAt: now,
      };
    }
    const bucket = profile.vulnLearning[event.vulnType]!;
    bucket.lastSeenAt = now;

    // Ensure the per-rule bucket exists
    if (!bucket.ruleAdjustments[event.ruleId]) {
      bucket.ruleAdjustments[event.ruleId] = {
        fixedCount: 0,
        ignoredCount: 0,
        falsePositiveCount: 0,
        adjustedConfidence: null,
        lastUpdatedAt: now,
      };
    }
    const ruleBucket = bucket.ruleAdjustments[event.ruleId];
    ruleBucket.lastUpdatedAt = now;

    switch (event.kind) {
      case 'DETECTED':
        bucket.totalDetections++;
        break;

      case 'FIXED':
        bucket.totalFixes++;
        ruleBucket.fixedCount++;
        // Boost confidence for rules the developer learns to fix correctly
        ruleBucket.adjustedConfidence = this.computeAdjustedConfidence(
          ruleBucket, +0.02
        );
        break;

      case 'IGNORED':
        bucket.totalIgnored++;
        ruleBucket.ignoredCount++;
        // Slightly dampen confidence for rules the developer consistently ignores
        ruleBucket.adjustedConfidence = this.computeAdjustedConfidence(
          ruleBucket, -0.01
        );
        break;

      case 'FALSE_POSITIVE':
        bucket.totalFalsePositives++;
        ruleBucket.falsePositiveCount++;
        // Significantly dampen confidence — developer says this is a false positive
        ruleBucket.adjustedConfidence = this.computeAdjustedConfidence(
          ruleBucket, -0.08
        );
        // Auto-suppress rule if >= 3 FPs reported for this vuln type
        if (bucket.totalFalsePositives >= 3) {
          bucket.suppressed = true;
          console.log(
            `[LearningStore] Auto-suppressed ${event.vulnType} for ${developerId} ` +
            `(${bucket.totalFalsePositives} false positives reported)`
          );
        }
        // Add snippet hash to FP list (cap at 100)
        if (!profile.falsePositiveSnippetHashes.includes(event.snippetHash)) {
          profile.falsePositiveSnippetHashes.push(event.snippetHash);
          if (profile.falsePositiveSnippetHashes.length > 100) {
            profile.falsePositiveSnippetHashes.shift();
          }
        }
        break;
    }

    profile.updatedAt = now;
    this.cache.set(developerId, profile);
    this.flush(developerId, profile);
  }

  /**
   * Get the adjusted confidence for a specific rule + vuln type.
   * Returns null if no adjustment has been learned yet (caller uses rule default).
   */
  getAdjustedConfidence(
    developerId: string,
    vulnType: VulnerabilityType,
    ruleId: string,
  ): number | null {
    const profile = this.load(developerId);
    if (!profile) { return null; }
    return profile.vulnLearning[vulnType]?.ruleAdjustments[ruleId]?.adjustedConfidence ?? null;
  }

  /**
   * Check whether a vuln type is suppressed for this developer.
   */
  isSuppressed(developerId: string, vulnType: VulnerabilityType): boolean {
    const profile = this.load(developerId);
    if (!profile) { return false; }
    return profile.vulnLearning[vulnType]?.suppressed ?? false;
  }

  /**
   * Check whether a code snippet (by hash) was previously marked as a false positive.
   */
  isFalsePositiveSnippet(developerId: string, snippetHash: string): boolean {
    const profile = this.load(developerId);
    if (!profile) { return false; }
    return profile.falsePositiveSnippetHashes.includes(snippetHash);
  }

  /**
   * Return a rich context string about the developer's learning history,
   * intended to be injected into AI prompts for personalised feedback.
   */
  buildAIContext(developerId: string, vulnType: VulnerabilityType): string {
    const profile = this.load(developerId);
    if (!profile) {
      return 'No learning history available for this developer.';
    }

    const bucket = profile.vulnLearning[vulnType];
    if (!bucket) {
      return `This is the first time this developer has encountered ${vulnType}.`;
    }

    const fixRate = bucket.totalDetections > 0
      ? Math.round((bucket.totalFixes / bucket.totalDetections) * 100)
      : 0;

    const lines: string[] = [
      `Developer learning history for ${vulnType}:`,
      `  Total detections: ${bucket.totalDetections}`,
      `  Times fixed: ${bucket.totalFixes} (fix rate: ${fixRate}%)`,
      `  Times ignored: ${bucket.totalIgnored}`,
      `  False positive reports: ${bucket.totalFalsePositives}`,
      `  First seen: ${bucket.firstSeenAt}`,
      `  Most recently seen: ${bucket.lastSeenAt}`,
    ];

    if (bucket.suppressed) {
      lines.push(`  ⚠️  This rule is currently suppressed due to repeated false positives.`);
    }

    const struggling = Object.entries(profile.vulnLearning)
      .filter(([, b]) => b && b.totalDetections >= 3 && b.totalFixes < b.totalDetections * 0.5)
      .map(([type]) => type);

    if (struggling.length > 0) {
      lines.push(`  Recurring weaknesses: ${struggling.join(', ')}`);
    }

    return lines.join('\n');
  }

  /**
   * Get complete learning profile for a developer (for dashboard display).
   */
  getProfile(developerId: string): DeveloperLearningProfile | null {
    return this.load(developerId);
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  private computeAdjustedConfidence(
    ruleBucket: PatternFeedback,
    delta: number,
  ): number {
    const current = ruleBucket.adjustedConfidence ?? 0.80; // default base
    const adjusted = Math.max(0.10, Math.min(0.99, current + delta));
    return Math.round(adjusted * 100) / 100; // round to 2 dp
  }

  private getOrCreate(developerId: string): DeveloperLearningProfile {
    const existing = this.load(developerId);
    if (existing) { return existing; }

    const profile: DeveloperLearningProfile = {
      developerId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      vulnLearning: {},
      suppressedRules: {},
      falsePositiveSnippetHashes: [],
    };
    this.cache.set(developerId, profile);
    return profile;
  }

  private load(developerId: string): DeveloperLearningProfile | null {
    // Check memory cache first
    if (this.cache.has(developerId)) {
      return this.cache.get(developerId)!;
    }
    // Try disk
    const filePath = this.profilePath(developerId);
    if (!fs.existsSync(filePath)) { return null; }
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      const profile = JSON.parse(raw) as DeveloperLearningProfile;
      this.cache.set(developerId, profile);
      return profile;
    } catch {
      return null;
    }
  }

  private flush(developerId: string, profile: DeveloperLearningProfile): void {
    const filePath = this.profilePath(developerId);
    try {
      fs.writeFileSync(filePath, JSON.stringify(profile, null, 2), 'utf-8');
    } catch (err) {
      console.error(`[LearningStore] Failed to write profile for ${developerId}:`, err);
    }
  }

  private profilePath(developerId: string): string {
    return path.join(this.dataDir, `${developerId}_learning.json`);
  }
}

// ─── Snippet Hasher (simple, fast, non-cryptographic) ────────────────────────

/**
 * Produces a short hash of a code snippet for false-positive deduplication.
 * Not cryptographic — just fast enough for in-memory comparison.
 */
export function hashSnippet(snippet: string): string {
  let hash = 5381;
  for (let i = 0; i < snippet.length; i++) {
    hash = ((hash << 5) + hash) ^ snippet.charCodeAt(i);
    hash = hash & hash; // convert to 32-bit int
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}
