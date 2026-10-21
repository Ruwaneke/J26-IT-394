/**
 * Sentinel — AI-Enhanced Analyzer
 *
 * This wraps the base SecurityAnalyzer with a learning/AI layer that:
 *
 *   1. POST-FILTERS raw findings using the DeveloperLearningStore:
 *      - Skips findings for vuln types the developer suppressed (too many FPs)
 *      - Skips findings whose snippet hash was marked as a false positive
 *      - Applies per-developer, per-rule confidence adjustments
 *
 *   2. ENRICHES findings by calling the Intelligent Feedback Engine (IFE)
 *      asynchronously — fetching AI-generated explanations and personalised
 *      fixes without blocking the real-time underline display.
 *
 *   3. LEARNS from developer actions:
 *      - FIX → boosts confidence for that rule
 *      - IGNORE / DISMISS → dampens confidence
 *      - FALSE_POSITIVE → suppresses snippet + reduces rule weight
 *
 * Architecture:
 *   VS Code doc change
 *     → SecurityAnalyzer.analyze()   [raw regex detections]
 *     → AIEnhancedAnalyzer.filter()  [apply learning store filters]
 *     → DiagnosticManager            [show underlines immediately]
 *     → AIEnhancedAnalyzer.enrich()  [async IFE call → AI explanation]
 *     → DeveloperLearningStore       [record DETECTED event]
 */

import { SecurityAnalyzer } from '../analyzer/securityAnalyzer.js';
import { SecurityFinding, VulnerabilityType } from '../analyzer/types.js';
import { DeveloperLearningStore, hashSnippet, LearningEvent } from './developerLearningStore.js';

// ─── Types ────────────────────────────────────────────────────────────────────

/** Finding enriched with AI-generated context (returned async) */
export interface EnrichedFinding extends SecurityFinding {
  /** AI-generated contextual explanation of why THIS code is vulnerable */
  aiExplanation?: string;
  /** AI-generated personalised fix for THIS specific snippet */
  aiPersonalisedFix?: string;
  /** Whether the AI was actually used (vs rule-based fallback) */
  aiGenerated?: boolean;
  /** Escalation level from the behaviour analyser */
  feedbackLevel?: string;
  /** Escalation message (shown as VS Code notification) */
  escalationMessage?: string;
  /** Developer's current security score */
  securityScore?: number;
}

/** Config passed in from extension.ts */
export interface AIEnhancedAnalyzerConfig {
  /** Developer identifier for learning store lookup */
  developerId: string;
  /** Current session ID */
  sessionId: string;
  /** URL of the Intelligent Feedback Engine (Component 3) */
  ifeUrl: string;
  /** Whether IFE integration is enabled */
  ifeEnabled: boolean;
  /** Minimum confidence threshold — findings below this are hidden */
  minConfidence: number;
}

// ─── AI Enhanced Analyzer ─────────────────────────────────────────────────────

export class AIEnhancedAnalyzer {
  private readonly baseAnalyzer: SecurityAnalyzer;
  private readonly learningStore: DeveloperLearningStore;

  constructor(
    baseAnalyzer: SecurityAnalyzer,
    learningStore: DeveloperLearningStore,
  ) {
    this.baseAnalyzer = baseAnalyzer;
    this.learningStore = learningStore;
  }

  // ─── Step 1: Analyze + Filter ─────────────────────────────────────────────

  /**
   * Run the base analyzer, then apply learning-store filters.
   * Returns immediately (synchronous) — used by the diagnostic manager.
   *
   * @param text       - Full document text
   * @param fileName   - File path
   * @param languageId - VS Code language ID
   * @param config     - Per-session config
   */
  analyze(
    text: string,
    fileName: string,
    languageId: string,
    config: AIEnhancedAnalyzerConfig,
  ): SecurityFinding[] {
    // Run all registered rules
    const raw = this.baseAnalyzer.analyze(text, fileName, languageId);

    // Apply learning-store filters
    return raw
      .filter(f => this.passesLearningFilter(f, config))
      .map(f => this.applyConfidenceAdjustment(f, config));
  }

  // ─── Step 2: Enrich (async IFE call) ─────────────────────────────────────

  /**
   * Call the IFE to get AI explanation + personalised fix.
   * Runs AFTER diagnostics are already shown — non-blocking.
   *
   * Returns an EnrichedFinding[] in the same order as `findings`.
   * If IFE is disabled or unavailable, returns findings unchanged.
   */
  async enrich(
    findings: SecurityFinding[],
    config: AIEnhancedAnalyzerConfig,
  ): Promise<EnrichedFinding[]> {
    if (!config.ifeEnabled || findings.length === 0) {
      return findings as EnrichedFinding[];
    }

    // Only enrich the top 3 most severe findings (avoid flooding IFE)
    const toEnrich = findings.slice(0, 3);
    const enriched: EnrichedFinding[] = [...findings] as EnrichedFinding[];

    await Promise.allSettled(
      toEnrich.map(async (finding, idx) => {
        try {
          const ifeResult = await this.callIFE(finding, config);
          if (ifeResult) {
            enriched[idx] = { ...finding, ...ifeResult };
          }
        } catch (err) {
          console.warn(`[AIEnhancedAnalyzer] IFE enrichment failed for finding ${finding.id}:`, err);
        }
      })
    );

    return enriched;
  }

  // ─── Step 3: Record Developer Action (learning feedback loop) ─────────────

  /**
   * Call this when the developer takes an action on a finding.
   * Drives the learning loop — adjusts confidence for future analyses.
   */
  recordAction(
    finding: SecurityFinding,
    action: 'FIXED' | 'IGNORED' | 'FALSE_POSITIVE',
    developerId: string,
  ): void {
    const snippetHash = hashSnippet(finding.codeSnippet);
    const eventKind: LearningEvent['kind'] =
      action === 'FIXED'          ? 'FIXED' :
      action === 'FALSE_POSITIVE' ? 'FALSE_POSITIVE' :
                                    'IGNORED';

    this.learningStore.recordEvent(developerId, {
      kind:        eventKind,
      ruleId:      finding.detectedByRule,
      vulnType:    finding.type,
      snippetHash,
    });

    console.log(
      `[AIEnhancedAnalyzer] Recorded ${action} for ${finding.type} ` +
      `(rule: ${finding.detectedByRule}, dev: ${developerId})`
    );
  }

  /**
   * Record that a finding was detected (for the learning store counter).
   * Call this after showing diagnostics to the developer.
   */
  recordDetection(finding: SecurityFinding, developerId: string): void {
    this.learningStore.recordEvent(developerId, {
      kind:        'DETECTED',
      ruleId:      finding.detectedByRule,
      vulnType:    finding.type,
      snippetHash: hashSnippet(finding.codeSnippet),
    });
  }

  // ─── Private: Learning Store Filter ─────────────────────────────────────

  private passesLearningFilter(
    finding: SecurityFinding,
    config: AIEnhancedAnalyzerConfig,
  ): boolean {
    const { developerId, minConfidence } = config;

    // 1. Confidence threshold filter
    if (finding.confidence < minConfidence) {
      return false;
    }

    // 2. Vuln type suppressed for this developer?
    if (this.learningStore.isSuppressed(developerId, finding.type)) {
      console.log(
        `[AIEnhancedAnalyzer] Suppressing ${finding.type} for ${developerId} ` +
        `(suppressed by learning store)`
      );
      return false;
    }

    // 3. Specific snippet previously marked as FP?
    const snippetHash = hashSnippet(finding.codeSnippet);
    if (this.learningStore.isFalsePositiveSnippet(developerId, snippetHash)) {
      return false;
    }

    return true;
  }

  private applyConfidenceAdjustment(
    finding: SecurityFinding,
    config: AIEnhancedAnalyzerConfig,
  ): SecurityFinding {
    const adjusted = this.learningStore.getAdjustedConfidence(
      config.developerId,
      finding.type,
      finding.detectedByRule,
    );
    if (adjusted === null) {
      return finding; // no adjustment — use rule default
    }
    return { ...finding, confidence: adjusted };
  }

  // ─── Private: IFE HTTP Call ──────────────────────────────────────────────

  private async callIFE(
    finding: SecurityFinding,
    config: AIEnhancedAnalyzerConfig,
  ): Promise<Partial<EnrichedFinding> | null> {
    const { ifeUrl, developerId, sessionId } = config;

    // Build the learning context to inject into the IFE request
    const learningContext = this.learningStore.buildAIContext(
      developerId,
      finding.type,
    );

    const payload = {
      developerId,
      sessionId,
      vulnerabilityType: finding.type,
      severity:          finding.severity,
      confidence:        finding.confidence,
      codeSnippet:       finding.codeSnippet,
      fileName:          finding.fileName,
      lineNumber:        finding.lineNumber,
      timestamp:         finding.detectedAt,
      // ← NEW: inject the learning context so IFE can personalise even further
      learningContext,
    };

    const response = await fetch(`${ifeUrl}/api/feedback/request`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      // Timeout after 4 seconds — don't block the developer's workflow
      signal:  AbortSignal.timeout(4000),
    });

    if (!response.ok) {
      throw new Error(`IFE returned ${response.status}`);
    }

    const data = await response.json() as {
      status:                string;
      contextualExplanation: string;
      personalizedFix:       string;
      escalationMessage:     string;
      feedbackLevel:         string;
      securityScore:         number;
      aiGenerated:           boolean;
    };

    if (data.status !== 'ok') {
      return null;
    }

    return {
      aiExplanation:     data.contextualExplanation,
      aiPersonalisedFix: data.personalizedFix,
      aiGenerated:       data.aiGenerated,
      feedbackLevel:     data.feedbackLevel,
      escalationMessage: data.escalationMessage,
      securityScore:     data.securityScore,
    };
  }
}
