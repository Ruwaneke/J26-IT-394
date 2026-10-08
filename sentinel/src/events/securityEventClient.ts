/**
 * Sentinel — Security Event Client
 *
 * Sends security events and developer action events to Member 2's backend API.
 *   DETECTED            → POST /api/security-events
 *   developer actions   → POST /api/developer-interactions
 *
 * Every request carries the backend developerId obtained via GitHub login
 * (POST /api/auth/github). Events are held in the queue until that id is
 * known, and are retried if the backend is unavailable.
 */

import { SecurityFinding, DeveloperAction, Severity } from '../analyzer/types.js';
import * as vscode from 'vscode';

/** Backend BehaviourAction values */
type BackendAction = 'OPEN' | 'IGNORE' | 'FIX' | 'REOPEN' | 'DISMISS';

/** Extension action → backend BehaviourAction (null = not sent) */
const ACTION_MAP: Record<DeveloperAction, BackendAction | null> = {
  [DeveloperAction.DETECTED]:              null,
  [DeveloperAction.WARNING_SHOWN]:         null,
  [DeveloperAction.EXPLANATION_VIEWED]:    'OPEN',
  [DeveloperAction.SECURE_EXAMPLE_VIEWED]: 'OPEN',
  [DeveloperAction.FIX_APPLIED]:           'FIX',
  [DeveloperAction.FIXED]:                 'FIX',
  [DeveloperAction.IGNORED]:               'IGNORE',
  [DeveloperAction.MARKED_FALSE_POSITIVE]: 'IGNORE',
  [DeveloperAction.DISMISSED]:             'DISMISS',
};

const MAX_RETRIES = 3;
const MAX_QUEUE   = 500;

interface QueuedEvent {
  finding: SecurityFinding;
  action: DeveloperAction;
  retries: number;
}

export class SecurityEventClient {
  private sessionId: string;
  private queue: QueuedEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | undefined;
  private flushing = false;
  /**
   * findingKey → backend SecurityEvent.id. Finding ids are regenerated on every
   * analysis pass, so events are keyed on file + line + type instead.
   */
  private backendEventIds = new Map<string, number>();
  /** Keys whose detection is queued or already sent (prevents duplicates on re-analysis) */
  private reportedKeys = new Set<string>();

  /**
   * @param getDeveloperId resolves the backend developerId of the logged-in
   *        GitHub user, or undefined if there is none yet.
   */
  constructor(private readonly getDeveloperId: () => Promise<number | undefined>) {
    this.sessionId = this.generateSessionId();
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Called by extension.ts when a vulnerability is first detected.
   */
  async reportDetection(finding: SecurityFinding): Promise<void> {
    const key = this.findingKey(finding);
    if (this.reportedKeys.has(key)) {
      return; // same vulnerability seen on an earlier analysis pass
    }
    this.reportedKeys.add(key);
    this.enqueue(finding, DeveloperAction.DETECTED);
  }

  /**
   * Called when the developer takes an action on a finding (Explain / Fix / Ignore).
   */
  async reportAction(finding: SecurityFinding, action: DeveloperAction): Promise<void> {
    if (ACTION_MAP[action] === null) {
      return; // no backend equivalent
    }
    this.enqueue(finding, action);
  }

  /**
   * Get the current session ID (used to group events in one coding session).
   */
  getSessionId(): string {
    return this.sessionId;
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private enqueue(finding: SecurityFinding, action: DeveloperAction): void {
    this.queue.push({ finding, action, retries: 0 });
    if (this.queue.length > MAX_QUEUE) {
      // drop oldest if no developer identity is ever obtained
      const dropped = this.queue.shift()!;
      if (dropped.action === DeveloperAction.DETECTED) {
        this.reportedKeys.delete(this.findingKey(dropped.finding));
      }
    }
    this.scheduleFlush(1000); // batch sends every 1 second
  }

  private scheduleFlush(delayMs: number): void {
    if (this.flushTimer !== undefined) {
      return; // already scheduled
    }
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, delayMs);
  }

  private async flush(): Promise<void> {
    if (this.queue.length === 0 || this.flushing) {
      return;
    }
    this.flushing = true;
    try {
      const developerId = await this.getDeveloperId();
      if (developerId === undefined) {
        // Not logged in with GitHub (or backend unreachable) — keep events and wait
        this.scheduleFlush(5000);
        return;
      }

      const backendUrl = vscode.workspace.getConfiguration('sentinel')
        .get<string>('backendUrl') ?? 'http://localhost:8080';

      const toSend = [...this.queue];
      this.queue = [];

      // Sent in order so a detection is created before actions that reference it
      for (const item of toSend) {
        try {
          await this.send(backendUrl, developerId, item);
        } catch {
          // Re-queue with retry counter; after MAX_RETRIES, silently drop
          // (don't crash extension over backend issues)
          if (item.retries < MAX_RETRIES) {
            this.queue.push({ ...item, retries: item.retries + 1 });
          } else if (item.action === DeveloperAction.DETECTED) {
            this.reportedKeys.delete(this.findingKey(item.finding)); // allow re-detection later
          }
        }
      }
    } finally {
      this.flushing = false;
    }

    // If there are still items waiting (from failures), schedule another flush
    if (this.queue.length > 0) {
      this.scheduleFlush(5000);
    }
  }

  private async send(backendUrl: string, developerId: number, item: QueuedEvent): Promise<void> {
    const { finding, action } = item;

    if (action === DeveloperAction.DETECTED) {
      const created = await this.post(`${backendUrl}/api/security-events`, {
        developerId,
        vulnerabilityType: finding.type,
        severity:          finding.severity === Severity.INFO ? Severity.LOW : finding.severity,
        fileName:          finding.fileName,
        lineNumber:        finding.lineNumber,
        message:           finding.message,
      }) as { id: number };
      this.backendEventIds.set(this.findingKey(finding), created.id);
      return;
    }

    const securityEventId = this.backendEventIds.get(this.findingKey(finding));
    if (securityEventId === undefined) {
      throw new Error(`No backend security event for finding ${finding.id}`);
    }

    await this.post(`${backendUrl}/api/developer-interactions`, {
      securityEventId,
      developerId,
      action:    ACTION_MAP[action],
      sessionId: this.sessionId,
      source:    'VSCODE',
      metadata:  JSON.stringify({ extensionAction: action, confidence: finding.confidence }),
    });
  }

  private async post(url: string, body: unknown): Promise<unknown> {
    // Use dynamic import to avoid ESM/CJS issues in VS Code extension host
    const { default: fetch } = await import('node-fetch');
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000), // 5-second timeout
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }
    return response.json();
  }

  private findingKey(finding: SecurityFinding): string {
    return `${finding.fileName}:${finding.lineNumber}:${finding.type}`;
  }

  private generateSessionId(): string {
    return `SESSION-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
  }

  dispose(): void {
    if (this.flushTimer !== undefined) {
      clearTimeout(this.flushTimer);
    }
  }
}
