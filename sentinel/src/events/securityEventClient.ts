/**
 * Sentinel — Security Event Client
 *
 * Sends security events and developer action events to Member 2's backend API.
 * Includes offline queueing so events aren't lost if the backend is unavailable.
 */

import { SecurityFinding, SecurityEvent, DeveloperAction } from '../analyzer/types.js';
import * as vscode from 'vscode';

interface QueuedEvent {
  event: SecurityEvent;
  retries: number;
}

export class SecurityEventClient {
  private sessionId: string;
  private queue: QueuedEvent[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    this.sessionId = this.generateSessionId();
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Called by extension.ts when a vulnerability is first detected.
   */
  async reportDetection(finding: SecurityFinding): Promise<void> {
    const event = this.buildEvent(finding, DeveloperAction.DETECTED);
    await this.enqueue(event);
  }

  /**
   * Called when the developer takes an action on a finding (Explain / Fix / Ignore).
   */
  async reportAction(finding: SecurityFinding, action: DeveloperAction): Promise<void> {
    const event = this.buildEvent(finding, action);
    await this.enqueue(event);
  }

  /**
   * Get the current session ID (used to group events in one coding session).
   */
  getSessionId(): string {
    return this.sessionId;
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private buildEvent(finding: SecurityFinding, action: DeveloperAction): SecurityEvent {
    const config = vscode.workspace.getConfiguration('sentinel');
    return {
      eventId: finding.id,
      developerId: config.get<string>('developerId') ?? 'DEV001',
      sessionId: this.sessionId,
      vulnerabilityType: finding.type,
      severity: finding.severity,
      confidence: finding.confidence,
      fileName: finding.fileName,
      lineNumber: finding.lineNumber,
      action,
      timestamp: new Date().toISOString(),
    };
  }

  private async enqueue(event: SecurityEvent): Promise<void> {
    this.queue.push({ event, retries: 0 });
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.flushTimer !== undefined) {
      return; // already scheduled
    }
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, 1000); // batch sends every 1 second
  }

  private async flush(): Promise<void> {
    if (this.queue.length === 0) {
      return;
    }

    const config = vscode.workspace.getConfiguration('sentinel');
    const backendUrl = config.get<string>('backendUrl') ?? 'http://localhost:3000';
    const url = `${backendUrl}/api/security-events`;

    const toSend = [...this.queue];
    this.queue = [];

    for (const item of toSend) {
      try {
        await this.post(url, item.event);
      } catch {
        // Re-queue with retry counter
        if (item.retries < 3) {
          this.queue.push({ event: item.event, retries: item.retries + 1 });
        }
        // After 3 retries, silently drop (don't crash extension over backend issues)
      }
    }

    // If there are still items waiting (from failures), schedule another flush
    if (this.queue.length > 0) {
      setTimeout(() => void this.flush(), 5000);
    }
  }

  private async post(url: string, body: SecurityEvent): Promise<void> {
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
