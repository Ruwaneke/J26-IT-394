/**
 * Sentinel — Component 1 API Server
 *
 * Exposes Component 1's detection data as a local read-only REST API so that
 * Component 2 (Developer Behaviour Tracker) can PULL it on demand. This complements
 * the existing PUSH channel (SecurityEventClient → POST {backendUrl}/api/security-events).
 *
 * Runs inside the VS Code extension host using Node's built-in `http` module.
 * Binds to 127.0.0.1 only. If `sentinel.api.key` is set, every request except
 * /health must send it in the `X-Sentinel-Api-Key` header.
 *
 * Endpoints (all GET, JSON):
 *   /api/v1/health
 *   /api/v1/findings/live
 *   /api/v1/events?since=<ISO>&limit=<n>
 *   /api/v1/vulnerabilities?developerId=&status=OPEN|FIXED|IGNORED|ALL&limit=
 *   /api/v1/stats?developerId=
 *   /api/v1/developers/{developerId}/insights
 *   /api/v1/developers/{developerId}/behaviour
 *   /api/v1/developers/{developerId}/feedback
 *   /api/v1/developers/{developerId}/shifts
 *
 * Contract documented in shared/api-contracts/component-1-sentinel-api.md
 */

import * as http from 'http';
import { SecurityFinding, SecurityEvent } from '../analyzer/types.js';
import { NeonDatabaseService } from '../data/neonDatabaseService.js';
import { DeveloperLearningProfile } from '../ai/developerLearningStore.js';
import { Shift, ShiftSession } from '../data/projectStore.js';
import { computeDeveloperInsights, DeveloperInsights } from '../analytics/developerInsights.js';

export const API_VERSION = 'v1';

/** Callbacks into extension state — keeps this server decoupled from extension.ts globals. */
export interface SentinelApiDataProvider {
  getLiveFindings(): SecurityFinding[];
  getRecentEvents(sinceIso?: string, limit?: number): SecurityEvent[];
  getCurrentDeveloperId(): Promise<string>;
  getLearningProfile(developerId: string): DeveloperLearningProfile | null;
  getShifts(developerId: string): { assigned: Shift[]; active: ShiftSession | null; sessions: ShiftSession[] };
  getSessionId(): string;
  getExtensionVersion(): string;
}

export interface SentinelApiServerOptions {
  port: number;
  apiKey?: string;
  log?: (msg: string) => void;
}

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export class SentinelApiServer {
  private server: http.Server | undefined;
  private startedAt: string | null = null;

  constructor(
    private readonly provider: SentinelApiDataProvider,
    private options: SentinelApiServerOptions,
  ) {}

  get isRunning(): boolean { return !!this.server?.listening; }
  get url(): string { return `http://127.0.0.1:${this.options.port}/api/${API_VERSION}`; }

  start(): Promise<void> {
    if (this.server) { return Promise.resolve(); }
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => { void this.handle(req, res); });
      server.once('error', err => {
        this.server = undefined;
        reject(err);
      });
      server.listen(this.options.port, '127.0.0.1', () => {
        this.server = server;
        this.startedAt = new Date().toISOString();
        this.options.log?.(`🌐 Sentinel API listening on ${this.url}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    const s = this.server;
    this.server = undefined;
    this.startedAt = null;
    return new Promise(resolve => (s ? s.close(() => resolve()) : resolve()));
  }

  async restart(options: SentinelApiServerOptions): Promise<void> {
    await this.stop();
    this.options = options;
    await this.start();
  }

  // ─── Request handling ──────────────────────────────────────────────────────

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Sentinel-Api-Key');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');

    if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }

    try {
      if (req.method !== 'GET') { throw new HttpError(405, 'Only GET is supported'); }
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const path = url.pathname.replace(/\/+$/, '');

      if (path !== `/api/${API_VERSION}/health` && this.options.apiKey) {
        if (req.headers['x-sentinel-api-key'] !== this.options.apiKey) {
          throw new HttpError(401, 'Missing or invalid X-Sentinel-Api-Key header');
        }
      }

      const data = await this.route(path, url.searchParams);
      this.send(res, 200, { success: true, apiVersion: API_VERSION, generatedAt: new Date().toISOString(), data });
    } catch (err: any) {
      const status = err instanceof HttpError ? err.status : 500;
      this.send(res, status, { success: false, apiVersion: API_VERSION, error: err?.message ?? String(err) });
    }
  }

  private async route(path: string, q: URLSearchParams): Promise<unknown> {
    const base = `/api/${API_VERSION}`;
    const db = NeonDatabaseService.getInstance();

    switch (path) {
      case `${base}/health`:
        return {
          status: 'UP',
          component: 'component-1-sentinel',
          extensionVersion: this.provider.getExtensionVersion(),
          sessionId: this.provider.getSessionId(),
          startedAt: this.startedAt,
          database: db.getStatus(),
        };

      case `${base}/findings/live`: {
        const findings = this.provider.getLiveFindings();
        return { count: findings.length, findings };
      }

      case `${base}/events`: {
        const events = this.provider.getRecentEvents(q.get('since') ?? undefined, this.intParam(q, 'limit', 200, 1000));
        return { count: events.length, events };
      }

      case `${base}/vulnerabilities`: {
        const devId = q.get('developerId') ?? await this.provider.getCurrentDeveloperId();
        const status = (q.get('status') ?? 'ALL').toUpperCase();
        const records = await db.getVulnerabilityRecords(devId, status, this.intParam(q, 'limit', 100, 1000));
        return { developerId: devId, count: records.length, records };
      }

      case `${base}/stats`: {
        const devId = q.get('developerId') ?? await this.provider.getCurrentDeveloperId();
        return { developerId: devId, stats: await db.getVulnerabilityStats(devId) };
      }
    }

    const m = path.match(new RegExp(`^${base}/developers/([^/]+)/(insights|behaviour|feedback|shifts)$`));
    if (m) {
      const devId = decodeURIComponent(m[1]);
      if (m[2] === 'shifts') {
        return { developerId: devId, ...this.provider.getShifts(devId) };
      }
      const insights = await this.buildInsights(devId);
      switch (m[2]) {
        case 'insights':  return insights;
        case 'behaviour': return { developerId: devId, behaviour: insights.behaviour, trend: insights.trend, fixRateByType: insights.fixRateByType };
        case 'feedback':  return { developerId: devId, feedback: insights.feedback, ratings: insights.feedbackRatings };
      }
    }

    throw new HttpError(404, `Unknown endpoint: ${path}`);
  }

  /** Build the full insight snapshot for one developer (same data the dashboard shows). */
  async buildInsights(developerId: string): Promise<DeveloperInsights> {
    const db = NeonDatabaseService.getInstance();
    const [records, activities] = await Promise.all([
      db.getVulnerabilityRecords(developerId, 'ALL', 1000),
      db.getRecentActivities(developerId, 500),
    ]);
    const isCurrent = developerId === await this.provider.getCurrentDeveloperId();
    return computeDeveloperInsights({
      developerId,
      liveFindings: isCurrent ? this.provider.getLiveFindings() : [],
      records,
      learningProfile: this.provider.getLearningProfile(developerId),
      activities,
      shiftSessions: this.provider.getShifts(developerId).sessions,
    });
  }

  private intParam(q: URLSearchParams, name: string, def: number, max: number): number {
    const n = parseInt(q.get(name) ?? '', 10);
    return Number.isFinite(n) && n > 0 ? Math.min(n, max) : def;
  }

  private send(res: http.ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  }
}
