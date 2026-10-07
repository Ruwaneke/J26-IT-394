/**
 * Sentinel — Project Store
 *
 * Manages Projects, Shifts, and ShiftSessions.
 * All data is persisted to sentinel/src/DATA/:
 *   projects.json       — all projects
 *   shifts.json         — all shifts
 *   shift_sessions.json — all completed + active sessions
 */

import * as fs from 'fs';
import * as path from 'path';

// ─── Core Types ───────────────────────────────────────────────────────────────

export type ProjectStatus = 'active' | 'completed' | 'archived';
export type ShiftStatus   = 'scheduled' | 'active' | 'completed';

export interface Project {
  id: string;
  name: string;
  description: string;
  supervisorId: string;
  supervisorName: string;
  createdAt: string;
  status: ProjectStatus;
}

export interface Shift {
  id: string;
  projectId: string;
  projectName: string;
  name: string;
  description: string;
  scheduledStart: string;   // ISO datetime
  scheduledEnd: string;
  assignedDeveloperIds: string[];   // array of username/developerId
  assignedDeveloperNames: string[]; // for display
  status: ShiftStatus;
  createdAt: string;
  createdBy: string;        // supervisorId
}

export interface SessionFinding {
  id: string;
  type: string;
  severity: string;
  confidence: number;
  fileName: string;
  lineNumber: number;
  codeSnippet: string;
  detectedAt: string;
  ruleId: string;
}

export interface ShiftSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  byType: Record<string, number>;
  filesAffected: string[];
  durationMinutes: number;
  securityScore: number;
  trend: 'improving' | 'declining' | 'stable';
  recommendations: string[];
  generatedAt: string;
}

export interface ShiftSession {
  id: string;
  shiftId: string;
  shiftName: string;
  projectId: string;
  projectName: string;
  developerId: string;
  developerUsername: string;
  developerDisplayName: string;
  githubAvatarUrl?: string;
  startedAt: string;
  endedAt: string | null;   // null = still active
  findings: SessionFinding[];
  summary: ShiftSummary | null;
}

// ─── Project Store ─────────────────────────────────────────────────────────────

export class ProjectStore {
  private readonly dataDir: string;

  // In-memory caches
  private projects: Project[]      = [];
  private shifts: Shift[]          = [];
  private sessions: ShiftSession[] = [];

  constructor(extensionPath: string) {
    this.dataDir = path.join(extensionPath, 'src', 'data');
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    this.load();
  }

  // ─── Projects ───────────────────────────────────────────────────────────────

  createProject(
    name: string,
    description: string,
    supervisorId: string,
    supervisorName: string,
  ): Project {
    const project: Project = {
      id:             `proj-${Date.now()}`,
      name:           name.trim(),
      description:    description.trim(),
      supervisorId,
      supervisorName,
      createdAt:      new Date().toISOString(),
      status:         'active',
    };
    this.projects.push(project);
    this.flushProjects();
    return project;
  }

  getProjects(supervisorId?: string): Project[] {
    this.loadProjects();
    if (supervisorId) {
      return this.projects.filter(p => p.supervisorId === supervisorId);
    }
    return [...this.projects];
  }

  getProject(projectId: string): Project | undefined {
    this.loadProjects();
    return this.projects.find(p => p.id === projectId);
  }

  updateProjectStatus(projectId: string, status: ProjectStatus): boolean {
    this.loadProjects();
    const p = this.projects.find(p => p.id === projectId);
    if (!p) { return false; }
    p.status = status;
    this.flushProjects();
    return true;
  }

  deleteProject(projectId: string): boolean {
    this.loadProjects();
    const idx = this.projects.findIndex(p => p.id === projectId);
    if (idx === -1) { return false; }
    this.projects.splice(idx, 1);
    this.flushProjects();
    return true;
  }

  // ─── Shifts ─────────────────────────────────────────────────────────────────

  createShift(
    projectId: string,
    name: string,
    description: string,
    scheduledStart: string,
    scheduledEnd: string,
    assignedDeveloperIds: string[],
    assignedDeveloperNames: string[],
    createdBy: string,
  ): Shift | null {
    const project = this.getProject(projectId);
    if (!project) { return null; }

    const shift: Shift = {
      id:                    `shift-${Date.now()}`,
      projectId,
      projectName:           project.name,
      name:                  name.trim(),
      description:           description.trim(),
      scheduledStart,
      scheduledEnd,
      assignedDeveloperIds,
      assignedDeveloperNames,
      status:                'scheduled',
      createdAt:             new Date().toISOString(),
      createdBy,
    };
    this.shifts.push(shift);
    this.flushShifts();
    return shift;
  }

  getShifts(projectId?: string): Shift[] {
    this.loadShifts();
    if (projectId) {
      return this.shifts.filter(s => s.projectId === projectId);
    }
    return [...this.shifts];
  }

  /** Get all shifts assigned to a specific developer */
  getShiftsForDeveloper(developerId: string): Shift[] {
    this.loadShifts();
    return this.shifts.filter(s => s.assignedDeveloperIds.includes(developerId));
  }

  getShift(shiftId: string): Shift | undefined {
    this.loadShifts();
    return this.shifts.find(s => s.id === shiftId);
  }

  updateShiftStatus(shiftId: string, status: ShiftStatus): boolean {
    this.loadShifts();
    const s = this.shifts.find(s => s.id === shiftId);
    if (!s) { return false; }
    s.status = status;
    this.flushShifts();
    return true;
  }

  updateShiftAssignments(
    shiftId: string,
    developerIds: string[],
    developerNames: string[],
  ): boolean {
    this.loadShifts();
    const s = this.shifts.find(s => s.id === shiftId);
    if (!s) { return false; }
    s.assignedDeveloperIds   = developerIds;
    s.assignedDeveloperNames = developerNames;
    this.flushShifts();
    return true;
  }

  deleteShift(shiftId: string): boolean {
    this.loadShifts();
    const idx = this.shifts.findIndex(s => s.id === shiftId);
    if (idx === -1) { return false; }
    this.shifts.splice(idx, 1);
    this.flushShifts();
    return true;
  }

  // ─── Shift Sessions ──────────────────────────────────────────────────────────

  /** Start a new shift session for a developer */
  startSession(
    shift: Shift,
    developerId: string,
    developerUsername: string,
    developerDisplayName: string,
    githubAvatarUrl?: string,
  ): ShiftSession {
    this.loadSessions();

    // Mark any previously active session for this dev as ended (safety)
    for (const s of this.sessions) {
      if (s.developerId === developerId && s.endedAt === null) {
        s.endedAt = new Date().toISOString();
        s.summary = this.generateSummary(s);
      }
    }

    const session: ShiftSession = {
      id:                   `sess-${Date.now()}`,
      shiftId:              shift.id,
      shiftName:            shift.name,
      projectId:            shift.projectId,
      projectName:          shift.projectName,
      developerId,
      developerUsername,
      developerDisplayName,
      githubAvatarUrl,
      startedAt:            new Date().toISOString(),
      endedAt:              null,
      findings:             [],
      summary:              null,
    };

    this.sessions.push(session);
    this.flushSessions();

    // Mark shift as active
    this.updateShiftStatus(shift.id, 'active');

    return session;
  }

  /** Add a finding to an active session */
  addFindingToSession(
    sessionId: string,
    finding: SessionFinding,
  ): void {
    this.loadSessions();
    const session = this.sessions.find(s => s.id === sessionId);
    if (!session || session.endedAt !== null) { return; }

    // Deduplicate by finding id
    if (!session.findings.find(f => f.id === finding.id)) {
      session.findings.push(finding);
      this.flushSessions();
    }
  }

  /** End a shift session and generate its summary */
  endSession(sessionId: string): ShiftSession | null {
    this.loadSessions();
    const session = this.sessions.find(s => s.id === sessionId);
    if (!session) { return null; }

    session.endedAt = new Date().toISOString();
    session.summary = this.generateSummary(session);
    this.flushSessions();

    // Check if all developers have ended — then mark shift completed
    this.checkShiftCompletion(session.shiftId);

    return session;
  }

  /** Get the active (not yet ended) session for a developer */
  getActiveSession(developerId: string): ShiftSession | null {
    this.loadSessions();
    return this.sessions.find(
      s => s.developerId === developerId && s.endedAt === null
    ) ?? null;
  }

  /** Get all sessions for a shift */
  getSessionsForShift(shiftId: string): ShiftSession[] {
    this.loadSessions();
    return this.sessions.filter(s => s.shiftId === shiftId);
  }

  /** Get all completed sessions for a developer */
  getSessionsForDeveloper(developerId: string): ShiftSession[] {
    this.loadSessions();
    return this.sessions
      .filter(s => s.developerId === developerId && s.endedAt !== null)
      .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  }

  /** Get all sessions (for supervisor overview) */
  getAllSessions(): ShiftSession[] {
    this.loadSessions();
    return [...this.sessions];
  }

  // ─── Summary Generation ──────────────────────────────────────────────────────

  generateSummary(session: ShiftSession): ShiftSummary {
    const findings = session.findings;
    const byType: Record<string, number> = {};
    const filesSet = new Set<string>();

    let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0;

    for (const f of findings) {
      byType[f.type] = (byType[f.type] ?? 0) + 1;
      filesSet.add(path.basename(f.fileName));
      switch (f.severity) {
        case 'CRITICAL': criticalCount++; break;
        case 'HIGH':     highCount++;     break;
        case 'MEDIUM':   mediumCount++;   break;
        case 'LOW':      lowCount++;      break;
        default:         infoCount++;     break;
      }
    }

    const start    = new Date(session.startedAt).getTime();
    const end      = session.endedAt ? new Date(session.endedAt).getTime() : Date.now();
    const durationMinutes = Math.round((end - start) / 60000);

    // Security score: start at 100, deduct per finding
    const securityScore = Math.max(0, Math.min(100,
      100
      - criticalCount * 20
      - highCount     * 10
      - mediumCount   * 4
      - lowCount      * 1
    ));

    const recommendations = this.buildRecommendations(byType, findings.length, durationMinutes);

    return {
      totalFindings: findings.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      byType,
      filesAffected: [...filesSet],
      durationMinutes,
      securityScore,
      trend: securityScore >= 80 ? 'improving' : securityScore >= 50 ? 'stable' : 'declining',
      recommendations,
      generatedAt: new Date().toISOString(),
    };
  }

  private buildRecommendations(
    byType: Record<string, number>,
    total: number,
    durationMinutes: number,
  ): string[] {
    const recs: string[] = [];

    if ((byType['SQL_INJECTION'] ?? 0) >= 2) {
      recs.push('Consistently use parameterized queries / prepared statements for all database operations.');
    }
    if ((byType['XSS'] ?? 0) >= 1) {
      recs.push('Replace innerHTML/dangerouslySetInnerHTML with textContent or sanitize with DOMPurify.');
    }
    if ((byType['HARDCODED_SECRET'] ?? 0) >= 1) {
      recs.push('Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, Vault).');
    }
    if ((byType['COMMAND_INJECTION'] ?? 0) >= 1) {
      recs.push('Use execFile() with array arguments instead of exec() with shell strings.');
    }
    if (total > 15) {
      recs.push('High vulnerability density detected. Consider a dedicated secure code review session.');
    }
    if (durationMinutes > 0 && total === 0) {
      recs.push('Excellent session — no vulnerabilities detected! Keep following secure coding practices.');
    }
    if (recs.length === 0) {
      recs.push('Good session. Continue reviewing OWASP Top 10 patterns to maintain your security score.');
    }

    return recs;
  }

  private checkShiftCompletion(shiftId: string): void {
    const shift = this.getShift(shiftId);
    if (!shift) { return; }

    // If all assigned developers have ended their sessions, mark shift completed
    const sessions = this.getSessionsForShift(shiftId);
    const endedCount = sessions.filter(s => s.endedAt !== null).length;

    if (endedCount >= shift.assignedDeveloperIds.length && endedCount > 0) {
      this.updateShiftStatus(shiftId, 'completed');
    }
  }

  // ─── Persistence ────────────────────────────────────────────────────────────

  private load(): void {
    this.loadProjects();
    this.loadShifts();
    this.loadSessions();
  }

  private loadProjects(): void {
    try {
      const raw = fs.readFileSync(path.join(this.dataDir, 'projects.json'), 'utf8');
      this.projects = JSON.parse(raw) as Project[];
    } catch { this.projects = []; }
  }

  private loadShifts(): void {
    try {
      const raw = fs.readFileSync(path.join(this.dataDir, 'shifts.json'), 'utf8');
      this.shifts = JSON.parse(raw) as Shift[];
    } catch { this.shifts = []; }
  }

  private loadSessions(): void {
    try {
      const raw = fs.readFileSync(path.join(this.dataDir, 'shift_sessions.json'), 'utf8');
      this.sessions = JSON.parse(raw) as ShiftSession[];
    } catch { this.sessions = []; }
  }

  private flushProjects(): void {
    this.write('projects.json', this.projects);
  }

  private flushShifts(): void {
    this.write('shifts.json', this.shifts);
  }

  private flushSessions(): void {
    this.write('shift_sessions.json', this.sessions);
  }

  private write(filename: string, data: unknown): void {
    try {
      fs.writeFileSync(
        path.join(this.dataDir, filename),
        JSON.stringify(data, null, 2),
        'utf8'
      );
    } catch (err) {
      console.error(`[ProjectStore] Failed to write ${filename}:`, err);
    }
  }
}
