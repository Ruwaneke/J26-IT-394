/**
 * Sentinel — System-wide alerts & notifications
 *
 * Every Sentinel user (developer, supervisor, administrator) runs their own VS Code instance,
 * so notifications are stored in Neon (`sentinel_documents`, collection "notifications",
 * one row per notification) and every instance polls for the ones addressed to its user.
 *
 * Delivery for the signed-in user:
 *   • VS Code pop-up (information / warning / error by level, respecting `sentinel.notifications.popups`)
 *   • Bell + dropdown and toast inside whichever Sentinel dashboard is open
 *
 * Producers: shift lifecycle (assigned / changed / cancelled / started / ended), scheduled checks
 * (starting soon, not started, overrunning), critical findings during a shift, supervisor
 * announcements and admin account changes.
 *
 * Scheduled notifications use deterministic ids + insert-if-absent, so several running
 * instances generate each reminder exactly once.
 */

import * as vscode from 'vscode';
import { NeonDatabaseService } from '../data/neonDatabaseService.js';
import { UserRole } from '../auth/authManager.js';
import { Shift, ShiftSession, Project } from '../data/projectStore.js';

export type NotificationLevel = 'info' | 'success' | 'warning' | 'critical';
export type NotificationCategory = 'shift' | 'project' | 'security' | 'announcement' | 'system';

export interface SentinelNotification {
  id: string;
  createdAt: string;
  level: NotificationLevel;
  category: NotificationCategory;
  title: string;
  message: string;
  /** Any of: user id, username, GitHub username. */
  recipientIds: string[];
  /** Everyone with one of these roles also receives it. */
  recipientRoles: UserRole[];
  /** Dashboard section to open when clicked, e.g. "shift", "shifts", "alerts". */
  section?: string;
  createdBy?: string;
  readBy: string[];
}

export interface Principal {
  userId: string;
  username: string;
  githubUsername?: string;
  role: UserRole;
  displayName: string;
}

const COLLECTION = 'notifications';
const RETENTION_DAYS = 30;

function newId(prefix = 'ntf'): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function principalIds(p: Principal): string[] {
  return [p.userId, p.username, p.githubUsername].filter((x): x is string => !!x);
}

export function isRecipient(n: SentinelNotification, p: Principal): boolean {
  const ids = principalIds(p);
  return n.recipientRoles.includes(p.role) || n.recipientIds.some(id => ids.includes(id));
}

/** Format a time in the user's locale for notification text. */
function when(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString('en-GB', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

export class NotificationService implements vscode.Disposable {
  private cache: SentinelNotification[] = [];
  private shown: Set<string>;
  private pollTimer: ReturnType<typeof setInterval> | undefined;
  private listeners: Array<(items: SentinelNotification[], fresh: SentinelNotification[]) => void> = [];

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly getPrincipal: () => Principal | null,
    private readonly onOpen: (section?: string) => void,
    private readonly log: (msg: string) => void,
  ) {
    this.shown = new Set(context.globalState.get<string[]>('sentinel.notifications.shown', []));
  }

  // ─── Subscription / polling ────────────────────────────────────────────────

  onChange(fn: (items: SentinelNotification[], fresh: SentinelNotification[]) => void): void {
    this.listeners.push(fn);
  }

  start(intervalMs = 30000): void {
    this.stop();
    void this.refresh();
    this.pollTimer = setInterval(() => void this.refresh(), intervalMs);
    void NeonDatabaseService.getInstance().pruneDocuments(COLLECTION, RETENTION_DAYS);
  }

  stop(): void {
    if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = undefined; }
  }

  dispose(): void { this.stop(); }

  /** Notifications for the signed-in user, newest first. */
  list(): SentinelNotification[] {
    const p = this.getPrincipal();
    if (!p) { return []; }
    return this.cache.filter(n => isRecipient(n, p)).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  unreadCount(): number {
    const p = this.getPrincipal();
    if (!p) { return 0; }
    return this.list().filter(n => !n.readBy.includes(p.userId)).length;
  }

  /** Reload from the database, pop up anything new for this user, notify listeners. */
  async refresh(): Promise<void> {
    const p = this.getPrincipal();
    const docs = await NeonDatabaseService.getInstance().loadRecentDocuments<SentinelNotification>(COLLECTION, RETENTION_DAYS);
    this.cache = docs.map(d => d.data).filter(n => n && n.id);
    if (!p) { return; }
    const mine = this.list();
    const fresh = mine.filter(n => !this.shown.has(n.id) && !n.readBy.includes(p.userId));
    // Don't flood a user who has been offline: pop up at most the 3 newest.
    for (const n of fresh.slice(0, 3)) { this.popup(n); }
    if (fresh.length) {
      fresh.forEach(n => this.shown.add(n.id));
      void this.context.globalState.update('sentinel.notifications.shown', [...this.shown].slice(-500));
    }
    this.listeners.forEach(fn => fn(mine, fresh));
  }

  // ─── Producing notifications ───────────────────────────────────────────────

  async notify(input: Omit<SentinelNotification, 'id' | 'createdAt' | 'readBy'> & { id?: string }): Promise<SentinelNotification | null> {
    if (input.recipientIds.length === 0 && input.recipientRoles.length === 0) { return null; }
    const n: SentinelNotification = {
      ...input,
      recipientIds: [...new Set(input.recipientIds.filter(Boolean))],
      id: input.id ?? newId(),
      createdAt: new Date().toISOString(),
      readBy: [],
    };
    const inserted = await NeonDatabaseService.getInstance().insertDocumentIfAbsent(COLLECTION, n.id, n);
    if (!inserted) { return null; } // already generated by another instance (deterministic ids)
    this.log(`[Notify] ${n.level.toUpperCase()} → ${n.recipientIds.join(',') || n.recipientRoles.join(',')}: ${n.title}`);
    this.cache.unshift(n);
    const p = this.getPrincipal();
    if (p && isRecipient(n, p)) {
      this.shown.add(n.id);
      this.popup(n);
      this.listeners.forEach(fn => fn(this.list(), [n]));
    }
    return n;
  }

  async markRead(ids: string[] | 'all'): Promise<void> {
    const p = this.getPrincipal();
    if (!p) { return; }
    const targets = ids === 'all' ? this.list().filter(n => !n.readBy.includes(p.userId)) : this.cache.filter(n => ids.includes(n.id));
    const db = NeonDatabaseService.getInstance();
    await Promise.all(targets.map(async n => {
      if (!n.readBy.includes(p.userId)) { n.readBy.push(p.userId); }
      await db.addToDocumentArray(COLLECTION, n.id, 'readBy', p.userId);
    }));
    this.listeners.forEach(fn => fn(this.list(), []));
  }

  // ─── Shift lifecycle helpers ───────────────────────────────────────────────

  shiftAssigned(shift: Shift, devIds: string[], by: string): Promise<unknown> {
    return this.notify({
      level: 'info', category: 'shift', section: 'shift',
      title: `New shift: ${shift.name}`,
      message: `${by} assigned you to "${shift.name}" (${shift.projectName}) — ${when(shift.scheduledStart)} to ${when(shift.scheduledEnd)}.`,
      recipientIds: devIds, recipientRoles: [], createdBy: by,
    });
  }

  shiftUnassigned(shift: Shift, devIds: string[], by: string): Promise<unknown> {
    return this.notify({
      level: 'info', category: 'shift', section: 'shift',
      title: `Removed from shift: ${shift.name}`,
      message: `${by} removed you from "${shift.name}" (${shift.projectName}) on ${when(shift.scheduledStart)}.`,
      recipientIds: devIds, recipientRoles: [], createdBy: by,
    });
  }

  shiftChanged(shift: Shift, by: string): Promise<unknown> {
    return this.notify({
      level: 'warning', category: 'shift', section: 'shift',
      title: `Shift rescheduled: ${shift.name}`,
      message: `"${shift.name}" (${shift.projectName}) is now ${when(shift.scheduledStart)} to ${when(shift.scheduledEnd)}.`,
      recipientIds: shift.assignedDeveloperIds, recipientRoles: [], createdBy: by,
    });
  }

  shiftCancelled(shift: Shift, by: string): Promise<unknown> {
    return this.notify({
      level: 'warning', category: 'shift', section: 'shift',
      title: `Shift cancelled: ${shift.name}`,
      message: `${by} cancelled "${shift.name}" (${shift.projectName}) scheduled for ${when(shift.scheduledStart)}.`,
      recipientIds: shift.assignedDeveloperIds, recipientRoles: [], createdBy: by,
    });
  }

  shiftStarted(shift: Shift, project: Project | undefined, devName: string): Promise<unknown> {
    return this.notify({
      level: 'info', category: 'shift', section: 'overview',
      title: `${devName} started ${shift.name}`,
      message: `${devName} started "${shift.name}" (${shift.projectName}) at ${when(new Date().toISOString())}.`,
      recipientIds: [project?.supervisorId ?? shift.createdBy, shift.createdBy], recipientRoles: [],
    });
  }

  shiftEnded(session: ShiftSession, project: Project | undefined, shift: Shift | undefined): Promise<unknown> {
    const sum = session.summary;
    const score = sum?.securityScore ?? 100;
    return this.notify({
      level: score >= 80 ? 'success' : score >= 50 ? 'warning' : 'critical', category: 'shift', section: 'reports',
      title: `${session.developerDisplayName} finished ${session.shiftName} — score ${score}/100`,
      message: `${sum?.totalFindings ?? 0} findings (${sum?.criticalCount ?? 0} critical, ${sum?.highCount ?? 0} high) in ${sum?.durationMinutes ?? 0} min.`,
      recipientIds: [project?.supervisorId ?? '', shift?.createdBy ?? ''], recipientRoles: [],
    });
  }

  criticalFinding(findingId: string, type: string, file: string, line: number, devName: string, session: ShiftSession, project: Project | undefined): Promise<unknown> {
    return this.notify({
      id: `crit-${session.id}-${findingId}`,
      level: 'critical', category: 'security', section: 'overview',
      title: `Critical ${type.replace(/_/g, ' ')} during ${session.shiftName}`,
      message: `${devName} introduced a CRITICAL ${type.replace(/_/g, ' ')} in ${file}:${line}.`,
      recipientIds: [project?.supervisorId ?? ''], recipientRoles: [],
    });
  }

  /**
   * Time-based checks. Safe to run from every instance: ids are deterministic per shift + kind.
   *   • starting soon  → assigned developers + supervisor
   *   • not started 10 min after start → supervisor
   *   • still running 15 min after scheduled end → developer(s) + supervisor
   */
  async runScheduledChecks(shifts: Shift[], sessions: ShiftSession[], projects: Project[], reminderMinutes: number): Promise<void> {
    const now = Date.now();
    for (const sh of shifts) {
      const start = Date.parse(sh.scheduledStart), end = Date.parse(sh.scheduledEnd);
      if (isNaN(start) || isNaN(end)) { continue; }
      const sup = projects.find(p => p.id === sh.projectId)?.supervisorId ?? sh.createdBy;
      const shSessions = sessions.filter(s => s.shiftId === sh.id);

      if (sh.status === 'scheduled' && reminderMinutes > 0 && start > now && start - now <= reminderMinutes * 60000) {
        await this.notify({
          id: `rem-soon-${sh.id}`, level: 'info', category: 'shift', section: 'shift',
          title: `${sh.name} starts in ${Math.max(1, Math.round((start - now) / 60000))} min`,
          message: `"${sh.name}" (${sh.projectName}) starts at ${when(sh.scheduledStart)}. Open Sentinel to start the shift.`,
          recipientIds: [...sh.assignedDeveloperIds, sup], recipientRoles: [],
        });
      }
      if (sh.status === 'scheduled' && shSessions.length === 0 && now - start > 10 * 60000 && now < end) {
        await this.notify({
          id: `rem-late-${sh.id}`, level: 'warning', category: 'shift', section: 'shifts',
          title: `${sh.name} hasn't been started`,
          message: `"${sh.name}" (${sh.projectName}) was due at ${when(sh.scheduledStart)} but no developer has started it.`,
          recipientIds: [sup], recipientRoles: [],
        });
      }
      const running = shSessions.filter(s => !s.endedAt);
      if (running.length && now - end > 15 * 60000) {
        await this.notify({
          id: `rem-over-${sh.id}`, level: 'warning', category: 'shift', section: 'shift',
          title: `${sh.name} is running over`,
          message: `"${sh.name}" was scheduled to end at ${when(sh.scheduledEnd)}. Please end the shift to generate its report.`,
          recipientIds: [...running.map(s => s.developerId), sup], recipientRoles: [],
        });
      }
    }
  }

  // ─── VS Code pop-ups ───────────────────────────────────────────────────────

  private popup(n: SentinelNotification): void {
    const pref = vscode.workspace.getConfiguration('sentinel').get<string>('notifications.popups', 'all');
    if (pref === 'off') { return; }
    if (pref === 'important' && (n.level === 'info' || n.level === 'success')) { return; }
    const text = `Sentinel — ${n.title}: ${n.message}`;
    const action = 'Open';
    const show = n.level === 'critical' ? vscode.window.showErrorMessage
      : n.level === 'warning' ? vscode.window.showWarningMessage
      : vscode.window.showInformationMessage;
    void show(text, action, 'Mark as read').then(choice => {
      if (choice === action) { this.onOpen(n.section); void this.markRead([n.id]); }
      if (choice === 'Mark as read') { void this.markRead([n.id]); }
    });
  }
}
