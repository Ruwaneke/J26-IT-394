/**
 * Sentinel — Supervisor Dashboard
 *
 * Sections
 *   Overview  — live shifts, today's agenda, team KPIs, developers at risk
 *   Projects  — create / edit / colour / archive / delete projects
 *   Shifts    — filterable list; create & edit with date + time pickers, presets, repeat rules,
 *               developer picker with conflict warnings
 *   Calendar  — month view; click a day to schedule, click a shift for details
 *   Team      — live status, next shift, scores, direct messages
 *   Reports   — report builder (scope + date range) with CSV / JSON / HTML export,
 *               and end-of-shift summaries
 *   Alerts    — notification history, announcements, alert preferences
 *
 * Interactive views (shifts, calendar, reports) are rendered client-side from an embedded
 * JSON snapshot (see supervisorClient.ts). All writes go through the extension, which
 * re-checks the supervisor role and project ownership.
 */

import { AuthSession } from '../auth/authManager.js';
import { Project, Shift, ShiftSession, PROJECT_COLORS } from '../data/projectStore.js';
import { icon, ICON_CSS } from './icons.js';
import { THEME_CSS, THEME_SCRIPT, themeHtmlAttrs, themeSwitchHtml } from './theme.js';
import { CHART_CSS } from './charts.js';
import { CONSOLE_CSS } from './consoleStyles.js';
import { NOTIFY_CSS, notificationBellHtml, notifyScript } from './notificationsUi.js';
import { SUPERVISOR_CSS, SUPERVISOR_CLIENT_JS } from './supervisorClient.js';

// ── Developer stats cache (filled by the extension from Neon before rendering) ──
export interface DevStats {
  developerId: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
}

let developerStatsCache: DevStats[] = [];

/** Called by the extension (with data loaded from the DB) before rendering dashboards. */
export function setDeveloperStats(stats: DevStats[]): void {
  developerStatsCache = stats;
}

export function loadAllDeveloperStats(_dataDir?: string): DevStats[] {
  return developerStatsCache;
}

// ── Input ─────────────────────────────────────────────────────────────────────

export interface SupervisorDeveloper {
  /** Assignment key: GitHub username when known, else local username */
  key: string;
  userId: string;
  username: string;
  githubUsername?: string;
  displayName: string;
  githubAvatarUrl?: string;
  lastLoginAt?: string;
}

/** Compact vulnerability record for client-side reports */
export interface ReportRecord {
  d: string;   // developer key
  t: string;   // vulnerability type
  s: string;   // severity
  st: string;  // status
  at: string;  // detected at
  fx: string | null; // fixed at
}

export interface SupervisorDashboardInput {
  session: AuthSession;
  cspSource: string;
  logoUri: string;
  projects: Project[];
  shifts: Shift[];
  sessions: ShiftSession[];
  developers: SupervisorDeveloper[];
  records: ReportRecord[];
  devStats: DevStats[];
  prefs: { reminderMinutes: number; popups: string };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function esc(s: unknown): string {
  if (s === null || s === undefined) { return ''; }
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

function fmtDay(iso: string): string {
  return new Date(iso).toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short' });
}

function relTime(iso?: string | null): string {
  if (!iso) { return 'never'; }
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) { return 'just now'; }
  if (m < 60) { return `${m}m ago`; }
  const h = Math.round(m / 60);
  return h < 48 ? `${h}h ago` : `${Math.round(h / 24)}d ago`;
}

const scoreColor = (n: number) => n >= 80 ? '#10b981' : n >= 50 ? '#f59e0b' : '#ef4444';

/** JSON safe to embed inside a <script> element. */
function scriptJson(v: unknown): string {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function kpi(ico: string, label: string, value: string | number, note: string, color?: string): string {
  return `<div class="kpi"><div class="kpi-top"><span class="kpi-lbl">${esc(label)}</span>${icon(ico)}</div>
    <div class="kpi-num"${color ? ` style="color:${color}"` : ''}>${esc(value)}</div><div class="kpi-note">${note}</div></div>`;
}

const empty = (msg: string) => `<div class="empty">${msg}</div>`;

// ── Builder ───────────────────────────────────────────────────────────────────

export function buildSupervisorDashboardHtml(input: SupervisorDashboardInput): string {
  const { session, cspSource, logoUri, projects, shifts, sessions, developers, devStats, prefs } = input;
  const now = Date.now();
  const supName = session.githubUsername ? `@${session.githubUsername}` : session.displayName;
  const devName = (key: string) => developers.find(d => d.key === key || d.username === key || d.githubUsername === key)?.displayName ?? key;
  const projColor = (id: string) => projects.find(p => p.id === id)?.color ?? '#3b82f6';

  const live = sessions.filter(s => !s.endedAt);
  const startOfToday = new Date(); startOfToday.setHours(0, 0, 0, 0);
  const endOfToday = new Date(startOfToday); endOfToday.setDate(endOfToday.getDate() + 1);
  const todays = shifts.filter(s => Date.parse(s.scheduledStart) < endOfToday.getTime() && Date.parse(s.scheduledEnd) > startOfToday.getTime())
    .sort((a, b) => a.scheduledStart.localeCompare(b.scheduledStart));
  const upcoming7 = shifts.filter(s => s.status === 'scheduled' && Date.parse(s.scheduledStart) > now && Date.parse(s.scheduledStart) < now + 7 * 864e5);
  const completedSessions = sessions.filter(s => s.endedAt && s.summary);
  const avgShiftScore = completedSessions.length
    ? Math.round(completedSessions.reduce((a, s) => a + (s.summary?.securityScore ?? 0), 0) / completedSessions.length) : null;
  const teamKeys = new Set(developers.map(d => d.key));
  const openTeam = input.records.filter(r => r.st === 'OPEN' && teamKeys.has(r.d)).length;
  const critTeam = input.records.filter(r => r.st === 'OPEN' && r.s === 'CRITICAL' && teamKeys.has(r.d)).length;
  const activeProjects = projects.filter(p => p.status === 'active');

  // ── Overview pieces ──
  const liveCards = live.map(s => {
    const crit = s.findings.filter(f => f.severity === 'CRITICAL').length;
    return `<div class="live-card" style="border-left-color:${projColor(s.projectId)}">
      <div class="live-head"><span class="live-pill"><span class="live-dot"></span>LIVE</span><span class="mono live-timer" data-start="${esc(s.startedAt)}">--:--:--</span></div>
      <div class="u-name">${esc(s.developerDisplayName)}</div>
      <div class="u-sub">${esc(s.shiftName)} · ${esc(s.projectName)}</div>
      <div class="live-stats"><span><strong>${s.findings.length}</strong> findings</span><span${crit ? ' style="color:var(--t-red)"' : ''}><strong>${crit}</strong> critical</span></div>
    </div>`;
  }).join('') || empty('No shifts are running right now.');

  const agenda = todays.map(s => {
    const st = s.status === 'active' || sessions.some(x => x.shiftId === s.id && !x.endedAt) ? 'live' : s.status;
    return `<div class="agenda-row" onclick="openShiftDetail('${esc(s.id)}')">
      <span class="agenda-bar" style="background:${projColor(s.projectId)}"></span>
      <div class="agenda-time mono">${fmtTime(s.scheduledStart)}<br><span class="muted">${fmtTime(s.scheduledEnd)}</span></div>
      <div style="flex:1;min-width:0"><div class="u-name">${esc(s.name)}</div><div class="u-sub">${esc(s.projectName)} · ${s.assignedDeveloperIds.length} developer${s.assignedDeveloperIds.length === 1 ? '' : 's'}</div></div>
      <span class="st-pill st-${st}">${st}</span>
    </div>`;
  }).join('') || empty('Nothing scheduled today.');

  const risk = devStats.filter(d => teamKeys.has(d.developerId)).sort((a, b) => a.score - b.score).slice(0, 5);

  // ── Projects ──
  const projectCards = projects.map(p => {
    const ps = shifts.filter(s => s.projectId === p.id);
    const pss = sessions.filter(s => s.projectId === p.id);
    const devs = new Set(ps.flatMap(s => s.assignedDeveloperIds));
    const done = pss.filter(s => s.summary);
    const avg = done.length ? Math.round(done.reduce((a, s) => a + (s.summary?.securityScore ?? 0), 0) / done.length) : null;
    const next = ps.filter(s => s.status === 'scheduled' && Date.parse(s.scheduledStart) > now).sort((a, b) => a.scheduledStart.localeCompare(b.scheduledStart))[0];
    const liveN = pss.filter(s => !s.endedAt).length;
    const pj = scriptJson({ id: p.id, name: p.name, description: p.description, color: p.color ?? '#3b82f6', status: p.status }).replace(/'/g, '&#39;');
    return `<div class="proj-card ${p.status !== 'active' ? 'is-muted' : ''}" style="--pc:${p.color ?? '#3b82f6'}">
      <div class="proj-top">
        <div style="min-width:0"><div class="proj-name">${esc(p.name)}</div><div class="proj-desc">${esc(p.description || 'No description')}</div></div>
        <span class="st-pill st-${p.status}">${p.status}</span>
      </div>
      <div class="proj-stats">
        <div><strong>${ps.length}</strong>shifts</div><div><strong>${devs.size}</strong>developers</div>
        <div><strong>${liveN}</strong>live</div><div><strong style="color:${avg === null ? 'inherit' : scoreColor(avg)}">${avg ?? '—'}</strong>avg score</div>
      </div>
      <div class="proj-next">${next ? `${icon('clock')} Next: <strong>${esc(next.name)}</strong> · ${fmtDay(next.scheduledStart)} ${fmtTime(next.scheduledStart)}` : `<span class="muted">No upcoming shifts</span>`}</div>
      <div class="proj-actions">
        ${p.status === 'active' ? `<button class="btn btn-primary" onclick="openShiftModal({ projectId: '${esc(p.id)}' })">${icon('calendar-plus')} New shift</button>` : ''}
        <button class="btn btn-secondary" onclick="showSection('shifts'); setShiftFilter('${esc(p.id)}')">${icon('list')} Shifts</button>
        <span class="icon-group"><button class="btn-ghost" title="Edit project" onclick='openProjectModal(${pj})'>${icon('pen')}</button>
        <button class="btn-ghost" title="${p.status === 'archived' ? 'Restore' : 'Archive'} project" onclick="post({ command: 'UPDATE_PROJECT', projectId: '${esc(p.id)}', status: '${p.status === 'archived' ? 'active' : 'archived'}' })">${icon(p.status === 'archived' ? 'refresh' : 'archive')}</button>
        <button class="btn-ghost danger" title="Delete project" onclick="post({ command: 'DELETE_PROJECT', projectId: '${esc(p.id)}' })">${icon('trash')}</button></span>
      </div>
    </div>`;
  }).join('');

  // ── Team ──
  const teamRows = developers.map(d => {
    const ls = live.find(s => s.developerId === d.key || s.developerId === d.username || s.developerUsername === d.username);
    const nextShift = shifts.filter(s => s.status === 'scheduled' && Date.parse(s.scheduledStart) > now && s.assignedDeveloperIds.some(id => id === d.key || id === d.username))
      .sort((a, b) => a.scheduledStart.localeCompare(b.scheduledStart))[0];
    const st = devStats.find(x => x.developerId === d.key || x.developerId === d.username);
    const ds = completedSessions.filter(s => s.developerId === d.key || s.developerUsername === d.username);
    const avg = ds.length ? Math.round(ds.reduce((a, s) => a + (s.summary?.securityScore ?? 0), 0) / ds.length) : null;
    const open = input.records.filter(r => (r.d === d.key || r.d === d.username) && r.st === 'OPEN').length;
    return `<tr class="team-row" data-search="${esc(`${d.displayName} ${d.username} ${d.githubUsername ?? ''}`.toLowerCase())}">
      <td><div class="u-cell">${d.githubAvatarUrl ? `<img class="u-avatar" src="${esc(d.githubAvatarUrl)}?s=56" alt="">` : `<div class="u-avatar u-initial">${esc(d.displayName.charAt(0).toUpperCase())}</div>`}
        <div><div class="u-name">${esc(d.displayName)}</div><div class="u-sub">@${esc(d.key)}</div></div></div></td>
      <td>${ls ? `<span class="st-pill st-live">Live · ${esc(ls.shiftName)}</span>` : `<span class="muted">Idle</span>`}</td>
      <td class="nowrap">${nextShift ? `${esc(nextShift.name)}<div class="u-sub">${fmtDay(nextShift.scheduledStart)} ${fmtTime(nextShift.scheduledStart)}</div>` : '<span class="muted">—</span>'}</td>
      <td class="num">${ds.length}</td>
      <td class="num">${avg === null ? '<span class="muted">—</span>' : `<strong style="color:${scoreColor(avg)}">${avg}</strong>`}</td>
      <td class="num">${open}</td>
      <td class="num">${st ? `<strong style="color:${scoreColor(st.score)}">${st.score}</strong>` : '<span class="muted">—</span>'}</td>
      <td class="muted nowrap">${relTime(d.lastLoginAt)}</td>
      <td class="actions"><button class="btn-ghost" title="Send a message" onclick="openAnnounce('dev', '${esc(d.key)}')">${icon('megaphone')}</button>
        <button class="btn-ghost" title="Report" onclick="showSection('reports'); setReportScope('dev:${esc(d.key)}')">${icon('file-text')}</button></td>
    </tr>`;
  }).join('');

  // Snapshot for the client (calendar, shift list, modals, reports)
  const snapshot = {
    me: { name: session.displayName },
    projects: projects.map(p => ({ id: p.id, name: p.name, color: p.color ?? '#3b82f6', status: p.status })),
    shifts: shifts.map(s => ({
      id: s.id, projectId: s.projectId, projectName: s.projectName, name: s.name, description: s.description,
      start: s.scheduledStart, end: s.scheduledEnd, devs: s.assignedDeveloperIds, status: s.status, seriesId: s.seriesId ?? null,
    })),
    sessions: sessions.map(s => ({
      id: s.id, shiftId: s.shiftId, shiftName: s.shiftName, projectId: s.projectId, projectName: s.projectName,
      dev: s.developerId, devName: s.developerDisplayName, start: s.startedAt, end: s.endedAt,
      findings: s.findings.map(f => ({ t: f.type, s: f.severity })),
      summary: s.summary ? {
        score: s.summary.securityScore, total: s.summary.totalFindings, crit: s.summary.criticalCount, high: s.summary.highCount,
        med: s.summary.mediumCount, low: s.summary.lowCount, minutes: s.summary.durationMinutes, recs: s.summary.recommendations, trend: s.summary.trend,
      } : null,
    })),
    developers: developers.map(d => ({ key: d.key, username: d.username, name: d.displayName })),
    records: input.records,
    colors: PROJECT_COLORS,
  };

  const projectOptions = activeProjects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');

  return `<!DOCTYPE html>
<html lang="en" ${themeHtmlAttrs()}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Supervisor</title>
<style>
${THEME_CSS}
${ICON_CSS}
${CHART_CSS}
${CONSOLE_CSS}
${NOTIFY_CSS}
${SUPERVISOR_CSS}
</style>
</head>
<body>

<header class="top-nav">
  <div class="brand">
    ${logoUri ? `<img src="${esc(logoUri)}" alt="Sentinel" class="brand-logo">` : icon('shield-check', 30)}
    <div class="brand-name">Sentinel</div>
    <span class="brand-tag sup">Supervisor</span>
  </div>
  <div class="top-right">
    <button class="btn btn-primary" onclick="openShiftModal({})">${icon('calendar-plus')} Schedule shift</button>
    ${notificationBellHtml()}
    <div class="admin-chip">${icon('eye')} <strong>${esc(supName)}</strong></div>
    ${themeSwitchHtml()}
    <button class="btn-signout" onclick="post({ command: 'LOGOUT' })">Sign Out</button>
  </div>
</header>

<div class="app">
  <nav class="sidebar">
    <div class="nav-heading">Supervision</div>
    <button class="nav-btn active" id="nav-overview" onclick="showSection('overview')">${icon('layout')} Overview ${live.length ? `<span class="nav-count live-count">${live.length} live</span>` : ''}</button>
    <button class="nav-btn" id="nav-projects" onclick="showSection('projects')">${icon('folder')} Projects <span class="nav-count">${projects.length}</span></button>
    <button class="nav-btn" id="nav-shifts" onclick="showSection('shifts')">${icon('clock')} Shifts <span class="nav-count">${shifts.length}</span></button>
    <button class="nav-btn" id="nav-calendar" onclick="showSection('calendar')">${icon('calendar')} Calendar</button>
    <button class="nav-btn" id="nav-team" onclick="showSection('team')">${icon('users')} Team <span class="nav-count">${developers.length}</span></button>
    <button class="nav-btn" id="nav-reports" onclick="showSection('reports')">${icon('file-text')} Reports</button>
    <button class="nav-btn" id="nav-alerts" onclick="showSection('alerts')">${icon('bell')} Alerts <span class="nav-count" id="navAlertCount"></span></button>
    <div class="sidebar-foot">Signed in as ${esc(session.displayName)}</div>
  </nav>

  <main class="content">

    <!-- ═══ OVERVIEW ═══ -->
    <section class="section active" id="section-overview">
      <div class="page-head"><div><div class="page-title">${icon('layout')} Team Overview</div><div class="page-sub">What your team is working on right now and what's coming up</div></div>
        <button class="btn btn-secondary" onclick="post({ command: 'REFRESH_SUPERVISOR' })">${icon('refresh')} Refresh</button></div>
      <div class="kpis">
        ${kpi('radio', 'Live now', live.length, `${live.reduce((a, s) => a + s.findings.length, 0)} findings this shift`, live.length ? '#10b981' : undefined)}
        ${kpi('calendar', 'Today', todays.length, `${upcoming7.length} more in next 7 days`)}
        ${kpi('folder', 'Active projects', activeProjects.length, `${projects.length - activeProjects.length} archived / completed`)}
        ${kpi('users', 'Developers', developers.length, `${new Set(shifts.flatMap(s => s.assignedDeveloperIds)).size} assigned to shifts`)}
        ${kpi('shield', 'Open findings', openTeam, `${critTeam} critical`, critTeam ? '#ef4444' : undefined)}
        ${kpi('target', 'Avg shift score', avgShiftScore ?? '—', `${completedSessions.length} completed sessions`, avgShiftScore === null ? undefined : scoreColor(avgShiftScore))}
      </div>
      <div class="card"><div class="card-title">${icon('radio')} Live shifts</div><div class="live-grid">${liveCards}</div></div>
      <div class="grid-2">
        <div class="card"><div class="card-title">${icon('calendar')} Today's schedule</div>${agenda}
          <div style="margin-top:10px"><button class="btn btn-secondary" onclick="showSection('calendar')">Open calendar ${icon('arrow-right')}</button></div></div>
        <div class="card"><div class="card-title">${icon('alert-triangle')} Developers needing attention</div>
          ${risk.length ? `<table class="data"><thead><tr><th>Developer</th><th class="num">Findings</th><th class="num">Critical</th><th class="num">Score</th></tr></thead><tbody>
            ${risk.map(r => `<tr><td><div class="u-name">${esc(devName(r.developerId))}</div><div class="u-sub">@${esc(r.developerId)}</div></td><td class="num">${r.total}</td><td class="num">${r.critical}</td><td class="num"><strong style="color:${scoreColor(r.score)}">${r.score}</strong></td></tr>`).join('')}
          </tbody></table>` : empty('No findings recorded for your team yet.')}</div>
      </div>
    </section>

    <!-- ═══ PROJECTS ═══ -->
    <section class="section" id="section-projects">
      <div class="page-head"><div><div class="page-title">${icon('folder')} Projects</div><div class="page-sub">Each project groups its shifts, developers and reports</div></div>
        <button class="btn btn-primary" onclick="openProjectModal(null)">${icon('plus')} New project</button></div>
      ${projectCards ? `<div class="proj-grid">${projectCards}</div>` : `<div class="empty-hero">${icon('folder', 34)}<div class="u-name" style="margin-top:10px">No projects yet</div><div class="muted" style="font-size:.85em;margin:4px 0 14px">Create a project, then schedule shifts for your developers.</div><button class="btn btn-primary" onclick="openProjectModal(null)">${icon('plus')} Create your first project</button></div>`}
    </section>

    <!-- ═══ SHIFTS ═══ -->
    <section class="section" id="section-shifts">
      <div class="page-head"><div><div class="page-title">${icon('clock')} Shifts</div><div class="page-sub">Schedule, edit and track every shift across your projects</div></div>
        <button class="btn btn-primary" onclick="openShiftModal({})">${icon('calendar-plus')} Schedule shift</button></div>
      <div class="toolbar">
        <select class="select" id="sfProject" onchange="renderShiftList()"><option value="">All projects</option>${projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select>
        <select class="select" id="sfStatus" onchange="renderShiftList()">
          <option value="upcoming">Upcoming &amp; live</option><option value="live">Live</option><option value="scheduled">Scheduled</option><option value="completed">Completed</option><option value="all">All</option>
        </select>
        <input class="input search" id="sfSearch" placeholder="Search shift or developer…" oninput="renderShiftList()">
      </div>
      <div id="shiftList"></div>
    </section>

    <!-- ═══ CALENDAR ═══ -->
    <section class="section" id="section-calendar">
      <div class="page-head"><div><div class="page-title">${icon('calendar')} Calendar</div><div class="page-sub">Click a day to schedule a shift there, or a shift to see its details</div></div>
        <div class="cal-nav">
          <button class="btn btn-secondary" onclick="calMove(-1)" aria-label="Previous month">${icon('chevron-left')}</button>
          <button class="btn btn-secondary" onclick="calToday()">Today</button>
          <button class="btn btn-secondary" onclick="calMove(1)" aria-label="Next month">${icon('chevron-right')}</button>
          <select class="select" id="calProject" onchange="renderCalendar()"><option value="">All projects</option>${projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select>
        </div></div>
      <div class="cal-title" id="calTitle"></div>
      <div class="cal-grid" id="calGrid"></div>
      <div class="card" style="margin-top:18px"><div class="card-title" id="calDayTitle">${icon('calendar')} Selected day</div><div id="calDayList"></div></div>
    </section>

    <!-- ═══ TEAM ═══ -->
    <section class="section" id="section-team">
      <div class="page-head"><div><div class="page-title">${icon('users')} Team</div><div class="page-sub">Live status, upcoming shifts and security scores for every developer</div></div>
        <button class="btn btn-secondary" onclick="openAnnounce('all')">${icon('megaphone')} Message everyone</button></div>
      <div class="toolbar"><input class="input search" id="teamSearch" placeholder="Search developers…" oninput="filterTeam()"></div>
      <div class="table-wrap"><table class="data" id="teamTable">
        <thead><tr><th>Developer</th><th>Status</th><th>Next shift</th><th class="num">Sessions</th><th class="num">Avg shift score</th><th class="num">Open findings</th><th class="num">Overall score</th><th>Last login</th><th></th></tr></thead>
        <tbody>${teamRows || `<tr><td colspan="9">${empty('No developers registered yet. Developers appear here after their first GitHub sign-in.')}</td></tr>`}</tbody>
      </table></div>
    </section>

    <!-- ═══ REPORTS ═══ -->
    <section class="section" id="section-reports">
      <div class="page-head"><div><div class="page-title">${icon('file-text')} Reports</div><div class="page-sub">Build a security report for a project, shift or developer over any period, then export it</div></div></div>
      <div class="card">
        <div class="form-grid rep-form">
          <div class="fg"><label for="rpScope">Scope</label><select class="select" id="rpScope">
            <option value="all">All my projects</option>
            <optgroup label="Project">${projects.map(p => `<option value="proj:${esc(p.id)}">${esc(p.name)}</option>`).join('')}</optgroup>
            <optgroup label="Developer">${developers.map(d => `<option value="dev:${esc(d.key)}">${esc(d.displayName)}</option>`).join('')}</optgroup>
            <optgroup label="Shift">${shifts.slice().sort((a, b) => b.scheduledStart.localeCompare(a.scheduledStart)).slice(0, 100).map(s => `<option value="shift:${esc(s.id)}">${esc(s.name)} — ${fmtDay(s.scheduledStart)}</option>`).join('')}</optgroup>
          </select></div>
          <div class="fg"><label>Period</label><div class="chip-row" id="rpPresets">
            <button type="button" class="chip" onclick="rpPreset(7)">7 days</button><button type="button" class="chip" onclick="rpPreset(30)">30 days</button>
            <button type="button" class="chip" onclick="rpPreset('month')">This month</button><button type="button" class="chip" onclick="rpPreset('all')">All time</button></div></div>
          <div class="fg"><label for="rpFrom">From</label><input class="input" type="date" id="rpFrom"></div>
          <div class="fg"><label for="rpTo">To</label><input class="input" type="date" id="rpTo"></div>
          <div class="fg"><button class="btn btn-primary" onclick="generateReport()">${icon('file-text')} Generate report</button></div>
        </div>
      </div>
      <div id="reportOut"></div>
      <div class="card"><div class="card-title">${icon('history')} End-of-shift summaries</div><div id="sessionSummaries"></div></div>
    </section>

    <!-- ═══ ALERTS ═══ -->
    <section class="section" id="section-alerts">
      <div class="page-head"><div><div class="page-title">${icon('bell')} Alerts &amp; Notifications</div><div class="page-sub">Everything Sentinel has told you, team announcements and alert preferences</div></div>
        <button class="btn btn-secondary" onclick="ntfMarkAll()">${icon('check')} Mark all as read</button></div>
      <div class="grid-2">
        <div class="card"><div class="card-title">${icon('megaphone')} Send an announcement</div>
          <div class="form-grid" style="grid-template-columns:1fr 1fr">
            <div class="fg"><label for="anAudience">To</label><select class="select" id="anAudience" onchange="anAudienceChanged()">
              <option value="all">All developers</option><option value="project">A project team</option><option value="dev">One developer</option></select></div>
            <div class="fg"><label for="anLevel">Priority</label><select class="select" id="anLevel"><option value="info">Normal</option><option value="warning">Important</option><option value="critical">Urgent</option></select></div>
            <div class="fg" id="anProjectWrap" style="display:none;grid-column:1/-1"><label for="anProject">Project</label><select class="select" id="anProject">${projectOptions || '<option value="">No active projects</option>'}</select></div>
            <div class="fg" id="anDevWrap" style="display:none;grid-column:1/-1"><label for="anDev">Developer</label><select class="select" id="anDev">${developers.map(d => `<option value="${esc(d.key)}">${esc(d.displayName)} (@${esc(d.key)})</option>`).join('')}</select></div>
            <div class="fg" style="grid-column:1/-1"><label for="anTitle">Title</label><input class="input" id="anTitle" maxlength="120" placeholder="e.g. Security review on Friday"></div>
            <div class="fg" style="grid-column:1/-1"><label for="anMsg">Message</label><textarea class="input" id="anMsg" rows="3" maxlength="600" placeholder="What should your team know?"></textarea></div>
          </div>
          <div style="margin-top:12px"><button class="btn btn-primary" onclick="sendAnnouncement()">${icon('send')} Send</button></div>
        </div>
        <div class="card"><div class="card-title">${icon('settings')} Alert preferences</div>
          <div class="card-sub">Applies to this VS Code installation</div>
          <div class="form-grid" style="grid-template-columns:1fr 1fr">
            <div class="fg"><label for="prReminder">Shift reminders</label><select class="select" id="prReminder">
              ${[0, 5, 10, 15, 30, 60].map(m => `<option value="${m}"${m === prefs.reminderMinutes ? ' selected' : ''}>${m === 0 ? 'Off' : `${m} min before start`}</option>`).join('')}</select></div>
            <div class="fg"><label for="prPopups">VS Code pop-ups</label><select class="select" id="prPopups">
              <option value="all"${prefs.popups === 'all' ? ' selected' : ''}>All notifications</option>
              <option value="important"${prefs.popups === 'important' ? ' selected' : ''}>Warnings &amp; critical only</option>
              <option value="off"${prefs.popups === 'off' ? ' selected' : ''}>Off (bell only)</option></select></div>
          </div>
          <div style="margin-top:12px"><button class="btn btn-secondary" onclick="savePrefs()">${icon('check')} Save preferences</button></div>
          <div class="card-sub" style="margin-top:14px;margin-bottom:0">You are alerted when developers start or finish shifts, when a shift is late or overruns, and when a critical vulnerability appears during a shift.</div>
        </div>
      </div>
      <div class="card"><div class="card-title">${icon('history')} Notification history</div>
        <div class="toolbar"><select class="select" id="alFilter" onchange="renderAlerts()"><option value="">All</option><option value="unread">Unread</option><option value="critical">Critical</option><option value="warning">Warnings</option><option value="shift">Shifts</option><option value="security">Security</option><option value="announcement">Announcements</option></select></div>
        <div id="alertList"><div class="loading">Loading…</div></div></div>
    </section>

  </main>
</div>

<!-- ═══ Project modal ═══ -->
<div class="modal-back" id="projectModal" onclick="if(event.target===this)closeModal('projectModal')">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="pmTitle">
    <div class="modal-head"><span id="pmTitle">New project</span><button class="btn-ghost" onclick="closeModal('projectModal')" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <input type="hidden" id="pmId">
      <div class="form-grid" style="grid-template-columns:1fr">
        <div class="fg"><label for="pmName">Project name</label><input class="input" id="pmName" maxlength="80" placeholder="e.g. Payments API hardening"></div>
        <div class="fg"><label for="pmDesc">Description</label><textarea class="input" id="pmDesc" rows="3" maxlength="400" placeholder="Goal, repository, scope…"></textarea></div>
        <div class="fg"><label>Colour</label><div class="swatches" id="pmColors"></div></div>
        <div class="fg" id="pmStatusWrap"><label for="pmStatus">Status</label><select class="select" id="pmStatus"><option value="active">Active</option><option value="completed">Completed</option><option value="archived">Archived</option></select></div>
      </div>
    </div>
    <div class="modal-foot"><button class="btn btn-secondary" onclick="closeModal('projectModal')">Cancel</button><button class="btn btn-primary" onclick="saveProject()">Save project</button></div>
  </div>
</div>

<!-- ═══ Shift modal (create / edit) ═══ -->
<div class="modal-back" id="shiftModal" onclick="if(event.target===this)closeModal('shiftModal')">
  <div class="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="smTitle">
    <div class="modal-head"><span id="smTitle">Schedule a shift</span><button class="btn-ghost" onclick="closeModal('shiftModal')" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body">
      <input type="hidden" id="smId">
      <div class="sm-grid">
        <div class="sm-col">
          <div class="fg"><label for="smProject">Project</label><select class="select" id="smProject">${projectOptions || '<option value="">Create a project first</option>'}</select></div>
          <div class="fg"><label for="smName">Shift name</label><input class="input" id="smName" maxlength="80" placeholder="e.g. Morning secure-coding sprint"></div>
          <div class="fg"><label for="smDesc">Notes <span class="muted">(optional)</span></label><textarea class="input" id="smDesc" rows="2" maxlength="400" placeholder="Focus area, tickets…"></textarea></div>

          <div class="fg"><label for="smDate">Date</label>
            <div class="chip-row"><button type="button" class="chip" onclick="smQuickDate(0)">Today</button><button type="button" class="chip" onclick="smQuickDate(1)">Tomorrow</button><button type="button" class="chip" onclick="smQuickDate('mon')">Next Monday</button></div>
            <input class="input" type="date" id="smDate" onchange="smUpdate()"></div>
          <div class="fg"><label>Time</label>
            <div class="chip-row"><button type="button" class="chip" onclick="smPreset('09:00','13:00')">Morning 9–13</button><button type="button" class="chip" onclick="smPreset('13:00','17:00')">Afternoon 13–17</button><button type="button" class="chip" onclick="smPreset('09:00','17:00')">Full day 9–17</button><button type="button" class="chip" onclick="smPreset('18:00','22:00')">Evening 18–22</button></div>
            <div class="time-row"><input class="input" type="time" id="smStart" step="300" onchange="smUpdate()" aria-label="Start time"><span class="muted">to</span><input class="input" type="time" id="smEnd" step="300" onchange="smUpdate()" aria-label="End time"></div>
            <div class="chip-row" style="margin-top:6px"><span class="muted" style="font-size:.72em;align-self:center">Duration:</span><button type="button" class="chip" onclick="smDuration(60)">1h</button><button type="button" class="chip" onclick="smDuration(120)">2h</button><button type="button" class="chip" onclick="smDuration(240)">4h</button><button type="button" class="chip" onclick="smDuration(480)">8h</button></div></div>
          <div class="fg" id="smRepeatWrap"><label for="smRepeat">Repeat</label>
            <div class="time-row"><select class="select" id="smRepeat" onchange="smUpdate()"><option value="none">Does not repeat</option><option value="daily">Every day</option><option value="weekdays">Every weekday (Mon–Fri)</option><option value="weekly">Every week</option></select>
              <span class="muted" id="smUntilLbl" style="display:none">until</span><input class="input" type="date" id="smUntil" style="display:none" onchange="smUpdate()" aria-label="Repeat until"></div></div>
          <div class="sm-summary" id="smSummary"></div>
        </div>
        <div class="sm-col">
          <div class="fg"><label>Developers</label>
            <div class="time-row"><input class="input" id="smDevSearch" placeholder="Search developers…" oninput="smRenderDevs()" style="flex:1"><button type="button" class="chip" onclick="smAllDevs(true)">All</button><button type="button" class="chip" onclick="smAllDevs(false)">None</button></div>
            <div class="dev-pick" id="smDevs"></div></div>
          <div id="smConflicts"></div>
        </div>
      </div>
    </div>
    <div class="modal-foot"><span class="muted" id="smFootNote" style="margin-right:auto;font-size:.75em"></span><button class="btn btn-secondary" onclick="closeModal('shiftModal')">Cancel</button><button class="btn btn-primary" id="smSave" onclick="saveShift()">Schedule shift</button></div>
  </div>
</div>

<!-- ═══ Shift detail modal ═══ -->
<div class="modal-back" id="detailModal" onclick="if(event.target===this)closeModal('detailModal')">
  <div class="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="sdTitle">
    <div class="modal-head"><span id="sdTitle">Shift</span><button class="btn-ghost" onclick="closeModal('detailModal')" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body" id="sdBody"></div>
    <div class="modal-foot" id="sdFoot"></div>
  </div>
</div>

<!-- ═══ Announcement modal (from Team) ═══ -->
<div class="modal-back" id="announceModal" onclick="if(event.target===this)closeModal('announceModal')">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="amTitle">
    <div class="modal-head"><span id="amTitle">Message</span><button class="btn-ghost" onclick="closeModal('announceModal')" aria-label="Close">${icon('x')}</button></div>
    <div class="modal-body"><div class="form-grid" style="grid-template-columns:1fr">
      <input type="hidden" id="amAudience"><input type="hidden" id="amTarget">
      <div class="fg"><label for="amLevel">Priority</label><select class="select" id="amLevel"><option value="info">Normal</option><option value="warning">Important</option><option value="critical">Urgent</option></select></div>
      <div class="fg"><label for="amTitleIn">Title</label><input class="input" id="amTitleIn" maxlength="120"></div>
      <div class="fg"><label for="amMsg">Message</label><textarea class="input" id="amMsg" rows="4" maxlength="600"></textarea></div>
    </div></div>
    <div class="modal-foot"><button class="btn btn-secondary" onclick="closeModal('announceModal')">Cancel</button><button class="btn btn-primary" onclick="sendAnnounceModal()">${icon('send')} Send</button></div>
  </div>
</div>

<div class="toast-wrap" id="toasts"></div>

<script>
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;
const DATA = ${scriptJson(snapshot)};
const ICON = ${scriptJson({
    clock: icon('clock'), users: icon('users'), pen: icon('pen'), trash: icon('trash'), copy: icon('copy'), file: icon('file-text'),
    alert: icon('alert-triangle'), ok: icon('check-circle'), plus: icon('plus'), radio: icon('radio'), download: icon('download'),
    info: icon('info'), crit: icon('alert-octagon'), cal: icon('calendar'), folder: icon('folder'),
  })};
${SUPERVISOR_CLIENT_JS}
</script>
<script>${notifyScript()}</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>`;
}
