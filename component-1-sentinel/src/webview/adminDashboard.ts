/**
 * Sentinel — Administrator Dashboard
 *
 * System-wide control panel for administrators.
 *
 * Sections
 *   Overview   — system KPIs, 14-day detected/fixed trend, developers needing attention, recent activity
 *   Users      — search / filter, edit role · name · email, add and remove accounts
 *   Analytics  — per-developer fix rates & scores, severity, OWASP and vulnerability-type breakdowns
 *   Database   — (dropdown) Overview · Data Browser · Maintenance · Backup
 *   Audit Log  — system-wide activity trail with filters
 *   System     — runtime configuration and integration status
 *
 * Every privileged action is posted to the extension, which re-checks the administrator role,
 * asks for a native confirmation on destructive operations and writes an audit-log entry.
 */

import { AuthSession, UserRole } from '../auth/authManager.js';
import { DbVulnerabilityRecord, UserActivityLog } from '../data/neonDatabaseService.js';
import { DeveloperInsights } from '../analytics/developerInsights.js';
import { icon, ICON_CSS } from './icons.js';
import { THEME_CSS, THEME_SCRIPT, themeHtmlAttrs, themeSwitchHtml } from './theme.js';
import { CHART_CSS, barRowHtml, trendChartSvg, trendLegendHtml } from './charts.js';
import { CONSOLE_CSS } from './consoleStyles.js';
import { NOTIFY_CSS, notificationBellHtml, notifyScript } from './notificationsUi.js';

// ─── Input types ──────────────────────────────────────────────────────────────

export interface AdminUserRow {
  id: string;
  username: string;
  githubUsername: string | null;
  role: UserRole;
  displayName: string;
  email: string;
  githubAvatarUrl: string | null;
  createdAt: string;
  lastLoginAt: string;
}

export interface AdminDevStat {
  developerId: string;
  total: number; critical: number; high: number; medium: number; low: number; score: number;
}

export interface AdminSystemInfo {
  extensionVersion: string;
  backendUrl: string;
  ifeUrl: string;
  apiUrl: string;
  apiRunning: boolean;
  apiError: string | null;
  theme: string;
  minConfidence: number;
  analysisEnabled: boolean;
  aiEnabled: boolean;
  rulesCount: number;
  debounceMs: number;
}

export interface AdminDashboardInput {
  session: AuthSession;
  cspSource: string;
  logoUri: string;
  users: AdminUserRow[];
  devStats: AdminDevStat[];
  records: DbVulnerabilityRecord[];
  activities: UserActivityLog[];
  insights: DeveloperInsights;
  dbStatus: { isOnline: boolean; pingMs: number; error: string | null };
  system: AdminSystemInfo;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function esc(s: unknown): string {
  if (s === null || s === undefined) { return ''; }
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtDate(iso: string | null | undefined): string {
  if (!iso) { return '—'; }
  const d = new Date(iso);
  return isNaN(d.getTime()) ? '—' : d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function relTime(iso: string | null | undefined): string {
  if (!iso) { return 'never'; }
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) { return '—'; }
  const m = Math.round(ms / 60000);
  if (m < 1) { return 'just now'; }
  if (m < 60) { return `${m}m ago`; }
  const h = Math.round(m / 60);
  if (h < 48) { return `${h}h ago`; }
  return `${Math.round(h / 24)}d ago`;
}

const scoreColor = (n: number) => n >= 80 ? '#10b981' : n >= 50 ? '#f59e0b' : '#ef4444';
const sevColor = (s: string) => ({ CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' } as Record<string, string>)[s] ?? '#60a5fa';
const ROLE_META: Record<string, { icon: string; color: string; label: string }> = {
  administrator: { icon: 'lock',   color: 'var(--t-red)',   label: 'Administrator' },
  supervisor:    { icon: 'eye',    color: 'var(--t-amber)', label: 'Supervisor' },
  developer:     { icon: 'code',   color: 'var(--t-cyan)',  label: 'Developer' },
};
const pretty = (t: string) => esc((t || '').replace(/_/g, ' '));

// ─── Builder ──────────────────────────────────────────────────────────────────

export function buildAdminDashboardHtml(input: AdminDashboardInput): string {
  const { session, cspSource, logoUri, users, devStats, records, activities, insights: ins, dbStatus, system } = input;
  const adminName = session.githubUsername ? `@${session.githubUsername}` : session.displayName;

  // ── Per-developer aggregation (records keyed by developer or GitHub username) ──
  type DevRow = { id: string; name: string; total: number; open: number; fixed: number; ignored: number; critOpen: number; score: number; last: string | null };
  const devMap = new Map<string, DevRow>();
  const nameFor = (id: string) => {
    const u = users.find(x => x.username === id || x.githubUsername === id);
    return u ? u.displayName : id;
  };
  for (const r of records) {
    const id = r.githubUsername || r.developerId;
    const row = devMap.get(id) ?? { id, name: nameFor(id), total: 0, open: 0, fixed: 0, ignored: 0, critOpen: 0, score: 100, last: null };
    row.total++;
    if (r.status === 'FIXED') { row.fixed++; } else if (r.status === 'OPEN') { row.open++; } else { row.ignored++; }
    if (r.status === 'OPEN' && r.severity === 'CRITICAL') { row.critOpen++; }
    if (!row.last || r.detectedAt > row.last) { row.last = r.detectedAt; }
    devMap.set(id, row);
  }
  for (const s of devStats) {
    const row = devMap.get(s.developerId);
    if (row) { row.score = s.score; }
  }
  const devRows = [...devMap.values()].sort((a, b) => a.score - b.score || b.open - a.open);
  const attention = devRows.filter(d => d.open > 0).slice(0, 5);

  const roleCount = (r: string) => users.filter(u => u.role === r).length;
  const t = ins.totals;
  const critOpen = records.filter(r => r.status === 'OPEN' && r.severity === 'CRITICAL').length;
  const activeToday = new Set(activities.filter(a => Date.now() - new Date(a.createdAt).getTime() < 86400000).map(a => a.username || a.developerId)).size;

  // ── Users table ──
  const userRows = users.map(u => {
    const rm = ROLE_META[u.role] ?? ROLE_META.developer;
    const ds = devMap.get(u.githubUsername || u.username) ?? devMap.get(u.username);
    const isSelf = u.id === session.userId;
    const search = `${u.username} ${u.githubUsername ?? ''} ${u.displayName} ${u.email} ${u.role}`.toLowerCase();
    return `<tr class="user-row" data-role="${esc(u.role)}" data-search="${esc(search)}">
      <td>
        <div class="u-cell">
          ${u.githubAvatarUrl
            ? `<img class="u-avatar" src="${esc(u.githubAvatarUrl)}?s=56" alt="">`
            : `<div class="u-avatar u-initial">${esc(u.displayName.charAt(0).toUpperCase())}</div>`}
          <div>
            <div class="u-name">${esc(u.displayName)} ${isSelf ? '<span class="you-pill">You</span>' : ''}</div>
            <div class="u-sub">@${esc(u.githubUsername || u.username)}${u.email ? ` · ${esc(u.email)}` : ''}</div>
          </div>
        </div>
      </td>
      <td><span class="role-pill" style="color:${rm.color}">${icon(rm.icon)} ${rm.label}</span></td>
      <td class="num">${ds ? `${ds.total} <span class="muted">(${ds.open} open)</span>` : '<span class="muted">—</span>'}</td>
      <td class="muted nowrap" title="${esc(fmtDate(u.lastLoginAt))}">${relTime(u.lastLoginAt)}</td>
      <td class="muted nowrap">${fmtDate(u.createdAt).split(',')[0]}</td>
      <td class="actions">
        <button class="btn-ghost" onclick='openEditUser(${JSON.stringify({ id: u.id, username: u.username, displayName: u.displayName, email: u.email, role: u.role }).replace(/'/g, '&#39;')})' title="Edit user">${icon('pen')} Edit</button>
        ${isSelf ? '' : `<button class="btn-ghost danger" onclick="removeUser('${esc(u.id)}','${esc(u.username)}')" title="Remove user">${icon('trash')}</button>`}
      </td>
    </tr>`;
  }).join('');

  // ── Analytics rows ──
  const devTableRows = devRows.map(d => {
    const rate = d.total ? Math.round((d.fixed / d.total) * 1000) / 10 : 0;
    return `<tr>
      <td><div class="u-name">${esc(d.name)}</div><div class="u-sub">@${esc(d.id)}</div></td>
      <td class="num">${d.total}</td>
      <td class="num">${d.open}</td>
      <td class="num">${d.fixed}</td>
      <td style="min-width:150px">${barRowHtml('', rate, 100, `${rate}%`, scoreColor(rate), `${d.fixed}/${d.total} fixed`).replace('<div class="bar-label"></div>', '')}</td>
      <td class="num">${d.critOpen ? `<span style="color:var(--t-red);font-weight:700">${d.critOpen}</span>` : '0'}</td>
      <td class="num"><span style="color:${scoreColor(d.score)};font-weight:800">${d.score}</span></td>
      <td class="muted nowrap">${relTime(d.last)}</td>
    </tr>`;
  }).join('');

  const sevKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const sevMax = Math.max(1, ...sevKeys.map(k => ins.severity[k]));
  const sevRows = sevKeys.map(k => barRowHtml(`<span class="sev-dot" style="background:${sevColor(k)}"></span>${k}`,
    ins.severity[k], sevMax, `${ins.severity[k]}`, sevColor(k), `${k}: ${ins.severity[k]}`)).join('');
  const owaspMax = Math.max(1, ...ins.owasp.map(o => o.count));
  const owaspRows = ins.owasp.map(o => barRowHtml(`<span class="mono muted">${esc(o.id.split(':')[0])}</span>${esc(o.name)}`,
    o.count, owaspMax, `${o.count}`, '#3b82f6', `${o.id} ${o.name}: ${o.count}`)).join('') || empty('No OWASP data yet.');
  const typeRows = ins.fixRateByType.slice(0, 10).map(x => barRowHtml(pretty(x.vulnerabilityType), x.fixRate, 100,
    `${x.fixRate}% <span class="muted">(${x.fixed}/${x.detected})</span>`, scoreColor(x.fixRate),
    `${x.vulnerabilityType}: ${x.fixed} fixed of ${x.detected}`)).join('') || empty('No vulnerability data yet.');

  // ── Activity ──
  const actionTypes = [...new Set(activities.map(a => a.actionType))].sort();
  const activityRow = (a: UserActivityLog) => {
    const isAdmin = a.actionType.startsWith('ADMIN_');
    return `<tr class="audit-row" data-action="${esc(a.actionType)}" data-search="${esc(`${a.username ?? ''} ${a.developerId ?? ''} ${a.actionType} ${a.vulnerabilityType ?? ''}`.toLowerCase())}">
      <td class="muted nowrap">${fmtDate(a.createdAt)}</td>
      <td>${esc(a.username || a.githubUsername || a.developerId || 'system')}</td>
      <td><span class="action-pill ${isAdmin ? 'admin' : ''}">${pretty(a.actionType)}</span></td>
      <td class="muted">${esc(a.vulnerabilityType ?? '')}${a.findingId ? ` <span class="mono">${esc(a.findingId)}</span>` : ''}</td>
    </tr>`;
  };
  const recentActivity = activities.slice(0, 8).map(a => `
    <div class="feed-item">
      <span class="feed-dot ${a.actionType.startsWith('ADMIN_') ? 'admin' : ''}"></span>
      <div class="feed-body"><strong>${esc(a.username || a.developerId || 'system')}</strong> <span class="muted">${pretty(a.actionType).toLowerCase()}</span>${a.vulnerabilityType ? ` · ${pretty(a.vulnerabilityType)}` : ''}</div>
      <span class="muted nowrap">${relTime(a.createdAt)}</span>
    </div>`).join('') || empty('No activity recorded yet.');

  const developerOptions = devRows.map(d => `<option value="${esc(d.id)}">${esc(d.name)} (@${esc(d.id)}) — ${d.total} records</option>`).join('');

  return `<!DOCTYPE html>
<html lang="en" ${themeHtmlAttrs()}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Admin</title>
<style>
${THEME_CSS}
${ICON_CSS}
${CHART_CSS}
${CONSOLE_CSS}
${NOTIFY_CSS}
</style>
</head>
<body>

<header class="top-nav">
  <div class="brand">
    ${logoUri ? `<img src="${esc(logoUri)}" alt="Sentinel" class="brand-logo">` : icon('shield-check', 30)}
    <div class="brand-name">Sentinel</div>
    <span class="brand-tag">Administrator</span>
  </div>
  <div class="db-pill ${dbStatus.isOnline ? 'on' : 'off'}" id="dbPill" title="${esc(dbStatus.error ?? 'Neon Serverless PostgreSQL')}">
    <span class="dot"></span><span id="dbPillText">Neon DB: ${dbStatus.isOnline ? `Connected (${dbStatus.pingMs}ms)` : 'Offline'}</span>
  </div>
  <div class="top-right">
    ${notificationBellHtml()}
    <div class="admin-chip">${icon('lock')} <strong>${esc(adminName)}</strong></div>
    ${themeSwitchHtml()}
    <button class="btn-signout" onclick="post({ command: 'LOGOUT' })">Sign Out</button>
  </div>
</header>

<div class="app">
  <nav class="sidebar">
    <div class="nav-heading">Administration</div>
    <button class="nav-btn active" id="nav-overview" onclick="showSection('overview')">${icon('layout')} Overview</button>
    <button class="nav-btn" id="nav-users" onclick="showSection('users')">${icon('users')} Users <span class="nav-count">${users.length}</span></button>
    <button class="nav-btn" id="nav-analytics" onclick="showSection('analytics')">${icon('bar-chart')} Analytics</button>
    <div class="nav-dropdown open" id="dd-database">
      <button class="nav-btn" id="nav-database" onclick="toggleDropdown('database')" aria-expanded="true">${icon('database')} Database <span class="nav-chevron">${icon('chevron-down')}</span></button>
      <div class="nav-sub-group">
        <button class="nav-sub" id="nav-db-overview" onclick="showSection('db-overview')">${icon('server')} Overview</button>
        <button class="nav-sub" id="nav-db-browse" onclick="showSection('db-browse')">${icon('table')} Data Browser</button>
        <button class="nav-sub" id="nav-db-maint" onclick="showSection('db-maint')">${icon('wrench')} Maintenance</button>
        <button class="nav-sub" id="nav-db-backup" onclick="showSection('db-backup')">${icon('download')} Backup</button>
      </div>
    </div>
    <button class="nav-btn" id="nav-audit" onclick="showSection('audit')">${icon('history')} Audit Log</button>
    <button class="nav-btn" id="nav-system" onclick="showSection('system')">${icon('settings')} System</button>
    <div class="sidebar-foot">Sentinel v${esc(system.extensionVersion)}</div>
  </nav>

  <main class="content">

    <!-- ═══ OVERVIEW ═══ -->
    <section class="section active" id="section-overview">
      <div class="page-head"><div><div class="page-title">${icon('layout')} System Overview</div><div class="page-sub">Health of the Sentinel research deployment across all users</div></div>
        <button class="btn btn-secondary" onclick="post({ command: 'REFRESH_ADMIN' })">${icon('refresh')} Refresh</button></div>
      <div class="kpis">
        ${kpi('users', 'Users', users.length, `${roleCount('developer')} dev · ${roleCount('supervisor')} sup · ${roleCount('administrator')} admin`)}
        ${kpi('activity', 'Active (24h)', activeToday, 'distinct users with activity')}
        ${kpi('shield', 'Findings', t.identified, `${t.open} open · ${t.ignored} ignored`)}
        ${kpi('check-circle', 'Fix rate', `${t.fixRate}%`, `${t.fixed} fixed`, scoreColor(t.fixRate))}
        ${kpi('alert-octagon', 'Critical open', critOpen, 'need immediate attention', critOpen ? '#ef4444' : undefined)}
        ${kpi('database', 'Database', dbStatus.isOnline ? 'Online' : 'Offline', dbStatus.isOnline ? `${dbStatus.pingMs} ms latency` : esc(dbStatus.error ?? ''), dbStatus.isOnline ? '#10b981' : '#ef4444')}
      </div>
      <div class="card">
        <div class="chart-head"><div class="card-title" style="margin:0">${icon('bar-chart')} Detected vs fixed — last ${ins.trend.length} days (all developers)</div>${trendLegendHtml(ins.trend)}</div>
        ${trendChartSvg(ins.trend)}
      </div>
      <div class="grid-2">
        <div class="card">
          <div class="card-title">${icon('alert-triangle')} Developers needing attention</div>
          ${attention.length ? `<table class="data"><thead><tr><th>Developer</th><th class="num">Open</th><th class="num">Critical</th><th class="num">Score</th></tr></thead><tbody>
            ${attention.map(d => `<tr><td><div class="u-name">${esc(d.name)}</div><div class="u-sub">@${esc(d.id)}</div></td><td class="num">${d.open}</td><td class="num">${d.critOpen}</td><td class="num"><span style="color:${scoreColor(d.score)};font-weight:800">${d.score}</span></td></tr>`).join('')}
          </tbody></table>` : empty('No developers with open findings.')}
        </div>
        <div class="card">
          <div class="card-title">${icon('history')} Recent activity</div>
          ${recentActivity}
          <div style="margin-top:10px"><button class="btn btn-secondary" onclick="showSection('audit')">Open audit log ${icon('arrow-right')}</button></div>
        </div>
      </div>
    </section>

    <!-- ═══ USERS ═══ -->
    <section class="section" id="section-users">
      <div class="page-head"><div><div class="page-title">${icon('users')} User Management</div><div class="page-sub">Edit roles and details, add local accounts, remove users. GitHub users are created automatically on first sign-in.</div></div></div>
      <div class="toolbar">
        <input class="input search" id="userSearch" placeholder="Search name, username, email…" oninput="filterUsers()">
        <select class="select" id="userRole" onchange="filterUsers()">
          <option value="">All roles (${users.length})</option>
          <option value="developer">Developers (${roleCount('developer')})</option>
          <option value="supervisor">Supervisors (${roleCount('supervisor')})</option>
          <option value="administrator">Administrators (${roleCount('administrator')})</option>
        </select>
      </div>
      <div class="table-wrap" style="margin-bottom:18px">
        <table class="data" id="userTable">
          <thead><tr><th>User</th><th>Role</th><th class="num">Findings</th><th>Last login</th><th>Joined</th><th></th></tr></thead>
          <tbody>${userRows || `<tr><td colspan="6">${empty('No users.')}</td></tr>`}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">${icon('user-plus')} Add local user</div>
        <div class="form-grid">
          <div class="fg"><label for="nu-username">Username</label><input class="input" id="nu-username" placeholder="e.g. dev03" autocomplete="off"></div>
          <div class="fg"><label for="nu-password">Password</label><input class="input" id="nu-password" type="password" placeholder="Min 6 characters" autocomplete="new-password"></div>
          <div class="fg"><label for="nu-display">Display name</label><input class="input" id="nu-display" placeholder="e.g. Charlie"></div>
          <div class="fg"><label for="nu-email">Email</label><input class="input" id="nu-email" type="email" placeholder="user@domain.com"></div>
          <div class="fg"><label for="nu-role">Role</label><select class="select" id="nu-role"><option value="developer">Developer</option><option value="supervisor">Supervisor</option><option value="administrator">Administrator</option></select></div>
          <div class="fg"><button class="btn btn-primary" onclick="addUser()">${icon('user-plus')} Add user</button></div>
        </div>
      </div>
    </section>

    <!-- ═══ ANALYTICS ═══ -->
    <section class="section" id="section-analytics">
      <div class="page-head"><div><div class="page-title">${icon('bar-chart')} Team Analytics</div><div class="page-sub">Security posture of every developer, sorted by risk</div></div></div>
      <div class="table-wrap" style="margin-bottom:18px">
        <table class="data">
          <thead><tr><th>Developer</th><th class="num">Total</th><th class="num">Open</th><th class="num">Fixed</th><th>Fix rate</th><th class="num">Critical open</th><th class="num">Score</th><th>Last finding</th></tr></thead>
          <tbody>${devTableRows || `<tr><td colspan="8">${empty('No developer records yet.')}</td></tr>`}</tbody>
        </table>
      </div>
      <div class="grid-2">
        <div class="card"><div class="card-title">Severity distribution</div><div class="bar-list">${sevRows}</div></div>
        <div class="card"><div class="card-title">OWASP Top 10 (2021)</div><div class="bar-list">${owaspRows}</div></div>
      </div>
      <div class="card"><div class="card-title">Fix rate by vulnerability type</div><div class="bar-list">${typeRows}</div></div>
    </section>

    <!-- ═══ DATABASE: shared sub-tabs ═══ -->
    <div class="subtabs" id="dbTabs" style="display:none">
      <button class="subtab" id="tab-db-overview" onclick="showSection('db-overview')">${icon('server')} Overview</button>
      <button class="subtab" id="tab-db-browse" onclick="showSection('db-browse')">${icon('table')} Data Browser</button>
      <button class="subtab" id="tab-db-maint" onclick="showSection('db-maint')">${icon('wrench')} Maintenance</button>
      <button class="subtab" id="tab-db-backup" onclick="showSection('db-backup')">${icon('download')} Backup</button>
    </div>

    <!-- ═══ DATABASE › OVERVIEW ═══ -->
    <section class="section" id="section-db-overview">
      <div class="page-head"><div><div class="page-title">${icon('database')} Database</div><div class="page-sub">Neon Serverless PostgreSQL — connection, storage and table statistics</div></div>
        <div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="dbOp('DB_PING')">${icon('activity')} Test connection</button><button class="btn btn-secondary" onclick="loadDbOverview()">${icon('refresh')} Refresh</button></div></div>
      <div id="dbOverview"><div class="loading">Loading database statistics…</div></div>
    </section>

    <!-- ═══ DATABASE › BROWSER ═══ -->
    <section class="section" id="section-db-browse">
      <div class="page-head"><div><div class="page-title">${icon('table')} Data Browser</div><div class="page-sub">Read-only view of every table, with row-level edits where safe. Click a row to see the full record.</div></div></div>
      <div class="toolbar">
        <select class="select" id="brTable" onchange="browse(1)">
          <option value="vulnerability_records">Vulnerability Records</option>
          <option value="user_activity_logs">Activity Logs</option>
          <option value="sentinel_documents">Documents</option>
          <option value="users">Users (read-only)</option>
        </select>
        <select class="select" id="brStatus" onchange="browse(1)">
          <option value="">Any status</option><option>OPEN</option><option>FIXED</option><option>IGNORED</option><option>FALSE_POSITIVE</option>
        </select>
        <input class="input search" id="brSearch" placeholder="Search…" onkeydown="if(event.key==='Enter')browse(1)">
        <button class="btn btn-secondary" onclick="browse(1)">${icon('search')} Search</button>
      </div>
      <div id="brResult"><div class="loading">Choose a table to browse.</div></div>
    </section>

    <!-- ═══ DATABASE › MAINTENANCE ═══ -->
    <section class="section" id="section-db-maint">
      <div class="page-head"><div><div class="page-title">${icon('wrench')} Maintenance</div><div class="page-sub">Housekeeping jobs. Destructive jobs ask for confirmation in VS Code and are recorded in the audit log.</div></div></div>
      <div class="maint-grid">
        <div class="card">
          <div class="card-title">${icon('history')} Purge old activity logs</div>
          <div class="card-sub">Delete audit-log entries older than the given number of days.</div>
          <div class="maint-row"><input class="input" id="mLogDays" type="number" min="1" value="90" style="width:90px"> <span class="muted" style="font-size:.8em">days</span>
            <button class="btn btn-danger" onclick="dbOp('DB_PURGE_LOGS', { days: num('mLogDays') })">${icon('trash')} Purge</button></div>
        </div>
        <div class="card">
          <div class="card-title">${icon('check-circle')} Purge resolved findings</div>
          <div class="card-sub">Delete FIXED / IGNORED / FALSE_POSITIVE records not updated for this many days. Open findings are kept.</div>
          <div class="maint-row"><input class="input" id="mRecDays" type="number" min="1" value="180" style="width:90px"> <span class="muted" style="font-size:.8em">days</span>
            <button class="btn btn-danger" onclick="dbOp('DB_PURGE_RESOLVED', { days: num('mRecDays') })">${icon('trash')} Purge</button></div>
        </div>
        <div class="card">
          <div class="card-title">${icon('user')} Delete a developer's data</div>
          <div class="card-sub">Removes all vulnerability records and activity logs for one developer. The user account is kept.</div>
          <div class="maint-row"><select class="select" id="mDev" style="flex:1;min-width:0">${developerOptions || '<option value="">No developers with data</option>'}</select>
            <button class="btn btn-danger" ${developerOptions ? '' : 'disabled'} onclick="dbOp('DB_DELETE_DEVELOPER', { developerId: val('mDev') })">${icon('trash')} Delete</button></div>
        </div>
        <div class="card">
          <div class="card-title">${icon('activity')} Optimise tables</div>
          <div class="card-sub">Run VACUUM (ANALYZE) on all Sentinel tables to reclaim space and refresh planner statistics.</div>
          <div class="maint-row"><button class="btn btn-secondary" onclick="dbOp('DB_VACUUM')">${icon('wrench')} Run VACUUM ANALYZE</button></div>
        </div>
        <div class="card">
          <div class="card-title">${icon('refresh')} Re-run schema migration</div>
          <div class="card-sub">Re-checks the connection and re-creates any missing tables or indexes. Safe to run any time; no data is changed.</div>
          <div class="maint-row"><button class="btn btn-secondary" onclick="dbOp('DB_MIGRATE')">${icon('refresh')} Run migration</button></div>
        </div>
        <div class="card danger-zone">
          <div class="card-title">${icon('alert-octagon')} Danger zone — clear data</div>
          <div class="card-sub">Permanently delete every row of a table, or one document collection. Export a backup first.</div>
          <div class="maint-row">
            <select class="select" id="mClear" style="flex:1;min-width:0">
              <option value="vulnerability_records">All vulnerability records</option>
              <option value="user_activity_logs">All activity logs</option>
              <option value="sentinel_documents">All documents</option>
              <option value="collection:projects">Documents › projects</option>
              <option value="collection:shifts">Documents › shifts</option>
              <option value="collection:shift_sessions">Documents › shift_sessions</option>
              <option value="collection:learning">Documents › learning profiles</option>
            </select>
            <button class="btn btn-danger" onclick="clearData()">${icon('trash')} Clear</button>
          </div>
        </div>
      </div>
    </section>

    <!-- ═══ DATABASE › BACKUP ═══ -->
    <section class="section" id="section-db-backup">
      <div class="page-head"><div><div class="page-title">${icon('download')} Backup</div><div class="page-sub">Export a full JSON snapshot of the database to a file on this machine.</div></div></div>
      <div class="card">
        <div class="card-title">${icon('download')} Export database</div>
        <div class="card-sub">Includes users (without password hashes), vulnerability records, activity logs and all documents. VS Code will ask where to save the file.</div>
        <button class="btn btn-primary" onclick="dbOp('DB_EXPORT')">${icon('download')} Export JSON backup</button>
      </div>
      <div class="card">
        <div class="card-title">${icon('info')} About backups</div>
        <div class="kv"><span>Format</span><strong>JSON — one array per table</strong></div>
        <div class="kv"><span>Secrets</span><strong>password_hash is never exported</strong></div>
        <div class="kv"><span>Point-in-time restore</span><strong>Use Neon branching / PITR in the Neon console</strong></div>
      </div>
    </section>

    <!-- ═══ AUDIT LOG ═══ -->
    <section class="section" id="section-audit">
      <div class="page-head"><div><div class="page-title">${icon('history')} Audit Log</div><div class="page-sub">Latest ${activities.length} actions across the system. Administrator actions are highlighted.</div></div></div>
      <div class="toolbar">
        <input class="input search" id="auditSearch" placeholder="Search user, action, vulnerability…" oninput="filterAudit()">
        <select class="select" id="auditAction" onchange="filterAudit()">
          <option value="">All actions</option>
          ${actionTypes.map(a => `<option value="${esc(a)}">${pretty(a)}</option>`).join('')}
        </select>
        <span class="muted" style="font-size:.78em" id="auditCount">${activities.length} entries</span>
      </div>
      <div class="table-wrap">
        <table class="data" id="auditTable">
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>${activities.map(activityRow).join('') || `<tr><td colspan="4">${empty('No activity yet.')}</td></tr>`}</tbody>
        </table>
      </div>
    </section>

    <!-- ═══ SYSTEM ═══ -->
    <section class="section" id="section-system">
      <div class="page-head"><div><div class="page-title">${icon('settings')} System</div><div class="page-sub">Runtime configuration and integrations</div></div>
        <div style="display:flex;gap:8px"><button class="btn btn-secondary" onclick="post({ command: 'ADMIN_OPEN_SETTINGS' })">${icon('settings')} Open Sentinel settings</button><button class="btn btn-secondary" onclick="post({ command: 'ADMIN_SHOW_OUTPUT' })">${icon('terminal')} Show output log</button></div></div>
      <div class="grid-2">
        <div class="card">
          <div class="card-title">${icon('shield')} Detection engine</div>
          <div class="kv"><span>Real-time analysis</span><strong>${system.analysisEnabled ? 'Enabled' : 'Disabled'}</strong></div>
          <div class="kv"><span>Rules loaded</span><strong>${system.rulesCount}</strong></div>
          <div class="kv"><span>Minimum confidence</span><strong>${Math.round(system.minConfidence * 100)}%</strong></div>
          <div class="kv"><span>Debounce</span><strong>${system.debounceMs} ms</strong></div>
          <div class="kv"><span>AI enrichment (IFE)</span><strong>${system.aiEnabled ? 'Enabled' : 'Disabled'}</strong></div>
          <div class="kv"><span>Theme</span><strong>${esc(system.theme)}</strong></div>
        </div>
        <div class="card">
          <div class="card-title">${icon('plug')} Integrations</div>
          <div class="kv"><span>Component 2 API (pull)</span><strong style="color:${system.apiRunning ? 'var(--t-green)' : 'var(--t-red)'}">${system.apiRunning ? 'Online' : 'Offline'}</strong></div>
          <div class="kv"><span>API base URL</span><code class="mono">${esc(system.apiUrl || '—')}</code></div>
          ${system.apiError ? `<div class="kv"><span>API error</span><strong>${esc(system.apiError)}</strong></div>` : ''}
          <div class="kv"><span>Behaviour tracker (push)</span><code class="mono">${esc(system.backendUrl)}</code></div>
          <div class="kv"><span>Feedback engine (IFE)</span><code class="mono">${esc(system.ifeUrl)}</code></div>
          <div class="kv"><span>Database</span><strong>${dbStatus.isOnline ? `Neon PostgreSQL · ${dbStatus.pingMs} ms` : 'Offline'}</strong></div>
          <div class="kv"><span>Extension version</span><strong>${esc(system.extensionVersion)}</strong></div>
        </div>
      </div>
    </section>

  </main>
</div>

<!-- Edit-user modal -->
<div class="modal-back" id="editModal" onclick="if(event.target===this)closeModal('editModal')">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="editTitle">
    <div class="modal-head"><span id="editTitle">Edit user</span><button class="btn-ghost" onclick="closeModal('editModal')">${icon('x')}</button></div>
    <div class="modal-body">
      <input type="hidden" id="eu-id">
      <div class="form-grid" style="grid-template-columns:1fr">
        <div class="fg"><label for="eu-display">Display name</label><input class="input" id="eu-display"></div>
        <div class="fg"><label for="eu-email">Email</label><input class="input" id="eu-email" type="email"></div>
        <div class="fg"><label for="eu-role">Role</label><select class="select" id="eu-role"><option value="developer">Developer</option><option value="supervisor">Supervisor</option><option value="administrator">Administrator</option></select></div>
      </div>
    </div>
    <div class="modal-foot"><button class="btn btn-secondary" onclick="closeModal('editModal')">Cancel</button><button class="btn btn-primary" onclick="saveUser()">Save changes</button></div>
  </div>
</div>

<!-- Row-detail modal -->
<div class="modal-back" id="rowModal" onclick="if(event.target===this)closeModal('rowModal')">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="rowTitle" style="width:min(720px,100%)">
    <div class="modal-head"><span id="rowTitle">Record</span><button class="btn-ghost" onclick="closeModal('rowModal')">${icon('x')}</button></div>
    <div class="modal-body"><pre class="json" id="rowJson"></pre></div>
  </div>
</div>

<div class="toast-wrap" id="toasts"></div>

<script>
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;
const ICON = {
  ok: ${JSON.stringify(icon('check-circle'))}, err: ${JSON.stringify(icon('alert-triangle'))},
  trash: ${JSON.stringify(icon('trash'))}, left: ${JSON.stringify(icon('chevron-left'))}, right: ${JSON.stringify(icon('chevron-right'))},
  table: ${JSON.stringify(icon('table'))}, eye: ${JSON.stringify(icon('eye'))}
};
const DB_SECTIONS = ['db-overview', 'db-browse', 'db-maint', 'db-backup'];
const DISPLAY_COLS = {
  vulnerability_records: ['severity', 'vulnerability_type', 'developer_id', 'status', 'file_name', 'line_number', 'detected_at'],
  user_activity_logs: ['created_at', 'username', 'action_type', 'vulnerability_type', 'finding_id'],
  sentinel_documents: ['collection', 'doc_key', 'data', 'updated_at'],
  users: ['username', 'github_username', 'role', 'display_name', 'email', 'last_login_at']
};
let dbLoaded = false;
let lastBrowse = null;

function post(msg) { vscode.postMessage(msg); }
function val(id) { return (document.getElementById(id) || {}).value || ''; }
function num(id) { return parseInt(val(id), 10); }
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtBytes(n) {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0; n = Number(n);
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}
function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s); if (isNaN(d.getTime())) return esc(s);
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function toast(ok, text) {
  const el = document.createElement('div');
  el.className = 'toast ' + (ok ? 'ok' : 'err');
  el.innerHTML = (ok ? ICON.ok : ICON.err) + '<span>' + esc(text) + '</span>';
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

// ── Navigation ──
function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn, .nav-sub, .subtab').forEach(b => b.classList.remove('active'));
  const sec = document.getElementById('section-' + id); if (sec) sec.classList.add('active');
  const isDb = DB_SECTIONS.includes(id);
  const nav = document.getElementById('nav-' + (isDb ? 'database' : id)); if (nav) nav.classList.add('active');
  if (isDb) {
    const sub = document.getElementById('nav-' + id); if (sub) sub.classList.add('active');
    const tab = document.getElementById('tab-' + id); if (tab) tab.classList.add('active');
    toggleDropdown('database', true);
    if (!dbLoaded && id === 'db-overview') loadDbOverview();
    if (id === 'db-browse' && !lastBrowse) browse(1);
  }
  document.getElementById('dbTabs').style.display = isDb ? 'flex' : 'none';
  vscode.setState(Object.assign({}, vscode.getState() || {}, { section: id }));
}
function toggleDropdown(name, force) {
  const dd = document.getElementById('dd-' + name); if (!dd) return;
  const open = force === undefined ? !dd.classList.contains('open') : force;
  dd.classList.toggle('open', open);
  if (force === undefined && open && !DB_SECTIONS.some(s => document.getElementById('section-' + s).classList.contains('active'))) showSection('db-overview');
}

// ── Users ──
function filterUsers() {
  const q = val('userSearch').toLowerCase().trim(), role = val('userRole');
  document.querySelectorAll('#userTable .user-row').forEach(r => {
    const ok = (!role || r.dataset.role === role) && (!q || r.dataset.search.includes(q));
    r.style.display = ok ? '' : 'none';
  });
}
function addUser() {
  const username = val('nu-username').trim(), password = val('nu-password'), displayName = val('nu-display').trim(),
        email = val('nu-email').trim(), role = val('nu-role');
  if (!username || !password || !displayName || !email) { toast(false, 'Please fill in all fields.'); return; }
  if (password.length < 6) { toast(false, 'Password must be at least 6 characters.'); return; }
  post({ command: 'ADMIN_ADD_USER', username, password, displayName, email, role });
}
function removeUser(userId, username) { post({ command: 'ADMIN_REMOVE_USER', userId, username }); }
function openEditUser(u) {
  document.getElementById('eu-id').value = u.id;
  document.getElementById('eu-display').value = u.displayName || '';
  document.getElementById('eu-email').value = u.email || '';
  document.getElementById('eu-role').value = u.role;
  document.getElementById('editTitle').textContent = 'Edit @' + u.username;
  document.getElementById('editModal').classList.add('open');
  document.getElementById('eu-display').focus();
}
function saveUser() {
  post({ command: 'ADMIN_UPDATE_USER', userId: val('eu-id'), displayName: val('eu-display').trim(), email: val('eu-email').trim(), role: val('eu-role') });
  closeModal('editModal');
}
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') document.querySelectorAll('.modal-back.open').forEach(m => m.classList.remove('open')); });

// ── Audit ──
function filterAudit() {
  const q = val('auditSearch').toLowerCase().trim(), a = val('auditAction');
  let n = 0;
  document.querySelectorAll('#auditTable .audit-row').forEach(r => {
    const ok = (!a || r.dataset.action === a) && (!q || r.dataset.search.includes(q));
    r.style.display = ok ? '' : 'none'; if (ok) n++;
  });
  document.getElementById('auditCount').textContent = n + ' entries';
}

// ── Database ──
function dbOp(command, extra) { post(Object.assign({ command }, extra || {})); }
function loadDbOverview() {
  document.getElementById('dbOverview').innerHTML = '<div class="loading">Loading database statistics…</div>';
  dbOp('DB_OVERVIEW');
}
function clearData() {
  const v = val('mClear');
  if (v.indexOf('collection:') === 0) dbOp('DB_CLEAR', { table: 'sentinel_documents', collection: v.slice(11) });
  else dbOp('DB_CLEAR', { table: v });
}
function renderOverview(o) {
  const pill = document.getElementById('dbPill');
  pill.className = 'db-pill ' + (o.online ? 'on' : 'off');
  document.getElementById('dbPillText').textContent = 'Neon DB: ' + (o.online ? 'Connected (' + o.pingMs + 'ms)' : 'Offline');
  if (!o.online) {
    document.getElementById('dbOverview').innerHTML = '<div class="card danger-zone"><div class="card-title">' + ICON.err + ' Database offline</div><div class="card-sub">' + esc(o.error || 'Unable to reach the database.') + '</div></div>';
    return;
  }
  const totalRows = o.tables.reduce((a, t) => a + t.rows, 0);
  let h = '<div class="kpis">'
    + kpiJs('Status', 'Online', o.pingMs + ' ms round-trip', '#10b981')
    + kpiJs('Storage used', fmtBytes(o.sizeBytes), esc(o.database || ''))
    + kpiJs('Total rows', totalRows.toLocaleString(), o.tables.length + ' tables')
    + kpiJs('Open findings', (o.statusBreakdown.OPEN || 0).toLocaleString(), (o.statusBreakdown.FIXED || 0) + ' fixed')
    + '</div><div class="grid-2"><div class="card"><div class="card-title">Connection</div>'
    + kv('Host', '<code class="mono">' + esc(o.host) + '</code>')
    + kv('Database', esc(o.database)) + kv('Server', esc(o.serverVersion))
    + kv('Server time', fmtDate(o.serverTime)) + kv('SSL', 'Required')
    + '</div><div class="card"><div class="card-title">Document collections</div>'
    + (o.collections.length ? o.collections.map(c => kv(esc(c.collection), c.count.toLocaleString())).join('') : '<div class="empty">No documents.</div>')
    + '</div></div><div class="table-cards">';
  o.tables.forEach(t => {
    h += '<div class="tcard"><div class="tcard-name">' + ICON.table + ' ' + esc(t.label) + '</div>'
      + '<div class="tcard-desc">' + esc(t.description) + '</div>'
      + '<div class="tcard-stats"><div><strong>' + t.rows.toLocaleString() + '</strong>rows</div><div><strong>' + fmtBytes(t.sizeBytes) + '</strong>size</div></div>'
      + '<div class="muted" style="font-size:.72em">Last activity: ' + fmtDate(t.lastActivity) + '</div>'
      + '<div style="margin-top:8px"><button class="btn btn-secondary" onclick="openTable(\\'' + t.table + '\\')">' + ICON.eye + ' Browse</button></div></div>';
  });
  document.getElementById('dbOverview').innerHTML = h + '</div>';
  dbLoaded = true;
}
function kpiJs(lbl, v, note, color) {
  return '<div class="kpi"><div class="kpi-lbl">' + esc(lbl) + '</div><div class="kpi-num"' + (color ? ' style="color:' + color + '"' : '') + '>' + esc(v) + '</div><div class="kpi-note">' + note + '</div></div>';
}
function kv(k, v) { return '<div class="kv"><span>' + k + '</span><strong>' + v + '</strong></div>'; }
function openTable(t) { document.getElementById('brTable').value = t; showSection('db-browse'); browse(1); }

function browse(page) {
  const table = val('brTable');
  document.getElementById('brStatus').style.display = table === 'vulnerability_records' ? '' : 'none';
  lastBrowse = { table, page, search: val('brSearch'), status: table === 'vulnerability_records' ? val('brStatus') : '' };
  document.getElementById('brResult').innerHTML = '<div class="loading">Loading…</div>';
  dbOp('DB_BROWSE', lastBrowse);
}
function cell(col, v) {
  if (v === null || v === undefined || v === '') return '<span class="muted">—</span>';
  if (col === 'data') { const s = JSON.stringify(v); return '<span class="muted">' + fmtBytes(s.length) + ' JSON</span>'; }
  if (/_at$/.test(col)) return '<span class="nowrap">' + fmtDate(v) + '</span>';
  if (col === 'severity') { const c = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' }[v] || 'var(--text-2)'; return '<span style="color:' + c + ';font-weight:700">' + esc(v) + '</span>'; }
  if (col === 'file_name') { const s = String(v).replace(/\\\\/g, '/'); return '<span class="mono" title="' + esc(s) + '">' + esc(s.split('/').pop()) + '</span>'; }
  return '<div class="cell-trunc" title="' + esc(typeof v === 'object' ? JSON.stringify(v) : v) + '">' + esc(typeof v === 'object' ? JSON.stringify(v) : v) + '</div>';
}
let browseRows = [];
function renderBrowse(r) {
  browseRows = r.rows;
  const cols = DISPLAY_COLS[r.table] || r.columns;
  const isRec = r.table === 'vulnerability_records';
  let h = '<div class="table-wrap"><table class="data"><thead><tr>' + cols.map(c => '<th>' + esc(c.replace(/_/g, ' ')) + '</th>').join('') + '<th></th></tr></thead><tbody>';
  if (!r.rows.length) h += '<tr><td colspan="' + (cols.length + 1) + '"><div class="empty">No rows match.</div></td></tr>';
  r.rows.forEach((row, i) => {
    h += '<tr style="cursor:pointer" onclick="showRow(' + i + ')">';
    cols.forEach(c => {
      if (isRec && c === 'status') {
        h += '<td onclick="event.stopPropagation()"><select class="select status-select" onchange="setStatus(\\'' + esc(row.record_id) + '\\', this.value)">'
          + ['OPEN', 'FIXED', 'IGNORED', 'FALSE_POSITIVE'].map(s => '<option' + (s === row.status ? ' selected' : '') + '>' + s + '</option>').join('') + '</select></td>';
      } else h += '<td>' + cell(c, row[c]) + '</td>';
    });
    h += '<td class="actions" onclick="event.stopPropagation()">' + (r.deletable ? '<button class="btn-ghost danger" title="Delete row" onclick="deleteRow(' + i + ')">' + ICON.trash + '</button>' : '') + '</td></tr>';
  });
  const from = r.total ? (r.page - 1) * r.pageSize + 1 : 0, to = Math.min(r.total, r.page * r.pageSize);
  const pages = Math.max(1, Math.ceil(r.total / r.pageSize));
  h += '</tbody></table></div><div class="pager"><span>' + from + '–' + to + ' of ' + r.total.toLocaleString() + ' rows</span><div style="display:flex;gap:6px">'
    + '<button class="btn btn-secondary" ' + (r.page <= 1 ? 'disabled' : '') + ' onclick="browse(' + (r.page - 1) + ')">' + ICON.left + ' Prev</button>'
    + '<span style="align-self:center">Page ' + r.page + ' / ' + pages + '</span>'
    + '<button class="btn btn-secondary" ' + (r.page >= pages ? 'disabled' : '') + ' onclick="browse(' + (r.page + 1) + ')">Next ' + ICON.right + '</button></div></div>';
  document.getElementById('brResult').innerHTML = h;
}
function keyOf(table, row) {
  const pk = { vulnerability_records: ['record_id'], user_activity_logs: ['id'], sentinel_documents: ['collection', 'doc_key'], users: ['id'] }[table];
  const k = {}; pk.forEach(c => k[c] = String(row[c])); return k;
}
function showRow(i) {
  const row = browseRows[i]; if (!row) return;
  document.getElementById('rowTitle').textContent = (lastBrowse ? lastBrowse.table : 'Record');
  document.getElementById('rowJson').textContent = JSON.stringify(row, null, 2);
  document.getElementById('rowModal').classList.add('open');
}
function deleteRow(i) { const row = browseRows[i]; if (row) dbOp('DB_DELETE_ROW', { table: lastBrowse.table, key: keyOf(lastBrowse.table, row) }); }
function setStatus(recordId, status) { dbOp('DB_SET_STATUS', { recordId, status }); }

// ── Messages from the extension ──
window.addEventListener('message', e => {
  const m = e.data || {};
  if (m.command === 'ADMIN_ADD_RESULT' || m.command === 'ADMIN_USER_RESULT') {
    toast(m.success, m.message);
    if (m.success) {
      if (m.command === 'ADMIN_ADD_RESULT') ['nu-username', 'nu-password', 'nu-display', 'nu-email'].forEach(id => document.getElementById(id).value = '');
      setTimeout(() => post({ command: 'REFRESH_ADMIN' }), 900);
    }
  }
  if (m.command === 'DB_RESULT') {
    if (m.op === 'DB_OVERVIEW') { if (m.success) renderOverview(m.data); else document.getElementById('dbOverview').innerHTML = '<div class="empty">' + esc(m.message) + '</div>'; return; }
    if (m.op === 'DB_BROWSE') { if (m.success) renderBrowse(m.data); else document.getElementById('brResult').innerHTML = '<div class="empty">' + esc(m.message) + '</div>'; return; }
    if (m.message) toast(m.success, m.message);
    if (m.success && m.op !== 'DB_EXPORT' && m.op !== 'DB_PING') { dbLoaded = false; if (lastBrowse && document.getElementById('section-db-browse').classList.contains('active')) browse(lastBrowse.page); }
    if (m.op === 'DB_PING' || (m.success && document.getElementById('section-db-overview').classList.contains('active'))) loadDbOverview();
  }
});

(function restore() {
  const st = vscode.getState() || {};
  showSection(st.section && document.getElementById('section-' + st.section) ? st.section : 'overview');
})();
</script>
<script>${notifyScript()}</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>`;
}

function kpi(ico: string, label: string, value: string | number, note: string, color?: string): string {
  return `<div class="kpi">
    <div class="kpi-top"><span class="kpi-lbl">${esc(label)}</span>${icon(ico)}</div>
    <div class="kpi-num"${color ? ` style="color:${color}"` : ''}>${typeof value === 'number' ? value.toLocaleString() : value}</div>
    <div class="kpi-note">${note}</div>
  </div>`;
}

function empty(msg: string): string {
  return `<div class="empty">${msg}</div>`;
}
