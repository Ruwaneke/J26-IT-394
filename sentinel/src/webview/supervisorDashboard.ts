/**
 * Sentinel — Supervisor Dashboard  (v3 — Sidebar Nav + Project/Shift Management)
 *
 * Sections:
 *   Overview    — team stats aggregated from DATA/
 *   Projects    — create and manage projects
 *   Shifts      — create shifts, assign developers
 *   Reports     — per-shift, per-developer shift summaries
 *   Developers  — roster of all developers in the system
 */

import * as fs from 'fs';
import * as path from 'path';
import { AuthSession } from '../auth/authManager.js';
import { Project, Shift, ShiftSession } from '../data/projectStore.js';
import { buildHeaderBar } from './loginView.js';

function esc(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

// ── Developer stats loader (from DATA/*.json records) ───────────────────────
interface DevRecord {
  developerId: string;
  vulnerabilityType: string;
  severity: string;
  confidence: number;
  fileName: string;
  lineNumber: number;
  detectedAt: string;
}
export interface DevStats {
  developerId: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  score: number;
}
export function loadAllDeveloperStats(dataDir: string): DevStats[] {
  const result: DevStats[] = [];
  try {
    const files = fs.readdirSync(dataDir).filter(f => f.endsWith('_vulnerability_records.json'));
    for (const file of files) {
      try {
        const raw  = fs.readFileSync(path.join(dataDir, file), 'utf8');
        const recs = JSON.parse(raw) as DevRecord[];
        const id   = file.replace('_vulnerability_records.json', '');
        const s: DevStats = { developerId: id, total: recs.length, critical: 0, high: 0, medium: 0, low: 0, score: 100 };
        for (const r of recs) {
          if (r.severity === 'CRITICAL') s.critical++;
          else if (r.severity === 'HIGH') s.high++;
          else if (r.severity === 'MEDIUM') s.medium++;
          else s.low++;
        }
        s.score = Math.max(0, 100 - s.critical * 25 - s.high * 10 - s.medium * 5 - s.low * 2);
        result.push(s);
      } catch { /* skip bad files */ }
    }
  } catch { /* dataDir not ready */ }
  return result;
}

// ─── Supervisor Dashboard HTML ─────────────────────────────────────────────────

export function buildSupervisorDashboardHtml(
  session: AuthSession,
  dataDir: string,
  cspSource: string,
  logoUri: string,
  projects: Project[] = [],
  shifts: Shift[] = [],
  allDevelopers: Array<{ id: string; username: string; displayName: string; githubUsername?: string; githubAvatarUrl?: string }> = [],
  allSessions: ShiftSession[] = [],
): string {
  const devStats     = loadAllDeveloperStats(dataDir);
  const totalFindings = devStats.reduce((s, d) => s + d.total, 0);
  const avgScore      = devStats.length > 0
    ? Math.round(devStats.reduce((s, d) => s + d.score, 0) / devStats.length) : 100;

  const headerBar = buildHeaderBar(session, cspSource);
  const supInitial = esc(session.displayName.charAt(0).toUpperCase());

  // ── Projects list ──────────────────────────────────────────────────────────
  const projectCards = projects.length === 0
    ? `<div class="empty-state">📁 No projects yet. Create your first project below.</div>`
    : projects.map(p => {
        const pShifts = shifts.filter(s => s.projectId === p.id);
        const active  = pShifts.filter(s => s.status === 'active').length;
        const done    = pShifts.filter(s => s.status === 'completed').length;
        const statusColor = p.status === 'active' ? '#3fb950' : p.status === 'completed' ? '#58a6ff' : '#8b949e';
        return `
        <div class="proj-card">
          <div class="proj-card-header">
            <div>
              <div class="proj-card-name">📁 ${esc(p.name)}</div>
              <div class="proj-card-desc">${esc(p.description || 'No description')}</div>
            </div>
            <span class="status-badge" style="color:${statusColor};border-color:${statusColor}20;background:${statusColor}10">${p.status.toUpperCase()}</span>
          </div>
          <div class="proj-meta">
            <span>Created ${fmtDate(p.createdAt)}</span>
            <span>·</span>
            <span>${pShifts.length} shift${pShifts.length !== 1 ? 's' : ''}</span>
            ${active ? `<span>· <strong style="color:#3fb950">${active} active</strong></span>` : ''}
            ${done ? `<span>· <strong style="color:#58a6ff">${done} done</strong></span>` : ''}
          </div>
          <div class="proj-actions">
            <button class="btn-sm btn-primary" onclick="showCreateShift('${esc(p.id)}','${esc(p.name)}')">+ New Shift</button>
            <button class="btn-sm btn-ghost" onclick="showSection('shifts');filterProject('${esc(p.id)}')">View Shifts</button>
          </div>
        </div>`;
      }).join('');

  // ── Shifts list ────────────────────────────────────────────────────────────
  const shiftCards = shifts.length === 0
    ? `<div class="empty-state">📅 No shifts yet. Create a shift from a project.</div>`
    : shifts.map(sh => {
        const statusColor = sh.status === 'active' ? '#3fb950' : sh.status === 'completed' ? '#58a6ff' : '#8b949e';
        const statusIcon  = sh.status === 'active' ? '🟢' : sh.status === 'completed' ? '✅' : '📅';
        const shSessions  = allSessions.filter(s => s.shiftId === sh.id);
        const devPills    = sh.assignedDeveloperNames.map(n =>
          `<span class="dev-pill">🧑‍💻 ${esc(n)}</span>`).join('');

        return `
        <div class="shift-card" data-project-id="${esc(sh.projectId)}">
          <div class="shift-card-header">
            <div>
              <div class="shift-name">${statusIcon} ${esc(sh.name)}</div>
              <div class="shift-project">📁 ${esc(sh.projectName)}</div>
            </div>
            <span class="status-badge" style="color:${statusColor};border-color:${statusColor}20;background:${statusColor}10">${sh.status.toUpperCase()}</span>
          </div>
          <div class="shift-meta">
            🕐 ${fmtDate(sh.scheduledStart)} → ${fmtDate(sh.scheduledEnd)}
          </div>
          ${sh.description ? `<div class="shift-desc">${esc(sh.description)}</div>` : ''}
          <div class="dev-pills">${devPills || '<span style="color:#484f58;font-size:.75em">No developers assigned</span>'}</div>
          <div class="shift-sessions-info">
            ${shSessions.length > 0
              ? `<span style="font-size:.73em;color:#8b949e">${shSessions.filter(s => !s.endedAt).length} active · ${shSessions.filter(s => s.endedAt).length} completed sessions</span>`
              : `<span style="font-size:.73em;color:#484f58">No sessions started</span>`}
          </div>
          <div class="shift-actions">
            <button class="btn-sm btn-primary" onclick="showAssignDev('${esc(sh.id)}','${esc(sh.name)}')">👥 Manage Devs</button>
            <button class="btn-sm btn-ghost" onclick="viewShiftReport('${esc(sh.id)}')">📊 Report</button>
          </div>
        </div>`;
      }).join('');

  // ── Developers roster ──────────────────────────────────────────────────────
  const devRows = allDevelopers.map(dev => {
    const stats = devStats.find(s => s.developerId === dev.username);
    const score = stats?.score ?? 100;
    const sc    = score >= 80 ? '#3fb950' : score >= 50 ? '#d29922' : '#f47067';
    const avatarHtml = dev.githubAvatarUrl
      ? `<img src="${esc(dev.githubAvatarUrl)}?s=40" class="dev-avatar-img" onerror="this.style.display='none';">`
      : `<div class="dev-avatar-initials">${esc(dev.displayName.charAt(0).toUpperCase())}</div>`;
    return `
    <div class="dev-row">
      <div class="dev-row-left">
        <div class="dev-avatar-wrap">${avatarHtml}</div>
        <div>
          <div class="dev-row-name">${esc(dev.displayName)}</div>
          <div class="dev-row-username">${dev.githubUsername ? `@${esc(dev.githubUsername)}` : esc(dev.username)}</div>
        </div>
      </div>
      <div class="dev-row-stats">
        <span style="color:${sc};font-weight:700;font-size:.85em">${score}</span>
        <span style="font-size:.7em;color:#8b949e">score</span>
        <span style="font-size:.78em;color:#8b949e">${stats?.total ?? 0} issues</span>
      </div>
    </div>`;
  }).join('') || `<div class="empty-state">No developers in the system yet.</div>`;

  // ── Reports ────────────────────────────────────────────────────────────────
  const completedSessions = allSessions.filter(s => s.endedAt && s.summary);
  const reportRows = completedSessions.length === 0
    ? `<div class="empty-state">📊 No completed shift reports yet.</div>`
    : completedSessions.slice(0, 20).map(s => {
        const sum = s.summary!;
        const sc  = sum.securityScore >= 80 ? '#3fb950' : sum.securityScore >= 50 ? '#d29922' : '#f47067';
        return `
        <div class="report-card">
          <div class="report-card-header">
            <div>
              <div class="report-dev-name">🧑‍💻 ${esc(s.developerDisplayName)}</div>
              <div class="report-shift-name">${esc(s.shiftName)} · ${esc(s.projectName)}</div>
              <div class="report-meta">${fmtDate(s.startedAt)} — ${s.endedAt ? fmtDate(s.endedAt) : 'Active'} · ${sum.durationMinutes}m</div>
            </div>
            <div class="report-score" style="color:${sc};border-color:${sc}">${sum.securityScore}</div>
          </div>
          <div class="report-stats">
            <span style="color:#f47067">${sum.criticalCount} CRIT</span>
            <span style="color:#e09b3d">${sum.highCount} HIGH</span>
            <span style="color:#d29922">${sum.mediumCount} MED</span>
            <span style="color:#3fb950">${sum.lowCount} LOW</span>
            <span style="color:#58a6ff">${sum.totalFindings} TOTAL</span>
          </div>
          ${sum.recommendations.map(r => `<div class="report-rec">💡 ${esc(r)}</div>`).join('')}
        </div>`;
      }).join('');

  // Developer select options for shift creation
  const devOptions = allDevelopers.map(d =>
    `<option value="${esc(d.username)}" data-name="${esc(d.displayName)}">${esc(d.displayName)} (${d.githubUsername ? '@' + esc(d.githubUsername) : esc(d.username)})</option>`
  ).join('');

  // Project select options for shift creation form
  const projectOptions = projects.filter(p => p.status === 'active').map(p =>
    `<option value="${esc(p.id)}">${esc(p.name)}</option>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Supervisor</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:#0d1117;color:#e6edf3;height:100vh;overflow:hidden;display:flex;flex-direction:column}
.app{display:flex;flex:1;overflow:hidden}
.sidebar{width:220px;flex-shrink:0;background:#161b22;border-right:1px solid rgba(255,255,255,.08);display:flex;flex-direction:column;padding:16px 0;overflow-y:auto}
.content{flex:1;overflow-y:auto;padding:24px}

.sidebar-logo{display:flex;align-items:center;gap:10px;padding:0 16px 18px;border-bottom:1px solid rgba(255,255,255,.06);margin-bottom:8px}
.sidebar-logo-icon{width:32px;height:32px;background:linear-gradient(135deg,#b08800,#d29922);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.sidebar-logo-text{font-size:.85em;font-weight:800;color:#e6edf3;letter-spacing:-.3px}
.sidebar-logo-role{font-size:.62em;color:#d29922;font-weight:600;letter-spacing:.3px;text-transform:uppercase}
.nav-section-label{font-size:.62em;font-weight:700;color:#484f58;letter-spacing:.8px;text-transform:uppercase;padding:12px 16px 4px}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 16px;margin:1px 8px;border-radius:8px;font-size:.82em;font-weight:500;color:#8b949e;cursor:pointer;transition:all .15s;border:none;background:none;width:calc(100% - 16px);text-align:left;font-family:inherit}
.nav-item:hover{background:rgba(255,255,255,.06);color:#e6edf3}
.nav-item.active{background:rgba(210,153,34,.12);color:#d29922;font-weight:600}
.nav-icon{font-size:1em;width:18px;text-align:center}
.nav-badge{margin-left:auto;background:rgba(88,166,255,.15);color:#58a6ff;border-radius:100px;padding:1px 7px;font-size:.65em;font-weight:700}
.sidebar-bottom{margin-top:auto;padding:12px 16px 0;border-top:1px solid rgba(255,255,255,.06)}
.sidebar-user{display:flex;align-items:center;gap:8px}
.sidebar-avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;flex-shrink:0}
.sidebar-avatar-initials{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#b08800,#d29922);display:flex;align-items:center;justify-content:center;font-size:.75em;font-weight:800;color:#fff;flex-shrink:0}
.sidebar-user-name{font-size:.75em;font-weight:600;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sidebar-user-role{font-size:.62em;color:#d29922;font-weight:600}

.section-title{font-size:1.2em;font-weight:800;color:#e6edf3;margin-bottom:6px;display:flex;align-items:center;gap:8px}
.section-sub{font-size:.8em;color:#8b949e;margin-bottom:20px}
.section-content{display:none}
.section-content.active{display:block}

/* Stats */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;transition:border-color .2s}
.stat-card:hover{border-color:rgba(210,153,34,.2)}
.stat-num{font-size:1.8em;font-weight:800;line-height:1}
.stat-label{font-size:.7em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}

/* Project cards */
.proj-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:12px;transition:border-color .2s}
.proj-card:hover{border-color:rgba(210,153,34,.2)}
.proj-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:12px}
.proj-card-name{font-size:.95em;font-weight:700;color:#e6edf3;margin-bottom:3px}
.proj-card-desc{font-size:.75em;color:#8b949e}
.proj-meta{font-size:.73em;color:#484f58;display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.proj-actions{display:flex;gap:8px;flex-wrap:wrap}
.status-badge{font-size:.65em;font-weight:700;border:1px solid;border-radius:100px;padding:2px 9px;white-space:nowrap}

/* Shift cards */
.shift-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:12px;transition:border-color .2s}
.shift-card:hover{border-color:rgba(210,153,34,.2)}
.shift-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;gap:12px}
.shift-name{font-size:.95em;font-weight:700;color:#e6edf3;margin-bottom:3px}
.shift-project{font-size:.75em;color:#58a6ff;font-weight:600}
.shift-meta{font-size:.73em;color:#8b949e;margin-bottom:6px}
.shift-desc{font-size:.75em;color:#8b949e;margin-bottom:8px;line-height:1.4}
.dev-pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.dev-pill{font-size:.7em;font-weight:600;color:#58a6ff;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.2);border-radius:100px;padding:2px 9px}
.shift-sessions-info{margin-bottom:10px}
.shift-actions{display:flex;gap:8px;flex-wrap:wrap}

/* Dev roster */
.dev-row{display:flex;justify-content:space-between;align-items:center;background:#161b22;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:12px 16px;margin-bottom:8px}
.dev-row-left{display:flex;align-items:center;gap:10px}
.dev-avatar-wrap{flex-shrink:0}
.dev-avatar-img{width:36px;height:36px;border-radius:50%;object-fit:cover;display:block}
.dev-avatar-initials{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.85em;color:#fff}
.dev-row-name{font-size:.85em;font-weight:700;color:#e6edf3;margin-bottom:1px}
.dev-row-username{font-size:.72em;color:#8b949e}
.dev-row-stats{display:flex;align-items:center;gap:10px}

/* Reports */
.report-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:12px}
.report-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;gap:12px}
.report-dev-name{font-size:.92em;font-weight:700;color:#e6edf3;margin-bottom:2px}
.report-shift-name{font-size:.78em;color:#58a6ff;font-weight:600;margin-bottom:2px}
.report-meta{font-size:.72em;color:#8b949e}
.report-score{width:52px;height:52px;border-radius:50%;border:3px solid;display:flex;align-items:center;justify-content:center;font-size:1.2em;font-weight:800;flex-shrink:0}
.report-stats{display:flex;gap:12px;flex-wrap:wrap;font-size:.78em;font-weight:700;margin-bottom:10px}
.report-rec{font-size:.75em;color:#8b949e;background:rgba(88,166,255,.05);border:1px solid rgba(88,166,255,.1);border-radius:6px;padding:6px 10px;margin-bottom:5px;line-height:1.4}

/* Buttons */
.btn-sm{border-radius:7px;padding:6px 13px;font-size:.78em;font-weight:700;cursor:pointer;font-family:inherit;transition:all .15s;border:1px solid}
.btn-primary{background:rgba(210,153,34,.15);border-color:rgba(210,153,34,.3);color:#d29922}
.btn-primary:hover{background:rgba(210,153,34,.25);transform:translateY(-1px)}
.btn-ghost{background:rgba(255,255,255,.04);border-color:rgba(255,255,255,.1);color:#8b949e}
.btn-ghost:hover{background:rgba(255,255,255,.08);color:#e6edf3}
.btn-danger{background:rgba(248,81,73,.1);border-color:rgba(248,81,73,.25);color:#f85149}
.btn-danger:hover{background:rgba(248,81,73,.2)}

/* Create forms */
.create-form{background:#161b22;border:1px solid rgba(210,153,34,.2);border-radius:14px;padding:20px;margin-bottom:20px}
.create-form-title{font-size:.9em;font-weight:700;color:#d29922;margin-bottom:14px;display:flex;align-items:center;gap:7px}
.form-group{margin-bottom:12px}
.form-label{display:block;font-size:.72em;font-weight:700;color:#8b949e;letter-spacing:.5px;text-transform:uppercase;margin-bottom:5px}
.form-input{width:100%;background:rgba(13,17,23,.8);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:9px 12px;color:#e6edf3;font-size:.85em;font-family:inherit;outline:none;transition:border-color .2s}
.form-input:focus{border-color:rgba(210,153,34,.4);box-shadow:0 0 0 3px rgba(210,153,34,.08)}
.form-input option{background:#161b22;color:#e6edf3}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-actions{display:flex;gap:8px;margin-top:14px}
.btn-submit{background:linear-gradient(135deg,#b08800,#d29922);border:none;border-radius:8px;color:#000;font-size:.85em;font-weight:800;padding:9px 20px;cursor:pointer;font-family:inherit;transition:all .15s}
.btn-submit:hover{opacity:.9;transform:translateY(-1px)}
.btn-cancel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#8b949e;font-size:.85em;font-weight:600;padding:9px 16px;cursor:pointer;font-family:inherit;transition:all .15s}
.btn-cancel:hover{color:#e6edf3}

/* Multi-select */
.dev-select-list{border:1px solid rgba(255,255,255,.1);border-radius:8px;max-height:150px;overflow-y:auto;background:rgba(13,17,23,.8)}
.dev-select-list option{padding:7px 12px;font-size:.85em}

.empty-state{text-align:center;color:#484f58;font-size:.85em;padding:32px 16px;background:rgba(255,255,255,.02);border:1px dashed rgba(255,255,255,.06);border-radius:12px;margin-bottom:12px}
.section-actions{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:#161b22;border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:24px;width:100%;max-width:480px;max-height:90vh;overflow-y:auto}
.modal-title{font-size:1em;font-weight:800;color:#e6edf3;margin-bottom:16px}
</style>
</head>
<body>
${headerBar}
<div class="app">
  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">👁️</div>
      <div>
        <div class="sidebar-logo-text">Sentinel</div>
        <div class="sidebar-logo-role">Supervisor</div>
      </div>
    </div>

    <div class="nav-section-label">Menu</div>
    <button class="nav-item active" id="nav-overview" onclick="showSection('overview')">
      <span class="nav-icon">🏠</span> Overview
    </button>
    <button class="nav-item" id="nav-projects" onclick="showSection('projects')">
      <span class="nav-icon">📁</span> Projects
      ${projects.length > 0 ? `<span class="nav-badge">${projects.length}</span>` : ''}
    </button>
    <button class="nav-item" id="nav-shifts" onclick="showSection('shifts')">
      <span class="nav-icon">📅</span> Shifts
      ${shifts.filter(s => s.status === 'active').length > 0 ? `<span class="nav-badge">${shifts.filter(s => s.status === 'active').length}</span>` : ''}
    </button>
    <button class="nav-item" id="nav-reports" onclick="showSection('reports')">
      <span class="nav-icon">📊</span> Reports
    </button>
    <button class="nav-item" id="nav-developers" onclick="showSection('developers')">
      <span class="nav-icon">👥</span> Developers
      ${allDevelopers.length > 0 ? `<span class="nav-badge">${allDevelopers.length}</span>` : ''}
    </button>

    <div class="sidebar-bottom">
      <div class="sidebar-user">
        ${session.githubAvatarUrl
          ? `<img src="${esc(session.githubAvatarUrl)}?s=48" class="sidebar-avatar" onerror="this.style.display='none';">`
          : `<div class="sidebar-avatar-initials">${supInitial}</div>`}
        <div>
          <div class="sidebar-user-name">${esc(session.displayName)}</div>
          <div class="sidebar-user-role">👁️ Supervisor</div>
        </div>
      </div>
    </div>
  </nav>

  <!-- Content -->
  <main class="content">

    <!-- OVERVIEW -->
    <div class="section-content active" id="section-overview">
      <div class="section-title">🏠 Team Overview</div>
      <div class="section-sub">Aggregated security metrics for your team</div>
      <div class="stat-grid">
        <div class="stat-card"><div class="stat-num" style="color:#d29922">${projects.length}</div><div class="stat-label">Projects</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#58a6ff">${shifts.length}</div><div class="stat-label">Shifts</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#3fb950">${shifts.filter(s => s.status === 'active').length}</div><div class="stat-label">Active Now</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#f47067">${totalFindings}</div><div class="stat-label">Total Issues</div></div>
        <div class="stat-card"><div class="stat-num" style="color:${avgScore >= 80 ? '#3fb950' : avgScore >= 50 ? '#d29922' : '#f47067'}">${avgScore}</div><div class="stat-label">Avg Score</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#8b949e">${allDevelopers.length}</div><div class="stat-label">Developers</div></div>
      </div>

      ${allSessions.filter(s => !s.endedAt).length > 0 ? `
        <div style="background:rgba(63,185,80,.06);border:1px solid rgba(63,185,80,.2);border-radius:12px;padding:14px 16px;margin-bottom:16px">
          <div style="font-size:.82em;font-weight:700;color:#3fb950;margin-bottom:8px">🟢 Active Sessions Right Now</div>
          ${allSessions.filter(s => !s.endedAt).map(s =>
            `<div style="font-size:.78em;color:#8b949e;padding:3px 0">🧑‍💻 ${esc(s.developerDisplayName)} — ${esc(s.shiftName)} (${esc(s.projectName)})</div>`
          ).join('')}
        </div>` : ''}
    </div>

    <!-- PROJECTS -->
    <div class="section-content" id="section-projects">
      <div class="section-title">📁 Projects</div>
      <div class="section-sub">Manage your research projects</div>
      <div class="section-actions">
        <button class="btn-sm btn-submit" onclick="document.getElementById('create-project-form').style.display='block'">+ New Project</button>
      </div>

      <div id="create-project-form" style="display:none">
        <div class="create-form">
          <div class="create-form-title">📁 Create New Project</div>
          <div class="form-group">
            <label class="form-label">Project Name</label>
            <input class="form-input" id="proj-name" placeholder="e.g. E-Commerce Security Audit" />
          </div>
          <div class="form-group">
            <label class="form-label">Description</label>
            <input class="form-input" id="proj-desc" placeholder="Brief description of the project" />
          </div>
          <div class="form-actions">
            <button class="btn-submit" onclick="createProject()">Create Project</button>
            <button class="btn-cancel" onclick="document.getElementById('create-project-form').style.display='none'">Cancel</button>
          </div>
        </div>
      </div>

      ${projectCards}
    </div>

    <!-- SHIFTS -->
    <div class="section-content" id="section-shifts">
      <div class="section-title">📅 Shifts</div>
      <div class="section-sub">All shifts across your projects</div>
      <div class="section-actions">
        <button class="btn-sm btn-submit" onclick="showCreateShift('','')">+ New Shift</button>
      </div>

      <div id="create-shift-form" style="display:none">
        <div class="create-form">
          <div class="create-form-title">📅 Create New Shift</div>
          <div class="form-group">
            <label class="form-label">Project</label>
            <select class="form-input" id="shift-project-id">
              <option value="">Select a project…</option>
              ${projectOptions}
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Shift Name</label>
            <input class="form-input" id="shift-name" placeholder="e.g. Morning Security Sweep" />
          </div>
          <div class="form-group">
            <label class="form-label">Description</label>
            <input class="form-input" id="shift-desc" placeholder="What will developers be working on?" />
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Scheduled Start</label>
              <input class="form-input" type="datetime-local" id="shift-start" />
            </div>
            <div class="form-group">
              <label class="form-label">Scheduled End</label>
              <input class="form-input" type="datetime-local" id="shift-end" />
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">Assign Developers (hold Ctrl/Cmd to multi-select)</label>
            <select class="form-input dev-select-list" id="shift-devs" multiple size="5">
              ${devOptions}
            </select>
          </div>
          <div class="form-actions">
            <button class="btn-submit" onclick="createShift()">Create Shift</button>
            <button class="btn-cancel" onclick="document.getElementById('create-shift-form').style.display='none'">Cancel</button>
          </div>
        </div>
      </div>

      <div id="shift-list">${shiftCards}</div>
    </div>

    <!-- REPORTS -->
    <div class="section-content" id="section-reports">
      <div class="section-title">📊 Shift Reports</div>
      <div class="section-sub">End-of-shift performance summaries for all developers</div>
      ${reportRows}
    </div>

    <!-- DEVELOPERS -->
    <div class="section-content" id="section-developers">
      <div class="section-title">👥 Developers</div>
      <div class="section-sub">All developers registered in the Sentinel system</div>
      ${devRows}
    </div>

  </main>
</div>

<!-- Assign Developers Modal -->
<div class="modal-overlay" id="assign-modal">
  <div class="modal">
    <div class="modal-title">👥 Manage Developers — <span id="assign-shift-name"></span></div>
    <div class="form-group">
      <label class="form-label">Select Developers</label>
      <select class="form-input dev-select-list" id="assign-devs" multiple size="6">
        ${devOptions}
      </select>
    </div>
    <div class="form-actions">
      <button class="btn-submit" onclick="saveAssignment()">Save</button>
      <button class="btn-cancel" onclick="closeAssignModal()">Cancel</button>
    </div>
  </div>
</div>

<script>
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;
let currentAssignShiftId = '';

function showSection(id) {
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.add('active');
  const nav = document.getElementById('nav-' + id);
  if (nav) nav.classList.add('active');
}

function filterProject(projectId) {
  document.querySelectorAll('.shift-card').forEach(card => {
    card.style.display = (card.dataset.projectId === projectId || !projectId) ? '' : 'none';
  });
}

function showCreateShift(projectId, projectName) {
  const form = document.getElementById('create-shift-form');
  form.style.display = 'block';
  if (projectId) {
    const sel = document.getElementById('shift-project-id');
    sel.value = projectId;
  }
  showSection('shifts');
  form.scrollIntoView({ behavior: 'smooth' });
}

function createProject() {
  const name = document.getElementById('proj-name').value.trim();
  const desc = document.getElementById('proj-desc').value.trim();
  if (!name) { alert('Project name is required.'); return; }
  vscode.postMessage({ command: 'CREATE_PROJECT', name, description: desc });
}

function createShift() {
  const projectId = document.getElementById('shift-project-id').value;
  const name      = document.getElementById('shift-name').value.trim();
  const desc      = document.getElementById('shift-desc').value.trim();
  const start     = document.getElementById('shift-start').value;
  const end       = document.getElementById('shift-end').value;
  const sel       = document.getElementById('shift-devs');
  const selectedOptions = Array.from(sel.selectedOptions);
  const devIds    = selectedOptions.map(o => o.value);
  const devNames  = selectedOptions.map(o => o.dataset.name || o.text);

  if (!projectId) { alert('Please select a project.'); return; }
  if (!name)      { alert('Shift name is required.'); return; }
  if (!start || !end) { alert('Please set shift start and end times.'); return; }

  vscode.postMessage({ command: 'CREATE_SHIFT', projectId, name, description: desc,
    scheduledStart: new Date(start).toISOString(), scheduledEnd: new Date(end).toISOString(),
    developerIds: devIds, developerNames: devNames });
}

function showAssignDev(shiftId, shiftName) {
  currentAssignShiftId = shiftId;
  document.getElementById('assign-shift-name').textContent = shiftName;
  document.getElementById('assign-modal').classList.add('open');
}

function closeAssignModal() {
  document.getElementById('assign-modal').classList.remove('open');
}

function saveAssignment() {
  const sel  = document.getElementById('assign-devs');
  const selectedOptions = Array.from(sel.selectedOptions);
  const ids  = selectedOptions.map(o => o.value);
  const names = selectedOptions.map(o => o.dataset.name || o.text);
  vscode.postMessage({ command: 'UPDATE_SHIFT_ASSIGNMENT', shiftId: currentAssignShiftId, developerIds: ids, developerNames: names });
  closeAssignModal();
}

function viewShiftReport(shiftId) {
  showSection('reports');
}

// Close modal when clicking overlay
document.getElementById('assign-modal').addEventListener('click', function(e) {
  if (e.target === this) closeAssignModal();
});
</script>
</body>
</html>`;
}
