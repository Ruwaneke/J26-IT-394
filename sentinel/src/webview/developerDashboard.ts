/**
 * Sentinel — Developer Dashboard  (v3 — Sidebar Nav + Shift Management)
 *
 * Sections:
 *   Overview    — security score, live findings, vuln breakdown
 *   My Shifts   — assigned shifts, Start/End shift controls
 *   Active      — live vulnerability stream during an active shift
 *   Reports     — completed shift summaries
 */

import { SecurityFinding } from '../analyzer/types.js';
import { AuthSession } from '../auth/authManager.js';
import { Shift, ShiftSession, ShiftSummary } from '../data/projectStore.js';
import { buildHeaderBar } from './loginView.js';

function esc(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function sevColor(sev: string): string {
  return sev === 'CRITICAL' ? '#f47067' : sev === 'HIGH' ? '#e09b3d'
       : sev === 'MEDIUM'   ? '#d29922' : '#3fb950';
}

function scoreColor(n: number): string {
  return n >= 80 ? '#3fb950' : n >= 50 ? '#d29922' : '#f47067';
}

function buildSummaryCard(summary: ShiftSummary, shiftName: string): string {
  const sc = scoreColor(summary.securityScore);
  const trendIcon = summary.trend === 'improving' ? '📈' : summary.trend === 'declining' ? '📉' : '➡️';
  const byTypeRows = Object.entries(summary.byType).map(([t, c]) =>
    `<div class="sum-type-row">
       <span class="sum-type-label">${esc(t.replace(/_/g, ' '))}</span>
       <span class="sum-type-count" style="color:${t.includes('SQL') ? '#f47067' : t.includes('XSS') ? '#e09b3d' : '#d29922'}">${c}</span>
     </div>`
  ).join('');

  const recs = summary.recommendations.map(r =>
    `<li class="rec-item">💡 ${esc(r)}</li>`
  ).join('');

  return `
  <div class="summary-card">
    <div class="summary-header">
      <div>
        <div class="summary-title">📋 ${esc(shiftName)}</div>
        <div class="summary-meta">${fmtDate(summary.generatedAt)} · ${summary.durationMinutes}m duration</div>
      </div>
      <div class="summary-score-circle" style="border-color:${sc};color:${sc}">
        <div class="summary-score-num">${summary.securityScore}</div>
        <div class="summary-score-label">SCORE</div>
      </div>
    </div>
    <div class="summary-stats-row">
      <div class="sum-stat" style="color:#f47067">${summary.criticalCount}<span>CRIT</span></div>
      <div class="sum-stat" style="color:#e09b3d">${summary.highCount}<span>HIGH</span></div>
      <div class="sum-stat" style="color:#d29922">${summary.mediumCount}<span>MED</span></div>
      <div class="sum-stat" style="color:#3fb950">${summary.lowCount}<span>LOW</span></div>
      <div class="sum-stat" style="color:#58a6ff">${summary.totalFindings}<span>TOTAL</span></div>
    </div>
    ${byTypeRows ? `<div class="sum-type-section">${byTypeRows}</div>` : ''}
    ${summary.filesAffected.length ? `
      <div class="sum-files">📂 ${summary.filesAffected.slice(0, 5).map(f => `<code>${esc(f)}</code>`).join(', ')}
        ${summary.filesAffected.length > 5 ? `<em>+${summary.filesAffected.length - 5} more</em>` : ''}
      </div>` : ''}
    <div class="sum-trend">${trendIcon} Trend: <strong style="color:${sc}">${summary.trend.toUpperCase()}</strong></div>
    ${recs ? `<ul class="rec-list">${recs}</ul>` : ''}
  </div>`;
}

function buildShiftCard(shift: Shift, activeSessionId: string | null, isAssigned: boolean): string {
  const statusColor = shift.status === 'active' ? '#3fb950'
                    : shift.status === 'completed' ? '#58a6ff' : '#8b949e';
  const statusIcon  = shift.status === 'active' ? '🟢'
                    : shift.status === 'completed' ? '✅' : '📅';

  const canStart = isAssigned && shift.status !== 'completed' && !activeSessionId;
  const canEnd   = isAssigned && activeSessionId !== null;

  const actions = canEnd
    ? `<button class="btn-end-shift" onclick="endShift('${esc(shift.id)}','${esc(activeSessionId!)}')">⏹ End Shift</button>`
    : canStart
    ? `<button class="btn-start-shift" onclick="startShift('${esc(shift.id)}')">▶ Start Shift</button>`
    : shift.status === 'completed'
    ? `<span class="shift-done-label">✅ Completed</span>`
    : `<span class="shift-not-assigned-label">Waiting to start</span>`;

  return `
  <div class="shift-card ${shift.status === 'active' && activeSessionId ? 'shift-card-active' : ''}">
    <div class="shift-card-header">
      <div>
        <div class="shift-card-name">${statusIcon} ${esc(shift.name)}</div>
        <div class="shift-card-project">📁 ${esc(shift.projectName)}</div>
      </div>
      <span class="shift-status-badge" style="color:${statusColor};border-color:${statusColor}20;background:${statusColor}10">${shift.status.toUpperCase()}</span>
    </div>
    <div class="shift-card-meta">
      <span>🕐 ${fmtDate(shift.scheduledStart)}</span>
      <span>→</span>
      <span>${fmtDate(shift.scheduledEnd)}</span>
    </div>
    ${shift.description ? `<div class="shift-card-desc">${esc(shift.description)}</div>` : ''}
    <div class="shift-card-actions">${actions}</div>
  </div>`;
}

export function buildDeveloperDashboardHtml(
  summary: any,
  findings: SecurityFinding[],
  session: AuthSession,
  logoUri: string,
  cspSource: string,
  rulesCount: number,
  sessionId: string,
  assignedShifts: Shift[] = [],
  activeSession: ShiftSession | null = null,
  recentSessions: ShiftSession[] = [],
): string {
  // ── Overview: security score ──────────────────────────────────────────────
  const scoreRaw = findings.length === 0 ? 100
    : Math.max(0, 100 - (summary.criticalCount * 25 + summary.highCount * 10
        + summary.mediumCount * 5 + summary.lowCount * 2));
  const sc = scoreColor(scoreRaw);
  const circumference = 283;
  const dashOffset = circumference - (scoreRaw / 100) * circumference;

  const typeMap: Record<string, number> = {};
  for (const f of findings) { typeMap[f.type] = (typeMap[f.type] ?? 0) + 1; }
  const typeRows = Object.entries(typeMap).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
    const pct = findings.length ? Math.round((count / findings.length) * 100) : 0;
    const c = type.includes('INJECTION') ? '#f47067' : type.includes('XSS') ? '#e09b3d' : '#d29922';
    return `<div class="brow"><span class="btype">${type.replace(/_/g, ' ')}</span>
      <div class="bbar-wrap"><div class="bbar" style="width:${pct}%;background:${c}"></div></div>
      <span class="bcount">${count}</span></div>`;
  }).join('');

  const findingCards = findings.slice(0, 8).map(f => {
    const sc2 = sevColor(f.severity);
    return `<div class="fcard">
      <div class="fcard-header">
        <span class="fcard-type" style="color:${sc2}">${esc(f.type.replace(/_/g, ' '))}</span>
        <span class="fcard-sev" style="color:${sc2}">${esc(f.severity)}</span>
      </div>
      <div class="fcard-file">${esc(f.fileName.split('/').pop() ?? f.fileName)} : ${f.lineNumber}</div>
      <code class="fcard-snippet">${esc(f.codeSnippet.slice(0, 90))}${f.codeSnippet.length > 90 ? '…' : ''}</code>
    </div>`;
  }).join('');

  // ── My Shifts section ─────────────────────────────────────────────────────
  const shiftCards = assignedShifts.length === 0
    ? `<div class="empty-state">📅 No shifts assigned yet. Ask your supervisor to assign you to a shift.</div>`
    : assignedShifts.map(sh => buildShiftCard(sh, activeSession?.shiftId === sh.id ? activeSession.id : null, true)).join('');

  // ── Active session section ────────────────────────────────────────────────
  let activeContent = '';
  if (activeSession) {
    const elapsed = Math.round((Date.now() - new Date(activeSession.startedAt).getTime()) / 60000);
    const liveFindingCards = activeSession.findings.slice(-10).reverse().map(f => {
      const sc2 = sevColor(f.severity);
      return `<div class="live-finding">
        <span class="live-finding-type" style="color:${sc2}">${esc(f.type.replace(/_/g, ' '))}</span>
        <span class="live-finding-sev" style="color:${sc2}">${esc(f.severity)}</span>
        <span class="live-finding-file">${esc(f.fileName.split('/').pop() ?? '')}:${f.lineNumber}</span>
        <span class="live-finding-time">${new Date(f.detectedAt).toLocaleTimeString()}</span>
      </div>`;
    }).join('') || `<div class="empty-state">✅ No vulnerabilities detected yet in this session.</div>`;

    activeContent = `
    <div class="active-session-banner">
      <div class="active-pulse"></div>
      <div>
        <div class="active-title">🟢 Active Shift: <strong>${esc(activeSession.shiftName)}</strong></div>
        <div class="active-meta">📁 ${esc(activeSession.projectName)} · Started ${fmtDate(activeSession.startedAt)} · ${elapsed}m elapsed</div>
      </div>
      <button class="btn-end-shift-banner" onclick="endShift('${esc(activeSession.shiftId)}','${esc(activeSession.id)}')">⏹ End Shift</button>
    </div>
    <div class="live-findings-header">
      <span>🔴 Live Vulnerability Stream</span>
      <span class="live-count">${activeSession.findings.length} detected</span>
    </div>
    <div class="live-findings-list">${liveFindingCards}</div>`;
  } else {
    activeContent = `<div class="empty-state">⏸ No active shift session. Start a shift from <strong>My Shifts</strong>.</div>`;
  }

  // ── Reports section ───────────────────────────────────────────────────────
  const reportCards = recentSessions.length === 0
    ? `<div class="empty-state">📊 No completed shift reports yet.</div>`
    : recentSessions.slice(0, 10).map(s =>
        s.summary ? buildSummaryCard(s.summary, s.shiftName) : ''
      ).join('');

  const headerBar = buildHeaderBar(session, cspSource);
  const devInitial = esc(session.displayName.charAt(0).toUpperCase());

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Developer</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:#0d1117;color:#e6edf3;height:100vh;overflow:hidden;display:flex;flex-direction:column}

/* ── Layout ── */
.app{display:flex;flex:1;overflow:hidden}
.sidebar{
  width:220px;flex-shrink:0;background:#161b22;border-right:1px solid rgba(255,255,255,.08);
  display:flex;flex-direction:column;padding:16px 0;overflow-y:auto;
}
.content{flex:1;overflow-y:auto;padding:24px}

/* ── Sidebar ── */
.sidebar-logo{display:flex;align-items:center;gap:10px;padding:0 16px 18px;border-bottom:1px solid rgba(255,255,255,.06);margin-bottom:8px}
.sidebar-logo-icon{width:32px;height:32px;background:linear-gradient(135deg,#1f6feb,#388bfd);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.sidebar-logo-text{font-size:.85em;font-weight:800;color:#e6edf3;letter-spacing:-.3px}
.sidebar-logo-role{font-size:.62em;color:#58a6ff;font-weight:600;letter-spacing:.3px;text-transform:uppercase}

.nav-section-label{font-size:.62em;font-weight:700;color:#484f58;letter-spacing:.8px;text-transform:uppercase;padding:12px 16px 4px}
.nav-item{
  display:flex;align-items:center;gap:9px;
  padding:8px 16px;margin:1px 8px;border-radius:8px;
  font-size:.82em;font-weight:500;color:#8b949e;
  cursor:pointer;transition:all .15s;border:none;background:none;width:calc(100% - 16px);text-align:left;font-family:inherit;
}
.nav-item:hover{background:rgba(255,255,255,.06);color:#e6edf3}
.nav-item.active{background:rgba(88,166,255,.12);color:#58a6ff;font-weight:600}
.nav-item .nav-icon{font-size:1em;width:18px;text-align:center}
.nav-badge{margin-left:auto;background:rgba(247,129,102,.2);color:#f78166;border-radius:100px;padding:1px 7px;font-size:.65em;font-weight:700}
.nav-badge.green{background:rgba(63,185,80,.15);color:#3fb950}

.sidebar-bottom{margin-top:auto;padding:12px 16px 0;border-top:1px solid rgba(255,255,255,.06)}
.sidebar-user{display:flex;align-items:center;gap:8px}
.sidebar-avatar{width:28px;height:28px;border-radius:50%;object-fit:cover;flex-shrink:0}
.sidebar-avatar-initials{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-size:.75em;font-weight:800;color:#fff;flex-shrink:0}
.sidebar-user-name{font-size:.75em;font-weight:600;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sidebar-user-role{font-size:.62em;color:#58a6ff;font-weight:600}

/* ── Section titles ── */
.section-title{font-size:1.2em;font-weight:800;color:#e6edf3;margin-bottom:6px;display:flex;align-items:center;gap:8px}
.section-sub{font-size:.8em;color:#8b949e;margin-bottom:20px}

/* ── Stat cards ── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;transition:border-color .2s}
.stat-card:hover{border-color:rgba(88,166,255,.2)}
.stat-num{font-size:1.8em;font-weight:800;line-height:1}
.stat-label{font-size:.7em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}

/* ── Score circle ── */
.score-wrap{display:flex;align-items:center;gap:24px;background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:20px;margin-bottom:20px}
.score-svg{flex-shrink:0}
.score-info{flex:1}
.score-info-title{font-size:1em;font-weight:700;color:#e6edf3;margin-bottom:4px}
.score-info-sub{font-size:.78em;color:#8b949e;line-height:1.5}

/* ── Breakdown ── */
.breakdown{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:16px}
.breakdown-title{font-size:.78em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.brow{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:.78em}
.btype{color:#8b949e;width:160px;flex-shrink:0;font-weight:500}
.bbar-wrap{flex:1;background:rgba(255,255,255,.06);border-radius:4px;height:6px;overflow:hidden}
.bbar{height:100%;border-radius:4px;transition:width .4s}
.bcount{color:#e6edf3;font-weight:700;width:24px;text-align:right}

/* ── Finding cards ── */
.fcard{background:#161b22;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:12px;margin-bottom:8px;transition:border-color .15s}
.fcard:hover{border-color:rgba(88,166,255,.2)}
.fcard-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
.fcard-type{font-size:.78em;font-weight:700}
.fcard-sev{font-size:.7em;font-weight:700;background:rgba(0,0,0,.2);padding:1px 6px;border-radius:4px}
.fcard-file{font-size:.72em;color:#8b949e;margin-bottom:5px}
.fcard-snippet{font-size:.7em;color:#8b949e;font-family:'Courier New',monospace;background:rgba(0,0,0,.2);padding:4px 6px;border-radius:4px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── Shift cards ── */
.shift-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:12px;transition:border-color .2s}
.shift-card-active{border-color:rgba(63,185,80,.4);box-shadow:0 0 16px rgba(63,185,80,.08)}
.shift-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px}
.shift-card-name{font-size:.95em;font-weight:700;color:#e6edf3;margin-bottom:3px}
.shift-card-project{font-size:.75em;color:#58a6ff;font-weight:600}
.shift-status-badge{font-size:.65em;font-weight:700;border:1px solid;border-radius:100px;padding:2px 9px;white-space:nowrap}
.shift-card-meta{font-size:.73em;color:#8b949e;display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap}
.shift-card-desc{font-size:.76em;color:#8b949e;margin-bottom:10px;line-height:1.4}
.shift-card-actions{display:flex;gap:8px;flex-wrap:wrap}
.btn-start-shift{background:linear-gradient(135deg,#1a7f37,#238636);border:none;border-radius:8px;color:#fff;font-size:.8em;font-weight:700;padding:7px 16px;cursor:pointer;font-family:inherit;transition:all .15s}
.btn-start-shift:hover{opacity:.88;transform:translateY(-1px)}
.btn-end-shift{background:rgba(248,81,73,.15);border:1px solid rgba(248,81,73,.3);border-radius:8px;color:#f85149;font-size:.8em;font-weight:700;padding:7px 16px;cursor:pointer;font-family:inherit;transition:all .15s}
.btn-end-shift:hover{background:rgba(248,81,73,.25);transform:translateY(-1px)}
.shift-done-label{font-size:.78em;color:#58a6ff;font-weight:600}
.shift-not-assigned-label{font-size:.78em;color:#8b949e}

/* ── Active session ── */
.active-session-banner{background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);border-radius:12px;padding:16px;margin-bottom:16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.active-pulse{width:12px;height:12px;border-radius:50%;background:#3fb950;box-shadow:0 0 8px #3fb950;animation:pulse 1.5s infinite;flex-shrink:0}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.active-title{font-size:.92em;font-weight:700;color:#e6edf3;margin-bottom:2px}
.active-meta{font-size:.74em;color:#8b949e}
.btn-end-shift-banner{margin-left:auto;background:rgba(248,81,73,.15);border:1px solid rgba(248,81,73,.3);border-radius:8px;color:#f85149;font-size:.82em;font-weight:700;padding:8px 18px;cursor:pointer;font-family:inherit;transition:all .15s}
.btn-end-shift-banner:hover{background:rgba(248,81,73,.25)}
.live-findings-header{display:flex;justify-content:space-between;align-items:center;font-size:.8em;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
.live-count{background:rgba(248,81,73,.15);color:#f85149;border-radius:100px;padding:2px 10px;font-size:.85em;font-weight:700;text-transform:none;letter-spacing:0}
.live-findings-list{display:flex;flex-direction:column;gap:6px}
.live-finding{background:#161b22;border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:10px 14px;display:grid;grid-template-columns:auto auto 1fr auto;gap:10px;align-items:center;font-size:.78em}
.live-finding-type{font-weight:700}
.live-finding-sev{font-weight:700;padding:1px 6px;border-radius:4px;background:rgba(0,0,0,.2);font-size:.85em}
.live-finding-file{color:#8b949e;font-family:'Courier New',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.live-finding-time{color:#484f58;font-size:.85em;white-space:nowrap}

/* ── Summary cards ── */
.summary-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:20px;margin-bottom:16px}
.summary-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;gap:12px}
.summary-title{font-size:.95em;font-weight:700;color:#e6edf3;margin-bottom:3px}
.summary-meta{font-size:.72em;color:#8b949e}
.summary-score-circle{width:64px;height:64px;border-radius:50%;border:3px solid;display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}
.summary-score-num{font-size:1.3em;font-weight:800;line-height:1}
.summary-score-label{font-size:.5em;font-weight:700;letter-spacing:.5px;opacity:.7}
.summary-stats-row{display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap}
.sum-stat{display:flex;flex-direction:column;align-items:center;background:rgba(0,0,0,.2);border-radius:8px;padding:8px 14px;min-width:52px}
.sum-stat{font-size:1.4em;font-weight:800}
.sum-stat span{font-size:.45em;font-weight:700;letter-spacing:.5px;opacity:.7;margin-top:2px}
.sum-type-section{display:flex;flex-direction:column;gap:4px;margin-bottom:12px}
.sum-type-row{display:flex;justify-content:space-between;align-items:center;font-size:.78em;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.sum-type-label{color:#8b949e;font-weight:500}
.sum-type-count{font-weight:700}
.sum-files{font-size:.73em;color:#8b949e;margin-bottom:10px}
.sum-files code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px;font-size:.9em;margin:0 2px}
.sum-trend{font-size:.8em;color:#8b949e;margin-bottom:10px}
.rec-list{list-style:none;display:flex;flex-direction:column;gap:6px}
.rec-item{font-size:.78em;color:#8b949e;background:rgba(88,166,255,.05);border:1px solid rgba(88,166,255,.1);border-radius:7px;padding:7px 10px;line-height:1.4}

/* ── Misc ── */
.empty-state{text-align:center;color:#484f58;font-size:.85em;padding:32px 16px;background:rgba(255,255,255,.02);border:1px dashed rgba(255,255,255,.06);border-radius:12px}
.section-content{display:none}
.section-content.active{display:block}
</style>
</head>
<body>
${headerBar}
<div class="app">
  <!-- ── Sidebar ── -->
  <nav class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">🛡</div>
      <div>
        <div class="sidebar-logo-text">Sentinel</div>
        <div class="sidebar-logo-role">Developer</div>
      </div>
    </div>

    <div class="nav-section-label">Main</div>
    <button class="nav-item active" id="nav-overview" onclick="showSection('overview')">
      <span class="nav-icon">🏠</span> Overview
    </button>
    <button class="nav-item" id="nav-shifts" onclick="showSection('shifts')">
      <span class="nav-icon">📅</span> My Shifts
      ${assignedShifts.filter(s => s.status !== 'completed').length > 0 ? `<span class="nav-badge green">${assignedShifts.filter(s => s.status !== 'completed').length}</span>` : ''}
    </button>
    <button class="nav-item" id="nav-active" onclick="showSection('active')">
      <span class="nav-icon">${activeSession ? '🟢' : '⏸'}</span> Active Session
      ${activeSession ? `<span class="nav-badge green">LIVE</span>` : ''}
    </button>
    <button class="nav-item" id="nav-reports" onclick="showSection('reports')">
      <span class="nav-icon">📊</span> Reports
      ${recentSessions.length > 0 ? `<span class="nav-badge">${recentSessions.length}</span>` : ''}
    </button>

    <div class="sidebar-bottom">
      <div class="sidebar-user">
        ${session.githubAvatarUrl
          ? `<img src="${esc(session.githubAvatarUrl)}?s=48" class="sidebar-avatar" onerror="this.style.display='none';">`
          : `<div class="sidebar-avatar-initials">${devInitial}</div>`}
        <div>
          <div class="sidebar-user-name">${esc(session.displayName)}</div>
          <div class="sidebar-user-role">🧑‍💻 Developer</div>
        </div>
      </div>
    </div>
  </nav>

  <!-- ── Content ── -->
  <main class="content">

    <!-- OVERVIEW -->
    <div class="section-content active" id="section-overview">
      <div class="section-title">🏠 Security Overview</div>
      <div class="section-sub">Your live security score and current findings</div>

      <div class="score-wrap">
        <svg class="score-svg" width="90" height="90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="8"/>
          <circle cx="50" cy="50" r="45" fill="none" stroke="${sc}" stroke-width="8"
            stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}"
            stroke-linecap="round" transform="rotate(-90 50 50)" style="transition:stroke-dashoffset .6s"/>
          <text x="50" y="54" text-anchor="middle" font-size="22" font-weight="800" fill="${sc}" font-family="Inter,sans-serif">${scoreRaw}</text>
        </svg>
        <div class="score-info">
          <div class="score-info-title" style="color:${sc}">Security Score: ${scoreRaw}/100</div>
          <div class="score-info-sub">
            Session: <code>${esc(sessionId.slice(0, 16))}…</code><br>
            Rules active: ${rulesCount} · Findings: ${findings.length}
          </div>
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-card"><div class="stat-num" style="color:#f47067">${summary.criticalCount}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#e09b3d">${summary.highCount}</div><div class="stat-label">High</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#d29922">${summary.mediumCount}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#3fb950">${summary.lowCount}</div><div class="stat-label">Low</div></div>
      </div>

      ${typeRows ? `<div class="breakdown"><div class="breakdown-title">Vulnerability Breakdown</div>${typeRows}</div>` : ''}
      ${findingCards || `<div class="empty-state">✅ No vulnerabilities in currently open files.</div>`}
    </div>

    <!-- MY SHIFTS -->
    <div class="section-content" id="section-shifts">
      <div class="section-title">📅 My Shifts</div>
      <div class="section-sub">Shifts you have been assigned to by your supervisor</div>
      ${shiftCards}
    </div>

    <!-- ACTIVE SESSION -->
    <div class="section-content" id="section-active">
      <div class="section-title">${activeSession ? '🟢 Active Session' : '⏸ No Active Session'}</div>
      <div class="section-sub">
        ${activeSession ? `Live vulnerability tracking for <strong>${esc(activeSession.shiftName)}</strong>` : 'Start a shift from My Shifts to begin tracking'}
      </div>
      ${activeContent}
    </div>

    <!-- REPORTS -->
    <div class="section-content" id="section-reports">
      <div class="section-title">📊 Shift Reports</div>
      <div class="section-sub">End-of-shift summaries with your security performance</div>
      ${reportCards}
    </div>

  </main>
</div>

<script>
// acquireVsCodeApi() must be called EXACTLY ONCE per page.
// We store it on window._vscode so the header bar's doLogout() can also use it.
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;

function showSection(id) {
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.add('active');
  const nav = document.getElementById('nav-' + id);
  if (nav) nav.classList.add('active');
}

function startShift(shiftId) {
  vscode.postMessage({ command: 'START_SHIFT', shiftId });
}

function endShift(shiftId, sessionId) {
  vscode.postMessage({ command: 'END_SHIFT', shiftId, sessionId });
}

// Auto-navigate to Active section if a session is running
${activeSession ? "showSection('active');" : ''}
</script>
</body>
</html>`;
}
