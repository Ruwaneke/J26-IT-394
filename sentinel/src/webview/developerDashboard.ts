/**
 * Sentinel — Modern Developer Security Dashboard
 *
 * Exclusively for developers authenticated via GitHub.
 *
 * Features:
 *   1. Precise Vulnerability Resolution Progress Bar with exact percentage
 *      metrics (Identified vs Fixed findings count).
 *   2. In-depth Vulnerability Explanation cards showing:
 *      - Why is this vulnerable? (Root cause & security risk)
 *      - How to fix? (Step-by-step remediation guide)
 *      - Code Comparison (Vulnerable code vs Secure replacement)
 *      - Concrete attack scenarios
 *   3. Actions: [⚡ Apply Fix to Code], [✓ Mark Fixed in DB], [👁️ Jump to Line], [✕ Ignore].
 *   4. Permanent Database Vulnerability History from Neon PostgreSQL.
 *   5. Real-time Neon PostgreSQL status indicator & audit activity.
 *   6. State-of-the-art dark glassmorphic UI aesthetics.
 */

import { SecurityFinding } from '../analyzer/types.js';
import { AuthSession } from '../auth/authManager.js';
import { Shift, ShiftSession } from '../data/projectStore.js';
import { DbVulnerabilityRecord, VulnerabilityStats, UserActivityLog } from '../data/neonDatabaseService.js';
import { generateContextualExplanation, ContextualExplanation } from '../diagnostics/contextualExplainer.js';
import { buildHeaderBar } from './loginView.js';

function esc(s: any): string {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function sevColor(sev: string): string {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH':     return '#f97316';
    case 'MEDIUM':   return '#f59e0b';
    case 'LOW':      return '#10b981';
    default:         return '#60a5fa';
  }
}

function scoreColor(n: number): string {
  return n >= 80 ? '#10b981' : n >= 50 ? '#f59e0b' : '#ef4444';
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
  stats?: VulnerabilityStats,
  dbRecords: DbVulnerabilityRecord[] = [],
  dbStatus: { isOnline: boolean; pingMs: number; error: string | null } = { isOnline: true, pingMs: 42, error: null },
  activities: UserActivityLog[] = [],
): string {
  const devId = session.githubUsername ?? session.username;
  const devInitial = esc((session.displayName || session.username || 'D').charAt(0).toUpperCase());

  // ── 1. Calculate Mathematically Precise Progress & Metrics ──────────────────
  // Current active open findings in the editor (the ones with red squiggly lines)
  const currentOpenCount = findings.length;

  // Historical fixed and ignored records
  const historicalFixedCount = stats ? stats.fixedCount : dbRecords.filter(r => r.status === 'FIXED').length;
  const ignoredCount = stats ? stats.ignoredCount : dbRecords.filter(r => r.status === 'IGNORED').length;

  // Total identified findings count: at least live open findings + historical fixed + ignored
  const totalIdentified = Math.max(
    currentOpenCount + historicalFixedCount + ignoredCount,
    stats ? stats.totalIdentified : 0,
    dbRecords.length
  );

  const fixedCount = historicalFixedCount;
  const openCount = currentOpenCount;

  // Precise percentages:
  // When 6 vulnerabilities exist and 0 are fixed -> 0.0% Fixed! (NOT 100%)
  // When all 6 are fixed -> 100.0% Fixed!
  const fixPercentage = totalIdentified > 0
    ? Math.round((fixedCount / totalIdentified) * 1000) / 10
    : 0.0;
  const openPercentage = totalIdentified > 0
    ? Math.round((openCount / totalIdentified) * 1000) / 10
    : 0.0;

  // Security score
  const scoreRaw = openCount === 0 ? 100 : Math.max(0, 100 - (summary.criticalCount * 25 + summary.highCount * 10 + summary.mediumCount * 5 + summary.lowCount * 2));
  const scColor = scoreColor(scoreRaw);

  // ── 2. Build Rich Vulnerability Cards with "Why & How to Fix" ────────────────
  const findingCards = findings.map(f => {
    const ctx: ContextualExplanation = generateContextualExplanation(f);
    const confPct = Math.round(f.confidence * 100);
    const sevCol = sevColor(f.severity);

    return `
    <div class="vuln-card" id="card-${f.id}">
      <div class="vuln-card-header" onclick="toggleDetails('${f.id}')">
        <div class="header-left">
          <span class="sev-pill" style="background:${sevCol}22;color:${sevCol};border:1px solid ${sevCol}55">
            ${f.severity === 'CRITICAL' ? '🚨' : f.severity === 'HIGH' ? '🔴' : f.severity === 'MEDIUM' ? '🟠' : '🟡'} ${f.severity}
          </span>
          <span class="status-pill status-open">⏳ OPEN</span>
          <div>
            <div class="vuln-title">${esc(f.type.replace(/_/g, ' '))}</div>
            <div class="vuln-file">
              <span class="file-icon">📄</span> <code>${esc(f.fileName.split('/').pop() ?? f.fileName)}</code> : Line ${f.lineNumber}
            </div>
          </div>
        </div>
        <div class="header-right">
          <span class="conf-badge">${confPct}% Confidence</span>
          <span class="rule-badge">${esc(f.detectedByRule)}</span>
          <button class="btn-jump" onclick="event.stopPropagation(); jumpToCode('${esc(f.fileName)}', ${f.lineNumber})" title="Jump to line in editor">👁️ Jump</button>
          <span class="chevron" id="chev-${f.id}">▼</span>
        </div>
      </div>

      <div class="vuln-body open" id="body-${f.id}">
        <!-- Why it's vulnerable -->
        <div class="expl-section why-section">
          <div class="expl-label why-label">
            <span class="expl-icon">❓</span> Why is this vulnerable?
          </div>
          <div class="expl-text">${esc(ctx.whyDangerous)}</div>
        </div>

        <!-- How to fix -->
        <div class="expl-section fix-section">
          <div class="expl-label fix-label">
            <span class="expl-icon">🛡️</span> How to fix
          </div>
          <div class="expl-text">${esc(ctx.fixExplanation)}</div>
        </div>

        <!-- Code Comparison -->
        <div class="code-compare-grid">
          <div class="code-box vulnerable-box">
            <div class="code-title danger-title">❌ Detected Vulnerable Code (Line ${f.lineNumber})</div>
            <pre class="code-pre danger-pre">${esc(ctx.vulnerableCode || f.codeSnippet)}</pre>
          </div>
          <div class="code-box fixed-box">
            <div class="code-title safe-title">✅ Recommended Secure Replacement</div>
            <pre class="code-pre safe-pre">${esc(ctx.fixedCode)}</pre>
          </div>
        </div>

        <!-- Attack Scenario -->
        <div class="attack-scenario">
          <div class="attack-title">⚡ Attack Scenario</div>
          <div class="attack-text">${esc(ctx.attackScenario)}</div>
        </div>

        <!-- Actions & AI Suggestion -->
        <div class="card-actions">
          <button class="btn-action btn-copy-fix" onclick="copyAiFix(this, ${JSON.stringify(ctx.fixedCode)})" title="Copy AI secure code suggestion to clipboard">
            📋 Copy AI Fix Suggestion
          </button>
          <button class="btn-action btn-inspect" onclick="jumpToCode('${esc(f.fileName)}', ${f.lineNumber})" title="Jump to line in editor to edit code">
            👁️ Jump to Line in Editor
          </button>
          <button class="btn-action btn-ignore" onclick="ignoreFinding('${esc(f.id)}')">
            ✕ Ignore Warning
          </button>
          <div class="ai-guidance-card">
            🤖 <strong>AI Suggestion:</strong> Sentinel guides you to fix vulnerabilities manually without relying on auto-fix buttons. Edit this line in your editor using the secure guidance above. Sentinel's real-time engine monitors keystrokes and automatically marks this vulnerability as <strong>FIXED</strong> once resolved!
          </div>
        </div>
      </div>
    </div>`;
  }).join('');

  // ── 3. Database Vulnerability Tracker Records ──────────────────────────────
  const dbRecordRows = dbRecords.map(r => {
    const sColor = sevColor(r.severity);
    const isFixed = r.status === 'FIXED';
    const isIgnored = r.status === 'IGNORED';
    const statusClass = isFixed ? 'status-fixed' : isIgnored ? 'status-ignored' : 'status-open';
    const statusIcon = isFixed ? '✅' : isIgnored ? '⚪' : '⏳';
    const cleanFileName = (r.fileName || '').replace(/\\/g, '/').split('/').pop() || r.fileName;
    const searchIdx = `${r.vulnerabilityType} ${cleanFileName} ${r.lineNumber} ${r.severity} ${r.status}`.toLowerCase();

    return `
    <tr class="db-row status-${r.status.toLowerCase()}" data-status="${r.status}" data-severity="${r.severity}" data-search="${esc(searchIdx)}">
      <td><span class="sev-pill-sm" style="color:${sColor}">${r.severity}</span></td>
      <td>
        <div class="row-vuln-type">${esc(r.vulnerabilityType.replace(/_/g, ' '))}</div>
        <div class="row-vuln-dev">@${esc(r.githubUsername || r.developerId)}</div>
      </td>
      <td>
        <div class="row-file" title="${esc(r.fileName)}">${esc(cleanFileName)}</div>
        <div class="row-line">Line ${r.lineNumber}</div>
      </td>
      <td><span class="status-pill ${statusClass}">${statusIcon} ${r.status}</span></td>
      <td class="row-date">${fmtDate(r.detectedAt)}</td>
      <td style="text-align: right;">
        <div class="table-actions" style="justify-content: flex-end;">
          ${isFixed
            ? `<span class="fixed-badge">✅ Remediated</span>`
            : `<button class="btn-table-jump" onclick="jumpToCode('${esc(r.fileName)}', ${r.lineNumber})" title="Jump to this line in your editor">👁️ Jump to Line</button>`}
        </div>
      </td>
    </tr>`;
  }).join('');

  // ── 4. Activity Audit Stream ────────────────────────────────────────────────
  const activityItems = activities.map(act => {
    return `
    <div class="activity-item">
      <div class="act-dot"></div>
      <div class="act-content">
        <div class="act-header">
          <span class="act-user">@${esc(act.githubUsername || act.username || 'user')}</span>
          <span class="act-type">${esc(act.actionType.replace(/_/g, ' '))}</span>
          <span class="act-time">${fmtDate(act.createdAt)}</span>
        </div>
        ${act.vulnerabilityType ? `<div class="act-detail">${esc(act.vulnerabilityType)} (${esc(act.findingId || '')})</div>` : ''}
      </div>
    </div>`;
  }).join('') || `<div class="empty-state">No recent activity recorded yet.</div>`;

  // ── 5. Shifts ───────────────────────────────────────────────────────────────
  const shiftCards = assignedShifts.length === 0
    ? `<div class="empty-state">📅 No shifts assigned yet. Ask your supervisor to assign you to a shift.</div>`
    : assignedShifts.map(sh => `
      <div class="shift-card">
        <div class="shift-card-header">
          <div>
            <div class="shift-card-name">📅 ${esc(sh.name)}</div>
            <div class="shift-card-project">📁 ${esc(sh.projectName)}</div>
          </div>
          <span class="status-pill status-${sh.status}">${sh.status.toUpperCase()}</span>
        </div>
        <div class="shift-card-meta">
          <span>🕐 ${fmtDate(sh.scheduledStart)} → ${fmtDate(sh.scheduledEnd)}</span>
        </div>
        ${sh.description ? `<div class="shift-card-desc">${esc(sh.description)}</div>` : ''}
        <div class="shift-card-actions">
          ${activeSession?.shiftId === sh.id
            ? `<button class="btn-action btn-end-shift" onclick="endShift('${esc(sh.id)}', '${esc(activeSession.id)}')">⏹ End Shift</button>`
            : `<button class="btn-action btn-start-shift" onclick="startShift('${esc(sh.id)}')">▶ Start Shift</button>`}
        </div>
      </div>
    `).join('');

  const headerBar = buildHeaderBar(session, cspSource);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Developer Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Fira+Code:wght@400;500;600&display=swap');

:root {
  --bg-primary: #090d16;
  --bg-card: rgba(17, 24, 39, 0.75);
  --border-card: rgba(255, 255, 255, 0.08);
  --border-focus: rgba(56, 189, 248, 0.35);
  --text-primary: #f3f4f6;
  --text-secondary: #9ca3af;
  --text-muted: #6b7280;
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-emerald: #10b981;
  --accent-amber: #f59e0b;
  --accent-rose: #f43f5e;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  height: 100vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

/* ── Top App Bar ── */
.top-nav {
  height: 60px;
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border-card);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  flex-shrink: 0;
  z-index: 100;
}
.brand-group { display: flex; align-items: center; gap: 12px; }
.logo-icon {
  width: 34px; height: 34px;
  background: linear-gradient(135deg, #0ea5e9, #3b82f6);
  border-radius: 9px;
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
  box-shadow: 0 0 16px rgba(14, 165, 233, 0.4);
}
.brand-name { font-size: 1.15em; font-weight: 800; letter-spacing: -0.3px; color: #fff; }
.brand-tag { font-size: 0.65em; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 2px 8px; border-radius: 100px; text-transform: uppercase; }

.db-status-pill {
  display: flex; align-items: center; gap: 7px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.25);
  border-radius: 100px;
  padding: 4px 12px;
  font-size: 0.72em;
  font-weight: 600;
  color: #34d399;
}
.db-dot { width: 7px; height: 7px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981; animation: pulse 2s infinite; }

.user-profile-group { display: flex; align-items: center; gap: 10px; }
.dev-profile-chip {
  display: flex; align-items: center; gap: 8px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border-card);
  border-radius: 10px;
  padding: 5px 12px;
}
.dev-avatar-img { width: 26px; height: 26px; border-radius: 50%; object-fit: cover; }
.dev-avatar-initial { width: 26px; height: 26px; border-radius: 50%; background: #3b82f6; display: flex; align-items: center; justify-content: center; font-size: 0.75em; font-weight: 700; color: #fff; }
.dev-meta { display: flex; flex-direction: column; text-align: left; }
.dev-username { font-size: 0.78em; font-weight: 700; color: #fff; line-height: 1.2; }
.dev-role-label { font-size: 0.62em; color: var(--accent-cyan); font-weight: 600; }

.btn-signout {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: #f87171;
  font-size: 0.72em;
  font-weight: 600;
  padding: 6px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-signout:hover { background: rgba(239, 68, 68, 0.25); }

/* ── Layout ── */
.app { display: flex; flex: 1; overflow: hidden; }
.sidebar {
  width: 230px;
  background: rgba(13, 17, 23, 0.95);
  border-right: 1px solid var(--border-card);
  display: flex;
  flex-direction: column;
  padding: 16px 0;
  overflow-y: auto;
  flex-shrink: 0;
}
.content {
  flex: 1;
  overflow-y: auto;
  padding: 24px 32px;
  background: radial-gradient(circle at top right, rgba(14, 165, 233, 0.04), transparent 40%),
              radial-gradient(circle at bottom left, rgba(16, 185, 129, 0.03), transparent 40%);
}

/* ── Nav Items ── */
.nav-heading { font-size: 0.62em; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; padding: 12px 18px 6px; }
.nav-btn {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 18px; margin: 2px 10px;
  border-radius: 9px;
  font-size: 0.82em; font-weight: 500;
  color: var(--text-secondary);
  border: none; background: none; width: calc(100% - 20px);
  cursor: pointer; text-align: left; font-family: inherit;
  transition: all 0.15s;
}
.nav-btn:hover { background: rgba(255, 255, 255, 0.05); color: #fff; }
.nav-btn.active { background: rgba(14, 165, 233, 0.12); color: #38bdf8; font-weight: 600; }
.nav-badge { margin-left: auto; background: rgba(239, 68, 68, 0.2); color: #f87171; border-radius: 100px; padding: 1px 7px; font-size: 0.7em; font-weight: 700; }
.nav-badge.green { background: rgba(16, 185, 129, 0.2); color: #34d399; }

/* ── Precise Progress Bar Card ── */
.progress-hero-card {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border-card);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
  position: relative;
  overflow: hidden;
}
.progress-hero-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, #10b981, #06b6d4, #3b82f6);
}
.progress-hero-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 16px; flex-wrap: wrap; gap: 12px;
}
.progress-title-wrap { display: flex; align-items: center; gap: 10px; }
.progress-title { font-size: 1.15em; font-weight: 800; color: #fff; letter-spacing: -0.2px; }
.progress-subtitle { font-size: 0.78em; color: var(--text-secondary); margin-top: 2px; }

.progress-big-stat {
  display: flex; align-items: baseline; gap: 6px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.25);
  border-radius: 12px;
  padding: 8px 16px;
}
.fix-num { font-size: 1.7em; font-weight: 800; color: #34d399; line-height: 1; }
.fix-label { font-size: 0.75em; font-weight: 700; color: #6ee7b7; text-transform: uppercase; }

/* Progress Track */
.progress-bar-container { margin: 16px 0 12px; }
.progress-track {
  width: 100%; height: 16px;
  background: rgba(255, 255, 255, 0.05);
  border-radius: 100px;
  overflow: hidden;
  display: flex;
  position: relative;
  box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.3);
}
.progress-seg-fixed {
  height: 100%;
  background: linear-gradient(90deg, #059669, #10b981);
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 0 12px rgba(16, 185, 129, 0.5);
}
.progress-seg-open {
  height: 100%;
  background: linear-gradient(90deg, #f59e0b, #ef4444);
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}
.progress-seg-ignored {
  height: 100%;
  background: #64748b;
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}

.progress-metric-chips {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin-top: 16px;
}
.metric-chip {
  background: rgba(255, 255, 255, 0.02);
  border: 1px solid var(--border-card);
  border-radius: 10px;
  padding: 10px 14px;
  display: flex;
  flex-direction: column;
}
.chip-num { font-size: 1.35em; font-weight: 800; line-height: 1.1; }
.chip-label { font-size: 0.67em; font-weight: 600; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; letter-spacing: 0.5px; }

/* ── Filter Toolbar ── */
.filter-toolbar {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 18px; flex-wrap: wrap; gap: 12px;
}
.filter-buttons { display: flex; gap: 6px; }
.btn-filter {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border-card);
  border-radius: 8px;
  color: var(--text-secondary);
  font-size: 0.75em; font-weight: 600;
  padding: 6px 12px;
  cursor: pointer; transition: all 0.15s; font-family: inherit;
}
.btn-filter:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
.btn-filter.active { background: rgba(14, 165, 233, 0.2); border-color: rgba(14, 165, 233, 0.4); color: #38bdf8; }

/* ── Vulnerability Cards ── */
.vuln-cards-list { display: flex; flex-direction: column; gap: 14px; }
.vuln-card {
  background: var(--bg-card);
  backdrop-filter: blur(16px);
  border: 1px solid var(--border-card);
  border-radius: 14px;
  overflow: hidden;
  transition: all 0.2s;
  box-shadow: 0 4px 18px rgba(0, 0, 0, 0.25);
}
.vuln-card:hover { border-color: rgba(56, 189, 248, 0.25); transform: translateY(-1px); }

.vuln-card-header {
  padding: 16px 20px;
  display: flex; align-items: center; justify-content: space-between;
  cursor: pointer; user-select: none;
  background: rgba(255, 255, 255, 0.02);
  gap: 12px; flex-wrap: wrap;
}
.header-left { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.sev-pill { font-size: 0.7em; font-weight: 800; border-radius: 100px; padding: 3px 10px; letter-spacing: 0.5px; }
.sev-pill-sm { font-size: 0.7em; font-weight: 800; }
.status-pill { font-size: 0.67em; font-weight: 700; border-radius: 100px; padding: 3px 9px; }
.status-open { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
.status-fixed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
.status-ignored { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }

.vuln-title { font-size: 0.95em; font-weight: 700; color: #fff; }
.vuln-file { font-size: 0.72em; color: var(--text-secondary); margin-top: 2px; }
.vuln-file code { background: rgba(255, 255, 255, 0.05); padding: 2px 6px; border-radius: 4px; font-family: 'Fira Code', monospace; }

.header-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.conf-badge { font-size: 0.7em; font-weight: 600; color: var(--text-muted); background: rgba(255, 255, 255, 0.04); padding: 3px 8px; border-radius: 6px; }
.rule-badge { font-size: 0.68em; font-weight: 600; color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 3px 8px; border-radius: 6px; }
.btn-jump { background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-card); color: #e2e8f0; border-radius: 6px; padding: 3px 8px; font-size: 0.7em; cursor: pointer; }
.btn-jump:hover { background: rgba(255, 255, 255, 0.1); }
.chevron { font-size: 0.7em; color: var(--text-muted); transition: transform 0.2s; }
.chevron.open { transform: rotate(180deg); }

.vuln-body { padding: 20px; border-top: 1px solid var(--border-card); background: rgba(10, 15, 26, 0.7); }

/* Explanation Sections */
.expl-section { border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
.why-section { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.15); }
.fix-section { background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); }
.expl-label { font-size: 0.75em; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
.why-label { color: #f87171; }
.fix-label { color: #34d399; }
.expl-text { font-size: 0.85em; color: #e2e8f0; line-height: 1.5; }

/* Code Comparison */
.code-compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
.code-box { border-radius: 8px; overflow: hidden; }
.code-title { font-size: 0.7em; font-weight: 700; padding: 6px 12px; letter-spacing: 0.5px; }
.danger-title { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.safe-title { background: rgba(16, 185, 129, 0.15); color: #34d399; }
.code-pre {
  font-family: 'Fira Code', monospace;
  font-size: 0.78em;
  padding: 12px;
  background: rgba(0, 0, 0, 0.4);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  max-height: 180px;
  overflow-y: auto;
}
.danger-pre { border: 1px solid rgba(239, 68, 68, 0.25); border-top: none; color: #fca5a5; }
.safe-pre { border: 1px solid rgba(16, 185, 129, 0.25); border-top: none; color: #86efac; }

/* Attack Scenario */
.attack-scenario {
  background: rgba(245, 158, 11, 0.05);
  border: 1px solid rgba(245, 158, 11, 0.18);
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 16px;
}
.attack-title { font-size: 0.72em; font-weight: 700; color: #fbbf24; text-transform: uppercase; margin-bottom: 4px; }
.attack-text { font-size: 0.8em; color: #fef3c7; font-family: 'Fira Code', monospace; line-height: 1.4; }

/* Actions */
.card-actions { display: flex; gap: 10px; flex-wrap: wrap; }
.btn-action {
  border-radius: 8px;
  font-size: 0.78em; font-weight: 700;
  padding: 8px 16px;
  cursor: pointer; font-family: inherit;
  transition: all 0.15s;
  border: none;
}
.btn-copy-fix { background: linear-gradient(135deg, #0284c7, #0ea5e9); color: #fff; box-shadow: 0 2px 10px rgba(14, 165, 233, 0.3); display: inline-flex; align-items: center; gap: 6px; }
.btn-copy-fix:hover { opacity: 0.92; transform: translateY(-1px); }
.btn-inspect { background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-card); color: #e2e8f0; }
.btn-inspect:hover { background: rgba(255, 255, 255, 0.16); }
.btn-ignore { background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-card); color: var(--text-muted); }
.btn-ignore:hover { color: #fff; background: rgba(255, 255, 255, 0.1); }
.ai-guidance-card { width: 100%; margin-top: 10px; background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.25); border-radius: 8px; padding: 10px 14px; font-size: 0.76em; color: #bae6fd; line-height: 1.5; }
.ai-guidance-card strong { color: #38bdf8; }
.fix-concept-banner {
  margin-top: 14px;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.22);
  border-radius: 8px;
  padding: 8px 14px;
  font-size: 0.76em;
  color: #bae6fd;
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn-table-jump { background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; border-radius: 6px; padding: 5px 12px; font-size: 0.82em; cursor: pointer; white-space: nowrap; font-family: inherit; transition: all 0.15s; }
.btn-table-jump:hover { background: rgba(56, 189, 248, 0.25); transform: translateY(-1px); }

/* ── Table & Tracker Responsiveness ── */
.table-wrap {
  background: var(--bg-card);
  border: 1px solid var(--border-card);
  border-radius: 14px;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  width: 100%;
  position: relative;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
}
.data-table {
  width: 100%;
  min-width: 680px;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.82em;
}
.data-table th {
  background: rgba(255, 255, 255, 0.04);
  color: var(--text-muted);
  padding: 12px 16px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border-card);
  font-size: 0.8em;
  white-space: nowrap;
}
.data-table td {
  padding: 12px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  vertical-align: middle;
}
.data-table tr:hover td { background: rgba(255, 255, 255, 0.025); }
.row-vuln-type { font-weight: 700; color: #fff; font-size: 0.95em; }
.row-vuln-dev { font-size: 0.8em; color: var(--accent-cyan); margin-top: 1px; }
.row-file {
  font-family: 'Fira Code', monospace;
  color: #cbd5e1;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row-line { font-size: 0.8em; color: var(--text-muted); margin-top: 1px; }
.row-date { font-size: 0.8em; color: var(--text-muted); white-space: nowrap; }
.fixed-badge { color: #34d399; font-weight: 700; font-size: 0.82em; white-space: nowrap; }

/* Tracker Controls */
.tracker-header-wrap {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}
.tracker-title { font-size: 1.2em; font-weight: 800; color: #fff; letter-spacing: -0.2px; }
.tracker-subtitle { font-size: 0.78em; color: var(--text-secondary); margin-top: 2px; }
.tracker-count-badge {
  background: rgba(14, 165, 233, 0.12);
  border: 1px solid rgba(14, 165, 233, 0.3);
  color: #38bdf8;
  font-size: 0.75em;
  font-weight: 700;
  padding: 4px 12px;
  border-radius: 100px;
}
.tracker-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
  gap: 12px;
  flex-wrap: wrap;
}
.tracker-status-filters { display: flex; gap: 6px; flex-wrap: wrap; }
.btn-tfilter {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border-card);
  border-radius: 8px;
  color: var(--text-secondary);
  font-size: 0.75em;
  font-weight: 600;
  padding: 6px 12px;
  cursor: pointer;
  transition: all 0.15s;
  font-family: inherit;
}
.btn-tfilter:hover { background: rgba(255, 255, 255, 0.08); color: #fff; }
.btn-tfilter.active {
  background: rgba(14, 165, 233, 0.2);
  border-color: rgba(14, 165, 233, 0.45);
  color: #38bdf8;
}
.tracker-search-wrap {
  display: flex;
  align-items: center;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid var(--border-card);
  border-radius: 8px;
  padding: 5px 12px;
  min-width: 220px;
  flex: 1;
  max-width: 340px;
}
.tracker-search-input {
  background: transparent;
  border: none;
  color: #fff;
  font-size: 0.78em;
  font-family: inherit;
  outline: none;
  width: 100%;
  margin-left: 6px;
}
.tracker-search-input::placeholder { color: var(--text-muted); }
.table-scroll-hint {
  display: none;
  font-size: 0.7em;
  color: var(--text-muted);
  text-align: right;
  margin-bottom: 6px;
}
.btn-jump-tracker {
  background: rgba(14, 165, 233, 0.12);
  border: 1px solid rgba(14, 165, 233, 0.35);
  color: #38bdf8;
  border-radius: 8px;
  padding: 8px 16px;
  font-size: 0.8em;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.15s;
  font-family: inherit;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.btn-jump-tracker:hover {
  background: rgba(14, 165, 233, 0.25);
  color: #fff;
  transform: translateY(-1px);
}

/* ── Activity Stream ── */
.activity-stream { display: flex; flex-direction: column; gap: 10px; }
.activity-item {
  background: var(--bg-card);
  border: 1px solid var(--border-card);
  border-radius: 10px;
  padding: 12px 16px;
  display: flex; align-items: center; gap: 12px;
}
.act-dot { width: 8px; height: 8px; border-radius: 50%; background: #06b6d4; }
.act-content { flex: 1; }
.act-header { display: flex; align-items: center; gap: 10px; font-size: 0.78em; }
.act-user { font-weight: 700; color: #fff; }
.act-type { color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 1px 6px; border-radius: 4px; font-size: 0.9em; }
.act-time { margin-left: auto; color: var(--text-muted); font-size: 0.85em; }
.act-detail { font-size: 0.75em; color: var(--text-secondary); margin-top: 3px; font-family: 'Fira Code', monospace; }

.section-content { display: none; }
.section-content.active { display: block; animation: fadeIn 0.2s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

.empty-state {
  text-align: center; color: var(--text-muted);
  padding: 48px 20px;
  border: 1px dashed var(--border-card);
  border-radius: 14px;
  font-size: 0.85em;
}

/* ── Responsive Media Queries for VS Code Window ── */
@media (max-width: 860px) {
  .top-nav {
    height: auto;
    min-height: 52px;
    padding: 8px 14px;
    flex-wrap: wrap;
    gap: 8px;
  }
  .brand-name { font-size: 1em; }
  .app {
    flex-direction: column;
  }
  .sidebar {
    width: 100%;
    flex-direction: row;
    border-right: none;
    border-bottom: 1px solid var(--border-card);
    padding: 6px 10px;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
  }
  .nav-heading { display: none; }
  .nav-btn {
    width: auto;
    white-space: nowrap;
    padding: 7px 12px;
    margin: 0;
    flex-shrink: 0;
    font-size: 0.78em;
  }
  .content {
    padding: 14px 12px;
  }
  .table-scroll-hint {
    display: block;
  }
  .tracker-search-wrap {
    max-width: 100%;
    width: 100%;
  }
}

@media (max-width: 580px) {
  .user-profile-group {
    width: 100%;
    justify-content: space-between;
  }
  .progress-big-stat {
    width: 100%;
    justify-content: center;
  }
  .progress-metric-chips {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
</head>
<body>

<!-- ── Top App Bar ── -->
<header class="top-nav">
  <div class="brand-group">
    <div class="logo-icon">🛡️</div>
    <div>
      <div class="brand-name">Sentinel</div>
    </div>
    <span class="brand-tag">Developer</span>
  </div>

  <div class="db-status-pill" title="Connected to Neon Serverless PostgreSQL">
    <div class="db-dot"></div>
    <span>Neon DB: ${dbStatus.isOnline ? `Connected (${dbStatus.pingMs}ms)` : 'Offline Fallback'}</span>
  </div>

  <div class="user-profile-group">
    <div class="dev-profile-chip">
      ${session.githubAvatarUrl
        ? `<img src="${esc(session.githubAvatarUrl)}?s=48" class="dev-avatar-img">`
        : `<div class="dev-avatar-initial">${devInitial}</div>`}
      <div class="dev-meta">
        <div class="dev-username">@${esc(devId)}</div>
        <div class="dev-role-label">Authenticated via GitHub</div>
      </div>
    </div>
    <button class="btn-signout" onclick="doLogout()">Sign Out</button>
  </div>
</header>

<!-- ── Main App Layout ── -->
<div class="app">
  <!-- Sidebar Navigation -->
  <nav class="sidebar">
    <div class="nav-heading">Main Navigation</div>
    <button class="nav-btn active" id="nav-overview" onclick="showSection('overview')">
      <span>🏠</span> Security Overview
      ${findings.length > 0 ? `<span class="nav-badge">${findings.length}</span>` : ''}
    </button>
    <button class="nav-btn" id="nav-tracker" onclick="showSection('tracker')">
      <span>🗄️</span> DB Vulnerability Tracker
      <span class="nav-badge green">${dbRecords.length}</span>
    </button>
    <button class="nav-btn" id="nav-shifts" onclick="showSection('shifts')">
      <span>📅</span> My Shifts
      ${assignedShifts.length > 0 ? `<span class="nav-badge">${assignedShifts.length}</span>` : ''}
    </button>
    <button class="nav-btn" id="nav-activity" onclick="showSection('activity')">
      <span>📜</span> Activity Audit Log
    </button>
  </nav>

  <!-- Main Content Area -->
  <main class="content">

    <!-- ── TAB 1: OVERVIEW ── -->
    <div class="section-content active" id="section-overview">

      <!-- Precise Progress Bar Hero Card -->
      <div class="progress-hero-card">
        <div class="progress-hero-header">
          <div class="progress-title-wrap">
            <div>
              <div class="progress-title">🎯 Vulnerability Remediation &amp; Fix Progress</div>
              <div class="progress-subtitle">Real-time resolution metric for <strong>@${esc(devId)}</strong></div>
            </div>
          </div>

          <div class="progress-big-stat">
            <span class="fix-num">${totalIdentified === 0 ? '100%' : `${fixPercentage}%`}</span>
            <span class="fix-label">${totalIdentified === 0 ? 'Clean (0/0)' : `Fixed (${fixedCount}/${totalIdentified})`}</span>
          </div>
        </div>

        <!-- Precise Segmented Progress Bar -->
        <div class="progress-bar-container">
          <div class="progress-track">
            ${totalIdentified === 0 ? `
              <div class="progress-seg-fixed" style="width: 100%; background: linear-gradient(90deg, #10b981, #059669);" title="Clean: 100% (No vulnerabilities detected)"></div>
            ` : `
              <div class="progress-seg-fixed" style="width: ${fixPercentage}%" title="Fixed: ${fixPercentage}% (${fixedCount} resolved)"></div>
              <div class="progress-seg-open" style="width: ${openPercentage}%" title="Open: ${openPercentage}% (${openCount} active with red lines)"></div>
              <div class="progress-seg-ignored" style="width: ${totalIdentified > 0 ? Math.round((ignoredCount / totalIdentified) * 100) : 0}%" title="Ignored: ${ignoredCount}"></div>
            `}
          </div>
        </div>

        <div class="fix-concept-banner">
          <span>💡</span>
          <span><strong>Resolution Concept:</strong> A vulnerability is marked as <strong>FIXED</strong> only when you correct the code in your file so the red squiggly line disappears. (Currently: <strong>${openCount}</strong> active open, <strong>${fixedCount}</strong> fixed out of <strong>${totalIdentified}</strong> total).</span>
        </div>

        <!-- KPI Metric Chips -->
        <div class="progress-metric-chips">
          <div class="metric-chip">
            <span class="chip-num" style="color:#60a5fa">${totalIdentified}</span>
            <span class="chip-label">Total Identified</span>
          </div>
          <div class="metric-chip">
            <span class="chip-num" style="color:#34d399">${fixedCount}</span>
            <span class="chip-label">Remediated (${fixPercentage}%)</span>
          </div>
          <div class="metric-chip">
            <span class="chip-num" style="color:#f87171">${openCount}</span>
            <span class="chip-label">Active Open (${openPercentage}%)</span>
          </div>
          <div class="metric-chip">
            <span class="chip-num" style="color:#94a3b8">${ignoredCount}</span>
            <span class="chip-label">Ignored</span>
          </div>
          <div class="metric-chip">
            <span class="chip-num" style="color:${scColor}">${scoreRaw}/100</span>
            <span class="chip-label">Health Score</span>
          </div>
        </div>

        <div style="margin-top: 16px; display: flex; justify-content: flex-end;">
          <button class="btn-jump-tracker" onclick="showSection('tracker')">
            <span>🗄️</span> Open DB Vulnerability Tracker (${dbRecords.length} records) &rarr;
          </button>
        </div>
      </div>

      <!-- Vulnerability Header & Filter Toolbar -->
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:#fff;">Detected Vulnerabilities</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Current findings detected in your code with root-cause explanations and remediation</div>
        </div>
        <div class="filter-buttons">
          <button class="btn-filter active" onclick="filterCards('ALL')">All (${findings.length})</button>
          <button class="btn-filter" onclick="filterCards('CRITICAL')">Critical (${summary.criticalCount})</button>
          <button class="btn-filter" onclick="filterCards('HIGH')">High (${summary.highCount})</button>
        </div>
      </div>

      <!-- Vulnerability Cards List with Why & How to Fix -->
      <div class="vuln-cards-list">
        ${findingCards || `<div class="empty-state">🎉 All Clear! No vulnerabilities detected in currently open files.</div>`}
      </div>

    </div>

    <!-- ── TAB 2: DATABASE TRACKER ── -->
    <div class="section-content" id="section-tracker">
      <div class="tracker-header-wrap">
        <div>
          <h2 class="tracker-title">🗄️ PostgreSQL Vulnerability Tracker</h2>
          <div class="tracker-subtitle">Permanent real-time record history stored in Neon DB for @${esc(devId)}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <button class="btn-action" style="padding:6px 14px;font-size:0.8em;background:linear-gradient(135deg,#2563eb,#3b82f6);color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:700;display:flex;align-items:center;gap:6px;" onclick="scanWorkspace()">
            <span>⚡</span> Scan Workspace &amp; Sync DB
          </button>
          <div class="tracker-count-badge">
            <span>${dbRecords.length} Total Records</span>
          </div>
        </div>
      </div>

      <!-- Tracker Filter & Search Controls -->
      <div class="tracker-controls">
        <div class="tracker-status-filters">
          <button class="btn-tfilter active" onclick="filterTrackerStatus('ALL', this)">All (${dbRecords.length})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('OPEN', this)">⏳ Open (${openCount})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('FIXED', this)">✅ Fixed (${fixedCount})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('IGNORED', this)">⚪ Ignored (${ignoredCount})</button>
        </div>
        <div class="tracker-search-wrap">
          <span style="font-size:0.85em;">🔍</span>
          <input type="text" id="trackerSearch" class="tracker-search-input" placeholder="Search vulnerability, file, or line..." oninput="searchTracker(this.value)">
        </div>
      </div>

      <!-- Mobile / Scroll Hint -->
      <div class="table-scroll-hint">
        <span>↔ Scroll table horizontally to view all columns</span>
      </div>

      <!-- Responsive Table Container -->
      <div class="table-wrap">
        <table class="data-table" id="trackerTable">
          <thead>
            <tr>
              <th style="width: 85px;">Severity</th>
              <th style="min-width: 170px;">Vulnerability</th>
              <th style="min-width: 180px;">File &amp; Line</th>
              <th style="width: 120px;">Status</th>
              <th style="width: 130px;">Detected Date</th>
              <th style="width: 140px; text-align: right;">Action</th>
            </tr>
          </thead>
          <tbody>
            ${dbRecordRows || `<tr id="trackerEmptyRow"><td colspan="6" style="text-align:center;padding:36px;color:var(--text-muted);">No historical database records found.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>

    <!-- ── TAB 3: SHIFTS ── -->
    <div class="section-content" id="section-shifts">
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:#fff;">My Assigned Shifts</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Manage and execute your scheduled shifts</div>
        </div>
      </div>
      ${shiftCards}
    </div>

    <!-- ── TAB 4: AUDIT ACTIVITY ── -->
    <div class="section-content" id="section-activity">
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:#fff;">Activity Audit Log</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Audit trail of user actions &amp; vulnerability changes in PostgreSQL</div>
        </div>
      </div>
      <div class="activity-stream">
        ${activityItems}
      </div>
    </div>

  </main>
</div>

<script>
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;

function showSection(id) {
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.add('active');
  const nav = document.getElementById('nav-' + id);
  if (nav) nav.classList.add('active');
}

function toggleDetails(id) {
  const body = document.getElementById('body-' + id);
  const chev = document.getElementById('chev-' + id);
  if (body) body.classList.toggle('open');
  if (chev) chev.classList.toggle('open');
}

function jumpToCode(fileName, line) {
  vscode.postMessage({ command: 'JUMP_TO_CODE', fileName, line });
}

function copyAiFix(btn, code) {
  if (!navigator.clipboard) {
    const ta = document.createElement('textarea');
    ta.value = code;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  } else {
    navigator.clipboard.writeText(code);
  }
  const orig = btn.innerHTML;
  btn.innerHTML = '✅ Copied to Clipboard!';
  btn.style.background = 'linear-gradient(135deg, #059669, #10b981)';
  setTimeout(() => {
    btn.innerHTML = orig;
    btn.style.background = '';
  }, 2200);
}

function markFixed(findingId) {
  vscode.postMessage({ command: 'MARK_FIXED', findingId });
}

function ignoreFinding(findingId) {
  vscode.postMessage({ command: 'MARK_IGNORED', findingId });
}

function doLogout() {
  vscode.postMessage({ command: 'LOGOUT' });
}

function scanWorkspace() {
  vscode.postMessage({ command: 'SCAN_WORKSPACE' });
}

function filterCards(sev) {
  document.querySelectorAll('.filter-buttons .btn-filter').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.vuln-card').forEach(card => {
    if (sev === 'ALL') {
      card.style.display = 'block';
    } else {
      const isMatch = card.innerHTML.includes(sev);
      card.style.display = isMatch ? 'block' : 'none';
    }
  });
}

function startShift(shiftId) {
  vscode.postMessage({ command: 'START_SHIFT', shiftId });
}

function endShift(shiftId, sessionId) {
  vscode.postMessage({ command: 'END_SHIFT', shiftId, sessionId });
}

// ── Client-side filtering & search for DB Vulnerability Tracker ──
let currentTrackerStatus = 'ALL';
let currentTrackerSearch = '';

function filterTrackerStatus(status, btn) {
  currentTrackerStatus = status;
  document.querySelectorAll('.btn-tfilter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyTrackerFilters();
}

function searchTracker(val) {
  currentTrackerSearch = (val || '').toLowerCase().trim();
  applyTrackerFilters();
}

function applyTrackerFilters() {
  const rows = document.querySelectorAll('#trackerTable tbody tr.db-row');
  let visibleCount = 0;
  rows.forEach(row => {
    const status = row.getAttribute('data-status') || '';
    const searchText = (row.getAttribute('data-search') || row.innerText || '').toLowerCase();

    const matchStatus = (currentTrackerStatus === 'ALL' || status === currentTrackerStatus);
    const matchSearch = (!currentTrackerSearch || searchText.includes(currentTrackerSearch));

    if (matchStatus && matchSearch) {
      row.style.display = '';
      visibleCount++;
    } else {
      row.style.display = 'none';
    }
  });

  let emptyRow = document.getElementById('trackerEmptyRow');
  if (visibleCount === 0) {
    if (!emptyRow) {
      emptyRow = document.createElement('tr');
      emptyRow.id = 'trackerEmptyRow';
      emptyRow.innerHTML = '<td colspan="6" style="text-align:center;padding:36px;color:var(--text-muted);">No matching vulnerability records found.</td>';
      const tbody = document.querySelector('#trackerTable tbody');
      if (tbody) tbody.appendChild(emptyRow);
    } else {
      emptyRow.style.display = '';
    }
  } else if (emptyRow) {
    emptyRow.style.display = 'none';
  }
}
</script>
</body>
</html>`;
}
