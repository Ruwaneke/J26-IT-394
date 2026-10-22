/**
 * Sentinel — Modern Developer Security Dashboard
 *
 * Exclusively for developers authenticated via GitHub.
 *
 * Navigation categories:
 *   Shift     — live shift session tracker, shift KPIs, assigned shifts, history
 *   Detect    — sub-tabs: Warnings (live findings), Vulnerability Types (detection catalogue
 *               grouped by OWASP category with fixed-vs-identified progress)
 *   Behaviour — sub-tabs: Overview (pattern, responsiveness, repeated mistakes, activity log),
 *               Fixed Rate, History (Neon DB tracker)
 *   Feedback  — personalised recommendations + helpful/not-helpful ratings
 *   Analytics — 14-day trend, severity & OWASP distribution, hot files, Component 2 API status
 *
 * Features:
 *   1. Precise Vulnerability Resolution Progress Bar with exact percentage
 *      metrics (Identified vs Fixed findings count).
 *   2. In-depth Vulnerability Explanation cards showing:
 *      - Why is this vulnerable? (Root cause & security risk)
 *      - How to fix? (Step-by-step remediation guide)
 *      - Code Comparison (Vulnerable code vs Secure replacement)
 *      - Concrete attack scenarios
 *   3. Actions: [Copy AI Fix], [Jump to Line], [Ignore].
 *   4. Permanent Database Vulnerability History from Neon PostgreSQL.
 *   5. Real-time Neon PostgreSQL status indicator & audit activity.
 *   6. State-of-the-art dark glassmorphic UI aesthetics.
 */

import { SecurityFinding, VulnerabilityType, VULNERABILITY_TO_OWASP, OWASP_TOP_10_2021 } from '../analyzer/types.js';
import { VULNERABILITY_METADATA } from '../diagnostics/vulnerabilityMetadata.js';
import { AiFixProposal, AiFixState, AI_FIX_CONTEXT_LINES } from '../ai/aiFixEngine.js';
import { AuthSession } from '../auth/authManager.js';
import { Shift, ShiftSession } from '../data/projectStore.js';
import { DbVulnerabilityRecord, VulnerabilityStats, UserActivityLog } from '../data/neonDatabaseService.js';
import { generateContextualExplanation, ContextualExplanation } from '../diagnostics/contextualExplainer.js';
import { buildHeaderBar } from './loginView.js';
import { icon, ICON_CSS } from './icons.js';
import { DeveloperInsights } from '../analytics/developerInsights.js';
import { NOTIFY_CSS, notificationBellHtml, notifyScript } from './notificationsUi.js';
import { THEME_CSS, THEME_SCRIPT, themeHtmlAttrs, themeSwitchHtml } from './theme.js';

export interface ApiServerStatus {
  running: boolean;
  url: string;
  error: string | null;
}

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

// ── Detect › AI Fixing (also used by extension.ts to patch a card in place) ───

export interface AiFixDashboardData {
  /** A Gemini API key is stored in SecretStorage or present in the environment */
  configured: boolean;
  model: string;
  states: Record<string, AiFixState>;
  /** Most recent applied proposals, newest first */
  history: AiFixProposal[];
}

export function buildAiFixBodyHtml(findingId: string, state: AiFixState | undefined): string {
  const id = esc(findingId);
  if (!state) {
    return `<div class="aifix-actions"><button class="btn-action btn-copy-fix" onclick="aiFix('${id}')">${icon('sparkles')} Generate AI Fix</button></div>`;
  }
  if (state.status === 'pending') {
    return `<div class="aifix-pending"><span class="aifix-spinner"></span> Gemini is generating a fix and Sentinel is verifying it…</div>`;
  }
  if (state.status === 'error') {
    return `<div class="aifix-error">${icon('alert-circle')} ${esc(state.error)}</div>
      <div class="aifix-actions"><button class="btn-action btn-inspect" onclick="aiFix('${id}')">${icon('refresh')} Retry</button></div>`;
  }
  const p = state.proposal;
  const applied = state.status === 'applied';
  return `
    <div class="aifix-verdict ${p.verified ? 'ok' : 'warn'}">
      ${icon(p.verified ? 'shield-check' : 'alert-triangle')}
      <div><strong>${p.verified ? 'Verified by Sentinel rules' : 'Not verified — review carefully'}</strong>
      <div class="aifix-verdict-note">${esc(p.verifyNote)}${p.attempts > 1 ? ` (after ${p.attempts} attempts)` : ''}</div></div>
    </div>
    <div class="expl-section fix-section" style="margin:10px 0">
      <div class="expl-label fix-label">${icon('sparkles')} What the AI changed</div>
      <div class="expl-text">${esc(p.explanation)}</div>
      ${p.changes.length ? `<ul class="aifix-changes">${p.changes.map(c => `<li>${esc(c)}</li>`).join('')}</ul>` : ''}
    </div>
    <div class="code-compare-grid">
      <div class="code-box vulnerable-box">
        <div class="code-title danger-title">${icon('code')} Current code (lines ${p.startLine}–${p.endLine})</div>
        <pre class="code-pre danger-pre">${esc(p.originalCode)}</pre>
      </div>
      <div class="code-box fixed-box">
        <div class="code-title safe-title">${icon('check-circle')} AI fix · ${esc(p.model)}</div>
        <pre class="code-pre safe-pre">${esc(p.fixedCode)}</pre>
      </div>
    </div>
    <div class="aifix-actions">
      ${applied
        ? `<span class="fixed-badge">${icon('check-circle')} Applied — waiting for the real-time re-scan</span>`
        : `<button class="btn-action btn-start-shift" onclick="aiFixApply('${id}')">${icon('check')} Apply Fix</button>
           <button class="btn-action btn-inspect" onclick="aiFixDiff('${id}')">${icon('eye')} Open Diff</button>
           <button class="btn-action btn-inspect" onclick="aiFixCopy('${id}')">${icon('copy')} Copy</button>
           <button class="btn-action btn-inspect" onclick="aiFix('${id}')">${icon('refresh')} Regenerate</button>
           <button class="btn-action btn-ignore" onclick="aiFixDiscard('${id}')">${icon('x')} Discard</button>`}
    </div>`;
}

export function buildAiFixSummaryHtml(findings: SecurityFinding[], aiFix: AiFixDashboardData): string {
  const states = findings.map(f => aiFix.states[f.id]).filter(Boolean) as AiFixState[];
  const ready = states.filter(s => s.status === 'ready');
  const verified = ready.filter(s => s.status === 'ready' && s.proposal.verified).length;
  const pending = states.filter(s => s.status === 'pending').length;
  return `<div class="progress-metric-chips">
    <div class="metric-chip"><span class="chip-num" style="color:var(--t-red)">${findings.length}</span><span class="chip-label">Identified now</span></div>
    <div class="metric-chip"><span class="chip-num">${pending}</span><span class="chip-label">Generating</span></div>
    <div class="metric-chip"><span class="chip-num" style="color:var(--t-blue)">${ready.length}</span><span class="chip-label">Fixes ready</span></div>
    <div class="metric-chip"><span class="chip-num" style="color:var(--t-green)">${verified}</span><span class="chip-label">Verified fixes</span></div>
    <div class="metric-chip"><span class="chip-num">${aiFix.history.length}</span><span class="chip-label">Applied this session</span></div>
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
  stats?: VulnerabilityStats,
  dbRecords: DbVulnerabilityRecord[] = [],
  dbStatus: { isOnline: boolean; pingMs: number; error: string | null } = { isOnline: true, pingMs: 42, error: null },
  activities: UserActivityLog[] = [],
  insights?: DeveloperInsights,
  apiStatus: ApiServerStatus = { running: false, url: '', error: null },
  aiFix: AiFixDashboardData = { configured: false, model: '', states: {}, history: [] },
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
    <div class="vuln-card" id="card-${f.id}" data-severity="${f.severity}">
      <div class="vuln-card-header" onclick="toggleDetails('${f.id}')">
        <div class="header-left">
          <span class="sev-pill" style="background:${sevCol}22;color:${sevCol};border:1px solid ${sevCol}55">
            ${icon(f.severity === 'CRITICAL' ? 'alert-octagon' : f.severity === 'HIGH' ? 'alert-triangle' : f.severity === 'MEDIUM' ? 'alert-circle' : 'info')} ${f.severity}
          </span>
          <span class="status-pill status-open">${icon('clock')} OPEN</span>
          <div>
            <div class="vuln-title">${esc(f.type.replace(/_/g, ' '))}</div>
            <div class="vuln-file">
              <span class="file-icon">${icon('file')}</span> <code>${esc(f.fileName.split('/').pop() ?? f.fileName)}</code> : Line ${f.lineNumber}
            </div>
          </div>
        </div>
        <div class="header-right">
          <span class="conf-badge">${confPct}% Confidence</span>
          <span class="rule-badge">${esc(f.detectedByRule)}</span>
          <button class="btn-jump" onclick="event.stopPropagation(); jumpToCode('${esc(f.fileName)}', ${f.lineNumber})" title="Jump to line in editor">${icon('eye')} Jump</button>
          <span class="chevron" id="chev-${f.id}">▼</span>
        </div>
      </div>

      <div class="vuln-body open" id="body-${f.id}">
        <!-- Why it's vulnerable -->
        <div class="expl-section why-section">
          <div class="expl-label why-label">
            <span class="expl-icon">${icon('help-circle')}</span> Why is this vulnerable?
          </div>
          <div class="expl-text">${esc(ctx.whyDangerous)}</div>
        </div>

        <!-- How to fix -->
        <div class="expl-section fix-section">
          <div class="expl-label fix-label">
            <span class="expl-icon">${icon('shield-check')}</span> How to fix
          </div>
          <div class="expl-text">${esc(ctx.fixExplanation)}</div>
        </div>

        <!-- Code Comparison -->
        <div class="code-compare-grid">
          <div class="code-box vulnerable-box">
            <div class="code-title danger-title">${icon('code')} Detected Vulnerable Code (Line ${f.lineNumber})</div>
            <pre class="code-pre danger-pre">${esc(ctx.vulnerableCode || f.codeSnippet)}</pre>
          </div>
          <div class="code-box fixed-box">
            <div class="code-title safe-title">${icon('check-circle')} Recommended Secure Replacement</div>
            <pre class="code-pre safe-pre">${esc(ctx.fixedCode)}</pre>
          </div>
        </div>

        <!-- Attack Scenario -->
        <div class="attack-scenario">
          <div class="attack-title">${icon('zap')} Attack Scenario</div>
          <div class="attack-text">${esc(ctx.attackScenario)}</div>
        </div>

        <!-- Actions & AI Suggestion -->
        <div class="card-actions">
          <button class="btn-action btn-copy-fix" onclick="copyAiFix(this, ${JSON.stringify(ctx.fixedCode)})" title="Copy AI secure code suggestion to clipboard">
            ${icon('copy')} Copy AI Fix Suggestion
          </button>
          <button class="btn-action btn-inspect" onclick="jumpToCode('${esc(f.fileName)}', ${f.lineNumber})" title="Jump to line in editor to edit code">
            ${icon('eye')} Jump to Line in Editor
          </button>
          <button class="btn-action btn-ignore" onclick="ignoreFinding('${esc(f.id)}')">
            ${icon('eye-off')} Ignore Warning
          </button>
          <div class="rate-group" id="rate-${esc(f.id)}">
            <span class="rate-label">Was this explanation helpful?</span>
            <button class="btn-rate" onclick="rateFeedback('${esc(f.id)}', '${esc(f.type)}', true)">${icon('thumbs-up')} Yes</button>
            <button class="btn-rate" onclick="rateFeedback('${esc(f.id)}', '${esc(f.type)}', false)">${icon('thumbs-down')} No</button>
          </div>
          <div class="ai-guidance-card">
            ${icon('sparkles')} <strong>AI Suggestion:</strong> Sentinel guides you to fix vulnerabilities manually without relying on auto-fix buttons. Edit this line in your editor using the secure guidance above. Sentinel's real-time engine monitors keystrokes and automatically marks this vulnerability as <strong>FIXED</strong> once resolved!
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
    const statusIcon = icon(isFixed ? 'check-circle' : isIgnored ? 'ban' : 'clock');
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
            ? `<span class="fixed-badge">${icon('check-circle')} Remediated</span>`
            : `<button class="btn-table-jump" onclick="jumpToCode('${esc(r.fileName)}', ${r.lineNumber})" title="Jump to this line in your editor">${icon('eye')} Jump to Line</button>`}
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
    ? `<div class="empty-state">${icon('calendar')} No shifts assigned yet. Ask your supervisor to assign you to a shift.</div>`
    : assignedShifts.map(sh => `
      <div class="shift-card">
        <div class="shift-card-header">
          <div>
            <div class="shift-card-name">${icon('calendar')} ${esc(sh.name)}</div>
            <div class="shift-card-project">${icon('folder')} ${esc(sh.projectName)}</div>
          </div>
          <span class="status-pill status-${sh.status}">${sh.status.toUpperCase()}</span>
        </div>
        <div class="shift-card-meta">
          <span>${icon('clock')} ${fmtDate(sh.scheduledStart)} ${icon('arrow-right')} ${fmtDate(sh.scheduledEnd)}</span>
        </div>
        ${sh.description ? `<div class="shift-card-desc">${esc(sh.description)}</div>` : ''}
        <div class="shift-card-actions">
          ${activeSession?.shiftId === sh.id
            ? `<button class="btn-action btn-end-shift" onclick="endShift('${esc(sh.id)}', '${esc(activeSession.id)}')">${icon('stop')} End Shift</button>`
            : `<button class="btn-action btn-start-shift" onclick="startShift('${esc(sh.id)}')">${icon('play')} Start Shift</button>`}
        </div>
      </div>
    `).join('');

  // ── 6. Insights (shared with the Component 2 API) ──────────────────────────
  const ins: DeveloperInsights = insights ?? {
    developerId: devId, generatedAt: new Date().toISOString(),
    totals: { identified: totalIdentified, fixed: fixedCount, open: openCount, ignored: ignoredCount, liveWarnings: openCount, fixRate: fixPercentage, openRate: openPercentage },
    severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    liveSeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    owasp: [], fixRateByType: [], trend: [], topFiles: [],
    behaviour: { pattern: 'NEW', patternLabel: 'Building baseline — not enough data yet', responsivenessRate: 0, ignoreRate: 0, meanTimeToFixMinutes: null, medianTimeToFixMinutes: null, repeatedMistakes: [], suppressedTypes: [], actionCounts: {} },
    feedback: [], feedbackRatings: [],
    shift: { sessionsCompleted: 0, totalShiftMinutes: 0, findingsPerHour: 0, averageSecurityScore: null, latestTrend: null },
  };
  const prettyType = (t: string) => esc((t || '').replace(/_/g, ' '));
  const fmtMinutes = (m: number | null) => m === null ? '—' : m < 60 ? `${Math.round(m)}m` : `${Math.floor(m / 60)}h ${Math.round(m % 60)}m`;
  const barRow = (label: string, value: number, max: number, valueText: string, color: string, tip: string) => `
    <div class="bar-row" title="${esc(tip)}">
      <div class="bar-label">${label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${max > 0 && value > 0 ? Math.max(2, (value / max) * 100) : 0}%;background:${color}"></div></div>
      <div class="bar-value">${valueText}</div>
    </div>`;
  const emptyBox = (msg: string) => `<div class="empty-state small">${msg}</div>`;

  // ── 7. Detect › Fixed Rate per vulnerability type ───────────────────────────
  const typeRateRows = ins.fixRateByType.map(t =>
    barRow(prettyType(t.vulnerabilityType), t.fixRate, 100,
      `${t.fixRate}% <span class="muted">(${t.fixed}/${t.detected})</span>`,
      scoreColor(t.fixRate),
      `${t.vulnerabilityType}: ${t.fixed} fixed, ${t.open} open, ${t.ignored} ignored of ${t.detected} detected`)
  ).join('') || emptyBox('No vulnerability history yet — fix rates appear once findings are recorded.');

  const sevKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
  const sevFixRows = sevKeys.map(k => {
    const all = dbRecords.filter(r => r.severity === k);
    const fx = all.filter(r => r.status === 'FIXED').length;
    const rate = all.length ? Math.round((fx / all.length) * 1000) / 10 : 0;
    return barRow(`<span class="sev-dot" style="background:${sevColor(k)}"></span>${k}`, rate, 100,
      `${rate}% <span class="muted">(${fx}/${all.length})</span>`, scoreColor(rate), `${k}: ${fx} of ${all.length} fixed`);
  }).join('');

  // ── 7b. Detect › Vulnerability Types (detection catalogue by OWASP category) ─
  // open = live editor findings only (re-rendered on every analysis event), so stale
  // OPEN rows in the DB never count as "identified"; fixed/ignored = Neon DB history.
  type TypeCounts = { fixed: number; open: number; ignored: number; identified: number };
  const pct1 = (n: number, d: number) => d > 0 ? Math.round((n / d) * 1000) / 10 : 0;
  const liveByType = new Map<string, number>();
  for (const f of findings) { liveByType.set(f.type, (liveByType.get(f.type) ?? 0) + 1); }
  const countsFor = (t: string): TypeCounts => {
    const recs = dbRecords.filter(r => r.vulnerabilityType === t);
    const fixed = recs.filter(r => r.status === 'FIXED').length;
    const ignored = recs.filter(r => r.status === 'IGNORED').length;
    const open = liveByType.get(t) ?? 0;
    return { fixed, open, ignored, identified: open + fixed + ignored };
  };
  const sumCounts = (list: TypeCounts[]): TypeCounts => list.reduce(
    (a, c) => ({ fixed: a.fixed + c.fixed, open: a.open + c.open, ignored: a.ignored + c.ignored, identified: a.identified + c.identified }),
    { fixed: 0, open: 0, ignored: 0, identified: 0 });
  const typeTitle = (t: string) =>
    esc((VULNERABILITY_METADATA[t as VulnerabilityType]?.title ?? t.replace(/_/g, ' ')).replace(/\s*\(A\d{2}\)$/, ''));
  const segBar = (c: TypeCounts, slim = true) => `
    <div class="progress-track${slim ? ' slim' : ''}" title="${c.identified ? `Fixed ${c.fixed} · Open ${c.open} · Ignored ${c.ignored} of ${c.identified} identified` : 'Not identified in your code yet'}">
      ${c.identified ? `
        <div class="progress-seg-fixed" style="width:${pct1(c.fixed, c.identified)}%"></div>
        <div class="progress-seg-open" style="width:${pct1(c.open, c.identified)}%"></div>
        <div class="progress-seg-ignored" style="width:${pct1(c.ignored, c.identified)}%"></div>` : ''}
    </div>`;

  const knownTypes = Object.values(VulnerabilityType) as string[];
  const catGroups = Object.entries(OWASP_TOP_10_2021).map(([key, cat]) => ({
    id: cat.id, name: cat.name, url: cat.url,
    types: knownTypes.filter(t => VULNERABILITY_TO_OWASP[t as VulnerabilityType] === key),
  }));
  // Legacy / unmapped types that still appear in the history
  const otherTypes = [...new Set([...dbRecords.map(r => r.vulnerabilityType), ...findings.map(f => f.type as string)])]
    .filter(t => t && !knownTypes.includes(t));
  if (otherTypes.length) { catGroups.push({ id: 'Other', name: 'Other / legacy types', url: '', types: otherTypes }); }

  const catData = catGroups.map(g => {
    const types = g.types.map(t => ({ type: t, c: countsFor(t) }));
    return { ...g, typeRows: types, c: sumCounts(types.map(x => x.c)) };
  });
  const catalogTotals = sumCounts(catData.map(g => g.c));
  const identifiedTypeCount = catData.reduce((a, g) => a + g.typeRows.filter(x => x.c.identified > 0).length, 0);
  const liveTypeCount = liveByType.size;
  const catsWithFindings = catData.filter(g => g.c.identified > 0);
  const catsFullyFixed = catsWithFindings.filter(g => g.c.fixed === g.c.identified).length;

  const typeCatalogCards = catData.map(g => {
    const rate = pct1(g.c.fixed, g.c.identified);
    const rows = g.typeRows.map(({ type, c }) => {
      const r = pct1(c.fixed, c.identified);
      const desc = VULNERABILITY_METADATA[type as VulnerabilityType]?.description ?? '';
      return `
        <div class="type-row${c.identified ? '' : ' is-clean'}" data-identified="${c.identified > 0}" title="${esc(desc)}">
          <div class="type-row-head">
            <span class="type-name">${typeTitle(type)}</span>
            ${c.open ? `<span class="type-live">${c.open} open</span>` : ''}
            <span class="type-count">${c.identified
              ? `<strong style="color:${scoreColor(r)}">${r}%</strong> <span class="muted">(${c.fixed}/${c.identified} fixed)</span>`
              : `<span class="muted">${icon('shield-check')} Not identified</span>`}</span>
          </div>
          ${segBar(c)}
        </div>`;
    }).join('');
    return `
      <div class="cat-card" data-identified="${g.c.identified > 0}">
        <div class="cat-head">
          <div>
            <div class="cat-id">${g.url ? `<a href="#" onclick="openUrl('${esc(g.url)}');return false;" title="Open OWASP reference">${esc(g.id)} ${icon('external-link')}</a>` : esc(g.id)}</div>
            <div class="cat-name">${esc(g.name)}</div>
            <div class="cat-meta">${g.types.length} detectable type${g.types.length === 1 ? '' : 's'} · ${g.c.identified} identified · ${g.c.open} open</div>
          </div>
          <div class="cat-stat">
            <span class="cat-rate" style="color:${g.c.identified ? scoreColor(rate) : 'var(--text-3)'}">${g.c.identified ? `${rate}%` : '—'}</span>
            <span class="chip-label">${g.c.identified ? `Fixed ${g.c.fixed}/${g.c.identified}` : 'Clean'}</span>
          </div>
        </div>
        ${segBar(g.c, false)}
        <div class="type-list">${rows}</div>
      </div>`;
  }).join('');

  // ── 8. Shift (live session tracker) ─────────────────────────────────────────
  const fixedIds = new Set(dbRecords.filter(r => r.status === 'FIXED').map(r => r.findingId));
  const activeShift = activeSession ? assignedShifts.find(s => s.id === activeSession.shiftId) : undefined;
  const sessFindings = activeSession?.findings ?? [];
  const sessFixed = sessFindings.filter(f => fixedIds.has(f.id)).length;
  const sessSev = sevKeys.map(k => `<span class="mini-sev"><span class="sev-dot" style="background:${sevColor(k)}"></span>${k} ${sessFindings.filter(f => f.severity === k).length}</span>`).join('');
  const shiftHero = activeSession ? `
    <div class="shift-live-card">
      <div class="shift-live-head">
        <div>
          <div class="live-pill"><span class="live-dot"></span> SHIFT IN PROGRESS</div>
          <div class="shift-live-name">${esc(activeSession.shiftName)}</div>
          <div class="shift-live-proj">${icon('folder')} ${esc(activeSession.projectName)} · started ${fmtDate(activeSession.startedAt)}</div>
        </div>
        <div class="shift-timer-wrap">
          <div class="shift-timer" id="shiftTimer" data-start="${esc(activeSession.startedAt)}">00:00:00</div>
          <div class="chip-label">Elapsed</div>
        </div>
      </div>
      <div class="progress-metric-chips">
        <div class="metric-chip"><span class="chip-num">${sessFindings.length}</span><span class="chip-label">Findings this shift</span></div>
        <div class="metric-chip"><span class="chip-num">${sessFixed}</span><span class="chip-label">Fixed this shift</span></div>
        <div class="metric-chip"><span class="chip-num">${sessFindings.length ? Math.round((sessFixed / sessFindings.length) * 100) : 0}%</span><span class="chip-label">Shift fix rate</span></div>
        <div class="metric-chip"><span class="chip-num">${openCount}</span><span class="chip-label">Open warnings now</span></div>
      </div>
      <div class="mini-sev-row">${sessSev}</div>
      <div class="shift-card-actions">
        <button class="btn-action btn-end-shift" onclick="endShift('${esc(activeSession.shiftId)}', '${esc(activeSession.id)}')">${icon('stop')} End Shift &amp; Generate Summary</button>
      </div>
    </div>` : `
    <div class="shift-idle">
      <div style="font-size:1.6em;color:var(--text-muted)">${icon('clock')}</div>
      <div><strong>No shift in progress.</strong> Start an assigned shift below — Sentinel will attribute every warning you introduce and fix to that shift.</div>
    </div>`;

  const pastSessions = recentSessions.filter(s => s.endedAt)
    .sort((a, b) => (b.endedAt ?? '').localeCompare(a.endedAt ?? '')).slice(0, 10);
  const pastSessionRows = pastSessions.map(s => {
    const mins = (new Date(s.endedAt!).getTime() - new Date(s.startedAt).getTime()) / 60000;
    const score = s.summary?.securityScore;
    const trendIcon = s.summary?.trend === 'improving' ? `${icon('trending-up')} Improving` : s.summary?.trend === 'declining' ? `${icon('trending-down')} Declining` : s.summary ? `${icon('minus')} Stable` : '—';
    return `<tr>
      <td><div class="row-vuln-type">${esc(s.shiftName)}</div><div class="row-line">${esc(s.projectName)}</div></td>
      <td class="row-date">${fmtDate(s.startedAt)}</td>
      <td>${fmtMinutes(Number.isFinite(mins) ? mins : null)}</td>
      <td>${s.findings.length}</td>
      <td>${score === undefined ? '—' : `<span style="color:${scoreColor(score)};font-weight:700">${score}</span>/100`}</td>
      <td>${trendIcon}</td>
    </tr>`;
  }).join('');

  // ── 9. Behaviour ────────────────────────────────────────────────────────────
  const b = ins.behaviour;
  const patternMeta: Record<string, { icon: string; color: string }> = {
    PROACTIVE_FIXER: { icon: icon('award'), color: '#10b981' },
    STEADY:          { icon: icon('compass'), color: '#38bdf8' },
    DISMISSIVE:      { icon: icon('eye-off'), color: '#f59e0b' },
    AT_RISK:         { icon: icon('alert-triangle'), color: '#ef4444' },
    NEW:             { icon: icon('sprout'), color: '#94a3b8' },
  };
  const pm = patternMeta[b.pattern] ?? patternMeta.NEW;
  const maxRepeat = Math.max(1, ...b.repeatedMistakes.map(r => r.occurrences));
  const repeatRows = b.repeatedMistakes.map(r =>
    barRow(prettyType(r.vulnerabilityType), r.occurrences, maxRepeat,
      `${r.occurrences}× <span class="muted">(${r.fixed} fixed)</span>`, '#3b82f6',
      `${r.vulnerabilityType}: introduced ${r.occurrences} times, fixed ${r.fixed}`)
  ).join('') || emptyBox(`${icon('check-circle')} No repeated mistakes — no vulnerability type has appeared 3+ times.`);
  const actionRows = Object.entries(b.actionCounts).sort((x, y) => y[1] - x[1]).slice(0, 8)
    .map(([k, v]) => `<div class="kv-row"><span>${prettyType(k)}</span><strong>${v}</strong></div>`).join('')
    || `<div class="muted" style="font-size:0.8em">No actions logged yet.</div>`;

  // ── 10. Feedback ────────────────────────────────────────────────────────────
  const prioColor = (p: string) => p === 'HIGH' ? '#ef4444' : p === 'MEDIUM' ? '#f59e0b' : '#38bdf8';
  const feedbackCards = ins.feedback.map(fb => `
    <div class="fb-card">
      <div class="fb-head">
        <span class="sev-pill" style="background:${prioColor(fb.priority)}22;color:${prioColor(fb.priority)};border:1px solid ${prioColor(fb.priority)}55">${fb.priority} PRIORITY</span>
        <div class="vuln-title">${esc(fb.title)}</div>
      </div>
      <div class="fb-reason">${icon('info')} ${esc(fb.reason)}</div>
      <div class="expl-section fix-section" style="margin:10px 0">
        <div class="expl-label fix-label">${icon('shield-check')} Recommendation</div>
        <div class="expl-text">${esc(fb.recommendation)}</div>
      </div>
      ${fb.secureExample ? `<pre class="code-pre safe-pre" style="border-top:1px solid rgba(16,185,129,0.25);border-radius:8px">${esc(fb.secureExample)}</pre>` : ''}
      ${fb.references.length ? `<div class="fb-refs">${fb.references.map(u => `<a href="#" onclick="openUrl('${esc(u)}');return false;">${icon('external-link')} ${esc(u.replace(/^https?:\/\//, '').slice(0, 60))}</a>`).join('')}</div>` : ''}
      <div class="rate-group" id="rate-fb-${esc(fb.vulnerabilityType)}">
        <span class="rate-label">Was this recommendation helpful?</span>
        <button class="btn-rate" onclick="rateFeedback('fb-${esc(fb.vulnerabilityType)}', '${esc(fb.vulnerabilityType)}', true)">${icon('thumbs-up')} Yes</button>
        <button class="btn-rate" onclick="rateFeedback('fb-${esc(fb.vulnerabilityType)}', '${esc(fb.vulnerabilityType)}', false)">${icon('thumbs-down')} No</button>
      </div>
    </div>`).join('') || `<div class="empty-state">${icon('target')} No personalised feedback yet. Recommendations appear when you repeat a vulnerability type or leave warnings unfixed.</div>`;
  const helpfulCount = ins.feedbackRatings.filter(r => r.helpful).length;
  const ratingTotal = ins.feedbackRatings.length;
  const recentComments = ins.feedbackRatings.filter(r => r.comment).slice(0, 5).map(r => `
    <div class="activity-item"><div class="act-dot" style="background:${r.helpful ? '#10b981' : '#f59e0b'}"></div>
      <div class="act-content"><div class="act-header"><span class="act-user">${icon(r.helpful ? 'thumbs-up' : 'thumbs-down')} ${prettyType(r.vulnerabilityType ?? 'General')}</span><span class="act-time">${fmtDate(r.ratedAt)}</span></div>
      <div class="act-detail" style="font-family:inherit">${esc(r.comment)}</div></div></div>`).join('');

  // ── 11. Analytics ───────────────────────────────────────────────────────────
  // Two-series palette validated (dataviz validator, dark surface): detected #d97706, fixed #3b82f6.
  const C_DET = '#d97706';
  const C_FIX = '#3b82f6';
  const trendMax = Math.max(1, ...ins.trend.map(t => Math.max(t.detected, t.fixed)));
  const W = 700, H = 220, padL = 32, padB = 26, padT = 10;
  const plotW = W - padL - 8, plotH = H - padB - padT;
  const groupW = ins.trend.length ? plotW / ins.trend.length : plotW;
  const barW = Math.max(4, Math.min(14, (groupW - 10) / 2));
  const yOf = (v: number) => padT + plotH - (v / trendMax) * plotH;
  // Bar with 4px rounded top, square baseline end
  const barPath = (x: number, v: number) => {
    if (v <= 0) { return ''; }
    const y = yOf(v), base = padT + plotH, r = Math.min(4, barW / 2, base - y);
    return `M${x},${base} V${y + r} Q${x},${y} ${x + r},${y} H${x + barW - r} Q${x + barW},${y} ${x + barW},${y + r} V${base} Z`;
  };
  const gridVals = [0, Math.round(trendMax / 2), trendMax].filter((v, i, a) => a.indexOf(v) === i);
  const trendSvg = `
    <svg class="trend-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Detected versus fixed vulnerabilities per day, last ${ins.trend.length} days">
      ${gridVals.map(v => `<line x1="${padL}" x2="${W - 8}" y1="${yOf(v)}" y2="${yOf(v)}" class="grid-line"/><text x="${padL - 6}" y="${yOf(v) + 3}" class="axis-text" text-anchor="end">${v}</text>`).join('')}
      ${ins.trend.map((t, i) => {
        const gx = padL + i * groupW;
        const x1 = gx + (groupW - (barW * 2 + 2)) / 2;
        const label = new Date(t.date + 'T00:00:00').toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
        return `<g class="trend-group">
          <rect x="${gx}" y="${padT}" width="${groupW}" height="${plotH}" class="hit"><title>${label} — Detected: ${t.detected} · Fixed: ${t.fixed}</title></rect>
          <path d="${barPath(x1, t.detected)}" fill="${C_DET}" pointer-events="none"/>
          <path d="${barPath(x1 + barW + 2, t.fixed)}" fill="${C_FIX}" pointer-events="none"/>
          ${i % 2 === 0 ? `<text x="${gx + groupW / 2}" y="${H - 8}" class="axis-text" text-anchor="middle">${label}</text>` : ''}
        </g>`;
      }).join('')}
    </svg>`;
  const trendTableRows = ins.trend.map(t => `<tr><td>${t.date}</td><td>${t.detected}</td><td>${t.fixed}</td></tr>`).join('');
  const trendDetected = ins.trend.reduce((a, t) => a + t.detected, 0);
  const trendFixed = ins.trend.reduce((a, t) => a + t.fixed, 0);

  const sevMax = Math.max(1, ...sevKeys.map(k => ins.severity[k]));
  const sevDistRows = sevKeys.map(k =>
    barRow(`<span class="sev-dot" style="background:${sevColor(k)}"></span>${k}`, ins.severity[k], sevMax,
      `${ins.severity[k]}`, sevColor(k), `${k}: ${ins.severity[k]} findings recorded`)).join('');
  const owaspMax = Math.max(1, ...ins.owasp.map(o => o.count));
  const owaspRows = ins.owasp.map(o =>
    barRow(`<span class="owasp-id">${esc(o.id.split(':')[0])}</span>${esc(o.name)}`, o.count, owaspMax, `${o.count}`, '#3b82f6', `${o.id} ${o.name}: ${o.count}`)
  ).join('') || emptyBox('No OWASP data yet.');
  const fileRows = ins.topFiles.map(f => `<tr><td class="row-file" title="${esc(f.fileName)}">${esc(f.fileName)}</td><td>${f.total}</td><td>${f.open}</td></tr>`).join('');

  const apiEndpoints = ['health', 'findings/live', 'events?since=', 'vulnerabilities?status=OPEN', 'stats',
    `developers/${encodeURIComponent(devId)}/insights`, `developers/${encodeURIComponent(devId)}/behaviour`,
    `developers/${encodeURIComponent(devId)}/feedback`, `developers/${encodeURIComponent(devId)}/shifts`];

  const headerBar = buildHeaderBar(session, cspSource);

  return `<!DOCTYPE html>
<html lang="en" ${themeHtmlAttrs()}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data:; script-src 'unsafe-inline';">
<title>Sentinel — Developer Dashboard</title>
<style>
${THEME_CSS}
${NOTIFY_CSS}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Fira+Code:wght@400;500;600&display=swap');

:root {
  --bg-primary: var(--bg-app);
  --bg-card: rgba(var(--card-rgb),  0.75);
  --border-card: rgba(var(--ink),  0.08);
  --border-focus: rgba(56, 189, 248, 0.35);
  --text-primary: var(--text-1);
  --text-secondary: var(--text-2);
  --text-muted: var(--text-3);
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
  background: rgba(var(--nav-rgb),  0.85);
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
.brand-logo { width: 36px; height: 36px; object-fit: contain; flex-shrink: 0; padding: 4px; background: #f1f5f9; border-radius: 9px; box-shadow: 0 0 16px rgba(14, 165, 233, 0.35); }
.brand-name { font-size: 1.15em; font-weight: 800; letter-spacing: -0.3px; color: var(--text-strong); }
.brand-tag { font-size: 0.65em; font-weight: 700; background: rgba(56, 189, 248, 0.15); color: var(--t-cyan); padding: 2px 8px; border-radius: 100px; text-transform: uppercase; }

.db-status-pill {
  display: flex; align-items: center; gap: 7px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.25);
  border-radius: 100px;
  padding: 4px 12px;
  font-size: 0.72em;
  font-weight: 600;
  color: var(--t-green);
}
.db-dot { width: 7px; height: 7px; border-radius: 50%; background: #10b981; box-shadow: 0 0 8px #10b981; animation: pulse 2s infinite; }

.user-profile-group { display: flex; align-items: center; gap: 10px; }
.dev-profile-chip {
  display: flex; align-items: center; gap: 8px;
  background: rgba(var(--ink),  0.04);
  border: 1px solid var(--border-card);
  border-radius: 10px;
  padding: 5px 12px;
}
.dev-avatar-img { width: 26px; height: 26px; border-radius: 50%; object-fit: cover; }
.dev-avatar-initial { width: 26px; height: 26px; border-radius: 50%; background: #3b82f6; display: flex; align-items: center; justify-content: center; font-size: 0.75em; font-weight: 700; color: #fff; }
.dev-meta { display: flex; flex-direction: column; text-align: left; }
.dev-username { font-size: 0.78em; font-weight: 700; color: var(--text-strong); line-height: 1.2; }
.dev-role-label { font-size: 0.62em; color: var(--accent-cyan); font-weight: 600; }

.btn-signout {
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.3);
  color: var(--t-red);
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
  background: rgba(var(--sidebar-rgb),  0.95);
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
.nav-btn:hover { background: rgba(var(--ink),  0.05); color: var(--text-strong); }
.nav-btn.active { background: rgba(14, 165, 233, 0.12); color: var(--t-cyan); font-weight: 600; }
.nav-badge { margin-left: auto; background: rgba(239, 68, 68, 0.2); color: var(--t-red); border-radius: 100px; padding: 1px 7px; font-size: 0.7em; font-weight: 700; }
.nav-badge.green { background: rgba(16, 185, 129, 0.2); color: var(--t-green); }

/* ── Precise Progress Bar Card ── */
.progress-hero-card {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border-card);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, calc(0.35 * var(--shade-k)));
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
.progress-title { font-size: 1.15em; font-weight: 800; color: var(--text-strong); letter-spacing: -0.2px; }
.progress-subtitle { font-size: 0.78em; color: var(--text-secondary); margin-top: 2px; }

.progress-big-stat {
  display: flex; align-items: baseline; gap: 6px;
  background: rgba(16, 185, 129, 0.1);
  border: 1px solid rgba(16, 185, 129, 0.25);
  border-radius: 12px;
  padding: 8px 16px;
}
.fix-num { font-size: 1.7em; font-weight: 800; color: var(--t-green); line-height: 1; }
.fix-label { font-size: 0.75em; font-weight: 700; color: var(--t-green); text-transform: uppercase; }

/* Progress Track */
.progress-bar-container { margin: 16px 0 12px; }
.progress-track {
  width: 100%; height: 16px;
  background: rgba(var(--ink),  0.05);
  border-radius: 100px;
  overflow: hidden;
  display: flex;
  position: relative;
  box-shadow: inset 0 2px 4px rgba(0, 0, 0, calc(0.3 * var(--shade-k)));
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
  background: var(--text-3);
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
}

.progress-metric-chips {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin-top: 16px;
}
.metric-chip {
  background: rgba(var(--ink),  0.02);
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
  background: rgba(var(--ink),  0.04);
  border: 1px solid var(--border-card);
  border-radius: 8px;
  color: var(--text-secondary);
  font-size: 0.75em; font-weight: 600;
  padding: 6px 12px;
  cursor: pointer; transition: all 0.15s; font-family: inherit;
}
.btn-filter:hover { background: rgba(var(--ink),  0.08); color: var(--text-strong); }
.btn-filter.active { background: rgba(14, 165, 233, 0.2); border-color: rgba(14, 165, 233, 0.4); color: var(--t-cyan); }

/* ── Vulnerability Cards ── */
.vuln-cards-list { display: flex; flex-direction: column; gap: 14px; }
.vuln-card {
  background: var(--bg-card);
  backdrop-filter: blur(16px);
  border: 1px solid var(--border-card);
  border-radius: 14px;
  overflow: hidden;
  transition: all 0.2s;
  box-shadow: 0 4px 18px rgba(0, 0, 0, calc(0.25 * var(--shade-k)));
}
.vuln-card:hover { border-color: rgba(56, 189, 248, 0.25); transform: translateY(-1px); }

.vuln-card-header {
  padding: 16px 20px;
  display: flex; align-items: center; justify-content: space-between;
  cursor: pointer; user-select: none;
  background: rgba(var(--ink),  0.02);
  gap: 12px; flex-wrap: wrap;
}
.header-left { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.sev-pill { font-size: 0.7em; font-weight: 800; border-radius: 100px; padding: 3px 10px; letter-spacing: 0.5px; }
.sev-pill-sm { font-size: 0.7em; font-weight: 800; }
.status-pill { font-size: 0.67em; font-weight: 700; border-radius: 100px; padding: 3px 9px; }
.status-open { background: rgba(245, 158, 11, 0.15); color: var(--t-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
.status-fixed { background: rgba(16, 185, 129, 0.15); color: var(--t-green); border: 1px solid rgba(16, 185, 129, 0.3); }
.status-ignored { background: rgba(100, 116, 139, 0.15); color: var(--text-2); border: 1px solid rgba(100, 116, 139, 0.3); }

.vuln-title { font-size: 0.95em; font-weight: 700; color: var(--text-strong); }
.vuln-file { font-size: 0.72em; color: var(--text-secondary); margin-top: 2px; }
.vuln-file code { background: rgba(var(--ink),  0.05); padding: 2px 6px; border-radius: 4px; font-family: 'Fira Code', monospace; }

.header-right { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.conf-badge { font-size: 0.7em; font-weight: 600; color: var(--text-muted); background: rgba(var(--ink),  0.04); padding: 3px 8px; border-radius: 6px; }
.rule-badge { font-size: 0.68em; font-weight: 600; color: var(--t-cyan); background: rgba(56, 189, 248, 0.1); padding: 3px 8px; border-radius: 6px; }
.btn-jump { background: rgba(var(--ink),  0.05); border: 1px solid var(--border-card); color: var(--text-1); border-radius: 6px; padding: 3px 8px; font-size: 0.7em; cursor: pointer; }
.btn-jump:hover { background: rgba(var(--ink),  0.1); }
.chevron { font-size: 0.7em; color: var(--text-muted); transition: transform 0.2s; }
.chevron.open { transform: rotate(180deg); }

.vuln-body { padding: 20px; border-top: 1px solid var(--border-card); background: rgba(var(--inset-rgb),  0.7); }

/* Explanation Sections */
.expl-section { border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
.why-section { background: rgba(239, 68, 68, 0.05); border: 1px solid rgba(239, 68, 68, 0.15); }
.fix-section { background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); }
.expl-label { font-size: 0.75em; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
.why-label { color: var(--t-red); }
.fix-label { color: var(--t-green); }
.expl-text { font-size: 0.85em; color: var(--text-1); line-height: 1.5; }

/* Code Comparison */
.code-compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
.code-box { border-radius: 8px; overflow: hidden; }
.code-title { font-size: 0.7em; font-weight: 700; padding: 6px 12px; letter-spacing: 0.5px; }
.danger-title { background: rgba(239, 68, 68, 0.15); color: var(--t-red); }
.safe-title { background: rgba(16, 185, 129, 0.15); color: var(--t-green); }
.code-pre {
  font-family: 'Fira Code', monospace;
  font-size: 0.78em;
  padding: 12px;
  background: rgba(0, 0, 0, calc(0.4 * var(--shade-k)));
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  max-height: 180px;
  overflow-y: auto;
}
.danger-pre { border: 1px solid rgba(239, 68, 68, 0.25); border-top: none; color: var(--code-danger); }
.safe-pre { border: 1px solid rgba(16, 185, 129, 0.25); border-top: none; color: var(--code-safe); }

/* Attack Scenario */
.attack-scenario {
  background: rgba(245, 158, 11, 0.05);
  border: 1px solid rgba(245, 158, 11, 0.18);
  border-radius: 8px;
  padding: 12px 14px;
  margin-bottom: 16px;
}
.attack-title { font-size: 0.72em; font-weight: 700; color: var(--t-amber); text-transform: uppercase; margin-bottom: 4px; }
.attack-text { font-size: 0.8em; color: var(--t-amber-ink); font-family: 'Fira Code', monospace; line-height: 1.4; }

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
.btn-inspect { background: rgba(var(--ink),  0.08); border: 1px solid var(--border-card); color: var(--text-1); }
.btn-inspect:hover { background: rgba(var(--ink),  0.16); }
.btn-ignore { background: rgba(var(--ink),  0.05); border: 1px solid var(--border-card); color: var(--text-muted); }
.btn-ignore:hover { color: var(--text-strong); background: rgba(var(--ink),  0.1); }
.ai-guidance-card { width: 100%; margin-top: 10px; background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.25); border-radius: 8px; padding: 10px 14px; font-size: 0.76em; color: var(--t-info); line-height: 1.5; }
.ai-guidance-card strong { color: var(--t-cyan); }
.fix-concept-banner {
  margin-top: 14px;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.22);
  border-radius: 8px;
  padding: 8px 14px;
  font-size: 0.76em;
  color: var(--t-info);
  display: flex;
  align-items: center;
  gap: 8px;
}
.btn-table-jump { background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); color: var(--t-cyan); border-radius: 6px; padding: 5px 12px; font-size: 0.82em; cursor: pointer; white-space: nowrap; font-family: inherit; transition: all 0.15s; }
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
  box-shadow: 0 4px 20px rgba(0, 0, 0, calc(0.25 * var(--shade-k)));
}
.data-table {
  width: 100%;
  min-width: 680px;
  border-collapse: collapse;
  text-align: left;
  font-size: 0.82em;
}
.data-table th {
  background: rgba(var(--ink),  0.04);
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
  border-bottom: 1px solid rgba(var(--ink),  0.04);
  vertical-align: middle;
}
.data-table tr:hover td { background: rgba(var(--ink),  0.025); }
.row-vuln-type { font-weight: 700; color: var(--text-strong); font-size: 0.95em; }
.row-vuln-dev { font-size: 0.8em; color: var(--accent-cyan); margin-top: 1px; }
.row-file {
  font-family: 'Fira Code', monospace;
  color: var(--text-1);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row-line { font-size: 0.8em; color: var(--text-muted); margin-top: 1px; }
.row-date { font-size: 0.8em; color: var(--text-muted); white-space: nowrap; }
.fixed-badge { color: var(--t-green); font-weight: 700; font-size: 0.82em; white-space: nowrap; }

/* Tracker Controls */
.tracker-header-wrap {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}
.tracker-title { font-size: 1.2em; font-weight: 800; color: var(--text-strong); letter-spacing: -0.2px; }
.tracker-subtitle { font-size: 0.78em; color: var(--text-secondary); margin-top: 2px; }
.tracker-count-badge {
  background: rgba(14, 165, 233, 0.12);
  border: 1px solid rgba(14, 165, 233, 0.3);
  color: var(--t-cyan);
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
  background: rgba(var(--ink),  0.04);
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
.btn-tfilter:hover { background: rgba(var(--ink),  0.08); color: var(--text-strong); }
.btn-tfilter.active {
  background: rgba(14, 165, 233, 0.2);
  border-color: rgba(14, 165, 233, 0.45);
  color: var(--t-cyan);
}
.tracker-search-wrap {
  display: flex;
  align-items: center;
  background: rgba(var(--ink),  0.04);
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
  color: var(--text-strong);
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
  color: var(--t-cyan);
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
  color: var(--text-strong);
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
.act-user { font-weight: 700; color: var(--text-strong); }
.act-type { color: var(--t-cyan); background: rgba(56, 189, 248, 0.1); padding: 1px 6px; border-radius: 4px; font-size: 0.9em; }
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

/* ── Nav: categories & Detect sub-items ── */
.nav-dropdown { position: relative; }
.nav-chevron { display: inline-flex; margin-left: auto; color: var(--text-muted); transition: transform 0.2s ease; }
.nav-badge ~ .nav-chevron { margin-left: 2px; }
.nav-dropdown.open .nav-chevron { transform: rotate(180deg); }
.nav-sub-group {
  display: flex; flex-direction: column; margin: 0 10px 0 30px; border-left: 1px solid var(--border-card);
  max-height: 0; overflow: hidden; opacity: 0; transition: max-height 0.22s ease, opacity 0.18s ease, margin 0.22s ease;
}
.nav-dropdown.open .nav-sub-group { max-height: 200px; opacity: 1; margin-bottom: 4px; }
.nav-sub {
  display: flex; align-items: center; gap: 6px;
  background: none; border: none; font-family: inherit; cursor: pointer; text-align: left;
  color: var(--text-muted); font-size: 0.76em; font-weight: 500;
  padding: 6px 12px; border-radius: 0 7px 7px 0; transition: all 0.15s;
}
.nav-sub:hover { color: var(--text-strong); background: rgba(var(--ink),  0.04); }
.nav-sub.active { color: var(--t-cyan); font-weight: 600; background: rgba(14, 165, 233, 0.08); box-shadow: inset 2px 0 0 var(--t-cyan); }
.nav-sub-count { margin-left: auto; font-size: 0.9em; color: var(--text-muted); }
.nav-badge.live { background: rgba(239, 68, 68, 0.2); color: var(--t-red); animation: pulse 2s infinite; }
.sidebar-foot { margin-top: auto; padding: 12px 18px 4px; font-size: 0.68em; color: var(--text-muted); display: flex; align-items: center; gap: 7px; }
.api-dot { width: 7px; height: 7px; border-radius: 50%; }
.api-dot.on { background: #10b981; box-shadow: 0 0 6px #10b981; }
.api-dot.off { background: var(--text-3); }

/* ── Sub-tab bar (Detect) ── */
.subtab-bar { display: none; gap: 6px; margin-bottom: 18px; border-bottom: 1px solid var(--border-card); flex-wrap: wrap; }
.subtab-bar.visible { display: flex; }
.subtab {
  background: none; border: none; font-family: inherit; cursor: pointer;
  color: var(--text-secondary); font-size: 0.8em; font-weight: 600;
  padding: 9px 14px; border-bottom: 2px solid transparent; margin-bottom: -1px; transition: all 0.15s;
}
.subtab:hover { color: var(--text-strong); }
.subtab.active { color: var(--t-cyan); border-bottom-color: var(--t-cyan); }

/* ── Page & panels ── */
.page-head { margin-bottom: 18px; }
.page-title { font-size: 1.2em; font-weight: 800; color: var(--text-strong); letter-spacing: -0.2px; }
.page-sub { font-size: 0.78em; color: var(--text-secondary); margin-top: 3px; }
.block-title { font-size: 0.85em; font-weight: 700; color: var(--text-1); margin-bottom: 12px; }
.panel-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 14px; padding: 18px; margin-bottom: 18px; }
.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; }
.two-col .panel-card { margin-bottom: 0; }
.two-col + .two-col, .panel-card + .two-col { margin-top: 18px; }
.muted { color: var(--text-muted); }
.empty-state.small { padding: 20px; }
.kv-row { display: flex; justify-content: space-between; gap: 12px; font-size: 0.8em; padding: 7px 0; border-bottom: 1px solid rgba(var(--ink),  0.04); color: var(--text-secondary); }
.kv-row strong { color: var(--text-strong); }

/* ── Bar lists (thin bars, rounded data end, value in text ink) ── */
.bar-list { display: flex; flex-direction: column; gap: 9px; }
.bar-row { display: grid; grid-template-columns: minmax(110px, 38%) 1fr auto; align-items: center; gap: 10px; font-size: 0.78em; padding: 2px 0; }
.bar-row:hover .bar-track { background: rgba(var(--ink),  0.09); }
.bar-label { color: var(--text-1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
.bar-track { height: 8px; background: rgba(var(--ink),  0.05); border-radius: 0 4px 4px 0; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 0 4px 4px 0; transition: width 0.6s ease; }
.bar-value { color: var(--text-1); font-weight: 600; white-space: nowrap; text-align: right; min-width: 60px; }
.sev-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.owasp-id { font-family: 'Fira Code', monospace; color: var(--text-muted); font-size: 0.9em; }

/* ── Warnings summary tiles ── */
.warn-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 20px; }
.warn-sev-tile { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 10px; padding: 10px 14px; display: flex; flex-direction: column; }
.warn-sev-tile .chip-label { display: flex; align-items: center; gap: 6px; }

/* ── Feedback rating ── */
.rate-group { width: 100%; display: flex; align-items: center; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.rate-label { font-size: 0.74em; color: var(--text-muted); }
.btn-rate { background: rgba(var(--ink),  0.05); border: 1px solid var(--border-card); color: var(--text-1); border-radius: 6px; padding: 4px 10px; font-size: 0.72em; cursor: pointer; font-family: inherit; }
.btn-rate:hover { background: rgba(var(--ink),  0.12); }
.rate-done { font-size: 0.74em; color: var(--t-green); font-weight: 600; }
.fb-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 14px; padding: 18px; }
.fb-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
.fb-reason { font-size: 0.8em; color: var(--text-secondary); }
.fb-refs { display: flex; flex-direction: column; gap: 4px; margin-top: 10px; }
.fb-refs a { font-size: 0.74em; color: var(--t-cyan); text-decoration: none; }
.fb-refs a:hover { text-decoration: underline; }
.fb-textarea { width: 100%; min-height: 80px; background: rgba(0, 0, 0, calc(0.3 * var(--shade-k))); border: 1px solid var(--border-card); border-radius: 8px; color: var(--text-strong); font-family: inherit; font-size: 0.82em; padding: 10px; resize: vertical; }

/* ── Detect › Vulnerability Types ── */
.progress-track.slim { height: 6px; box-shadow: none; }
.progress-track.slim .progress-seg-fixed { box-shadow: none; }
.progress-hero-card .legend { margin-top: 2px; }
.types-filter { display: flex; gap: 6px; flex-wrap: wrap; }
.cat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(340px, 100%), 1fr)); gap: 16px; }
.cat-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 14px; padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
.cat-card[data-identified="false"] { opacity: 0.85; }
.cat-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.cat-id { font-family: 'Fira Code', monospace; font-size: 0.7em; color: var(--text-muted); }
.cat-id a { color: var(--t-cyan); text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
.cat-id a:hover { text-decoration: underline; }
.cat-name { font-size: 0.95em; font-weight: 700; color: var(--text-strong); margin-top: 2px; }
.cat-meta { font-size: 0.72em; color: var(--text-secondary); margin-top: 3px; }
.cat-stat { display: flex; flex-direction: column; align-items: flex-end; text-align: right; flex-shrink: 0; }
.cat-rate { font-size: 1.4em; font-weight: 800; line-height: 1.1; }
.type-list { display: flex; flex-direction: column; gap: 10px; border-top: 1px solid var(--border-card); padding-top: 12px; }
.type-row { display: flex; flex-direction: column; gap: 5px; }
.type-row-head { display: flex; align-items: center; gap: 8px; font-size: 0.78em; }
.type-name { color: var(--text-1); font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.type-row.is-clean .type-name { color: var(--text-secondary); font-weight: 500; }
.type-live { font-size: 0.85em; font-weight: 700; color: var(--t-red); background: rgba(239, 68, 68, 0.12); border-radius: 100px; padding: 1px 7px; white-space: nowrap; }
.type-count { margin-left: auto; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px; }

/* ── Detect › AI Fixing ── */
.aifix-key { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; font-size: 0.76em; }
.aifix-key code { font-family: 'Fira Code', monospace; }
.aifix-key-ok { color: var(--t-green); display: inline-flex; align-items: center; gap: 6px; font-weight: 600; }
.aifix-key-missing { color: var(--t-amber, #f59e0b); display: inline-flex; align-items: center; gap: 6px; font-weight: 600; }
.aifix-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 14px; padding: 16px 18px; display: flex; flex-direction: column; gap: 12px; }
.aifix-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.aifix-snippet { border-radius: 8px; max-height: 120px; overflow: auto; margin: 0; }
.aifix-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
.aifix-pending { display: flex; align-items: center; gap: 10px; font-size: 0.8em; color: var(--text-secondary); padding: 6px 0; }
.aifix-spinner { width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(var(--ink), 0.15); border-top-color: var(--t-cyan); animation: aifix-spin 0.8s linear infinite; }
@keyframes aifix-spin { to { transform: rotate(360deg); } }
.aifix-error { font-size: 0.8em; color: var(--t-red); display: flex; align-items: center; gap: 6px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px; padding: 9px 12px; }
.aifix-verdict { display: flex; gap: 10px; align-items: flex-start; font-size: 0.8em; border-radius: 10px; padding: 10px 12px; border: 1px solid; }
.aifix-verdict.ok { color: var(--t-green); background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.3); }
.aifix-verdict.warn { color: #f59e0b; background: rgba(245, 158, 11, 0.08); border-color: rgba(245, 158, 11, 0.3); }
.aifix-verdict-note { color: var(--text-secondary); margin-top: 2px; }
.aifix-changes { margin: 8px 0 0 18px; font-size: 0.8em; color: var(--text-1); line-height: 1.6; }
@media (prefers-reduced-motion: reduce) { .aifix-spinner { animation: none; } }

/* ── Behaviour ── */
.pattern-card { display: flex; align-items: center; gap: 16px; background: var(--bg-card); border: 1px solid; border-radius: 14px; padding: 18px 20px; margin-bottom: 16px; }
.pattern-icon { font-size: 2em; }
.pattern-name { font-size: 1.15em; font-weight: 800; color: var(--text-strong); margin-top: 2px; }
.pattern-desc { font-size: 0.8em; color: var(--text-secondary); margin-top: 2px; }
.suppressed-note { margin-top: 14px; font-size: 0.75em; color: var(--text-secondary); line-height: 1.8; }

/* ── Shift ── */
.shift-live-card { background: linear-gradient(135deg, rgba(16, 185, 129, 0.08), rgba(14, 165, 233, 0.06)); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 16px; padding: 20px; margin-bottom: 18px; }
.shift-live-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap; }
.live-pill { display: inline-flex; align-items: center; gap: 6px; font-size: 0.66em; font-weight: 800; letter-spacing: 0.8px; color: var(--t-green); background: rgba(16, 185, 129, 0.12); border-radius: 100px; padding: 3px 10px; }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: #10b981; animation: pulse 1.5s infinite; }
.shift-live-name { font-size: 1.2em; font-weight: 800; color: var(--text-strong); margin-top: 8px; }
.shift-live-proj { font-size: 0.76em; color: var(--text-secondary); margin-top: 3px; }
.shift-timer-wrap { text-align: right; }
.shift-timer { font-family: 'Fira Code', monospace; font-size: 1.8em; font-weight: 600; color: var(--text-strong); }
.mini-sev-row { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 12px; font-size: 0.72em; color: var(--text-secondary); }
.mini-sev { display: inline-flex; align-items: center; gap: 5px; }
.shift-idle { display: flex; gap: 14px; align-items: center; background: var(--bg-card); border: 1px dashed var(--border-card); border-radius: 14px; padding: 18px 20px; margin-bottom: 18px; font-size: 0.82em; color: var(--text-secondary); }
.shift-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px; }
.shift-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 12px; padding: 16px; }
.shift-card-header { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
.shift-card-name { font-weight: 700; color: var(--text-strong); font-size: 0.9em; }
.shift-card-project, .shift-card-meta, .shift-card-desc { font-size: 0.74em; color: var(--text-secondary); margin-top: 4px; }
.shift-card-actions { margin-top: 12px; display: flex; gap: 8px; }
.btn-start-shift { background: linear-gradient(135deg, #059669, #10b981); color: #fff; }
.btn-end-shift { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.35); color: var(--t-red); }
.status-scheduled { background: rgba(56, 189, 248, 0.12); color: var(--t-cyan); border: 1px solid rgba(56, 189, 248, 0.3); }
.status-active { background: rgba(16, 185, 129, 0.15); color: var(--t-green); border: 1px solid rgba(16, 185, 129, 0.3); }
.status-completed { background: rgba(100, 116, 139, 0.15); color: var(--text-2); border: 1px solid rgba(100, 116, 139, 0.3); }

/* ── Analytics chart ── */
.chart-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
.legend { display: flex; gap: 14px; font-size: 0.74em; color: var(--text-1); }
.legend > span { display: inline-flex; align-items: center; gap: 6px; }
.legend-swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.trend-svg { width: 100%; height: auto; display: block; }
.trend-svg .grid-line { stroke: rgba(var(--ink),  0.06); stroke-width: 1; }
.trend-svg .axis-text { fill: var(--text-3); font-size: 10px; font-family: 'Inter', sans-serif; }
.trend-svg .hit { fill: transparent; }
.trend-svg .trend-group:hover .hit { fill: rgba(var(--ink),  0.04); }
.table-toggle { margin-top: 10px; font-size: 0.78em; color: var(--text-secondary); }
.table-toggle summary { cursor: pointer; }
.table-toggle table { margin-top: 8px; }
.api-url { font-family: 'Fira Code', monospace; font-size: 0.95em; color: var(--t-cyan); word-break: break-all; }
.endpoint-list { display: flex; flex-direction: column; gap: 4px; margin-top: 10px; }
.endpoint-list code { font-family: 'Fira Code', monospace; font-size: 0.72em; color: var(--text-1); background: rgba(0, 0, 0, calc(0.3 * var(--shade-k))); padding: 4px 8px; border-radius: 5px; word-break: break-all; }

@media (max-width: 860px) {
  .sidebar { overflow: visible; position: relative; z-index: 50; }
  .nav-dropdown { flex-shrink: 0; }
  .nav-sub-group {
    position: absolute; top: calc(100% + 6px); left: 0; min-width: 190px; margin: 0;
    background: var(--bg-surface); border: 1px solid var(--border-card); border-radius: 10px; padding: 6px;
    box-shadow: 0 12px 30px rgba(0, 0, 0, calc(0.5 * var(--shade-k)));
  }
  .nav-dropdown.open .nav-sub-group { margin: 0; }
  .nav-sub { border-radius: 7px; padding: 8px 10px; }
  .nav-sub.active { box-shadow: none; }
  .sidebar-foot { display: none; }
  .bar-row { grid-template-columns: minmax(90px, 35%) 1fr auto; }
}
/* icons */
${ICON_CSS}
.nav-btn .ico { font-size: 1.15em; }
.page-title .ico, .tracker-title .ico, .progress-title .ico { color: var(--t-cyan); margin-right: 4px; }
.block-title .ico { color: var(--text-secondary); margin-right: 3px; }
.logo-icon .ico { color: #fff; font-size: 0.95em; }
.pattern-icon { color: inherit; display: flex; }
.btn-action, .btn-rate, .btn-filter, .btn-tfilter, .subtab, .nav-sub, .btn-jump, .btn-table-jump, .sev-pill, .status-pill, .fixed-badge { display: inline-flex; align-items: center; gap: 6px; }
.empty-state .ico { margin-right: 4px; }
</style>
</head>
<body>

<!-- ── Top App Bar ── -->
<header class="top-nav">
  <div class="brand-group">
    ${logoUri ? `<img src="${esc(logoUri)}" alt="Sentinel" class="brand-logo">` : `<div class="logo-icon">${icon('shield-check')}</div>`}
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
    ${notificationBellHtml()}
    ${themeSwitchHtml()}
    <button class="btn-signout" onclick="doLogout()">Sign Out</button>
  </div>
</header>

<!-- ── Main App Layout ── -->
<div class="app">
  <!-- Sidebar Navigation -->
  <nav class="sidebar">
    <div class="nav-heading">Developer Workspace</div>
    <button class="nav-btn" id="nav-shift" onclick="showSection('shift')">
      ${icon('clock')} Shift
      ${activeSession ? `<span class="nav-badge live">LIVE</span>` : assignedShifts.length > 0 ? `<span class="nav-badge green">${assignedShifts.length}</span>` : ''}
    </button>
    <div class="nav-dropdown open" id="dd-detect">
    <button class="nav-btn active" id="nav-detect" onclick="toggleDropdown('detect', event)" aria-haspopup="true" aria-expanded="true" aria-controls="nav-detect-sub">
      ${icon('shield')} Detect
      ${findings.length > 0 ? `<span class="nav-badge">${findings.length}</span>` : ''}
      <span class="nav-chevron">${icon('chevron-down')}</span>
    </button>
    <div class="nav-sub-group" id="nav-detect-sub" role="menu">
      <button class="nav-sub active" id="nav-detect-warnings" onclick="showSection('detect-warnings')">${icon('alert-triangle')} Warnings <span class="nav-sub-count">${findings.length}</span></button>
      <button class="nav-sub" id="nav-detect-types" onclick="showSection('detect-types')" title="Vulnerability types with live warnings right now">${icon('layers')} Vulnerability Types <span class="nav-sub-count">${liveTypeCount}</span></button>
      <button class="nav-sub" id="nav-detect-aifix" onclick="showSection('detect-aifix')">${icon('sparkles')} AI Fixing <span class="nav-sub-count">${findings.length}</span></button>
    </div>
    </div>
    <div class="nav-dropdown open" id="dd-behaviour">
    <button class="nav-btn" id="nav-behaviour" onclick="toggleDropdown('behaviour', event)" aria-haspopup="true" aria-expanded="true" aria-controls="nav-behaviour-sub">
      ${icon('activity')} Behaviour
      <span class="nav-chevron">${icon('chevron-down')}</span>
    </button>
    <div class="nav-sub-group" id="nav-behaviour-sub" role="menu">
      <button class="nav-sub" id="nav-behaviour-overview" onclick="showSection('behaviour-overview')">${icon('activity')} Overview</button>
      <button class="nav-sub" id="nav-behaviour-fixrate" onclick="showSection('behaviour-fixrate')">${icon('check-circle')} Fixed Rate <span class="nav-sub-count">${ins.totals.fixRate}%</span></button>
      <button class="nav-sub" id="nav-behaviour-history" onclick="showSection('behaviour-history')">${icon('database')} History <span class="nav-sub-count">${dbRecords.length}</span></button>
    </div>
    </div>
    <button class="nav-btn" id="nav-feedback" onclick="showSection('feedback')">
      ${icon('message')} Feedback
      ${ins.feedback.filter(f => f.priority === 'HIGH').length > 0 ? `<span class="nav-badge">${ins.feedback.filter(f => f.priority === 'HIGH').length}</span>` : ''}
    </button>
    <button class="nav-btn" id="nav-analytics" onclick="showSection('analytics')">
      ${icon('bar-chart')} Analytics
    </button>
    <div class="sidebar-foot" title="${apiStatus.running ? 'Component 2 can pull data from this endpoint' : esc(apiStatus.error ?? 'API server disabled')}">
      <span class="api-dot ${apiStatus.running ? 'on' : 'off'}"></span>
      <span>C2 API ${apiStatus.running ? 'online' : 'offline'}</span>
    </div>
  </nav>

  <!-- Main Content Area -->
  <main class="content">

    <!-- ══ SHIFT ══ -->
    <div class="section-content" id="section-shift">
      <div class="page-head">
        <h2 class="page-title">${icon('clock')} Shift</h2>
        <div class="page-sub">Track the security of your work shift by shift — every warning introduced and fixed during a shift is attributed to it.</div>
      </div>
      ${shiftHero}
      <div class="progress-metric-chips" style="margin-bottom:22px">
        <div class="metric-chip"><span class="chip-num">${ins.shift.sessionsCompleted}</span><span class="chip-label">Shifts completed</span></div>
        <div class="metric-chip"><span class="chip-num">${fmtMinutes(ins.shift.totalShiftMinutes)}</span><span class="chip-label">Total shift time</span></div>
        <div class="metric-chip"><span class="chip-num">${ins.shift.findingsPerHour}</span><span class="chip-label">Findings / hour</span></div>
        <div class="metric-chip"><span class="chip-num" ${ins.shift.averageSecurityScore !== null ? `style="color:${scoreColor(ins.shift.averageSecurityScore)}"` : ''}>${ins.shift.averageSecurityScore ?? '—'}</span><span class="chip-label">Avg shift score</span></div>
        <div class="metric-chip"><span class="chip-num">${ins.shift.latestTrend === 'improving' ? icon('trending-up') : ins.shift.latestTrend === 'declining' ? icon('trending-down') : ins.shift.latestTrend === 'stable' ? icon('minus') : '—'}</span><span class="chip-label">Latest trend${ins.shift.latestTrend ? ` (${ins.shift.latestTrend})` : ''}</span></div>
      </div>
      <h3 class="block-title">${icon('calendar')} Assigned Shifts</h3>
      <div class="shift-grid">${shiftCards}</div>
      <h3 class="block-title" style="margin-top:22px">${icon('layers')} Recent Shift Sessions</h3>
      ${pastSessionRows ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Shift</th><th>Started</th><th>Duration</th><th>Findings</th><th>Score</th><th>Trend</th></tr></thead><tbody>${pastSessionRows}</tbody></table></div>` : emptyBox('No completed shift sessions yet.')}
    </div>

    <!-- ══ DETECT › sub-tab bar (shared) ══ -->
    <div class="subtab-bar" id="detectSubtabs">
      <button class="subtab active" id="sub-detect-warnings" onclick="showSection('detect-warnings')">${icon('alert-triangle')} Warnings (${findings.length})</button>
      <button class="subtab" id="sub-detect-types" onclick="showSection('detect-types')">${icon('layers')} Vulnerability Types (${liveTypeCount} live)</button>
      <button class="subtab" id="sub-detect-aifix" onclick="showSection('detect-aifix')">${icon('sparkles')} AI Fixing (${findings.length})</button>
    </div>

    <!-- ══ DETECT › WARNINGS ══ -->
    <div class="section-content active" id="section-detect-warnings">
      <div class="warn-summary">
        ${sevKeys.map(k => `<div class="warn-sev-tile" style="border-color:${sevColor(k)}55"><span class="chip-num">${ins.liveSeverity[k]}</span><span class="chip-label"><span class="sev-dot" style="background:${sevColor(k)}"></span>${k}</span></div>`).join('')}
        <div class="warn-sev-tile"><span class="chip-num" style="color:${scColor}">${scoreRaw}/100</span><span class="chip-label">Health score</span></div>
      </div>
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:var(--text-strong);">Live Warnings</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Detected in real time as you type — why it is vulnerable, how it can be exploited, and how to fix it</div>
        </div>
        <div class="filter-buttons">
          <button class="btn-filter active" onclick="filterCards('ALL', this)">All (${findings.length})</button>
          <button class="btn-filter" onclick="filterCards('CRITICAL', this)">Critical (${summary.criticalCount})</button>
          <button class="btn-filter" onclick="filterCards('HIGH', this)">High (${summary.highCount})</button>
          <button class="btn-filter" onclick="filterCards('MEDIUM', this)">Medium (${summary.mediumCount})</button>
          <button class="btn-filter" onclick="filterCards('LOW', this)">Low (${summary.lowCount})</button>
        </div>
      </div>
      <div class="vuln-cards-list">
        ${findingCards || `<div class="empty-state">${icon('shield-check')} All Clear! No vulnerabilities detected in currently open files.</div>`}
      </div>
    </div>

    <!-- ══ DETECT › VULNERABILITY TYPES ══ -->
    <div class="section-content" id="section-detect-types">
      <div class="progress-hero-card">
        <div class="progress-hero-header">
          <div class="progress-title-wrap">
            <div>
              <div class="progress-title">${icon('layers')} Detectable Vulnerability Types</div>
              <div class="progress-subtitle">${knownTypes.length} vulnerability types across ${catGroups.filter(g => g.id !== 'Other').length} OWASP Top 10 (2021) categories, checked by ${rulesCount} detection rules in real time</div>
            </div>
          </div>
          <div class="progress-big-stat">
            <span class="fix-num">${catalogTotals.identified === 0 ? '100%' : `${pct1(catalogTotals.fixed, catalogTotals.identified)}%`}</span>
            <span class="fix-label">${catalogTotals.identified === 0 ? 'Clean (0/0)' : `Fixed (${catalogTotals.fixed}/${catalogTotals.identified})`}</span>
          </div>
        </div>
        <div class="progress-bar-container">${segBar(catalogTotals, false)}</div>
        <div class="legend">
          <span><span class="legend-swatch" style="background:#10b981"></span>Fixed (${catalogTotals.fixed})</span>
          <span><span class="legend-swatch" style="background:#ef4444"></span>Open (${catalogTotals.open})</span>
          <span><span class="legend-swatch" style="background:var(--text-3)"></span>Ignored (${catalogTotals.ignored})</span>
        </div>
        <div class="progress-metric-chips">
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-blue)">${knownTypes.length}</span><span class="chip-label">Detectable types</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:${liveTypeCount ? 'var(--t-red)' : 'var(--t-green)'}">${liveTypeCount}</span><span class="chip-label">Types with live warnings</span></div>
          <div class="metric-chip"><span class="chip-num">${identifiedTypeCount}</span><span class="chip-label">Types ever identified</span></div>
          <div class="metric-chip"><span class="chip-num">${catsWithFindings.length}/${catData.length}</span><span class="chip-label">Categories with findings</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-green)">${catsFullyFixed}</span><span class="chip-label">Categories fully fixed</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-red)">${catalogTotals.open}</span><span class="chip-label">Open now</span></div>
        </div>
      </div>
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:var(--text-strong);">Fix progress by category</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Fixed vs identified vulnerabilities for each OWASP category and each type Sentinel can detect</div>
        </div>
        <div class="types-filter">
          <button class="btn-filter active" onclick="filterTypes(false, this)">All types (${knownTypes.length})</button>
          <button class="btn-filter" onclick="filterTypes(true, this)">Identified only (${identifiedTypeCount})</button>
        </div>
      </div>
      <div class="cat-grid" id="typeCatalog">${typeCatalogCards}</div>
      <div class="empty-state" id="typesEmpty" style="display:none">${icon('shield-check')} No vulnerabilities identified yet — every category is clean.</div>
    </div>

    <!-- ══ DETECT › AI FIXING ══ -->
    <div class="section-content" id="section-detect-aifix">
      <div class="progress-hero-card">
        <div class="progress-hero-header">
          <div class="progress-title-wrap">
            <div>
              <div class="progress-title">${icon('sparkles')} AI Fixing</div>
              <div class="progress-subtitle">Google Gemini generates a patch for each identified vulnerability, then Sentinel re-scans the patched code to check the fix before you apply it.</div>
            </div>
          </div>
          <div class="aifix-key">
            ${aiFix.configured
              ? `<span class="aifix-key-ok">${icon('check-circle')} AI model connected · <code>${esc(aiFix.model)}</code></span>`
              : `<span class="aifix-key-missing">${icon('alert-triangle')} No Gemini API key configured</span>`}
            <button class="btn-action btn-inspect" onclick="aiFixSetKey()">${icon('pen')} ${aiFix.configured ? 'Change' : 'Set'} API key</button>
          </div>
        </div>
        <div id="aifixSummary">${buildAiFixSummaryHtml(findings, aiFix)}</div>
        <div class="fix-concept-banner">
          <span>${icon('info')}</span>
          <span>Up to ${AI_FIX_CONTEXT_LINES * 2 + 1} lines of code around each finding are sent to the Google Gemini API. Nothing is changed until you click <strong>Apply Fix</strong>. After that, the real-time engine marks the vulnerability <strong>FIXED</strong> once the warning disappears, and you can undo with Ctrl/Cmd+Z.</span>
        </div>
      </div>
      <div class="filter-toolbar">
        <div>
          <h2 style="font-size:1.1em;font-weight:800;color:var(--text-strong);">Identified vulnerabilities</h2>
          <div style="font-size:0.75em;color:var(--text-secondary);">Live warnings from your open files — updated in real time as you edit</div>
        </div>
        ${findings.length ? `<button class="btn-action btn-copy-fix" onclick="aiFixAll()">${icon('sparkles')} Generate fixes for all (${findings.length})</button>` : ''}
      </div>
      <div class="vuln-cards-list">
        ${findings.length ? findings.map(f => `
          <div class="aifix-card" id="aifix-card-${esc(f.id)}">
            <div class="aifix-head">
              <span class="sev-pill" style="background:${sevColor(f.severity)}22;color:${sevColor(f.severity)};border:1px solid ${sevColor(f.severity)}55">${f.severity}</span>
              <div style="min-width:0">
                <div class="vuln-title">${typeTitle(f.type)}</div>
                <div class="vuln-file">${icon('file')} <code>${esc(f.fileName.replace(/\\/g, '/').split('/').pop() ?? f.fileName)}</code> : Line ${f.lineNumber}</div>
              </div>
              <button class="btn-jump" style="margin-left:auto" onclick="jumpToCode('${esc(f.fileName)}', ${f.lineNumber})">${icon('eye')} Jump</button>
            </div>
            <pre class="code-pre danger-pre aifix-snippet">${esc(f.codeSnippet.trim())}</pre>
            <div class="aifix-body" id="aifix-body-${esc(f.id)}">${buildAiFixBodyHtml(f.id, aiFix.states[f.id])}</div>
          </div>`).join('')
          : `<div class="empty-state">${icon('shield-check')} No identified vulnerabilities — nothing to fix right now.</div>`}
      </div>
      ${aiFix.history.length ? `
        <h3 class="block-title" style="margin-top:22px">${icon('history')} Recently applied AI fixes</h3>
        <div class="activity-stream">${aiFix.history.map(p => `
          <div class="activity-item"><div class="act-dot" style="background:${p.verified ? '#10b981' : '#f59e0b'}"></div>
            <div class="act-content"><div class="act-header">
              <span class="act-user">${typeTitle(p.vulnerabilityType)}</span>
              <span class="act-type">${esc(p.fileName.replace(/\\/g, '/').split('/').pop())} · lines ${p.startLine}–${p.endLine}</span>
              <span class="act-time">${fmtDate(p.generatedAt)}</span>
            </div><div class="act-detail" style="font-family:inherit">${p.verified ? 'Verified' : 'Unverified'} · ${esc(p.model)}</div></div>
          </div>`).join('')}</div>` : ''}
    </div>

    <!-- ══ BEHAVIOUR › sub-tab bar (shared) ══ -->
    <div class="subtab-bar" id="behaviourSubtabs">
      <button class="subtab" id="sub-behaviour-overview" onclick="showSection('behaviour-overview')">${icon('activity')} Overview</button>
      <button class="subtab" id="sub-behaviour-fixrate" onclick="showSection('behaviour-fixrate')">${icon('check-circle')} Fixed Rate (${ins.totals.fixRate}%)</button>
      <button class="subtab" id="sub-behaviour-history" onclick="showSection('behaviour-history')">${icon('database')} History (${dbRecords.length})</button>
    </div>

    <!-- ══ BEHAVIOUR › FIXED RATE ══ -->
    <div class="section-content" id="section-behaviour-fixrate">
      <div class="progress-hero-card">
        <div class="progress-hero-header">
          <div class="progress-title-wrap">
            <div>
              <div class="progress-title">${icon('target')} Vulnerability Remediation &amp; Fix Rate</div>
              <div class="progress-subtitle">Real-time resolution metric for <strong>@${esc(devId)}</strong></div>
            </div>
          </div>
          <div class="progress-big-stat">
            <span class="fix-num">${totalIdentified === 0 ? '100%' : `${fixPercentage}%`}</span>
            <span class="fix-label">${totalIdentified === 0 ? 'Clean (0/0)' : `Fixed (${fixedCount}/${totalIdentified})`}</span>
          </div>
        </div>
        <div class="progress-bar-container">
          <div class="progress-track">
            ${totalIdentified === 0 ? `
              <div class="progress-seg-fixed" style="width: 100%;" title="Clean: no vulnerabilities detected"></div>
            ` : `
              <div class="progress-seg-fixed" style="width: ${fixPercentage}%" title="Fixed: ${fixPercentage}% (${fixedCount} resolved)"></div>
              <div class="progress-seg-open" style="width: ${openPercentage}%" title="Open: ${openPercentage}% (${openCount} active)"></div>
              <div class="progress-seg-ignored" style="width: ${Math.round((ignoredCount / totalIdentified) * 100)}%" title="Ignored: ${ignoredCount}"></div>
            `}
          </div>
        </div>
        <div class="fix-concept-banner">
          <span>${icon('info')}</span>
          <span><strong>Resolution Concept:</strong> A vulnerability is marked <strong>FIXED</strong> only when you correct the code so the red squiggly line disappears. (<strong>${openCount}</strong> open, <strong>${fixedCount}</strong> fixed of <strong>${totalIdentified}</strong> total.)</span>
        </div>
        <div class="progress-metric-chips">
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-blue)">${totalIdentified}</span><span class="chip-label">Total Identified</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-green)">${fixedCount}</span><span class="chip-label">Fixed (${fixPercentage}%)</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:var(--t-red)">${openCount}</span><span class="chip-label">Open (${openPercentage}%)</span></div>
          <div class="metric-chip"><span class="chip-num" style="color:var(--text-2)">${ignoredCount}</span><span class="chip-label">Ignored</span></div>
          <div class="metric-chip"><span class="chip-num">${fmtMinutes(b.medianTimeToFixMinutes)}</span><span class="chip-label">Median time to fix</span></div>
        </div>
      </div>
      <div class="two-col">
        <div class="panel-card">
          <h3 class="block-title">Fix rate by vulnerability type</h3>
          <div class="bar-list">${typeRateRows}</div>
        </div>
        <div class="panel-card">
          <h3 class="block-title">Fix rate by severity</h3>
          <div class="bar-list">${sevFixRows}</div>
        </div>
      </div>
    </div>

    <!-- ══ BEHAVIOUR › HISTORY (Neon DB tracker) ══ -->
    <div class="section-content" id="section-behaviour-history">
      <div class="tracker-header-wrap">
        <div>
          <h2 class="tracker-title">${icon('database')} Vulnerability History</h2>
          <div class="tracker-subtitle">Permanent record history stored in Neon PostgreSQL for @${esc(devId)}</div>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <button class="btn-action btn-copy-fix" onclick="scanWorkspace()">${icon('refresh')} Scan Workspace &amp; Sync DB</button>
          <div class="tracker-count-badge"><span>${dbRecords.length} Total Records</span></div>
        </div>
      </div>
      <div class="tracker-controls">
        <div class="tracker-status-filters">
          <button class="btn-tfilter active" onclick="filterTrackerStatus('ALL', this)">All (${dbRecords.length})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('OPEN', this)">${icon('clock')} Open (${dbRecords.filter(r => r.status === 'OPEN').length})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('FIXED', this)">${icon('check-circle')} Fixed (${dbRecords.filter(r => r.status === 'FIXED').length})</button>
          <button class="btn-tfilter" onclick="filterTrackerStatus('IGNORED', this)">${icon('ban')} Ignored (${dbRecords.filter(r => r.status === 'IGNORED').length})</button>
        </div>
        <div class="tracker-search-wrap">
          <span style="font-size:0.85em;color:var(--text-muted);display:flex">${icon('search')}</span>
          <input type="text" id="trackerSearch" class="tracker-search-input" placeholder="Search vulnerability, file, or line..." oninput="searchTracker(this.value)">
        </div>
      </div>
      <div class="table-scroll-hint"><span>${icon('move-h')} Scroll table horizontally to view all columns</span></div>
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

    <!-- ══ BEHAVIOUR › OVERVIEW ══ -->
    <div class="section-content" id="section-behaviour-overview">
      <div class="page-head">
        <h2 class="page-title">${icon('activity')} Behaviour</h2>
        <div class="page-sub">How you respond to security warnings — this is the behaviour profile shared with Component 2 (Behaviour Tracker).</div>
      </div>
      <div class="pattern-card" style="border-color:${pm.color}55">
        <div class="pattern-icon" style="color:${pm.color}">${pm.icon}</div>
        <div>
          <div class="chip-label">Current behaviour pattern</div>
          <div class="pattern-name">${esc(b.pattern.replace(/_/g, ' '))}</div>
          <div class="pattern-desc">${esc(b.patternLabel)}</div>
        </div>
      </div>
      <div class="progress-metric-chips" style="margin-bottom:22px">
        <div class="metric-chip"><span class="chip-num">${b.responsivenessRate}%</span><span class="chip-label">Responsiveness (fix vs dismiss)</span></div>
        <div class="metric-chip"><span class="chip-num">${b.ignoreRate}%</span><span class="chip-label">Ignore rate</span></div>
        <div class="metric-chip"><span class="chip-num">${fmtMinutes(b.meanTimeToFixMinutes)}</span><span class="chip-label">Mean time to fix</span></div>
        <div class="metric-chip"><span class="chip-num">${fmtMinutes(b.medianTimeToFixMinutes)}</span><span class="chip-label">Median time to fix</span></div>
        <div class="metric-chip"><span class="chip-num">${b.repeatedMistakes.length}</span><span class="chip-label">Repeated mistake types</span></div>
      </div>
      <div class="two-col">
        <div class="panel-card">
          <h3 class="block-title">${icon('repeat')} Repeated mistakes</h3>
          <div class="bar-list">${repeatRows}</div>
          ${b.suppressedTypes.length ? `<div class="suppressed-note">${icon('bell-off')} AI-suppressed for you (high false-positive rate): ${b.suppressedTypes.map(t => `<span class="rule-badge">${prettyType(t)}</span>`).join(' ')}</div>` : ''}
        </div>
        <div class="panel-card">
          <h3 class="block-title">${icon('list')} Action breakdown</h3>
          ${actionRows}
        </div>
      </div>
      <h3 class="block-title" style="margin-top:22px">${icon('history')} Activity Audit Log</h3>
      <div class="activity-stream">${activityItems}</div>
    </div>

    <!-- ══ FEEDBACK ══ -->
    <div class="section-content" id="section-feedback">
      <div class="page-head">
        <h2 class="page-title">${icon('message')} Feedback</h2>
        <div class="page-sub">Personalised secure-coding guidance based on your own vulnerability history. Rate it so Sentinel can learn what helps you.</div>
      </div>
      <div class="progress-metric-chips" style="margin-bottom:22px">
        <div class="metric-chip"><span class="chip-num">${ins.feedback.length}</span><span class="chip-label">Recommendations</span></div>
        <div class="metric-chip"><span class="chip-num">${ratingTotal}</span><span class="chip-label">Ratings given</span></div>
        <div class="metric-chip"><span class="chip-num">${ratingTotal ? Math.round((helpfulCount / ratingTotal) * 100) + '%' : '—'}</span><span class="chip-label">Rated helpful</span></div>
      </div>
      <div class="vuln-cards-list">${feedbackCards}</div>
      <div class="panel-card" style="margin-top:22px">
        <h3 class="block-title">${icon('pen')} Send feedback to Sentinel</h3>
        <textarea id="fbComment" class="fb-textarea" placeholder="Was a warning wrong, unclear, or especially useful? Tell us…"></textarea>
        <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
          <button class="btn-action btn-copy-fix" onclick="sendGeneralFeedback(true)">${icon('thumbs-up')} Send as positive</button>
          <button class="btn-action btn-inspect" onclick="sendGeneralFeedback(false)">${icon('thumbs-down')} Send as issue</button>
        </div>
        ${recentComments ? `<div class="activity-stream" style="margin-top:14px">${recentComments}</div>` : ''}
      </div>
    </div>

    <!-- ══ ANALYTICS ══ -->
    <div class="section-content" id="section-analytics">
      <div class="page-head">
        <h2 class="page-title">${icon('bar-chart')} Analytics</h2>
        <div class="page-sub">Security trends for @${esc(devId)} across all recorded findings.</div>
      </div>
      <div class="panel-card">
        <div class="chart-head">
          <h3 class="block-title" style="margin:0">Detected vs fixed — last ${ins.trend.length} days</h3>
          <div class="legend">
            <span><span class="legend-swatch" style="background:${C_DET}"></span>Detected (${trendDetected})</span>
            <span><span class="legend-swatch" style="background:${C_FIX}"></span>Fixed (${trendFixed})</span>
          </div>
        </div>
        ${trendSvg}
        <details class="table-toggle"><summary>View as table</summary>
          <table class="data-table" style="min-width:0"><thead><tr><th>Date</th><th>Detected</th><th>Fixed</th></tr></thead><tbody>${trendTableRows}</tbody></table>
        </details>
      </div>
      <div class="two-col">
        <div class="panel-card">
          <h3 class="block-title">Severity distribution</h3>
          <div class="bar-list">${sevDistRows}</div>
        </div>
        <div class="panel-card">
          <h3 class="block-title">OWASP Top 10 (2021) categories</h3>
          <div class="bar-list">${owaspRows}</div>
        </div>
      </div>
      <div class="two-col">
        <div class="panel-card">
          <h3 class="block-title">${icon('flame')} Hot files</h3>
          ${fileRows ? `<table class="data-table" style="min-width:0"><thead><tr><th>File</th><th>Total</th><th>Open</th></tr></thead><tbody>${fileRows}</tbody></table>` : emptyBox('No file data yet.')}
        </div>
        <div class="panel-card">
          <h3 class="block-title">${icon('plug')} Component 2 data API</h3>
          <div class="kv-row"><span>Status</span><strong style="color:${apiStatus.running ? 'var(--t-green)' : 'var(--t-red)'}">${apiStatus.running ? 'Online' : 'Offline'}</strong></div>
          ${apiStatus.error ? `<div class="kv-row"><span>Error</span><span class="muted">${esc(apiStatus.error)}</span></div>` : ''}
          ${apiStatus.url ? `<div class="kv-row"><span>Base URL</span><code class="api-url">${esc(apiStatus.url)}</code></div>` : ''}
          <div class="endpoint-list">${apiEndpoints.map(e => `<code>GET /${esc(e)}</code>`).join('')}</div>
          ${apiStatus.url ? `<button class="btn-action btn-inspect" style="margin-top:10px" onclick="copyText(this, '${esc(apiStatus.url)}')">${icon('copy')} Copy base URL</button>` : ''}
        </div>
      </div>
    </div>

  </main>
</div>

<script>
window._vscode = acquireVsCodeApi();
const vscode = window._vscode;
const ICON_CHECK = ${JSON.stringify(icon('check'))};

const NAV_GROUPS = {
  detect: ['detect-warnings', 'detect-types', 'detect-aifix'],
  behaviour: ['behaviour-overview', 'behaviour-fixrate', 'behaviour-history'],
};
// Section ids from before Fixed Rate / History moved under Behaviour
const LEGACY_SECTIONS = { 'detect-fixrate': 'behaviour-fixrate', 'detect-history': 'behaviour-history', 'behaviour': 'behaviour-overview' };

function showSection(id) {
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn, .nav-sub, .subtab').forEach(el => el.classList.remove('active'));
  const sec = document.getElementById('section-' + id);
  if (sec) sec.classList.add('active');
  const group = Object.keys(NAV_GROUPS).find(g => NAV_GROUPS[g].includes(id));
  const nav = document.getElementById('nav-' + (group || id));
  if (nav) nav.classList.add('active');
  const sub = document.getElementById('nav-' + id);
  if (group && sub) sub.classList.add('active');
  const tab = document.getElementById('sub-' + id);
  if (tab) tab.classList.add('active');
  Object.keys(NAV_GROUPS).forEach(g => {
    const bar = document.getElementById(g + 'Subtabs');
    if (bar) bar.classList.toggle('visible', g === group);
  });
  vscode.setState(Object.assign({}, vscode.getState() || {}, { section: id }));
}

// ── Detect › AI Fixing ──
const AIFIX_PENDING_HTML = ${JSON.stringify(buildAiFixBodyHtml('', { status: 'pending', startedAt: '' }))};
function aiFix(findingId) {
  const body = document.getElementById('aifix-body-' + findingId);
  if (body) body.innerHTML = AIFIX_PENDING_HTML;
  vscode.postMessage({ command: 'AI_FIX_GENERATE', findingId });
}
function aiFixAll() { vscode.postMessage({ command: 'AI_FIX_GENERATE_ALL' }); }
function aiFixApply(findingId) { vscode.postMessage({ command: 'AI_FIX_APPLY', findingId }); }
function aiFixDiff(findingId) { vscode.postMessage({ command: 'AI_FIX_DIFF', findingId }); }
function aiFixCopy(findingId) { vscode.postMessage({ command: 'AI_FIX_COPY', findingId }); }
function aiFixDiscard(findingId) { vscode.postMessage({ command: 'AI_FIX_DISCARD', findingId }); }
function aiFixSetKey() { vscode.postMessage({ command: 'AI_FIX_SET_KEY' }); }
window.addEventListener('message', e => {
  const m = e.data || {};
  if (m.command !== 'AI_FIX_UPDATE') return;
  const body = document.getElementById('aifix-body-' + m.findingId);
  if (body && typeof m.html === 'string') body.innerHTML = m.html;
  const sum = document.getElementById('aifixSummary');
  if (sum && typeof m.summaryHtml === 'string') sum.innerHTML = m.summaryHtml;
});

function filterTypes(identifiedOnly, btn) {
  document.querySelectorAll('.types-filter .btn-filter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  let visibleCats = 0;
  document.querySelectorAll('#typeCatalog .cat-card').forEach(card => {
    const show = !identifiedOnly || card.getAttribute('data-identified') === 'true';
    card.style.display = show ? '' : 'none';
    if (show) visibleCats++;
    card.querySelectorAll('.type-row').forEach(row => {
      row.style.display = (!identifiedOnly || row.getAttribute('data-identified') === 'true') ? '' : 'none';
    });
  });
  const empty = document.getElementById('typesEmpty');
  if (empty) empty.style.display = visibleCats === 0 ? '' : 'none';
}

const isCompactNav = () => window.matchMedia('(max-width: 860px)').matches;

function setDropdown(name, open) {
  const dd = document.getElementById('dd-' + name);
  if (!dd) return;
  dd.classList.toggle('open', open);
  const btn = document.getElementById('nav-' + name);
  if (btn) btn.setAttribute('aria-expanded', String(open));
  if (!isCompactNav()) {
    const dds = Object.assign({}, (vscode.getState() || {}).dropdowns || {}, { [name]: open });
    vscode.setState(Object.assign({}, vscode.getState() || {}, { dropdowns: dds }));
  }
}

function toggleDropdown(name, ev) {
  if (ev) ev.stopPropagation();
  const dd = document.getElementById('dd-' + name);
  setDropdown(name, !(dd && dd.classList.contains('open')));
}

// Compact (horizontal) nav: the dropdown floats, so close it after a choice or an outside click
document.addEventListener('click', ev => {
  if (!isCompactNav()) return;
  document.querySelectorAll('.nav-dropdown.open').forEach(dd => {
    if (!dd.contains(ev.target) || ev.target.closest('.nav-sub')) setDropdown(dd.id.slice(3), false);
  });
});
document.addEventListener('keydown', ev => {
  if (ev.key === 'Escape') document.querySelectorAll('.nav-dropdown.open').forEach(dd => {
    if (isCompactNav()) setDropdown(dd.id.slice(3), false);
  });
});

// Restore the last opened section and dropdown state across dashboard re-renders
(function restoreSection() {
  const st = vscode.getState() || {};
  const dds = st.dropdowns || {};
  Object.keys(NAV_GROUPS).forEach(g => setDropdown(g, isCompactNav() ? false : dds[g] !== false));
  const saved = LEGACY_SECTIONS[st.section] || st.section;
  showSection(saved && document.getElementById('section-' + saved) ? saved : 'detect-warnings');
})();

// Live shift timer
(function startShiftTimer() {
  const el = document.getElementById('shiftTimer');
  if (!el) return;
  const start = Date.parse(el.getAttribute('data-start') || '');
  if (isNaN(start)) return;
  const pad = n => String(n).padStart(2, '0');
  const tick = () => {
    const s = Math.max(0, Math.floor((Date.now() - start) / 1000));
    el.textContent = pad(Math.floor(s / 3600)) + ':' + pad(Math.floor((s % 3600) / 60)) + ':' + pad(s % 60);
  };
  tick();
  setInterval(tick, 1000);
})();

function rateFeedback(findingId, vulnerabilityType, helpful) {
  vscode.postMessage({ command: 'RATE_FEEDBACK', findingId, vulnerabilityType, helpful });
  const grp = document.getElementById('rate-' + findingId);
  if (grp) grp.innerHTML = '<span class="rate-done">' + ICON_CHECK + ' Thanks — feedback recorded (' + (helpful ? 'helpful' : 'not helpful') + ')</span>';
}

function sendGeneralFeedback(helpful) {
  const ta = document.getElementById('fbComment');
  const comment = (ta && ta.value || '').trim();
  if (!comment) { if (ta) ta.focus(); return; }
  vscode.postMessage({ command: 'RATE_FEEDBACK', findingId: null, vulnerabilityType: null, helpful, comment });
  ta.value = '';
}

function openUrl(url) {
  vscode.postMessage({ command: 'OPEN_URL', url });
}

function copyText(btn, text) {
  navigator.clipboard.writeText(text);
  const orig = btn.innerHTML;
  btn.innerHTML = ICON_CHECK + ' Copied';
  setTimeout(() => { btn.innerHTML = orig; }, 1800);
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
  btn.innerHTML = ICON_CHECK + ' Copied to Clipboard!';
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

function filterCards(sev, btn) {
  document.querySelectorAll('.filter-buttons .btn-filter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('.vuln-card').forEach(card => {
    card.style.display = (sev === 'ALL' || card.getAttribute('data-severity') === sev) ? 'block' : 'none';
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
<script>${notifyScript()}</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>`;
}
