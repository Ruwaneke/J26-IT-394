/**
 * Sentinel — shared "console" styles for the administrator and supervisor dashboards
 * (top bar, sidebar with dropdowns, cards, KPI tiles, tables, forms, modals, toasts).
 * Written against the theme tokens in theme.ts, so it works in light and dark mode.
 */

export const CONSOLE_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap');
:root { --border: rgba(var(--ink), 0.08); --card: rgba(var(--card-rgb), 0.75); }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg-app); color: var(--text-1); height: 100vh; overflow: hidden; display: flex; flex-direction: column; }
button, input, select, textarea { font-family: inherit; }
.mono { font-family: 'Fira Code', monospace; font-size: 0.92em; }
.muted { color: var(--text-3); }
.nowrap { white-space: nowrap; }
.num { text-align: right; font-variant-numeric: tabular-nums; }

/* Top bar */
.top-nav { height: 60px; flex-shrink: 0; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 0 24px; background: rgba(var(--nav-rgb), 0.85); backdrop-filter: blur(16px); border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 12px; }
.brand-logo { width: 36px; height: 36px; object-fit: contain; padding: 4px; background: #f1f5f9; border-radius: 9px; box-shadow: 0 0 16px rgba(14, 165, 233, 0.3); }
.brand-name { font-size: 1.15em; font-weight: 800; color: var(--text-strong); letter-spacing: -0.3px; }
.brand-tag { font-size: 0.65em; font-weight: 700; color: var(--t-red); background: rgba(239, 68, 68, 0.12); padding: 2px 8px; border-radius: 100px; text-transform: uppercase; }
.db-pill { display: flex; align-items: center; gap: 7px; font-size: 0.72em; font-weight: 600; padding: 4px 12px; border-radius: 100px; }
.db-pill.on { color: var(--t-green); background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.25); }
.db-pill.off { color: var(--t-red); background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.25); }
.dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.top-right { display: flex; align-items: center; gap: 10px; }
.admin-chip { display: flex; align-items: center; gap: 8px; padding: 5px 12px; border: 1px solid var(--border); border-radius: 10px; background: rgba(var(--ink), 0.03); font-size: 0.78em; }
.admin-chip strong { color: var(--text-strong); }
.btn-signout { background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); color: var(--t-red); font-size: 0.72em; font-weight: 600; padding: 6px 12px; border-radius: 8px; cursor: pointer; }

/* Layout */
.app { display: flex; flex: 1; overflow: hidden; }
.sidebar { width: 228px; flex-shrink: 0; display: flex; flex-direction: column; padding: 16px 0; overflow-y: auto; background: rgba(var(--sidebar-rgb), 0.95); border-right: 1px solid var(--border); }
.nav-heading { font-size: 0.62em; font-weight: 700; color: var(--text-3); text-transform: uppercase; letter-spacing: 1px; padding: 12px 18px 6px; }
.nav-btn { display: flex; align-items: center; gap: 10px; width: calc(100% - 20px); margin: 2px 10px; padding: 9px 12px; border: none; border-radius: 9px; background: none; color: var(--text-2); font-size: 0.82em; font-weight: 500; cursor: pointer; text-align: left; }
.nav-btn .ico { font-size: 1.15em; }
.nav-btn:hover { background: rgba(var(--ink), 0.05); color: var(--text-strong); }
.nav-btn.active { background: rgba(14, 165, 233, 0.12); color: var(--t-cyan); font-weight: 600; }
.nav-count { margin-left: auto; font-size: 0.78em; color: var(--text-3); }
.nav-chevron { margin-left: auto; display: inline-flex; color: var(--text-3); transition: transform 0.2s; }
.nav-dropdown.open .nav-chevron { transform: rotate(180deg); }
.nav-sub-group { display: flex; flex-direction: column; margin: 0 10px 0 30px; border-left: 1px solid var(--border); max-height: 0; overflow: hidden; opacity: 0; transition: max-height 0.22s, opacity 0.18s; }
.nav-dropdown.open .nav-sub-group { max-height: 220px; opacity: 1; margin-bottom: 4px; }
.nav-sub { display: flex; align-items: center; gap: 6px; padding: 6px 12px; border: none; background: none; color: var(--text-3); font-size: 0.76em; text-align: left; cursor: pointer; border-radius: 0 7px 7px 0; }
.nav-sub:hover { color: var(--text-strong); background: rgba(var(--ink), 0.04); }
.nav-sub.active { color: var(--t-cyan); font-weight: 600; background: rgba(14, 165, 233, 0.08); box-shadow: inset 2px 0 0 var(--t-cyan); }
.sidebar-foot { margin-top: auto; padding: 12px 18px 4px; font-size: 0.68em; color: var(--text-3); }
.content { flex: 1; overflow-y: auto; padding: 24px 32px 48px; }
.section { display: none; }
.section.active { display: block; animation: fade 0.2s ease; }
@keyframes fade { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }

/* Page elements */
.page-head { display: flex; justify-content: space-between; align-items: flex-end; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }
.page-title { font-size: 1.2em; font-weight: 800; color: var(--text-strong); display: flex; align-items: center; gap: 8px; }
.page-title .ico { color: var(--t-cyan); }
.page-sub { font-size: 0.78em; color: var(--text-2); margin-top: 3px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px; margin-bottom: 18px; }
.card-title { font-size: 0.85em; font-weight: 700; color: var(--text-strong); margin-bottom: 12px; display: flex; align-items: center; gap: 7px; }
.card-title .ico { color: var(--text-2); }
.card-sub { font-size: 0.74em; color: var(--text-2); margin: -6px 0 12px; }
.grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; margin-bottom: 18px; }
.grid-2 > .card { margin-bottom: 0; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 18px; }
.kpi { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
.kpi-top { display: flex; align-items: center; justify-content: space-between; color: var(--text-3); }
.kpi-num { font-size: 1.55em; font-weight: 800; color: var(--text-strong); line-height: 1.15; margin-top: 4px; }
.kpi-lbl { font-size: 0.66em; font-weight: 700; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; }
.kpi-note { font-size: 0.7em; color: var(--text-2); margin-top: 2px; }
.empty { text-align: center; color: var(--text-3); padding: 24px; font-size: 0.82em; border: 1px dashed var(--border); border-radius: 10px; }

/* Tables */
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; background: var(--card); }
table.data { width: 100%; border-collapse: collapse; font-size: 0.8em; }
table.data th { text-align: left; padding: 10px 14px; font-size: 0.82em; font-weight: 700; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.4px; background: rgba(var(--ink), 0.03); border-bottom: 1px solid var(--border); white-space: nowrap; }
table.data th.num { text-align: right; }
table.data td { padding: 10px 14px; border-bottom: 1px solid rgba(var(--ink), 0.04); vertical-align: middle; }
table.data tr:last-child td { border-bottom: none; }
table.data tbody tr:hover td { background: rgba(var(--ink), 0.025); }
.u-cell { display: flex; align-items: center; gap: 10px; }
.u-avatar { width: 30px; height: 30px; border-radius: 50%; object-fit: cover; flex-shrink: 0; }
.u-initial { display: flex; align-items: center; justify-content: center; background: #3b82f6; color: #fff; font-weight: 700; font-size: 0.85em; }
.u-name { font-weight: 700; color: var(--text-strong); }
.u-sub { font-size: 0.85em; color: var(--text-3); margin-top: 1px; }
.you-pill { font-size: 0.7em; font-weight: 700; color: var(--t-cyan); background: rgba(14, 165, 233, 0.12); padding: 1px 6px; border-radius: 100px; margin-left: 4px; }
.role-pill { display: inline-flex; align-items: center; gap: 5px; font-weight: 700; font-size: 0.92em; }
.action-pill { font-size: 0.85em; font-weight: 600; color: var(--t-cyan); background: rgba(14, 165, 233, 0.1); padding: 2px 7px; border-radius: 5px; white-space: nowrap; }
.action-pill.admin { color: var(--t-red); background: rgba(239, 68, 68, 0.1); }
.actions { text-align: right; white-space: nowrap; }

/* Controls */
.toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.input, .select { background: rgba(var(--ink), 0.04); border: 1px solid var(--border); border-radius: 8px; color: var(--text-strong); font-size: 0.8em; padding: 7px 10px; outline: none; }
.input:focus, .select:focus { border-color: var(--t-cyan); }
.input.search { min-width: 220px; flex: 1; max-width: 340px; }
.select option { background: var(--bg-surface); color: var(--text-1); }
.btn { display: inline-flex; align-items: center; gap: 6px; border-radius: 8px; font-size: 0.78em; font-weight: 700; padding: 7px 14px; cursor: pointer; border: 1px solid transparent; transition: all 0.15s; white-space: nowrap; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: linear-gradient(135deg, #0284c7, #0ea5e9); color: #fff; }
.btn-primary:hover:not(:disabled) { filter: brightness(1.08); }
.btn-secondary { background: rgba(var(--ink), 0.06); border-color: var(--border); color: var(--text-1); }
.btn-secondary:hover:not(:disabled) { background: rgba(var(--ink), 0.1); }
.btn-danger { background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.35); color: var(--t-red); }
.btn-danger:hover:not(:disabled) { background: rgba(239, 68, 68, 0.2); }
.btn-ghost { display: inline-flex; align-items: center; gap: 5px; background: none; border: 1px solid transparent; color: var(--text-2); font-size: 0.92em; padding: 4px 8px; border-radius: 6px; cursor: pointer; }
.btn-ghost:hover { background: rgba(var(--ink), 0.06); color: var(--text-strong); }
.btn-ghost.danger:hover { color: var(--t-red); background: rgba(239, 68, 68, 0.1); }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; align-items: end; }
.fg { display: flex; flex-direction: column; gap: 5px; }
.fg label { font-size: 0.68em; font-weight: 700; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.4px; }
.fg .input, .fg .select { width: 100%; }

/* Feed */
.feed-item { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(var(--ink), 0.04); font-size: 0.8em; }
.feed-item:last-child { border-bottom: none; }
.feed-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--t-cyan); flex-shrink: 0; }
.feed-dot.admin { background: var(--t-red); }
.feed-body { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.feed-body strong { color: var(--text-strong); }

/* Database */
.subtabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 18px; flex-wrap: wrap; }
.subtab { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; border-bottom: 2px solid transparent; margin-bottom: -1px; padding: 9px 14px; font-size: 0.8em; font-weight: 600; color: var(--text-2); cursor: pointer; }
.subtab:hover { color: var(--text-strong); }
.subtab.active { color: var(--t-cyan); border-bottom-color: var(--t-cyan); }
.table-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 14px; }
.tcard { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; display: flex; flex-direction: column; gap: 6px; }
.tcard-name { font-weight: 800; color: var(--text-strong); display: flex; align-items: center; gap: 7px; }
.tcard-desc { font-size: 0.74em; color: var(--text-2); min-height: 2.4em; }
.tcard-stats { display: flex; gap: 14px; font-size: 0.74em; color: var(--text-2); margin: 4px 0 6px; }
.tcard-stats strong { color: var(--text-strong); font-size: 1.15em; display: block; }
.kv { display: flex; justify-content: space-between; gap: 12px; font-size: 0.8em; padding: 8px 0; border-bottom: 1px solid rgba(var(--ink), 0.05); color: var(--text-2); }
.kv:last-child { border-bottom: none; }
.kv strong, .kv code { color: var(--text-strong); text-align: right; word-break: break-all; }
.cell-trunc { max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pager { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 10px; font-size: 0.78em; color: var(--text-2); }
.status-select { font-size: 0.92em; padding: 3px 6px; }
.maint-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
.maint-grid .card { margin-bottom: 0; display: flex; flex-direction: column; }
.maint-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: auto; }
.danger-zone { border-color: rgba(239, 68, 68, 0.35); }
.danger-zone .card-title .ico { color: var(--t-red); }
.loading { color: var(--text-3); font-size: 0.82em; padding: 18px; text-align: center; }

/* Modal & toast */
.modal-back { position: fixed; inset: 0; background: rgba(0, 0, 0, calc(0.55 * var(--shade-k) + 0.15)); display: none; align-items: center; justify-content: center; z-index: 200; padding: 16px; }
.modal-back.open { display: flex; }
.modal { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 14px; width: min(560px, 100%); max-height: 86vh; display: flex; flex-direction: column; box-shadow: 0 20px 60px rgba(0, 0, 0, calc(0.5 * var(--shade-k))); }
.modal-head { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-bottom: 1px solid var(--border); font-weight: 800; color: var(--text-strong); }
.modal-body { padding: 18px; overflow: auto; }
.modal-foot { padding: 12px 18px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 8px; }
pre.json { font-family: 'Fira Code', monospace; font-size: 0.75em; white-space: pre-wrap; word-break: break-word; color: var(--text-1); background: rgba(var(--ink), 0.04); border-radius: 8px; padding: 12px; }
.toast-wrap { position: fixed; right: 18px; bottom: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 300; }
.toast { min-width: 240px; max-width: 380px; padding: 10px 14px; border-radius: 10px; font-size: 0.8em; font-weight: 600; background: var(--bg-surface); border: 1px solid var(--border); box-shadow: 0 8px 24px rgba(0, 0, 0, calc(0.4 * var(--shade-k))); display: flex; gap: 8px; align-items: flex-start; animation: fade 0.2s; }
.toast.ok { border-color: rgba(16, 185, 129, 0.45); color: var(--t-green); }
.toast.err { border-color: rgba(239, 68, 68, 0.45); color: var(--t-red); }

@media (max-width: 860px) {
  .top-nav { height: auto; padding: 8px 14px; flex-wrap: wrap; }
  .app { flex-direction: column; }
  .sidebar { width: 100%; flex-direction: row; padding: 6px 10px; overflow-x: auto; border-right: none; border-bottom: 1px solid var(--border); }
  .nav-heading, .sidebar-foot, .nav-sub-group { display: none; }
  .nav-btn { width: auto; margin: 0; white-space: nowrap; flex-shrink: 0; }
  .nav-chevron { display: none; }
  .content { padding: 14px 12px 40px; }
}
`;
