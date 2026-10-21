/**
 * Sentinel — Notification bell, dropdown and toasts for every dashboard.
 *
 * Protocol (webview ⇄ extension)
 *   page → ext   NOTIFICATIONS_READY                     (on load; extension replies with the list)
 *   ext  → page  NOTIFICATIONS { items, unread, fresh }  (list refresh; `fresh` items also toast)
 *   page → ext   NOTIFICATIONS_MARK_READ { ids | 'all' }
 *   page → ext   NOTIFICATION_OPEN { id }                 (marks read; page navigates to item.section)
 *
 * Uses window._vscode lazily so it works on pages that acquire the API themselves.
 */

import { icon } from './icons.js';

export const NOTIFY_CSS = `
.ntf-wrap { position: relative; }
.ntf-bell { position: relative; display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 30px;
  border-radius: 8px; border: 1px solid rgba(var(--ink), 0.1); background: rgba(var(--ink), 0.04); color: var(--text-2); cursor: pointer; font-size: 15px; }
.ntf-bell:hover { color: var(--text-strong); background: rgba(var(--ink), 0.08); }
.ntf-bell.has-unread { color: var(--t-amber); }
.ntf-badge { position: absolute; top: -5px; right: -5px; min-width: 17px; height: 17px; padding: 0 4px; border-radius: 100px;
  background: #ef4444; color: #fff; font-size: 10px; font-weight: 800; display: none; align-items: center; justify-content: center;
  box-shadow: 0 0 0 2px rgba(var(--nav-rgb), 1); }
.ntf-bell.has-unread .ntf-badge { display: inline-flex; }
.ntf-panel { position: absolute; right: 0; top: calc(100% + 8px); width: 360px; max-width: calc(100vw - 24px); max-height: 460px;
  display: none; flex-direction: column; background: var(--bg-surface); border: 1px solid rgba(var(--ink), 0.1); border-radius: 12px;
  box-shadow: 0 16px 40px rgba(0, 0, 0, calc(0.45 * var(--shade-k) + 0.08)); z-index: 500; overflow: hidden; }
.ntf-panel.open { display: flex; }
.ntf-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 14px; border-bottom: 1px solid rgba(var(--ink), 0.08);
  font-size: 0.82em; font-weight: 800; color: var(--text-strong); }
.ntf-head button { background: none; border: none; color: var(--t-cyan); font-size: 0.9em; font-weight: 600; cursor: pointer; font-family: inherit; }
.ntf-list { overflow-y: auto; }
.ntf-item { display: flex; gap: 10px; padding: 11px 14px; border-bottom: 1px solid rgba(var(--ink), 0.05); cursor: pointer; text-align: left; }
.ntf-item:hover { background: rgba(var(--ink), 0.04); }
.ntf-item.unread { background: rgba(14, 165, 233, 0.06); }
.ntf-ico { flex-shrink: 0; font-size: 15px; margin-top: 1px; }
.ntf-ico.info { color: var(--t-cyan); } .ntf-ico.success { color: var(--t-green); }
.ntf-ico.warning { color: var(--t-amber); } .ntf-ico.critical { color: var(--t-red); }
.ntf-body { flex: 1; min-width: 0; }
.ntf-title { font-size: 0.8em; font-weight: 700; color: var(--text-strong); }
.ntf-msg { font-size: 0.74em; color: var(--text-2); margin-top: 2px; line-height: 1.4; }
.ntf-time { font-size: 0.68em; color: var(--text-3); margin-top: 4px; }
.ntf-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--t-cyan); margin-top: 6px; flex-shrink: 0; }
.ntf-empty { padding: 28px 16px; text-align: center; color: var(--text-3); font-size: 0.8em; }
.ntf-toasts { position: fixed; right: 18px; top: 72px; display: flex; flex-direction: column; gap: 8px; z-index: 600; pointer-events: none; }
.ntf-toast { pointer-events: auto; width: 340px; max-width: calc(100vw - 36px); display: flex; gap: 10px; padding: 12px 14px; border-radius: 12px;
  background: var(--bg-surface); border: 1px solid rgba(var(--ink), 0.12); border-left-width: 4px;
  box-shadow: 0 12px 30px rgba(0, 0, 0, calc(0.4 * var(--shade-k) + 0.08)); cursor: pointer; animation: ntfIn 0.25s ease; }
.ntf-toast.info { border-left-color: #0ea5e9; } .ntf-toast.success { border-left-color: #10b981; }
.ntf-toast.warning { border-left-color: #f59e0b; } .ntf-toast.critical { border-left-color: #ef4444; }
.ntf-toast.out { opacity: 0; transform: translateX(16px); transition: all 0.25s ease; }
@keyframes ntfIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
`;

export function notificationBellHtml(): string {
  return `<div class="ntf-wrap">
    <button class="ntf-bell" id="ntfBell" type="button" title="Notifications" aria-label="Notifications" aria-haspopup="true" aria-expanded="false" onclick="ntfToggle(event)">
      ${icon('bell')}<span class="ntf-badge" id="ntfBadge">0</span>
    </button>
    <div class="ntf-panel" id="ntfPanel" role="dialog" aria-label="Notifications">
      <div class="ntf-head"><span>Notifications</span><button type="button" onclick="ntfMarkAll()">Mark all as read</button></div>
      <div class="ntf-list" id="ntfList"><div class="ntf-empty">Loading…</div></div>
    </div>
  </div>
  <div class="ntf-toasts" id="ntfToasts"></div>`;
}

export function notifyScript(): string {
  const ICONS = {
    info: icon('info'), success: icon('check-circle'), warning: icon('alert-triangle'), critical: icon('alert-octagon'),
  };
  return `
(function () {
  const ICONS = ${JSON.stringify(ICONS)};
  let items = [];
  const api = () => window._vscode;
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  function ago(iso) {
    const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
    if (m < 1) return 'just now'; if (m < 60) return m + 'm ago';
    const h = Math.round(m / 60); if (h < 24) return h + 'h ago';
    return Math.round(h / 24) + 'd ago';
  }
  function render(unread) {
    const list = document.getElementById('ntfList'); if (!list) return;
    const bell = document.getElementById('ntfBell'), badge = document.getElementById('ntfBadge');
    bell.classList.toggle('has-unread', unread > 0);
    badge.textContent = unread > 99 ? '99+' : String(unread);
    if (!items.length) { list.innerHTML = '<div class="ntf-empty">You\\'re all caught up.</div>'; return; }
    list.innerHTML = items.slice(0, 40).map(function (n) {
      return '<div class="ntf-item' + (n.unread ? ' unread' : '') + '" onclick="ntfOpen(\\'' + esc(n.id) + '\\')">'
        + '<span class="ntf-ico ' + n.level + '">' + (ICONS[n.level] || ICONS.info) + '</span>'
        + '<div class="ntf-body"><div class="ntf-title">' + esc(n.title) + '</div><div class="ntf-msg">' + esc(n.message) + '</div>'
        + '<div class="ntf-time">' + ago(n.createdAt) + '</div></div>' + (n.unread ? '<span class="ntf-dot"></span>' : '') + '</div>';
    }).join('');
  }
  function toast(n) {
    const wrap = document.getElementById('ntfToasts'); if (!wrap) return;
    const el = document.createElement('div');
    el.className = 'ntf-toast ' + n.level;
    el.innerHTML = '<span class="ntf-ico ' + n.level + '">' + (ICONS[n.level] || ICONS.info) + '</span><div class="ntf-body"><div class="ntf-title">'
      + esc(n.title) + '</div><div class="ntf-msg">' + esc(n.message) + '</div></div>';
    el.onclick = function () { ntfOpen(n.id); el.remove(); };
    wrap.appendChild(el);
    setTimeout(function () { el.classList.add('out'); setTimeout(function () { el.remove(); }, 300); }, n.level === 'critical' ? 9000 : 6000);
  }
  window.ntfToggle = function (e) {
    if (e) e.stopPropagation();
    const p = document.getElementById('ntfPanel'), open = !p.classList.contains('open');
    p.classList.toggle('open', open);
    document.getElementById('ntfBell').setAttribute('aria-expanded', String(open));
  };
  window.ntfMarkAll = function () { const a = api(); if (a) a.postMessage({ command: 'NOTIFICATIONS_MARK_READ', ids: 'all' }); };
  window.ntfOpen = function (id) {
    const n = items.find(function (x) { return x.id === id; });
    const a = api(); if (a) a.postMessage({ command: 'NOTIFICATION_OPEN', id: id });
    document.getElementById('ntfPanel').classList.remove('open');
    if (n && n.section && typeof window.showSection === 'function' && document.getElementById('section-' + n.section)) window.showSection(n.section);
  };
  document.addEventListener('click', function (e) {
    const p = document.getElementById('ntfPanel');
    if (p && p.classList.contains('open') && !e.target.closest('.ntf-wrap')) p.classList.remove('open');
  });
  window.addEventListener('message', function (e) {
    const m = e.data || {};
    if (m.command === 'NAVIGATE') {
      if (m.section && typeof window.showSection === 'function' && document.getElementById('section-' + m.section)) window.showSection(m.section);
      return;
    }
    if (m.command !== 'NOTIFICATIONS') return;
    items = m.items || [];
    render(m.unread || 0);
    (m.fresh || []).slice(0, 3).forEach(toast);
  });
  function ready() { const a = api(); if (a) a.postMessage({ command: 'NOTIFICATIONS_READY' }); else setTimeout(ready, 50); }
  ready();
})();
`;
}
