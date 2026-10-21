/**
 * Sentinel — Light / Dark theme support for all webviews.
 *
 * How it works
 *   • Every page's CSS is written against the tokens below (`var(--text-strong)`,
 *     `rgba(var(--ink), 0.05)`, …). Dark values are the default; `:root[data-theme="light"]`
 *     swaps them.
 *   • The user picks Auto / Light / Dark (setting `sentinel.theme`). Auto follows the
 *     active VS Code colour theme and switches live when it changes.
 *   • The theme is resolved server-side (`themeHtmlAttrs()`), so pages render in the
 *     right mode with no flash, then `THEME_SCRIPT` keeps it in sync on the client.
 */

import { icon } from './icons.js';

export type ThemePreference = 'auto' | 'light' | 'dark';
export type ThemeKind = 'light' | 'dark';

let preference: ThemePreference = 'auto';
let vscodeKind: ThemeKind = 'dark';

export function setThemePreference(pref: ThemePreference): void {
  preference = pref === 'light' || pref === 'dark' ? pref : 'auto';
}

export function setVsCodeThemeKind(kind: ThemeKind): void {
  vscodeKind = kind;
}

export function resolvedTheme(): ThemeKind {
  return preference === 'auto' ? vscodeKind : preference;
}

/** Attributes for the <html> element: `<html lang="en" ${themeHtmlAttrs()}>` */
export function themeHtmlAttrs(): string {
  return `data-theme="${resolvedTheme()}" data-theme-pref="${preference}"`;
}

/**
 * Design tokens. Pages keep their own variable names (e.g. --bg-card) and the light block
 * below re-defines those too, so existing CSS picks the right value automatically.
 */
export const THEME_CSS = `
:root {
  color-scheme: dark;
  --ink: 255, 255, 255;            /* overlay/border colour, used as rgba(var(--ink), a) */
  --shade-k: 1;                    /* multiplier for black shadows / insets */
  --nav-rgb: 15, 23, 42;
  --sidebar-rgb: 13, 17, 23;
  --card-rgb: 17, 24, 39;
  --inset-rgb: 10, 15, 26;
  --bg-app: #090d16;
  --bg-surface: #111827;
  --text-strong: #ffffff;
  --text-1: #e2e8f0;
  --text-2: #94a3b8;
  --text-3: #64748b;
  --t-cyan: #38bdf8;
  --t-green: #34d399;
  --t-red: #f87171;
  --t-amber: #fbbf24;
  --t-amber-ink: #fef3c7;
  --t-blue: #60a5fa;
  --t-info: #bae6fd;
  --code-danger: #fca5a5;
  --code-safe: #86efac;
}
:root[data-theme="light"] {
  color-scheme: light;
  --ink: 15, 23, 42;
  --shade-k: 0.28;
  --nav-rgb: 255, 255, 255;
  --sidebar-rgb: 255, 255, 255;
  --card-rgb: 255, 255, 255;
  --inset-rgb: 248, 250, 252;
  --bg-app: #f4f6fa;
  --bg-surface: #ffffff;
  --text-strong: #0f172a;
  --text-1: #1e293b;
  --text-2: #475569;
  --text-3: #64748b;
  --t-cyan: #0369a1;
  --t-green: #047857;
  --t-red: #b91c1c;
  --t-amber: #b45309;
  --t-amber-ink: #78350f;
  --t-blue: #1d4ed8;
  --t-info: #075985;
  --code-danger: #b91c1c;
  --code-safe: #047857;

  /* Page-level variables used by the developer dashboard */
  --bg-primary: #f4f6fa;
  --bg-card: #ffffff;
  --border-card: rgba(15, 23, 42, 0.1);
  --border-focus: rgba(3, 105, 161, 0.35);
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
}
:root[data-theme="light"] .card, :root[data-theme="light"] .vuln-card, :root[data-theme="light"] .panel-card,
:root[data-theme="light"] .metric-chip, :root[data-theme="light"] .warn-sev-tile, :root[data-theme="light"] .fb-card {
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06), 0 4px 14px rgba(15, 23, 42, 0.05);
}
:root[data-theme="light"] .code-pre, :root[data-theme="light"] .endpoint-list code,
:root[data-theme="light"] .fb-textarea, :root[data-theme="light"] pre { background: #f1f5f9; }
:root[data-theme="light"] ::-webkit-scrollbar-thumb { background: rgba(15, 23, 42, 0.18); }
body { transition: background-color 0.2s ease, color 0.2s ease; }

/* Theme switch (Auto / Light / Dark) */
.theme-switch {
  display: inline-flex; align-items: center; gap: 2px; padding: 2px;
  background: rgba(var(--ink), 0.05); border: 1px solid rgba(var(--ink), 0.1); border-radius: 8px;
}
.theme-switch button {
  display: inline-flex; align-items: center; justify-content: center;
  width: 26px; height: 24px; border: none; border-radius: 6px; cursor: pointer;
  background: transparent; color: var(--text-2); font-size: 13px; padding: 0;
}
.theme-switch button:hover { color: var(--text-strong); background: rgba(var(--ink), 0.06); }
.theme-switch button[aria-pressed="true"] { color: var(--t-cyan); background: rgba(var(--ink), 0.1); }
.theme-switch .ico { width: 14px; height: 14px; }
`;

/** Auto / Light / Dark segmented control. */
export function themeSwitchHtml(): string {
  const btn = (pref: ThemePreference, ico: string, label: string) =>
    `<button type="button" data-theme-option="${pref}" aria-pressed="${preference === pref}" title="${label}" aria-label="${label}" onclick="sentinelSetTheme('${pref}')">${icon(ico)}</button>`;
  return `<div class="theme-switch" role="group" aria-label="Colour theme">
    ${btn('auto', 'monitor', 'Match VS Code theme')}${btn('light', 'sun', 'Light mode')}${btn('dark', 'moon', 'Dark mode')}
  </div>`;
}

/**
 * Client-side theme sync. Requires `script-src 'unsafe-inline'`.
 * Uses window._vscode lazily so it never calls acquireVsCodeApi() before the page does.
 */
export const THEME_SCRIPT = `
(function () {
  const root = document.documentElement;
  function vscodeKind() {
    const c = document.body ? document.body.classList : null;
    if (!c) return null;
    if (c.contains('vscode-light') || c.contains('vscode-high-contrast-light')) return 'light';
    if (c.contains('vscode-dark') || c.contains('vscode-high-contrast')) return 'dark';
    return null;
  }
  function apply() {
    const pref = root.getAttribute('data-theme-pref') || 'auto';
    const theme = pref === 'auto' ? (vscodeKind() || root.getAttribute('data-theme') || 'dark') : pref;
    root.setAttribute('data-theme', theme);
    document.querySelectorAll('[data-theme-option]').forEach(b =>
      b.setAttribute('aria-pressed', String(b.getAttribute('data-theme-option') === pref)));
  }
  window.sentinelSetTheme = function (pref) {
    root.setAttribute('data-theme-pref', pref);
    apply();
    const api = window._vscode;
    if (api) api.postMessage({ command: 'SET_THEME', pref });
  };
  function start() {
    apply();
    new MutationObserver(apply).observe(document.body, { attributes: true, attributeFilter: ['class'] });
  }
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();
`;
