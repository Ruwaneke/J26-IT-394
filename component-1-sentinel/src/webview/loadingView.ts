/**
 * Sentinel — Loading View
 *
 * Shown while GitHub sign-in completes and while dashboard data is fetched
 * from Neon PostgreSQL. Matches the dark glassmorphism style of the login view.
 */

import { THEME_CSS, themeHtmlAttrs } from './theme.js';

function escHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function buildLoadingHtml(
  cspSource: string,
  logoUri: string = '',
  title: string = 'Loading your workspace',
  subtitle: string = 'Fetching your data from the database…',
): string {
  const logo = logoUri
    ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">`
    : `<div class="logo-box">🛡️</div>`;

  return `<!DOCTYPE html>
<html lang="en" ${themeHtmlAttrs()}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src ${cspSource} data: *;">
<title>Sentinel — Loading</title>
<style>
${THEME_CSS}
:root {
  --bg-primary: var(--bg-app);
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-emerald: #10b981;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background: var(--bg-primary);
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  overflow: hidden; color: var(--text-1); position: relative;
}
body::before {
  content: ''; position: fixed; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(56,189,248,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56,189,248,0.04) 1px, transparent 1px);
  background-size: 40px 40px;
}
.glow-tl { position: fixed; top: -140px; left: -140px; width: 560px; height: 560px; pointer-events: none;
  background: radial-gradient(circle, rgba(14,165,233,0.20) 0%, transparent 70%); }
.glow-br { position: fixed; bottom: -120px; right: -120px; width: 480px; height: 480px; pointer-events: none;
  background: radial-gradient(circle, rgba(16,185,129,0.15) 0%, transparent 70%); }

.loader { position: relative; z-index: 1; text-align: center; padding: 24px; }
.ring-wrap { position: relative; width: 132px; height: 132px; margin: 0 auto 28px; }
.ring {
  position: absolute; inset: 0; border-radius: 50%;
  border: 3px solid rgba(var(--ink), 0.07);
  border-top-color: var(--accent-cyan);
  border-right-color: var(--accent-blue);
  animation: spin 1.1s linear infinite;
}
.ring.outer {
  inset: -10px; border-width: 2px;
  border-top-color: transparent; border-right-color: transparent;
  border-bottom-color: var(--accent-emerald); border-left-color: rgba(16,185,129,0.25);
  animation: spin 2.2s linear infinite reverse;
}
.logo-img, .logo-box {
  position: absolute; inset: 22px; width: 88px; height: 88px; object-fit: contain;
  border-radius: 20px; display: flex; align-items: center; justify-content: center;
  font-size: 40px; animation: pulse 2.4s ease-in-out infinite;
}
h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; margin-bottom: 8px; }
p  { font-size: 13px; color: var(--text-2); }
.dots::after { content: ''; animation: dots 1.5s steps(4, end) infinite; }
.bar { width: 220px; height: 4px; margin: 26px auto 0; border-radius: 4px;
  background: rgba(var(--ink), 0.07); overflow: hidden; }
.bar::before { content: ''; display: block; height: 100%; width: 40%; border-radius: 4px;
  background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue), var(--accent-emerald));
  animation: slide 1.4s ease-in-out infinite; }

@keyframes spin  { to { transform: rotate(360deg); } }
@keyframes pulse { 0%,100% { transform: scale(1); opacity: .95; } 50% { transform: scale(1.06); opacity: 1; } }
@keyframes slide { 0% { transform: translateX(-110%); } 100% { transform: translateX(260%); } }
@keyframes dots  { 0% { content: ''; } 25% { content: '.'; } 50% { content: '..'; } 75% { content: '...'; } }
@media (prefers-reduced-motion: reduce) { .ring, .logo-img, .logo-box, .bar::before { animation: none; } }
</style>
</head>
<body>
<div class="glow-tl"></div><div class="glow-br"></div>
<main class="loader" role="status" aria-live="polite">
  <div class="ring-wrap">
    <div class="ring outer"></div>
    <div class="ring"></div>
    ${logo}
  </div>
  <h1 id="loading-title">${escHtml(title)}<span class="dots"></span></h1>
  <p id="loading-subtitle">${escHtml(subtitle)}</p>
  <div class="bar"></div>
</main>
</body>
</html>`;
}
