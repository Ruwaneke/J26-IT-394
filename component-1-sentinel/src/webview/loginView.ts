/**
 * Sentinel — Authentication View
 *
 * Dedicated Portals:
 *   1. Developer Portal: Authenticates through GitHub OAuth exclusively.
 *      Tracks findings and fix progress under the developer's GitHub username in Neon DB.
 *   2. Supervisor & Admin Portal: Dedicated credentials window for supervisors and admins.
 *
 * Design: High-end dark glassmorphism.
 */

import { AuthSession } from '../auth/authManager.js';
import { THEME_CSS, THEME_SCRIPT, themeHtmlAttrs, themeSwitchHtml } from './theme.js';

function escHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function buildLoginHtml(
  cspSource: string,
  logoUri: string = '',
  errorMessage: string = '',
  githubError: string = '',
  initialTab: 'developer' | 'management' = 'developer'
): string {
  const logo = logoUri
    ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">`
    : `<div class="logo-box">🛡️</div>`;

  const errorBlock = errorMessage
    ? `<div class="error-msg"><span>⚠</span> ${escHtml(errorMessage)}</div>`
    : '';

  const githubErrorBlock = githubError
    ? `<div class="error-msg github-err"><span>⚠</span> ${escHtml(githubError)}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en" ${themeHtmlAttrs()}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data: *; script-src 'unsafe-inline';">
<title>Sentinel — Authentication Portal</title>
<style>
${THEME_CSS}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
  --bg-primary: var(--bg-app);
  --bg-card: rgba(var(--card-rgb),  0.88);
  --border-card: rgba(var(--ink),  0.10);
  --accent-cyan: #06b6d4;
  --accent-blue: #3b82f6;
  --accent-emerald: #10b981;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--bg-primary);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
  color: var(--text-1);
}

body::before {
  content: '';
  position: fixed; inset: 0;
  background-image:
    linear-gradient(rgba(56, 189, 248, 0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56, 189, 248, 0.04) 1px, transparent 1px);
  background-size: 40px 40px;
  pointer-events: none;
}
.glow-tl { position: fixed; top: -140px; left: -140px; width: 560px; height: 560px; background: radial-gradient(circle, rgba(14, 165, 233, 0.20) 0%, transparent 70%); pointer-events: none; }
.glow-br { position: fixed; bottom: -120px; right: -120px; width: 480px; height: 480px; background: radial-gradient(circle, rgba(16, 185, 129, 0.15) 0%, transparent 70%); pointer-events: none; }

.login-window-card {
  width: 100%; max-width: 460px; margin: 24px;
  background: var(--bg-card);
  border: 1px solid var(--border-card);
  border-radius: 22px;
  padding: 36px 36px 32px;
  backdrop-filter: blur(24px);
  box-shadow: 0 28px 72px rgba(0, 0, 0, calc(0.65 * var(--shade-k))), 0 0 0 1px rgba(56, 189, 248, 0.12);
  animation: fadeUp 0.4s cubic-bezier(0.4, 0, 0.2, 1) both;
}
@keyframes fadeUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }

.header { text-align: center; margin-bottom: 24px; }
.logo-wrap { display: inline-flex; align-items: center; justify-content: center; margin-bottom: 14px; }
.logo-img { width: 52px; height: 52px; object-fit: contain; border-radius: 14px; filter: drop-shadow(0 0 20px rgba(56, 189, 248, 0.45)); }
.logo-box { width: 52px; height: 52px; background: linear-gradient(135deg, #0ea5e9, #3b82f6); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 26px; box-shadow: 0 0 24px rgba(56, 189, 248, 0.4); }
.app-title { font-size: 1.6em; font-weight: 800; color: var(--text-strong); letter-spacing: -0.5px; margin-bottom: 4px; }
.app-subtitle { font-size: 0.8em; color: var(--text-2); }

/* ── Portal Switcher Tabs ── */
.portal-tabs {
  display: flex;
  background: rgba(0, 0, 0, calc(0.35 * var(--shade-k)));
  border: 1px solid var(--border-card);
  border-radius: 12px;
  padding: 4px;
  margin-bottom: 24px;
  gap: 4px;
}
.portal-tab-btn {
  flex: 1;
  padding: 10px 12px;
  border-radius: 9px;
  border: none;
  background: none;
  color: var(--text-2);
  font-size: 0.8em;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}
.portal-tab-btn:hover { color: var(--text-strong); }
.portal-tab-btn.active {
  background: rgba(56, 189, 248, 0.15);
  color: var(--t-cyan);
  font-weight: 700;
  box-shadow: 0 2px 8px rgba(0, 0, 0, calc(0.3 * var(--shade-k)));
}

/* ── Window Views ── */
.portal-window { display: none; }
.portal-window.active { display: block; animation: tabFade 0.25s ease; }
@keyframes tabFade { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

.portal-desc-box {
  background: rgba(var(--ink),  0.03);
  border: 1px solid var(--border-card);
  border-radius: 12px;
  padding: 14px;
  margin-bottom: 20px;
  font-size: 0.78em;
  color: var(--text-2);
  line-height: 1.5;
}
.portal-desc-title { font-weight: 700; color: var(--text-strong); margin-bottom: 4px; display: flex; align-items: center; gap: 6px; font-size: 1.05em; }

/* GitHub Button */
.btn-github {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  width: 100%;
  padding: 14px 20px;
  background: linear-gradient(135deg, #24292e, #2d333b);
  border: 1px solid rgba(var(--ink),  0.22);
  border-radius: 12px;
  color: #fff;
  font-size: 0.98em;
  font-weight: 700;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 4px 18px rgba(0, 0, 0, calc(0.35 * var(--shade-k)));
  margin-bottom: 16px;
}
.btn-github:hover {
  background: linear-gradient(135deg, #30363d, #3c444d);
  border-color: rgba(56, 189, 248, 0.5);
  box-shadow: 0 6px 24px rgba(56, 189, 248, 0.25);
  transform: translateY(-1px);
}
.gh-icon svg { width: 22px; height: 22px; fill: #fff; }

.features-list {
  list-style: none;
  font-size: 0.75em;
  color: var(--text-2);
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 14px;
  padding: 0 6px;
}
.features-list li { display: flex; align-items: center; gap: 8px; }
.check-icon { color: #10b981; font-weight: 800; }

/* Form */
.form-group { margin-bottom: 14px; text-align: left; }
label { display: block; font-size: 0.72em; font-weight: 700; color: var(--text-2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
input {
  width: 100%;
  background: rgba(var(--sidebar-rgb),  0.85);
  border: 1px solid var(--border-card);
  border-radius: 10px;
  padding: 11px 14px;
  color: var(--text-1);
  font-size: 0.88em;
  font-family: inherit;
  outline: none;
  transition: all 0.2s;
}
input:focus { border-color: var(--t-cyan); box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15); }
input::placeholder { color: var(--text-3); }

.btn-login {
  width: 100%; margin-top: 8px;
  padding: 12px;
  background: linear-gradient(135deg, #1d4ed8, #2563eb);
  border: none;
  border-radius: 10px;
  color: #fff;
  font-size: 0.88em;
  font-weight: 700;
  font-family: inherit;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
}
.btn-login:hover { opacity: 0.92; transform: translateY(-1px); }

/* Error Box */
.error-msg {
  display: flex; align-items: center; gap: 8px;
  background: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 10px;
  padding: 10px 14px;
  font-size: 0.8em;
  color: var(--t-red);
  margin-bottom: 16px;
}

/* Quick Fill Buttons */
.quick-fill-title { font-size: 0.68em; font-weight: 700; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; text-align: center; margin: 16px 0 8px; }
.quick-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.btn-quick {
  background: rgba(var(--ink),  0.03);
  border: 1px solid var(--border-card);
  border-radius: 8px;
  padding: 8px 10px;
  cursor: pointer;
  color: var(--text-2);
  font-family: inherit;
  transition: all 0.15s;
  text-align: left;
}
.btn-quick:hover { background: rgba(var(--ink),  0.07); color: var(--text-strong); border-color: rgba(56, 189, 248, 0.3); }
.quick-role { font-size: 0.72em; font-weight: 700; color: var(--t-cyan); display: block; }
.quick-creds { font-size: 0.64em; color: var(--text-3); font-family: monospace; display: block; margin-top: 2px; }

/* DB Status Footer */
.portal-footer {
  text-align: center; margin-top: 24px;
  font-size: 0.72em; color: var(--text-3);
  display: flex; align-items: center; justify-content: center; gap: 8px;
}
.db-dot { width: 6px; height: 6px; border-radius: 50%; background: #10b981; box-shadow: 0 0 6px #10b981; }
</style>
</head>
<body>
<div style="position:fixed;top:14px;right:16px;z-index:10">${themeSwitchHtml()}</div>
<div class="glow-tl"></div>
<div class="glow-br"></div>

<div class="login-window-card">
  <!-- Header -->
  <div class="header">
    <div class="logo-wrap">${logo}</div>
    <div class="app-title">Sentinel Security</div>
    <div class="app-subtitle">Real-time intelligent secure coding &amp; vulnerability tracking</div>
  </div>

  <!-- Portal Switcher Tabs -->
  <div class="portal-tabs">
    <button class="portal-tab-btn ${initialTab === 'developer' ? 'active' : ''}" id="tab-btn-dev" onclick="switchPortal('developer')">
      <span>🧑‍💻</span> Developer Portal
    </button>
    <button class="portal-tab-btn ${initialTab === 'management' ? 'active' : ''}" id="tab-btn-mgmt" onclick="switchPortal('management')">
      <span>🔐</span> Supervisor &amp; Admin
    </button>
  </div>

  <!-- ── 1. DEVELOPER WINDOW (GITHUB OAUTH) ── -->
  <div class="portal-window ${initialTab === 'developer' ? 'active' : ''}" id="window-developer">
    ${githubErrorBlock}

    <div class="portal-desc-box">
      <div class="portal-desc-title">🧑‍💻 Developer Authentication</div>
      Developers log in using your GitHub account. All code findings, security events, and remediation progress are tracked against your GitHub username in Neon PostgreSQL.
    </div>

    <button id="githubBtn" class="btn-github" onclick="doGitHubLogin()">
      <span class="gh-icon">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
        </svg>
      </span>
      <span>Sign in with GitHub</span>
    </button>

    <ul class="features-list">
      <li><span class="check-icon">✓</span> Seamless single sign-on with VS Code GitHub authentication</li>
      <li><span class="check-icon">✓</span> Persistent vulnerability records in Neon Serverless DB</li>
      <li><span class="check-icon">✓</span> Real-time fix detection and precise progress tracking</li>
    </ul>
  </div>

  <!-- ── 2. SUPERVISOR & ADMIN WINDOW (CREDENTIALS) ── -->
  <div class="portal-window ${initialTab === 'management' ? 'active' : ''}" id="window-management">
    ${errorBlock}

    <div class="portal-desc-box">
      <div class="portal-desc-title">🔐 Management Portal</div>
      Access for project supervisors and system administrators to manage team projects, shifts, audit logs, and developer progress.
    </div>

    <form id="mgmtLoginForm" onsubmit="doPasswordLogin(event)">
      <div class="form-group">
        <label for="usernameInput">Username</label>
        <input id="usernameInput" type="text" placeholder="e.g. supervisor01 or admin" autocomplete="username">
      </div>
      <div class="form-group">
        <label for="passwordInput">Password</label>
        <input id="passwordInput" type="password" placeholder="Enter password" autocomplete="current-password">
      </div>
      <button id="loginBtn" class="btn-login" type="submit">Sign In to Management Portal →</button>
    </form>

    <div class="quick-fill-title">Quick Demo Login</div>
    <div class="quick-grid">
      <button class="btn-quick" onclick="quickFill('supervisor01', 'sup123')">
        <span class="quick-role">👁️ Supervisor</span>
        <span class="quick-creds">supervisor01 / sup123</span>
      </button>
      <button class="btn-quick" onclick="quickFill('admin', 'admin123')">
        <span class="quick-role">🔐 Administrator</span>
        <span class="quick-creds">admin / admin123</span>
      </button>
    </div>
  </div>

  <!-- Footer -->
  <div class="portal-footer">
    <div class="db-dot"></div>
    <span>Neon PostgreSQL Database Online</span>
  </div>
</div>

<script>
const vscode = window._vscode = acquireVsCodeApi();

function switchPortal(portal) {
  document.querySelectorAll('.portal-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.portal-window').forEach(w => w.classList.remove('active'));

  if (portal === 'developer') {
    document.getElementById('tab-btn-dev').classList.add('active');
    document.getElementById('window-developer').classList.add('active');
  } else {
    document.getElementById('tab-btn-mgmt').classList.add('active');
    document.getElementById('window-management').classList.add('active');
  }
}

function doGitHubLogin() {
  const btn = document.getElementById('githubBtn');
  btn.style.opacity = '0.7';
  btn.querySelector('span:last-child').textContent = 'Connecting to GitHub…';
  vscode.postMessage({ command: 'GITHUB_LOGIN' });
}

function doPasswordLogin(e) {
  e.preventDefault();
  const u = document.getElementById('usernameInput').value.trim();
  const p = document.getElementById('passwordInput').value;
  if (!u || !p) { return; }
  vscode.postMessage({ command: 'LOGIN', username: u, password: p });
}

function quickFill(u, p) {
  document.getElementById('usernameInput').value = u;
  document.getElementById('passwordInput').value = p;
  document.getElementById('mgmtLoginForm').requestSubmit();
}
</script>
<script>${THEME_SCRIPT}</script>
</body>
</html>`;
}

export function buildHeaderBar(session: AuthSession, cspSource: string): string {
  const isDev = session.role === 'developer';
  const roleIcon = isDev ? '🧑‍💻' : session.role === 'supervisor' ? '👁️' : '🔐';
  const roleName = session.role.charAt(0).toUpperCase() + session.role.slice(1);
  const userDisplay = session.githubUsername ? `@${session.githubUsername}` : session.displayName;

  return `
  <div style="background:rgba(var(--nav-rgb), 0.9);border-bottom:1px solid rgba(var(--ink), 0.08);padding:8px 24px;display:flex;align-items:center;justify-content:space-between;font-size:0.78em;color:var(--text-2);">
    <div style="display:flex;align-items:center;gap:12px;">
      <span style="font-weight:700;color:var(--text-strong);">Sentinel Research</span>
      <span style="color:var(--text-3);">·</span>
      <span>Role: <strong style="color:${isDev ? '#38bdf8' : '#f59e0b'}">${roleIcon} ${roleName}</strong></span>
      <span style="color:var(--text-3);">·</span>
      <span>User: <strong style="color:var(--text-strong)">${escHtml(userDisplay)}</strong></span>
    </div>
    <div style="display:flex;align-items:center;gap:12px;">
      ${themeSwitchHtml()}
      <button onclick="window._vscode ? window._vscode.postMessage({command:'LOGOUT'}) : acquireVsCodeApi().postMessage({command:'LOGOUT'})"
        style="background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:var(--t-red);border-radius:6px;padding:3px 10px;font-size:0.85em;cursor:pointer;font-family:inherit;font-weight:600;">
        Sign Out
      </button>
    </div>
  </div>`;
}
