/**
 * Sentinel — Login View HTML Builder  (v2 — GitHub-first)
 *
 * Primary CTA: "Sign in with GitHub" (one click, uses VS Code OAuth)
 * Secondary:   Username / Password form (for supervisors & admins)
 *
 * Design: premium dark glassmorphism — matches existing Sentinel aesthetic.
 */

import { AuthSession } from '../auth/authManager.js';

// ─── Login Screen ─────────────────────────────────────────────────────────────

export function buildLoginHtml(
  cspSource: string,
  logoUri: string = '',
  errorMessage: string = '',
  githubError: string = '',
): string {
  const logo = logoUri
    ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">`
    : `<div class="logo-box">🛡</div>`;

  const errorBlock = errorMessage
    ? `<div class="error-msg"><span>⚠</span> ${escHtml(errorMessage)}</div>`
    : '';

  const githubErrorBlock = githubError
    ? `<div class="error-msg github-err"><span>⚠</span> ${escHtml(githubError)}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} https://avatars.githubusercontent.com https://github.com data: *; script-src 'unsafe-inline';">
<title>Sentinel — Sign In</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',system-ui,sans-serif;
  background:#0d1117;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  position:relative;
  overflow:hidden;
}

/* ── Background ── */
body::before{
  content:'';
  position:fixed;inset:0;
  background-image:
    linear-gradient(rgba(88,166,255,.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(88,166,255,.04) 1px,transparent 1px);
  background-size:44px 44px;
  pointer-events:none;
}
.glow-tl{position:fixed;top:-140px;left:-140px;width:560px;height:560px;background:radial-gradient(circle,rgba(31,111,235,.20) 0%,transparent 68%);pointer-events:none}
.glow-br{position:fixed;bottom:-120px;right:-120px;width:440px;height:440px;background:radial-gradient(circle,rgba(63,185,80,.13) 0%,transparent 68%);pointer-events:none}
.glow-center{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:700px;height:300px;background:radial-gradient(ellipse,rgba(88,166,255,.06) 0%,transparent 70%);pointer-events:none}

/* ── Card ── */
.card{
  width:100%;max-width:420px;margin:20px;
  background:rgba(22,27,34,.90);
  border:1px solid rgba(255,255,255,.10);
  border-radius:22px;
  padding:44px 40px 36px;
  backdrop-filter:blur(24px);
  box-shadow:0 28px 72px rgba(0,0,0,.60),0 0 0 1px rgba(88,166,255,.10);
  animation:fadeUp .45s cubic-bezier(.4,0,.2,1) both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}

/* ── Header ── */
.header{text-align:center;margin-bottom:34px}
.logo-wrap{display:inline-flex;align-items:center;justify-content:center;margin-bottom:18px}
.logo-img{width:56px;height:56px;object-fit:contain;border-radius:14px;filter:drop-shadow(0 0 20px rgba(88,166,255,.45))}
.logo-box{width:56px;height:56px;background:linear-gradient(135deg,#1f6feb,#388bfd);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:28px;box-shadow:0 0 26px rgba(88,166,255,.40)}
.title{font-size:1.7em;font-weight:800;color:#e6edf3;letter-spacing:-.6px;margin-bottom:5px}
.subtitle{font-size:.83em;color:#8b949e;font-weight:500;line-height:1.5}

/* ── GitHub Button (PRIMARY) ── */
.btn-github{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:10px;
  width:100%;
  padding:13px 20px;
  background:linear-gradient(135deg,#24292e,#2d333b);
  border:1px solid rgba(255,255,255,.18);
  border-radius:12px;
  color:#fff;
  font-size:.97em;
  font-weight:700;
  font-family:inherit;
  cursor:pointer;
  letter-spacing:.2px;
  transition:all .2s cubic-bezier(.4,0,.2,1);
  box-shadow:0 4px 18px rgba(0,0,0,.35),0 0 0 1px rgba(255,255,255,.06);
  position:relative;
  overflow:hidden;
  margin-bottom:6px;
}
.btn-github::before{
  content:'';
  position:absolute;inset:0;
  background:linear-gradient(135deg,rgba(255,255,255,.06),transparent);
  pointer-events:none;
}
.btn-github:hover{
  background:linear-gradient(135deg,#30363d,#3c444d);
  border-color:rgba(255,255,255,.28);
  box-shadow:0 6px 24px rgba(0,0,0,.40),0 0 0 1px rgba(255,255,255,.12);
  transform:translateY(-1px);
}
.btn-github:active{transform:translateY(0)}
.btn-github.loading{opacity:.7;pointer-events:none}

.gh-icon{
  display:flex;align-items:center;justify-content:center;
  flex-shrink:0;
}
.gh-icon svg{width:22px;height:22px;fill:#fff}

.btn-github-text{font-size:.93em}

/* GitHub badge */
.gh-badge{
  display:inline-flex;align-items:center;gap:5px;
  background:rgba(63,185,80,.10);
  border:1px solid rgba(63,185,80,.20);
  border-radius:100px;
  padding:3px 10px 3px 7px;
  font-size:.68em;
  color:#3fb950;
  font-weight:700;
  letter-spacing:.3px;
  margin-bottom:20px;
}
.gh-badge-dot{width:5px;height:5px;border-radius:50%;background:#3fb950;box-shadow:0 0 6px #3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* ── Divider ── */
.divider{
  display:flex;align-items:center;gap:10px;
  margin:22px 0 18px;
  color:#484f58;font-size:.72em;letter-spacing:.3px;text-transform:uppercase;font-weight:600;
}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.07)}

/* ── Password Form ── */
.form-group{margin-bottom:14px}
label{display:block;font-size:.72em;font-weight:600;color:#8b949e;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
input{
  width:100%;
  background:rgba(13,17,23,.8);
  border:1px solid rgba(255,255,255,.10);
  border-radius:10px;
  padding:10px 13px;
  color:#e6edf3;
  font-size:.88em;
  font-family:inherit;
  outline:none;
  transition:border-color .2s,box-shadow .2s;
}
input:focus{border-color:rgba(88,166,255,.5);box-shadow:0 0 0 3px rgba(88,166,255,.12)}
input::placeholder{color:#484f58}

.btn-login{
  width:100%;margin-top:6px;
  padding:11px;
  background:rgba(88,166,255,.12);
  border:1px solid rgba(88,166,255,.25);
  border-radius:10px;
  color:#58a6ff;
  font-size:.87em;
  font-weight:700;
  font-family:inherit;
  cursor:pointer;
  transition:all .18s;
}
.btn-login:hover{background:rgba(88,166,255,.20);border-color:rgba(88,166,255,.4);transform:translateY(-1px)}
.btn-login:active{transform:translateY(0)}

/* ── Error ── */
.error-msg{
  display:flex;align-items:center;gap:8px;
  background:rgba(244,112,103,.10);
  border:1px solid rgba(244,112,103,.28);
  border-radius:9px;
  padding:10px 13px;
  font-size:.80em;
  color:#f47067;
  margin-bottom:14px;
  animation:shake .35s cubic-bezier(.36,.07,.19,.97);
}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(3px)}30%,50%,70%{transform:translateX(-3px)}40%,60%{transform:translateX(3px)}}

/* ── Demo Quick Fill ── */
.demo-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px}
.demo-btn{
  background:rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.07);
  border-radius:8px;
  padding:8px 7px;
  text-align:center;
  cursor:pointer;
  transition:background .15s,border-color .15s,transform .12s;
  font-family:inherit;color:#8b949e;
}
.demo-btn:hover{background:rgba(255,255,255,.07);border-color:rgba(255,255,255,.14);transform:translateY(-1px)}
.demo-icon{font-size:1em;margin-bottom:2px}
.demo-label{font-size:.63em;font-weight:700;color:#58a6ff;display:block;letter-spacing:.3px}
.demo-creds{font-size:.58em;color:#484f58;display:block;margin-top:1px;font-family:'Courier New',monospace}

/* ── Footer ── */
.footer{text-align:center;margin-top:24px;font-size:.69em;color:#484f58}
.footer a{color:#58a6ff;text-decoration:none}

/* ── Collapse toggle ── */
details{margin-top:4px}
summary{
  font-size:.75em;color:#484f58;font-weight:600;cursor:pointer;
  list-style:none;text-align:center;padding:6px;letter-spacing:.3px;
  transition:color .15s;
}
summary:hover{color:#8b949e}
summary::-webkit-details-marker{display:none}
summary::before{content:'▸ '}
details[open] summary::before{content:'▾ '}
</style>
</head>
<body>
<div class="glow-tl"></div>
<div class="glow-br"></div>
<div class="glow-center"></div>

<div class="card">
  <div class="header">
    <div class="logo-wrap">${logo}</div>
    <div class="gh-badge">
      <span class="gh-badge-dot"></span>
      Sentinel Research System
    </div>
    <div class="title">Sign in to Sentinel</div>
    <div class="subtitle">Secure your code. Track your progress.</div>
  </div>

  ${githubErrorBlock}

  <!-- ── PRIMARY: GitHub OAuth ── -->
  <button id="githubBtn" class="btn-github" onclick="doGitHubLogin()">
    <span class="gh-icon">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
      </svg>
    </span>
    <span class="btn-github-text">Continue with GitHub</span>
  </button>

  <!-- ── SECONDARY: Password (collapsed, for admins/supervisors) ── -->
  <details>
    <summary>Sign in with username &amp; password</summary>

    <div style="padding-top:16px">
      ${errorBlock}

      <form id="loginForm" onsubmit="doPasswordLogin(event)">
        <div class="form-group">
          <label for="usernameInput">Username</label>
          <input id="usernameInput" type="text" placeholder="Enter your username" autocomplete="username">
        </div>
        <div class="form-group">
          <label for="passwordInput">Password</label>
          <input id="passwordInput" type="password" placeholder="Enter your password" autocomplete="current-password">
        </div>
        <button id="loginBtn" class="btn-login" type="submit">Sign In →</button>
      </form>

      <div style="margin-top:14px">
        <div style="font-size:.68em;color:#484f58;text-align:center;margin-bottom:8px;letter-spacing:.3px;font-weight:600;text-transform:uppercase">Quick Demo Fill</div>
        <div class="demo-grid">
          <button class="demo-btn" onclick="fill('supervisor01','sup123')">
            <div class="demo-icon">👁️</div>
            <span class="demo-label">Supervisor</span>
            <span class="demo-creds">supervisor01 / sup123</span>
          </button>
          <button class="demo-btn" onclick="fill('admin','admin123')">
            <div class="demo-icon">🔐</div>
            <span class="demo-label">Admin</span>
            <span class="demo-creds">admin / admin123</span>
          </button>
        </div>
      </div>
    </div>
  </details>

  <div class="footer">
    Developers: use <strong style="color:#58a6ff">GitHub</strong> · Supervisors &amp; Admins: use password
  </div>
</div>

<script>
const vscode = acquireVsCodeApi();

function doGitHubLogin() {
  const btn = document.getElementById('githubBtn');
  btn.classList.add('loading');
  btn.querySelector('.btn-github-text').textContent = 'Connecting to GitHub…';
  vscode.postMessage({ command: 'GITHUB_LOGIN' });
}

function fill(u, p) {
  document.getElementById('usernameInput').value = u;
  document.getElementById('passwordInput').value = p;
  document.getElementById('usernameInput').focus();
}

function doPasswordLogin(e) {
  e.preventDefault();
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value;
  if (!username || !password) { return; }
  const btn = document.getElementById('loginBtn');
  btn.textContent = 'Signing in…';
  btn.disabled = true;
  vscode.postMessage({ command: 'LOGIN', username, password });
}
</script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Header Bar (shown on all role dashboards after login) ────────────────────

/**
 * Returns a premium header bar HTML snippet with:
 *   - GitHub avatar (if available) or initials fallback
 *   - Display name + role badge
 *   - Auth method badge (GitHub / Password)
 *   - Sign Out button
 */
export function buildHeaderBar(session: AuthSession, _cspSource: string = ''): string {
  const roleColor =
    session.role === 'administrator' ? '#f47067' :
    session.role === 'supervisor'    ? '#d29922' :
                                       '#58a6ff';

  const roleIcon =
    session.role === 'administrator' ? '🔐' :
    session.role === 'supervisor'    ? '👁️' :
                                       '🧑‍💻';

  const roleLabel =
    session.role === 'administrator' ? 'Administrator' :
    session.role === 'supervisor'    ? 'Supervisor' :
                                       'Developer';

  // Avatar: GitHub profile picture or initials fallback
  // Append ?s=64 to request a 64 px image (GitHub CDN supports ?s=<size>)
  const avatarSrc = session.githubAvatarUrl
    ? `${escHtml(session.githubAvatarUrl)}${session.githubAvatarUrl.includes('?') ? '&' : '?'}s=64`
    : '';
  const initial = escHtml(session.displayName.charAt(0).toUpperCase());
  const avatarHtml = avatarSrc
    ? `<img
         src="${avatarSrc}"
         alt="${escHtml(session.displayName)}"
         class="auth-avatar-img"
         onerror="this.style.display='none';this.nextElementSibling.style.display='flex';"
       ><div class="auth-avatar-initials" style="display:none">${initial}</div>`
    : `<div class="auth-avatar-initials">${initial}</div>`;

  // Auth method badge
  const authBadge = session.authMethod === 'github'
    ? `<span class="auth-method-badge github">
         <svg viewBox="0 0 16 16" width="10" height="10" fill="currentColor">
           <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
         </svg>
         GitHub
       </span>`
    : `<span class="auth-method-badge password">🔑 Password</span>`;

  // GitHub username link (if available)
  const ghUsernameHtml = session.githubUsername
    ? `<div class="auth-gh-user">@${escHtml(session.githubUsername)}</div>`
    : '';

  return `
  <div class="auth-bar">
    <div class="auth-user">
      <div class="auth-avatar-wrap">${avatarHtml}</div>
      <div class="auth-info">
        <div class="auth-name">${escHtml(session.displayName)}${authBadge}</div>
        ${ghUsernameHtml}
        <div class="auth-role" style="color:${roleColor}">${roleIcon} ${roleLabel}</div>
      </div>
    </div>
    <button class="btn-logout" onclick="doLogout()">Sign Out</button>
  </div>
  <style>
  .auth-bar{
    display:flex;align-items:center;justify-content:space-between;
    padding:10px 22px;
    background:rgba(13,17,23,.95);
    border-bottom:1px solid rgba(255,255,255,.08);
    flex-wrap:wrap;gap:8px;
  }
  .auth-user{display:flex;align-items:center;gap:10px}
  .auth-avatar-wrap{flex-shrink:0}
  .auth-avatar-img{
    width:34px;height:34px;border-radius:50%;
    border:2px solid rgba(88,166,255,.35);
    object-fit:cover;display:block;
  }
  .auth-avatar-initials{
    width:34px;height:34px;border-radius:50%;
    background:linear-gradient(135deg,#1f6feb,#388bfd);
    display:flex;align-items:center;justify-content:center;
    font-weight:800;font-size:.9em;color:#fff;
    border:2px solid rgba(88,166,255,.35);
  }
  .auth-info{line-height:1.4}
  .auth-name{
    font-size:.83em;font-weight:700;color:#e6edf3;
    display:flex;align-items:center;gap:7px;flex-wrap:wrap;
  }
  .auth-gh-user{font-size:.70em;color:#8b949e;font-weight:500}
  .auth-role{font-size:.70em;font-weight:700}
  .auth-method-badge{
    display:inline-flex;align-items:center;gap:4px;
    border-radius:100px;
    padding:1px 7px;
    font-size:.62em;font-weight:700;letter-spacing:.2px;
  }
  .auth-method-badge.github{
    background:rgba(33,40,48,.9);
    border:1px solid rgba(255,255,255,.15);
    color:#cdd9e5;
  }
  .auth-method-badge.password{
    background:rgba(210,153,34,.12);
    border:1px solid rgba(210,153,34,.25);
    color:#d29922;
  }
  .btn-logout{
    background:rgba(244,112,103,.10);
    border:1px solid rgba(244,112,103,.22);
    border-radius:8px;
    padding:6px 14px;
    font-size:.75em;font-weight:700;color:#f47067;
    cursor:pointer;font-family:inherit;
    transition:background .15s,transform .12s;
  }
  .btn-logout:hover{background:rgba(244,112,103,.20);transform:translateY(-1px)}
  </style>
  <script>
  // NOTE: acquireVsCodeApi() is called ONCE by the page script below.
  // The header bar must NOT call it again — it would throw and break all navigation.
  // Instead we use window._vscode which the dashboard sets before anything else runs.
  function doLogout() {
    if (window._vscode) { window._vscode.postMessage({ command: 'LOGOUT' }); }
  }
  </script>`;
}
