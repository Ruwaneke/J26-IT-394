/**
 * Sentinel — Supervisor dashboard: page-specific styles and browser-side logic.
 *
 * The script runs inside the webview and expects these globals from supervisorDashboard.ts:
 *   vscode (webview API), DATA (snapshot of projects/shifts/sessions/developers/records), ICON (svg strings)
 *
 * Dates: <input type="date"> / <input type="time"> values are interpreted in the user's local
 * time zone and converted to ISO-8601 (UTC) before being sent to the extension.
 */

export const SUPERVISOR_CSS = `
.brand-tag.sup { color: var(--t-amber); background: rgba(245, 158, 11, 0.12); }
.nav-count.live-count { color: var(--t-green); font-weight: 700; }
textarea.input { resize: vertical; width: 100%; line-height: 1.45; }
.chip-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 6px; }
.chip { background: rgba(var(--ink), 0.05); border: 1px solid rgba(var(--ink), 0.1); color: var(--text-1); border-radius: 100px; padding: 4px 10px; font-size: 0.72em; font-weight: 600; cursor: pointer; font-family: inherit; }
.chip:hover { border-color: var(--t-cyan); color: var(--t-cyan); }
.chip.on { background: rgba(14, 165, 233, 0.14); border-color: var(--t-cyan); color: var(--t-cyan); }
.time-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.time-row .input[type="time"] { width: 120px; }
.time-row > .muted { font-size: 0.78em; }
.time-row .input[type="date"] { width: auto; flex: 1; min-width: 140px; }
.time-row .select { flex: 1; min-width: 180px; }
input[type="date"].input, input[type="time"].input { color-scheme: inherit; }
.st-pill { font-size: 0.68em; font-weight: 800; text-transform: uppercase; letter-spacing: 0.4px; padding: 3px 8px; border-radius: 100px; white-space: nowrap; }
.st-scheduled { color: var(--t-cyan); background: rgba(14, 165, 233, 0.12); }
.st-live, .st-active { color: var(--t-green); background: rgba(16, 185, 129, 0.14); }
.st-completed { color: var(--text-2); background: rgba(var(--ink), 0.07); }
.st-archived { color: var(--text-3); background: rgba(var(--ink), 0.06); }
.st-overdue { color: var(--t-amber); background: rgba(245, 158, 11, 0.14); }

/* Overview */
.live-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 12px; }
.live-card { border: 1px solid rgba(var(--ink), 0.08); border-left: 4px solid; border-radius: 10px; padding: 12px 14px; background: rgba(var(--ink), 0.02); }
.live-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.live-pill { display: inline-flex; align-items: center; gap: 5px; font-size: 0.64em; font-weight: 800; color: var(--t-green); letter-spacing: 0.6px; }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: #10b981; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }
.live-timer { font-size: 0.78em; color: var(--text-2); }
.live-stats { display: flex; gap: 14px; font-size: 0.74em; color: var(--text-2); margin-top: 8px; }
.live-stats strong { color: var(--text-strong); }
.agenda-row { display: flex; gap: 12px; align-items: center; padding: 9px 4px; border-bottom: 1px solid rgba(var(--ink), 0.05); cursor: pointer; border-radius: 8px; }
.agenda-row:hover { background: rgba(var(--ink), 0.03); }
.agenda-bar { width: 4px; align-self: stretch; border-radius: 4px; }
.agenda-time { font-size: 0.74em; line-height: 1.35; min-width: 44px; color: var(--text-1); }

/* Projects */
.proj-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
.proj-card { background: var(--card); border: 1px solid var(--border); border-top: 4px solid var(--pc); border-radius: 14px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
.proj-card.is-muted { opacity: 0.72; }
.proj-top { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
.proj-name { font-weight: 800; color: var(--text-strong); font-size: 0.98em; }
.proj-desc { font-size: 0.76em; color: var(--text-2); margin-top: 3px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.proj-stats { display: flex; justify-content: space-between; gap: 10px; font-size: 0.68em; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.3px; }
.proj-stats strong { display: block; font-size: 1.55em; color: var(--text-strong); letter-spacing: 0; }
.proj-next { font-size: 0.76em; color: var(--text-2); display: flex; gap: 6px; align-items: center; }
.proj-actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-top: auto; }
.proj-actions .icon-group { display: flex; gap: 2px; margin-left: auto; }
.empty-hero { text-align: center; padding: 48px 20px; border: 1px dashed var(--border); border-radius: 14px; color: var(--text-3); }
.swatches { display: flex; gap: 8px; flex-wrap: wrap; }
.swatch { width: 28px; height: 28px; border-radius: 50%; border: 2px solid transparent; cursor: pointer; box-shadow: inset 0 0 0 2px rgba(var(--ink), 0.08); }
.swatch.on { border-color: var(--text-strong); }

/* Shift list */
.day-group { margin-bottom: 18px; }
.day-label { font-size: 0.72em; font-weight: 800; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.6px; margin: 0 0 8px 2px; }
.shift-row { display: flex; gap: 12px; align-items: center; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; margin-bottom: 8px; }
.shift-row .agenda-bar { align-self: stretch; }
.shift-main { flex: 1; min-width: 0; cursor: pointer; }
.shift-meta { display: flex; gap: 10px; flex-wrap: wrap; font-size: 0.74em; color: var(--text-2); margin-top: 3px; }
.shift-meta .ico { color: var(--text-3); }
.dev-chips { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 6px; }
.dev-chip { font-size: 0.68em; font-weight: 600; color: var(--text-1); background: rgba(var(--ink), 0.06); border-radius: 100px; padding: 2px 8px; }
.dev-chip.live { color: var(--t-green); background: rgba(16, 185, 129, 0.12); }
.dev-chip.done { color: var(--t-cyan); background: rgba(14, 165, 233, 0.1); }

/* Calendar */
.cal-nav { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.cal-title { font-size: 1.05em; font-weight: 800; color: var(--text-strong); margin-bottom: 10px; }
.cal-grid { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; background: var(--card); }
.cal-dow { font-size: 0.66em; font-weight: 800; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; padding: 8px; border-bottom: 1px solid var(--border); background: rgba(var(--ink), 0.03); }
.cal-cell { min-height: 104px; padding: 6px; border-right: 1px solid rgba(var(--ink), 0.05); border-bottom: 1px solid rgba(var(--ink), 0.05); cursor: pointer; display: flex; flex-direction: column; gap: 3px; }
.cal-cell:nth-child(7n) { border-right: none; }
.cal-cell:hover { background: rgba(var(--ink), 0.03); }
.cal-cell.other { opacity: 0.45; }
.cal-cell.sel { box-shadow: inset 0 0 0 2px var(--t-cyan); }
.cal-num { font-size: 0.74em; font-weight: 700; color: var(--text-2); display: flex; justify-content: space-between; align-items: center; }
.cal-cell.today .cal-num span:first-child { background: #0ea5e9; color: #fff; border-radius: 100px; padding: 1px 7px; }
.cal-add { opacity: 0; color: var(--t-cyan); font-size: 12px; display: inline-flex; }
.cal-cell:hover .cal-add { opacity: 1; }
.cal-chip { font-size: 0.66em; font-weight: 600; color: var(--text-strong); border-left: 3px solid; background: rgba(var(--ink), 0.05); border-radius: 4px; padding: 2px 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cal-chip:hover { background: rgba(var(--ink), 0.1); }
.cal-chip.live { background: rgba(16, 185, 129, 0.14); }
.cal-more { font-size: 0.64em; color: var(--text-3); padding-left: 4px; }

/* Shift modal */
.modal-wide { width: min(920px, 100%); }
.sm-grid { display: grid; grid-template-columns: 1.15fr 1fr; gap: 20px; }
.sm-col { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
.sm-summary { font-size: 0.8em; color: var(--text-1); background: rgba(14, 165, 233, 0.08); border: 1px solid rgba(14, 165, 233, 0.22); border-radius: 10px; padding: 10px 12px; line-height: 1.5; }
.sm-summary .warn { color: var(--t-amber); font-weight: 600; }
.dev-pick { border: 1px solid var(--border); border-radius: 10px; max-height: 300px; overflow-y: auto; margin-top: 6px; }
.fg .dev-opt { text-transform: none; letter-spacing: 0; font-weight: 400; color: var(--text-1); }
.dev-opt { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-bottom: 1px solid rgba(var(--ink), 0.05); cursor: pointer; font-size: 0.8em; }
.dev-opt:last-child { border-bottom: none; }
.dev-opt:hover { background: rgba(var(--ink), 0.03); }
.dev-opt input { accent-color: #0ea5e9; width: 15px; height: 15px; }
.dev-opt .busy { margin-left: auto; font-size: 0.85em; color: var(--t-amber); font-weight: 600; }
.conflicts { margin-top: 10px; font-size: 0.76em; color: var(--t-amber); background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 10px; padding: 10px 12px; }
.conflicts ul { margin: 6px 0 0 16px; }

/* Reports */
.rep-form { grid-template-columns: 1.4fr 1.6fr 1fr 1fr auto; }
.rep-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
.rep-title { font-size: 1.05em; font-weight: 800; color: var(--text-strong); }
.rep-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.rec-list { margin: 0; padding-left: 18px; font-size: 0.8em; color: var(--text-1); line-height: 1.6; }
.sum-card { border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; margin-bottom: 8px; display: flex; gap: 14px; align-items: center; }
.sum-score { width: 46px; height: 46px; border-radius: 50%; border: 3px solid; display: flex; align-items: center; justify-content: center; font-weight: 800; flex-shrink: 0; }

/* Alerts */
.al-row { display: flex; gap: 12px; padding: 11px 6px; border-bottom: 1px solid rgba(var(--ink), 0.05); cursor: pointer; border-radius: 8px; }
.al-row:hover { background: rgba(var(--ink), 0.03); }
.al-row.unread .u-name::after { content: ''; display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--t-cyan); margin-left: 6px; vertical-align: middle; }
.al-ico { font-size: 16px; margin-top: 1px; }
.al-ico.info { color: var(--t-cyan); } .al-ico.success { color: var(--t-green); } .al-ico.warning { color: var(--t-amber); } .al-ico.critical { color: var(--t-red); }

@media (max-width: 900px) {
  .sm-grid { grid-template-columns: 1fr; }
  .rep-form { grid-template-columns: 1fr 1fr; }
  .cal-cell { min-height: 70px; }
  .cal-chip { font-size: 0.6em; }
}
`;

export const SUPERVISOR_CLIENT_JS = String.raw`
// ─── Utilities ──────────────────────────────────────────────────────────────
function post(msg) { vscode.postMessage(msg); }
function $(id) { return document.getElementById(id); }
function val(id) { var el = $(id); return el ? el.value : ''; }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function pad(n) { return (n < 10 ? '0' : '') + n; }
function ymd(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
function hm(d) { return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
function mins(t) { var p = (t || '0:0').split(':'); return parseInt(p[0], 10) * 60 + parseInt(p[1], 10); }
function fmtDay(d) { return new Date(d).toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short' }); }
function fmtDayLong(d) { return new Date(d).toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }); }
function fmtTime(d) { return new Date(d).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); }
function fmtDT(d) { return d ? fmtDay(d) + ' ' + fmtTime(d) : '—'; }
function durText(m) { m = Math.round(m); var h = Math.floor(m / 60), r = m % 60; return h ? h + 'h' + (r ? ' ' + r + 'm' : '') : r + 'm'; }
function scoreColor(n) { return n >= 80 ? '#10b981' : n >= 50 ? '#f59e0b' : '#ef4444'; }
function sevColor(s) { return { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' }[s] || '#60a5fa'; }
function projById(id) { return DATA.projects.find(function (p) { return p.id === id; }); }
function projColor(id) { var p = projById(id); return p ? p.color : '#3b82f6'; }
function devName(key) { var d = DATA.developers.find(function (x) { return x.key === key || x.username === key; }); return d ? d.name : key; }
function sameDev(a, b) { if (a === b) return true; var d = DATA.developers.find(function (x) { return x.key === a || x.username === a; }); return !!d && (d.key === b || d.username === b); }
function shiftSessions(id) { return DATA.sessions.filter(function (s) { return s.shiftId === id; }); }
function shiftState(sh) {
  var ss = shiftSessions(sh.id);
  if (ss.some(function (s) { return !s.end; })) return 'live';
  if (sh.status === 'completed') return 'completed';
  if (sh.status === 'scheduled' && Date.parse(sh.end) < Date.now()) return ss.length ? 'completed' : 'overdue';
  return sh.status === 'active' ? 'live' : sh.status;
}
function toast(ok, text) {
  var el = document.createElement('div');
  el.className = 'toast ' + (ok ? 'ok' : 'err');
  el.innerHTML = (ok ? ICON.ok : ICON.alert) + '<span>' + esc(text) + '</span>';
  $('toasts').appendChild(el);
  setTimeout(function () { el.remove(); }, 4500);
}
function closeModal(id) { $(id).classList.remove('open'); }
document.addEventListener('keydown', function (e) { if (e.key === 'Escape') document.querySelectorAll('.modal-back.open').forEach(function (m) { m.classList.remove('open'); }); });
function saveState(patch) { vscode.setState(Object.assign({}, vscode.getState() || {}, patch)); }

// ─── Navigation ─────────────────────────────────────────────────────────────
function showSection(id) {
  document.querySelectorAll('.section').forEach(function (s) { s.classList.remove('active'); });
  document.querySelectorAll('.nav-btn').forEach(function (b) { b.classList.remove('active'); });
  var sec = $('section-' + id); if (!sec) return;
  sec.classList.add('active');
  var nav = $('nav-' + id); if (nav) nav.classList.add('active');
  if (id === 'shifts') renderShiftList();
  if (id === 'calendar') renderCalendar();
  if (id === 'reports') renderSessionSummaries();
  saveState({ section: id });
}

// ─── Projects ───────────────────────────────────────────────────────────────
var pmColor = DATA.colors[0];
function openProjectModal(p) {
  $('pmId').value = p ? p.id : '';
  $('pmName').value = p ? p.name : '';
  $('pmDesc').value = p ? (p.description || '') : '';
  $('pmStatus').value = p ? p.status : 'active';
  $('pmStatusWrap').style.display = p ? '' : 'none';
  $('pmTitle').textContent = p ? 'Edit project' : 'New project';
  pmColor = p ? p.color : DATA.colors[DATA.projects.length % DATA.colors.length];
  $('pmColors').innerHTML = DATA.colors.map(function (c) {
    return '<button type="button" class="swatch' + (c === pmColor ? ' on' : '') + '" style="background:' + c + '" aria-label="Colour ' + c + '" onclick="pickColor(\'' + c + '\')"></button>';
  }).join('');
  $('projectModal').classList.add('open');
  $('pmName').focus();
}
function pickColor(c) { pmColor = c; document.querySelectorAll('#pmColors .swatch').forEach(function (s) { s.classList.toggle('on', s.style.background && s.getAttribute('aria-label') === 'Colour ' + c); }); }
function saveProject() {
  var name = val('pmName').trim();
  if (!name) { toast(false, 'Give the project a name.'); $('pmName').focus(); return; }
  var id = val('pmId');
  post(id
    ? { command: 'UPDATE_PROJECT', projectId: id, name: name, description: val('pmDesc'), color: pmColor, status: val('pmStatus') }
    : { command: 'CREATE_PROJECT', name: name, description: val('pmDesc'), color: pmColor });
  closeModal('projectModal');
}

// ─── Shift modal ────────────────────────────────────────────────────────────
var smSelected = [];
function openShiftModal(opts) {
  opts = opts || {};
  var activeProjects = DATA.projects.filter(function (p) { return p.status === 'active'; });
  if (!activeProjects.length) { toast(false, 'Create a project before scheduling shifts.'); showSection('projects'); return; }
  var sh = opts.shiftId ? DATA.shifts.find(function (s) { return s.id === opts.shiftId; }) : null;
  var dup = opts.duplicateOf ? DATA.shifts.find(function (s) { return s.id === opts.duplicateOf; }) : null;
  var src = sh || dup;
  $('smId').value = sh ? sh.id : '';
  $('smTitle').textContent = sh ? 'Edit shift' : dup ? 'Duplicate shift' : 'Schedule a shift';
  $('smSave').textContent = sh ? 'Save changes' : 'Schedule shift';
  $('smProject').value = src ? src.projectId : (opts.projectId || activeProjects[0].id);
  $('smProject').disabled = !!sh;
  $('smName').value = src ? src.name : '';
  $('smDesc').value = src ? (src.description || '') : '';
  var start, end;
  if (src) { start = new Date(src.start); end = new Date(src.end); if (dup) { start.setDate(start.getDate() + 7); end.setDate(end.getDate() + 7); } }
  else {
    var base = opts.date ? new Date(opts.date + 'T09:00') : new Date();
    if (!opts.date) { base.setMinutes(0, 0, 0); base.setHours(base.getHours() + 1); }
    start = base; end = new Date(base.getTime() + 4 * 3600000);
  }
  $('smDate').value = ymd(start); $('smStart').value = hm(start); $('smEnd').value = hm(end);
  $('smRepeat').value = 'none'; $('smUntil').value = '';
  $('smRepeatWrap').style.display = sh ? 'none' : '';
  smSelected = src ? src.devs.slice() : [];
  $('smDevSearch').value = '';
  $('shiftModal').classList.add('open');
  smUpdate();
  $('smName').focus();
}
function smQuickDate(k) {
  var d = new Date(); d.setHours(0, 0, 0, 0);
  if (k === 'mon') { d.setDate(d.getDate() + ((8 - d.getDay()) % 7 || 7)); } else { d.setDate(d.getDate() + k); }
  $('smDate').value = ymd(d); smUpdate();
}
function smPreset(a, b) { $('smStart').value = a; $('smEnd').value = b; smUpdate(); }
function smDuration(m) {
  var s = mins(val('smStart')) + m;
  $('smEnd').value = pad(Math.floor(s / 60) % 24) + ':' + pad(s % 60); smUpdate();
}
function smOccurrences() {
  var date = val('smDate'), s = val('smStart'), e = val('smEnd');
  if (!date || !s || !e) return [];
  var dur = mins(e) - mins(s); if (dur <= 0) dur += 1440;
  var rep = $('smRepeatWrap').style.display === 'none' ? 'none' : val('smRepeat');
  var until = rep === 'none' ? date : (val('smUntil') || date);
  var d = new Date(date + 'T00:00'), last = new Date(until + 'T00:00'), dow = d.getDay(), out = [];
  for (var i = 0; i < 400 && d <= last && out.length < 60; i++) {
    var inc = rep === 'none' ? i === 0 : rep === 'daily' ? true : rep === 'weekdays' ? (d.getDay() > 0 && d.getDay() < 6) : d.getDay() === dow;
    if (inc) { var st = new Date(ymd(d) + 'T' + s); out.push({ start: st.toISOString(), end: new Date(st.getTime() + dur * 60000).toISOString() }); }
    if (rep === 'none') break;
    d.setDate(d.getDate() + 1);
  }
  return out;
}
function smConflicts(occ) {
  var editId = val('smId'), list = [];
  smSelected.forEach(function (dev) {
    DATA.shifts.forEach(function (sh) {
      if (sh.id === editId || shiftState(sh) === 'completed') return;
      if (!sh.devs.some(function (x) { return sameDev(x, dev); })) return;
      occ.forEach(function (o) {
        if (Date.parse(o.start) < Date.parse(sh.end) && Date.parse(o.end) > Date.parse(sh.start)) list.push({ dev: dev, shift: sh });
      });
    });
  });
  return list;
}
function smUpdate() {
  var rep = val('smRepeat'), showUntil = rep !== 'none' && $('smRepeatWrap').style.display !== 'none';
  $('smUntil').style.display = showUntil ? '' : 'none'; $('smUntilLbl').style.display = showUntil ? '' : 'none';
  if (showUntil && !val('smUntil') && val('smDate')) { var u = new Date(val('smDate') + 'T00:00'); u.setDate(u.getDate() + (rep === 'weekly' ? 28 : 6)); $('smUntil').value = ymd(u); }
  var occ = smOccurrences(), html = '';
  if (!occ.length) { html = 'Pick a date and a start and end time.'; }
  else {
    var dur = (Date.parse(occ[0].end) - Date.parse(occ[0].start)) / 60000;
    var overnight = new Date(occ[0].end).getDate() !== new Date(occ[0].start).getDate();
    html = '<strong>' + fmtDayLong(occ[0].start) + '</strong><br>' + fmtTime(occ[0].start) + ' → ' + fmtTime(occ[0].end) + ' · ' + durText(dur)
      + (overnight ? ' <span class="warn">(ends next day)</span>' : '');
    if (occ.length > 1) html += '<br>Repeats: <strong>' + occ.length + ' shifts</strong> until ' + fmtDay(occ[occ.length - 1].start) + (occ.length >= 60 ? ' <span class="warn">(max 60)</span>' : '');
    if (Date.parse(occ[0].start) < Date.now() && !val('smId')) html += '<br><span class="warn">This start time is in the past.</span>';
    if (dur > 12 * 60) html += '<br><span class="warn">Longer than 12 hours.</span>';
  }
  $('smSummary').innerHTML = html;
  smRenderDevs(occ);
}
function smRenderDevs(occ) {
  occ = occ || smOccurrences();
  var q = val('smDevSearch').toLowerCase();
  var busy = {};
  DATA.developers.forEach(function (d) {
    DATA.shifts.forEach(function (sh) {
      if (sh.id === val('smId') || shiftState(sh) === 'completed') return;
      if (!sh.devs.some(function (x) { return sameDev(x, d.key); })) return;
      if (occ.some(function (o) { return Date.parse(o.start) < Date.parse(sh.end) && Date.parse(o.end) > Date.parse(sh.start); })) busy[d.key] = sh.name;
    });
  });
  var devs = DATA.developers.filter(function (d) { return !q || (d.name + ' ' + d.key).toLowerCase().indexOf(q) >= 0; });
  $('smDevs').innerHTML = devs.length ? devs.map(function (d) {
    var on = smSelected.some(function (x) { return sameDev(x, d.key); });
    return '<label class="dev-opt"><input type="checkbox"' + (on ? ' checked' : '') + ' onchange="smToggleDev(\'' + esc(d.key) + '\', this.checked)">'
      + '<span><strong>' + esc(d.name) + '</strong> <span class="muted">@' + esc(d.key) + '</span></span>'
      + (busy[d.key] ? '<span class="busy">Busy: ' + esc(busy[d.key]) + '</span>' : '') + '</label>';
  }).join('') : '<div class="empty" style="border:none">No developers match.</div>';
  var c = smConflicts(occ);
  $('smConflicts').innerHTML = c.length ? '<div class="conflicts">' + ICON.alert + ' <strong>Scheduling conflicts</strong> — you can still save.<ul>'
    + c.slice(0, 6).map(function (x) { return '<li>' + esc(devName(x.dev)) + ' is already on "' + esc(x.shift.name) + '" (' + fmtDT(x.shift.start) + ')</li>'; }).join('') + '</ul></div>' : '';
  $('smFootNote').textContent = smSelected.length + ' developer' + (smSelected.length === 1 ? '' : 's') + ' selected' + (occ.length > 1 ? ' · ' + occ.length + ' shifts' : '');
}
function smToggleDev(key, on) {
  smSelected = smSelected.filter(function (x) { return !sameDev(x, key); });
  if (on) smSelected.push(key);
  smRenderDevs();
}
function smAllDevs(on) { smSelected = on ? DATA.developers.map(function (d) { return d.key; }) : []; smRenderDevs(); }
function saveShift() {
  var name = val('smName').trim(), occ = smOccurrences();
  if (!val('smProject')) { toast(false, 'Choose a project.'); return; }
  if (!name) { toast(false, 'Give the shift a name.'); $('smName').focus(); return; }
  if (!occ.length) { toast(false, 'Choose a date and time.'); return; }
  var names = smSelected.map(devName), id = val('smId');
  if (id) post({ command: 'UPDATE_SHIFT', shiftId: id, name: name, description: val('smDesc'), scheduledStart: occ[0].start, scheduledEnd: occ[0].end, developerIds: smSelected, developerNames: names });
  else post({ command: 'CREATE_SHIFT', projectId: val('smProject'), name: name, description: val('smDesc'), occurrences: occ, developerIds: smSelected, developerNames: names });
  closeModal('shiftModal');
}

// ─── Shift detail ───────────────────────────────────────────────────────────
function openShiftDetail(id) {
  var sh = DATA.shifts.find(function (s) { return s.id === id; }); if (!sh) return;
  var ss = shiftSessions(id), st = shiftState(sh), p = projById(sh.projectId);
  $('sdTitle').textContent = sh.name;
  var h = '<div class="kv"><span>Project</span><strong><span class="sev-dot" style="background:' + projColor(sh.projectId) + '"></span> ' + esc(sh.projectName) + '</strong></div>'
    + '<div class="kv"><span>When</span><strong>' + fmtDayLong(sh.start) + ', ' + fmtTime(sh.start) + ' – ' + fmtTime(sh.end) + ' (' + durText((Date.parse(sh.end) - Date.parse(sh.start)) / 60000) + ')</strong></div>'
    + '<div class="kv"><span>Status</span><strong><span class="st-pill st-' + st + '">' + st + '</span></strong></div>'
    + (sh.description ? '<div class="kv"><span>Notes</span><strong>' + esc(sh.description) + '</strong></div>' : '')
    + '<div class="kv"><span>Developers</span><strong>' + (sh.devs.map(function (d) { return esc(devName(d)); }).join(', ') || '<span class="muted">None assigned</span>') + '</strong></div>';
  h += '<div class="card-title" style="margin-top:16px">' + ICON.users + ' Sessions</div>';
  h += ss.length ? '<table class="data"><thead><tr><th>Developer</th><th>Started</th><th>Ended</th><th class="num">Findings</th><th class="num">Critical</th><th class="num">Score</th></tr></thead><tbody>'
    + ss.map(function (s) {
      var crit = s.findings.filter(function (f) { return f.s === 'CRITICAL'; }).length;
      return '<tr><td>' + esc(s.devName) + '</td><td class="nowrap">' + fmtDT(s.start) + '</td><td class="nowrap">' + (s.end ? fmtDT(s.end) : '<span class="st-pill st-live">Live</span>') + '</td><td class="num">' + s.findings.length + '</td><td class="num">' + crit + '</td><td class="num">' + (s.summary ? '<strong style="color:' + scoreColor(s.summary.score) + '">' + s.summary.score + '</strong>' : '—') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="empty">No developer has started this shift yet.</div>';
  $('sdBody').innerHTML = h;
  var editable = st !== 'completed' && st !== 'live';
  $('sdFoot').innerHTML = (editable ? '<button class="btn btn-danger" style="margin-right:auto" onclick="cancelShift(\'' + sh.id + '\')">' + ICON.trash + ' Cancel shift</button>' : '<span style="margin-right:auto"></span>')
    + '<button class="btn btn-secondary" onclick="closeModal(\'detailModal\'); showSection(\'reports\'); setReportScope(\'shift:' + sh.id + '\')">' + ICON.file + ' Report</button>'
    + '<button class="btn btn-secondary" onclick="closeModal(\'detailModal\'); openShiftModal({ duplicateOf: \'' + sh.id + '\' })">' + ICON.copy + ' Duplicate</button>'
    + (editable && p && p.status === 'active' ? '<button class="btn btn-primary" onclick="closeModal(\'detailModal\'); openShiftModal({ shiftId: \'' + sh.id + '\' })">' + ICON.pen + ' Edit</button>' : '');
  $('detailModal').classList.add('open');
}
function cancelShift(id) { closeModal('detailModal'); post({ command: 'DELETE_SHIFT', shiftId: id }); }

// ─── Shift list ─────────────────────────────────────────────────────────────
function setShiftFilter(projectId) { $('sfProject').value = projectId; $('sfStatus').value = 'all'; renderShiftList(); }
function renderShiftList() {
  var pf = val('sfProject'), sf = val('sfStatus'), q = val('sfSearch').toLowerCase();
  saveState({ sf: { p: pf, s: sf } });
  var list = DATA.shifts.filter(function (sh) {
    var st = shiftState(sh);
    if (pf && sh.projectId !== pf) return false;
    if (sf === 'upcoming' && !(st === 'live' || st === 'scheduled' || st === 'overdue')) return false;
    if (sf === 'live' && st !== 'live') return false;
    if (sf === 'scheduled' && st !== 'scheduled') return false;
    if (sf === 'completed' && st !== 'completed') return false;
    if (q && (sh.name + ' ' + sh.projectName + ' ' + sh.devs.map(devName).join(' ')).toLowerCase().indexOf(q) < 0) return false;
    return true;
  }).sort(function (a, b) { return sf === 'completed' ? b.start.localeCompare(a.start) : a.start.localeCompare(b.start); });
  if (!list.length) { $('shiftList').innerHTML = '<div class="empty-hero">' + ICON.cal + '<div class="u-name" style="margin-top:8px">No shifts here</div><div class="muted" style="font-size:.85em;margin:4px 0 14px">Try another filter, or schedule a new shift.</div><button class="btn btn-primary" onclick="openShiftModal({ projectId: val(\'sfProject\') || undefined })">' + ICON.plus + ' Schedule shift</button></div>'; return; }
  var groups = {}, order = [];
  list.forEach(function (sh) { var k = ymd(new Date(sh.start)); if (!groups[k]) { groups[k] = []; order.push(k); } groups[k].push(sh); });
  var today = ymd(new Date()), tmr = new Date(); tmr.setDate(tmr.getDate() + 1); tmr = ymd(tmr);
  $('shiftList').innerHTML = order.map(function (k) {
    var label = k === today ? 'Today · ' + fmtDay(k + 'T00:00') : k === tmr ? 'Tomorrow · ' + fmtDay(k + 'T00:00') : fmtDayLong(k + 'T00:00');
    return '<div class="day-group"><div class="day-label">' + label + '</div>' + groups[k].map(shiftRowHtml).join('') + '</div>';
  }).join('');
}
function shiftRowHtml(sh) {
  var st = shiftState(sh), ss = shiftSessions(sh.id);
  var chips = sh.devs.map(function (d) {
    var s = ss.find(function (x) { return sameDev(x.dev, d); });
    return '<span class="dev-chip' + (s ? (s.end ? ' done' : ' live') : '') + '">' + esc(devName(d)) + '</span>';
  }).join('') || '<span class="muted" style="font-size:.72em">No developers assigned</span>';
  var editable = st !== 'completed' && st !== 'live';
  return '<div class="shift-row"><span class="agenda-bar" style="background:' + projColor(sh.projectId) + '"></span>'
    + '<div class="shift-main" onclick="openShiftDetail(\'' + sh.id + '\')"><div class="u-name">' + esc(sh.name) + '</div>'
    + '<div class="shift-meta"><span>' + ICON.clock + ' ' + fmtTime(sh.start) + ' – ' + fmtTime(sh.end) + ' (' + durText((Date.parse(sh.end) - Date.parse(sh.start)) / 60000) + ')</span><span>' + ICON.folder + ' ' + esc(sh.projectName) + '</span>'
    + (ss.length ? '<span>' + ss.filter(function (s) { return !s.end; }).length + ' live · ' + ss.filter(function (s) { return s.end; }).length + ' done</span>' : '') + '</div>'
    + '<div class="dev-chips">' + chips + '</div></div>'
    + '<span class="st-pill st-' + st + '">' + st + '</span>'
    + '<div class="actions">' + (editable ? '<button class="btn-ghost" title="Edit" onclick="openShiftModal({ shiftId: \'' + sh.id + '\' })">' + ICON.pen + '</button>' : '')
    + '<button class="btn-ghost" title="Duplicate" onclick="openShiftModal({ duplicateOf: \'' + sh.id + '\' })">' + ICON.copy + '</button>'
    + (editable ? '<button class="btn-ghost danger" title="Cancel shift" onclick="cancelShift(\'' + sh.id + '\')">' + ICON.trash + '</button>' : '') + '</div></div>';
}

// ─── Calendar ───────────────────────────────────────────────────────────────
var cal = (function () { var st = vscode.getState() || {}; var d = st.cal ? new Date(st.cal) : new Date(); return { y: d.getFullYear(), m: d.getMonth(), sel: ymd(new Date()) }; })();
function calMove(n) { cal.m += n; if (cal.m < 0) { cal.m = 11; cal.y--; } if (cal.m > 11) { cal.m = 0; cal.y++; } renderCalendar(); }
function calToday() { var d = new Date(); cal.y = d.getFullYear(); cal.m = d.getMonth(); cal.sel = ymd(d); renderCalendar(); }
function shiftsOnDay(key) {
  var pf = val('calProject'), dayStart = Date.parse(key + 'T00:00'), dayEnd = dayStart + 864e5;
  return DATA.shifts.filter(function (sh) { return (!pf || sh.projectId === pf) && Date.parse(sh.start) < dayEnd && Date.parse(sh.end) > dayStart; })
    .sort(function (a, b) { return a.start.localeCompare(b.start); });
}
function renderCalendar() {
  saveState({ cal: new Date(cal.y, cal.m, 1).toISOString() });
  $('calTitle').textContent = new Date(cal.y, cal.m, 1).toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
  var first = new Date(cal.y, cal.m, 1), offset = (first.getDay() + 6) % 7, start = new Date(cal.y, cal.m, 1 - offset), today = ymd(new Date());
  var h = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map(function (d) { return '<div class="cal-dow">' + d + '</div>'; }).join('');
  for (var i = 0; i < 42; i++) {
    var d = new Date(start); d.setDate(start.getDate() + i);
    var key = ymd(d), items = shiftsOnDay(key);
    h += '<div class="cal-cell' + (d.getMonth() !== cal.m ? ' other' : '') + (key === today ? ' today' : '') + (key === cal.sel ? ' sel' : '') + '" onclick="calSelect(\'' + key + '\')" ondblclick="openShiftModal({ date: \'' + key + '\' })">'
      + '<div class="cal-num"><span>' + d.getDate() + '</span><span class="cal-add" title="Schedule on this day" onclick="event.stopPropagation(); openShiftModal({ date: \'' + key + '\' })">' + ICON.plus + '</span></div>'
      + items.slice(0, 3).map(function (sh) {
        return '<div class="cal-chip' + (shiftState(sh) === 'live' ? ' live' : '') + '" style="border-left-color:' + projColor(sh.projectId) + '" title="' + esc(sh.name + ' — ' + fmtTime(sh.start) + '–' + fmtTime(sh.end)) + '" onclick="event.stopPropagation(); openShiftDetail(\'' + sh.id + '\')">' + fmtTime(sh.start) + ' ' + esc(sh.name) + '</div>';
      }).join('') + (items.length > 3 ? '<div class="cal-more">+' + (items.length - 3) + ' more</div>' : '') + '</div>';
    if (i === 34 && new Date(start.getTime() + 35 * 864e5).getMonth() !== cal.m) break;
  }
  $('calGrid').innerHTML = h;
  renderCalDay();
}
function calSelect(key) { cal.sel = key; renderCalendar(); }
function renderCalDay() {
  var items = shiftsOnDay(cal.sel);
  $('calDayTitle').innerHTML = ICON.cal + ' ' + fmtDayLong(cal.sel + 'T00:00');
  $('calDayList').innerHTML = (items.length ? items.map(shiftRowHtml).join('') : '<div class="empty">No shifts on this day.</div>')
    + '<div style="margin-top:10px"><button class="btn btn-primary" onclick="openShiftModal({ date: \'' + cal.sel + '\' })">' + ICON.plus + ' Schedule on this day</button></div>';
}

// ─── Team & announcements ───────────────────────────────────────────────────
function filterTeam() {
  var q = val('teamSearch').toLowerCase();
  document.querySelectorAll('#teamTable .team-row').forEach(function (r) { r.style.display = !q || r.dataset.search.indexOf(q) >= 0 ? '' : 'none'; });
}
function openAnnounce(aud, target) {
  $('amAudience').value = aud; $('amTarget').value = target || '';
  $('amTitle').textContent = aud === 'dev' ? 'Message ' + devName(target) : 'Message all developers';
  $('amTitleIn').value = ''; $('amMsg').value = ''; $('amLevel').value = 'info';
  $('announceModal').classList.add('open'); $('amTitleIn').focus();
}
function sendAnnounceModal() {
  var t = val('amTitleIn').trim(), m = val('amMsg').trim();
  if (!t || !m) { toast(false, 'Add a title and a message.'); return; }
  post({ command: 'ANNOUNCE', audience: val('amAudience'), target: val('amTarget'), level: val('amLevel'), title: t, message: m });
  closeModal('announceModal');
}
function anAudienceChanged() { var a = val('anAudience'); $('anProjectWrap').style.display = a === 'project' ? '' : 'none'; $('anDevWrap').style.display = a === 'dev' ? '' : 'none'; }
function sendAnnouncement() {
  var a = val('anAudience'), t = val('anTitle').trim(), m = val('anMsg').trim();
  if (!t || !m) { toast(false, 'Add a title and a message.'); return; }
  post({ command: 'ANNOUNCE', audience: a, target: a === 'project' ? val('anProject') : a === 'dev' ? val('anDev') : '', level: val('anLevel'), title: t, message: m });
  $('anTitle').value = ''; $('anMsg').value = '';
}
function savePrefs() { post({ command: 'SET_NOTIFICATION_PREFS', reminderMinutes: parseInt(val('prReminder'), 10), popups: val('prPopups') }); }

// ─── Alerts list (fed by the shared NOTIFICATIONS message) ──────────────────
var alertItems = [];
function renderAlerts() {
  var f = val('alFilter');
  var items = alertItems.filter(function (n) {
    return !f || (f === 'unread' ? n.unread : f === 'critical' || f === 'warning' ? n.level === f : n.category === f);
  });
  var icons = { info: ICON.info, success: ICON.ok, warning: ICON.alert, critical: ICON.crit };
  $('alertList').innerHTML = items.length ? items.map(function (n) {
    return '<div class="al-row' + (n.unread ? ' unread' : '') + '" onclick="ntfOpen(\'' + esc(n.id) + '\')"><span class="al-ico ' + n.level + '">' + (icons[n.level] || ICON.info) + '</span>'
      + '<div style="flex:1;min-width:0"><div class="u-name">' + esc(n.title) + '</div><div class="u-sub" style="font-size:.78em;margin-top:2px">' + esc(n.message) + '</div></div>'
      + '<span class="muted nowrap" style="font-size:.72em">' + fmtDT(n.createdAt) + '</span></div>';
  }).join('') : '<div class="empty">No notifications.</div>';
}
window.addEventListener('message', function (e) {
  var m = e.data || {};
  if (m.command === 'NOTIFICATIONS') {
    alertItems = m.items || []; renderAlerts();
    $('navAlertCount').textContent = m.unread ? m.unread + ' new' : '';
  }
  if (m.command === 'SUP_RESULT') toast(m.success, m.message);
});

// ─── Reports ────────────────────────────────────────────────────────────────
var lastReport = null;
function setReportScope(v) { $('rpScope').value = v; generateReport(); }
function rpPreset(k) {
  var to = new Date(), from = new Date();
  if (k === 'all') { $('rpFrom').value = ''; $('rpTo').value = ''; }
  else { if (k === 'month') from = new Date(to.getFullYear(), to.getMonth(), 1); else from.setDate(to.getDate() - (k - 1)); $('rpFrom').value = ymd(from); $('rpTo').value = ymd(to); }
  document.querySelectorAll('#rpPresets .chip').forEach(function (c, i) { c.classList.toggle('on', [7, 30, 'month', 'all'][i] === k); });
}
function generateReport() {
  var scope = val('rpScope'), from = val('rpFrom'), to = val('rpTo');
  var f = from ? Date.parse(from + 'T00:00') : -Infinity, t = to ? Date.parse(to + 'T23:59:59') : Infinity;
  var kind = scope.split(':')[0], key = scope.slice(kind.length + 1);
  var inRange = function (iso) { var x = Date.parse(iso); return x >= f && x <= t; };
  var shifts = DATA.shifts.filter(function (s) {
    if (!inRange(s.start)) return false;
    return kind === 'all' || (kind === 'proj' && s.projectId === key) || (kind === 'shift' && s.id === key) || (kind === 'dev' && s.devs.some(function (d) { return sameDev(d, key); }));
  });
  var sessions = DATA.sessions.filter(function (s) {
    if (!inRange(s.start)) return false;
    return kind === 'all' || (kind === 'proj' && s.projectId === key) || (kind === 'shift' && s.shiftId === key) || (kind === 'dev' && sameDev(s.dev, key));
  });
  var devKeys = {};
  if (kind === 'dev') devKeys[key] = 1;
  else if (kind === 'all') DATA.developers.forEach(function (d) { devKeys[d.key] = 1; });
  else shifts.forEach(function (s) { s.devs.forEach(function (d) { devKeys[d] = 1; }); });
  var records = DATA.records.filter(function (r) { return inRange(r.at) && Object.keys(devKeys).some(function (k) { return sameDev(r.d, k); }); });

  var sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, types = {}, recs = {}, minutes = 0, findings = 0;
  sessions.forEach(function (s) {
    s.findings.forEach(function (x) { findings++; if (sev[x.s] !== undefined) sev[x.s]++; types[x.t] = (types[x.t] || 0) + 1; });
    if (s.end) minutes += (Date.parse(s.end) - Date.parse(s.start)) / 60000;
    if (s.summary) s.summary.recs.forEach(function (r) { recs[r] = (recs[r] || 0) + 1; });
  });
  var done = sessions.filter(function (s) { return s.summary; });
  var avgScore = done.length ? Math.round(done.reduce(function (a, s) { return a + s.summary.score; }, 0) / done.length) : null;
  var fixed = records.filter(function (r) { return r.st === 'FIXED'; }).length;
  var perDev = Object.keys(devKeys).map(function (k) {
    var ds = sessions.filter(function (s) { return sameDev(s.dev, k); }), dd = ds.filter(function (s) { return s.summary; });
    var dr = records.filter(function (r) { return sameDev(r.d, k); }), df = dr.filter(function (r) { return r.st === 'FIXED'; }).length;
    return {
      developer: devName(k), key: k, sessions: ds.length,
      minutes: Math.round(ds.reduce(function (a, s) { return a + (s.end ? (Date.parse(s.end) - Date.parse(s.start)) / 60000 : 0); }, 0)),
      findings: ds.reduce(function (a, s) { return a + s.findings.length; }, 0),
      critical: ds.reduce(function (a, s) { return a + s.findings.filter(function (x) { return x.s === 'CRITICAL'; }).length; }, 0),
      avgScore: dd.length ? Math.round(dd.reduce(function (a, s) { return a + s.summary.score; }, 0) / dd.length) : null,
      detected: dr.length, fixed: df, fixRate: dr.length ? Math.round(df / dr.length * 1000) / 10 : null
    };
  }).sort(function (a, b) { return b.findings - a.findings; });

  var scopeLabel = $('rpScope').options[$('rpScope').selectedIndex].text;
  lastReport = {
    title: 'Sentinel security report — ' + scopeLabel,
    scope: scopeLabel, from: from || null, to: to || null, generatedAt: new Date().toISOString(), generatedBy: DATA.me.name,
    totals: { shifts: shifts.length, sessions: sessions.length, completedSessions: done.length, hours: Math.round(minutes / 6) / 10, findings: findings,
      critical: sev.CRITICAL, avgShiftScore: avgScore, recordsDetected: records.length, recordsFixed: fixed, fixRate: records.length ? Math.round(fixed / records.length * 1000) / 10 : null },
    severity: sev,
    topTypes: Object.keys(types).map(function (k) { return { type: k, count: types[k] }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, 8),
    developers: perDev,
    sessions: sessions.map(function (s) { return { developer: s.devName, shift: s.shiftName, project: s.projectName, started: s.start, ended: s.end,
      minutes: s.end ? Math.round((Date.parse(s.end) - Date.parse(s.start)) / 60000) : null, findings: s.findings.length,
      critical: s.summary ? s.summary.crit : null, high: s.summary ? s.summary.high : null, medium: s.summary ? s.summary.med : null, low: s.summary ? s.summary.low : null,
      score: s.summary ? s.summary.score : null }; }).sort(function (a, b) { return b.started.localeCompare(a.started); }),
    recommendations: Object.keys(recs).sort(function (a, b) { return recs[b] - recs[a]; }).slice(0, 6)
  };
  renderReport(lastReport);
}
function bar(label, v, max, color) {
  var w = max > 0 && v > 0 ? Math.max(2, v / max * 100) : 0;
  return '<div class="bar-row"><div class="bar-label">' + label + '</div><div class="bar-track"><div class="bar-fill" style="width:' + w + '%;background:' + color + '"></div></div><div class="bar-value">' + v + '</div></div>';
}
function renderReport(r) {
  var T = r.totals, sevMax = Math.max.apply(null, [1].concat(Object.keys(r.severity).map(function (k) { return r.severity[k]; })));
  var typeMax = Math.max.apply(null, [1].concat(r.topTypes.map(function (x) { return x.count; })));
  var period = r.from || r.to ? (r.from ? fmtDay(r.from + 'T00:00') : 'start') + ' – ' + (r.to ? fmtDay(r.to + 'T00:00') : 'today') : 'All time';
  var k = function (lbl, v, note, color) { return '<div class="kpi"><div class="kpi-lbl">' + lbl + '</div><div class="kpi-num"' + (color ? ' style="color:' + color + '"' : '') + '>' + v + '</div><div class="kpi-note">' + note + '</div></div>'; };
  var h = '<div class="card"><div class="rep-head"><div><div class="rep-title">' + esc(r.scope) + '</div><div class="muted" style="font-size:.78em">' + period + ' · generated ' + fmtDT(r.generatedAt) + '</div></div>'
    + '<div class="rep-actions"><button class="btn btn-secondary" onclick="exportReport(\'csv\')">' + ICON.download + ' CSV</button><button class="btn btn-secondary" onclick="exportReport(\'json\')">' + ICON.download + ' JSON</button><button class="btn btn-primary" onclick="exportReport(\'html\')">' + ICON.file + ' HTML report</button></div></div>'
    + '<div class="kpis">' + k('Shifts', T.shifts, T.sessions + ' sessions') + k('Hours', T.hours, T.completedSessions + ' completed sessions')
    + k('Findings', T.findings, T.critical + ' critical', T.critical ? '#ef4444' : '') + k('Avg shift score', T.avgShiftScore == null ? '—' : T.avgShiftScore, 'per completed session', T.avgShiftScore == null ? '' : scoreColor(T.avgShiftScore))
    + k('Fix rate', T.fixRate == null ? '—' : T.fixRate + '%', T.recordsFixed + ' of ' + T.recordsDetected + ' recorded', T.fixRate == null ? '' : scoreColor(T.fixRate)) + '</div>'
    + '<div class="grid-2" style="margin-bottom:0"><div class="card" style="margin:0"><div class="card-title">Findings by severity</div><div class="bar-list">'
    + ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (s) { return bar('<span class="sev-dot" style="background:' + sevColor(s) + '"></span>' + s, r.severity[s], sevMax, sevColor(s)); }).join('') + '</div></div>'
    + '<div class="card" style="margin:0"><div class="card-title">Top vulnerability types</div><div class="bar-list">'
    + (r.topTypes.length ? r.topTypes.map(function (x) { return bar(esc(x.type.replace(/_/g, ' ')), x.count, typeMax, '#3b82f6'); }).join('') : '<div class="empty">No findings in this period.</div>') + '</div></div></div></div>';
  h += '<div class="card"><div class="card-title">' + ICON.users + ' Developers</div>' + (r.developers.length ? '<div class="table-wrap"><table class="data"><thead><tr><th>Developer</th><th class="num">Sessions</th><th class="num">Hours</th><th class="num">Findings</th><th class="num">Critical</th><th class="num">Avg score</th><th class="num">Fix rate</th></tr></thead><tbody>'
    + r.developers.map(function (d) { return '<tr><td><div class="u-name">' + esc(d.developer) + '</div><div class="u-sub">@' + esc(d.key) + '</div></td><td class="num">' + d.sessions + '</td><td class="num">' + (Math.round(d.minutes / 6) / 10) + '</td><td class="num">' + d.findings + '</td><td class="num">' + d.critical + '</td><td class="num">' + (d.avgScore == null ? '—' : '<strong style="color:' + scoreColor(d.avgScore) + '">' + d.avgScore + '</strong>') + '</td><td class="num">' + (d.fixRate == null ? '—' : d.fixRate + '%') + '</td></tr>'; }).join('')
    + '</tbody></table></div>' : '<div class="empty">No developers in scope.</div>') + '</div>';
  h += '<div class="card"><div class="card-title">' + ICON.clock + ' Sessions</div>' + (r.sessions.length ? '<div class="table-wrap"><table class="data"><thead><tr><th>Developer</th><th>Shift</th><th>Started</th><th class="num">Minutes</th><th class="num">Findings</th><th class="num">Score</th></tr></thead><tbody>'
    + r.sessions.slice(0, 50).map(function (s) { return '<tr><td>' + esc(s.developer) + '</td><td>' + esc(s.shift) + '<div class="u-sub">' + esc(s.project) + '</div></td><td class="nowrap">' + fmtDT(s.started) + '</td><td class="num">' + (s.minutes == null ? '<span class="st-pill st-live">Live</span>' : s.minutes) + '</td><td class="num">' + s.findings + '</td><td class="num">' + (s.score == null ? '—' : '<strong style="color:' + scoreColor(s.score) + '">' + s.score + '</strong>') + '</td></tr>'; }).join('')
    + '</tbody></table></div>' : '<div class="empty">No sessions in this period.</div>') + '</div>';
  if (r.recommendations.length) h += '<div class="card"><div class="card-title">' + ICON.info + ' Recommendations</div><ol class="rec-list">' + r.recommendations.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ol></div>';
  $('reportOut').innerHTML = h;
}
function csvCell(v) { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function exportReport(fmt) {
  var r = lastReport; if (!r) { toast(false, 'Generate a report first.'); return; }
  var base = 'sentinel-report-' + r.scope.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) + '-' + ymd(new Date());
  var content;
  if (fmt === 'json') content = JSON.stringify(r, null, 2);
  else if (fmt === 'csv') {
    var rows = [['Report', r.title], ['Period', (r.from || 'start') + ' to ' + (r.to || 'today')], ['Generated', r.generatedAt], [],
      ['Developer', 'Shift', 'Project', 'Started', 'Ended', 'Minutes', 'Findings', 'Critical', 'High', 'Medium', 'Low', 'Score']];
    r.sessions.forEach(function (s) { rows.push([s.developer, s.shift, s.project, s.started, s.ended, s.minutes, s.findings, s.critical, s.high, s.medium, s.low, s.score]); });
    rows.push([]); rows.push(['Developer', 'Username', 'Sessions', 'Minutes', 'Findings', 'Critical', 'Avg score', 'Detected', 'Fixed', 'Fix rate %']);
    r.developers.forEach(function (d) { rows.push([d.developer, d.key, d.sessions, d.minutes, d.findings, d.critical, d.avgScore, d.detected, d.fixed, d.fixRate]); });
    content = rows.map(function (row) { return row.map(csvCell).join(','); }).join('\n');
  } else content = reportHtml(r);
  post({ command: 'REPORT_EXPORT', format: fmt, filename: base + '.' + fmt, content: content });
}
function reportHtml(r) {
  var T = r.totals, row = function (c) { return '<tr>' + c.map(function (x) { return '<td>' + esc(x == null ? '—' : x) + '</td>'; }).join('') + '</tr>'; };
  return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>' + esc(r.title) + '</title><style>'
    + 'body{font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#0f172a;max-width:960px;margin:32px auto;padding:0 20px;line-height:1.5}'
    + 'h1{font-size:22px;margin:0}h2{font-size:15px;margin:28px 0 8px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}.muted{color:#64748b;font-size:13px}'
    + '.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:18px}.kpi{border:1px solid #e2e8f0;border-radius:10px;padding:10px 12px}.kpi b{display:block;font-size:20px}.kpi span{font-size:11px;color:#64748b;text-transform:uppercase}'
    + 'table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0}th{background:#f8fafc;font-size:11px;text-transform:uppercase;color:#64748b}'
    + '@media print{body{margin:0}}</style></head><body>'
    + '<h1>' + esc(r.title) + '</h1><div class="muted">Period: ' + esc((r.from || 'start') + ' to ' + (r.to || 'today')) + ' · Generated ' + esc(new Date(r.generatedAt).toLocaleString()) + ' by ' + esc(r.generatedBy) + '</div>'
    + '<div class="kpis"><div class="kpi"><span>Shifts</span><b>' + T.shifts + '</b></div><div class="kpi"><span>Hours</span><b>' + T.hours + '</b></div><div class="kpi"><span>Findings</span><b>' + T.findings + '</b></div><div class="kpi"><span>Avg shift score</span><b>' + (T.avgShiftScore == null ? '—' : T.avgShiftScore) + '</b></div><div class="kpi"><span>Fix rate</span><b>' + (T.fixRate == null ? '—' : T.fixRate + '%') + '</b></div></div>'
    + '<h2>Findings by severity</h2><table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>' + row([r.severity.CRITICAL, r.severity.HIGH, r.severity.MEDIUM, r.severity.LOW]) + '</table>'
    + '<h2>Top vulnerability types</h2><table><tr><th>Type</th><th>Count</th></tr>' + r.topTypes.map(function (x) { return row([x.type.replace(/_/g, ' '), x.count]); }).join('') + '</table>'
    + '<h2>Developers</h2><table><tr><th>Developer</th><th>Sessions</th><th>Minutes</th><th>Findings</th><th>Critical</th><th>Avg score</th><th>Fix rate %</th></tr>' + r.developers.map(function (d) { return row([d.developer, d.sessions, d.minutes, d.findings, d.critical, d.avgScore, d.fixRate]); }).join('') + '</table>'
    + '<h2>Sessions</h2><table><tr><th>Developer</th><th>Shift</th><th>Project</th><th>Started</th><th>Minutes</th><th>Findings</th><th>Score</th></tr>' + r.sessions.map(function (s) { return row([s.developer, s.shift, s.project, new Date(s.started).toLocaleString(), s.minutes, s.findings, s.score]); }).join('') + '</table>'
    + (r.recommendations.length ? '<h2>Recommendations</h2><ol>' + r.recommendations.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ol>' : '')
    + '</body></html>';
}
function renderSessionSummaries() {
  var done = DATA.sessions.filter(function (s) { return s.end && s.summary; }).sort(function (a, b) { return b.end.localeCompare(a.end); }).slice(0, 15);
  $('sessionSummaries').innerHTML = done.length ? done.map(function (s) {
    var sm = s.summary, c = scoreColor(sm.score);
    return '<div class="sum-card"><div class="sum-score" style="border-color:' + c + ';color:' + c + '">' + sm.score + '</div>'
      + '<div style="flex:1;min-width:0"><div class="u-name">' + esc(s.devName) + ' · ' + esc(s.shiftName) + '</div><div class="u-sub">' + esc(s.projectName) + ' · ' + fmtDT(s.start) + ' · ' + durText(sm.minutes) + '</div>'
      + '<div class="shift-meta"><span style="color:var(--t-red)">' + sm.crit + ' critical</span><span>' + sm.high + ' high</span><span>' + sm.med + ' medium</span><span>' + sm.low + ' low</span></div>'
      + (sm.recs.length ? '<div class="u-sub" style="margin-top:4px">' + esc(sm.recs[0]) + '</div>' : '') + '</div>'
      + '<button class="btn-ghost" title="Report for this shift" onclick="setReportScope(\'shift:' + s.shiftId + '\')">' + ICON.file + '</button></div>';
  }).join('') : '<div class="empty">No completed shifts yet. Summaries appear when developers end their shifts.</div>';
}

// ─── Live timers ────────────────────────────────────────────────────────────
setInterval(function () {
  document.querySelectorAll('.live-timer').forEach(function (el) {
    var s = Math.max(0, Math.floor((Date.now() - Date.parse(el.dataset.start)) / 1000));
    el.textContent = pad(Math.floor(s / 3600)) + ':' + pad(Math.floor(s % 3600 / 60)) + ':' + pad(s % 60);
  });
}, 1000);

// ─── Restore UI state ───────────────────────────────────────────────────────
(function () {
  var st = vscode.getState() || {};
  if (st.sf) { $('sfProject').value = st.sf.p || ''; $('sfStatus').value = st.sf.s || 'upcoming'; }
  rpPreset(30);
  showSection(st.section && $('section-' + st.section) ? st.section : 'overview');
})();
`;
