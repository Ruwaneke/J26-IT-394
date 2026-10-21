/**
 * Sentinel — OWASP A01:2021  Broken Access Control
 *
 * Detects:
 *   • Path traversal / local file inclusion        (CWE-22)
 *   • Open redirects                               (CWE-601)
 *   • Permissive CORS configuration                (CWE-942)
 *   • CSRF protection switched off                 (CWE-352)
 *   • Authorization decisions based on client-controlled data (CWE-602 / CWE-639)
 *   • Insecure direct object references (IDOR)     (CWE-639)
 *   • Sensitive routes registered without any auth middleware (CWE-306 / CWE-862)
 *   • Mass assignment / privilege escalation via req.body (CWE-915)
 *
 * Includes taint tracking: `const f = req.query.file; fs.readFile(f)` is flagged.
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, TaintSink, pat, sink } from './patternEngine.js';

// Mitigations that, when present nearby, mean the developer already handled the risk
const PATH_SAFE = /path\.basename\s*\(|sanitize-filename|secure_filename|safe_join|realpath|getCanonicalPath|toRealPath|FilenameUtils\.getName|commonpath|\.startsWith\s*\(\s*\w*(?:base|root|dir|upload|safe)\w*|isPathInside|GetFullPath/i;
const REDIRECT_SAFE = /allowlist|whitelist|allowedHosts|allowed_hosts|isSafeUrl|is_safe_url|url_has_allowed_host_and_scheme|isLocalUrl|IsLocalUrl|startsWith\s*\(\s*["']\/(?!\/)/i;
const OWNERSHIP = /req\.user|userId|user_id|owner|currentUser|current_user|session|isOwner|authoriz|\bcan\s*\(|ability|permission|createdBy|belongsTo|\bacl\b|User\.Identity|principal/i;
const AUTH_MARKER = /login_required|jwt_required|auth_required|permission_required|roles_required|admin_required|requires_auth|before_request|PreAuthorize|Secured|RolesAllowed|hasRole|hasAuthority|\[Authorize|authenticate|isAuthenticated|requireAuth|verifyToken|protect\b/i;
const MASS_SAFE = /\bpick\s*\(|allowedFields|allowlist|whitelist|permitted|fillable|\.only\s*\(|\bjoi\b|\bzod\b|\byup\b|class-validator|validate\s*\(/i;

const FS_SINK = '(?:\\b(?:readFile(?:Sync)?|createReadStream|writeFile(?:Sync)?|createWriteStream|appendFile(?:Sync)?|unlink(?:Sync)?|readdir(?:Sync)?|sendFile|sendfile|send_file|FileResponse|new\\s+File(?:InputStream|Reader)?|Paths\\.get|File\\.(?:ReadAllText|ReadAllBytes|OpenRead|Delete|WriteAllText)|ReadFile|path\\.(?:join|resolve)|os\\.path\\.join|Path\\.Combine|filepath\\.Join)|(?<![\\w.$])(?:open|include|include_once|require_once|fopen|readfile))';

const PATTERNS: RulePattern[] = [
  // ── Path traversal ────────────────────────────────────────────────────────
  pat('a01-path-node', V.PATH_TRAVERSAL, S.HIGH, 0.92,
    /\b(?:readFile(?:Sync)?|createReadStream|writeFile(?:Sync)?|createWriteStream|appendFile(?:Sync)?|unlink(?:Sync)?|rmSync|readdir(?:Sync)?|sendFile|download|access(?:Sync)?|stat(?:Sync)?)\s*\([^\n]{0,80}?\b(?:req|request)\.(?:params|query|body)\b/g,
    '`fs` operation uses request data in the file path — Path Traversal risk. Resolve the path and verify it stays inside the base directory.',
    { safeIfContext: PATH_SAFE, languages: [...LANGS.JS] }),
  pat('a01-path-join-node', V.PATH_TRAVERSAL, S.HIGH, 0.90,
    /\bpath\.(?:join|resolve)\s*\([^\n]{0,80}?\b(?:req|request)\.(?:params|query|body)\b/g,
    '`path.join/resolve` called with request data — `../` sequences can escape the intended folder.',
    { safeIfContext: PATH_SAFE, languages: [...LANGS.JS] }),
  pat('a01-path-python', V.PATH_TRAVERSAL, S.HIGH, 0.90,
    /\b(?:open|send_file|FileResponse|os\.path\.join)\s*\([^\n]{0,80}?\brequest\.(?:args|form|values|GET|POST|json|files|data)\b/g,
    'File path built from request data — Path Traversal risk. Use `secure_filename()` and validate with `os.path.realpath`.',
    { safeIfContext: PATH_SAFE, languages: ['python'] }),
  pat('a01-lfi-php-include', V.PATH_TRAVERSAL, S.CRITICAL, 0.95,
    /\b(?:include|require)(?:_once)?\s*\(?\s*[^\n;]{0,40}?\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
    'PHP `include/require` with user input — Local/Remote File Inclusion leads to code execution.',
    { languages: ['php'] }),
  pat('a01-path-php-fs', V.PATH_TRAVERSAL, S.HIGH, 0.92,
    /\b(?:fopen|readfile|file|unlink|file_put_contents|highlight_file|show_source)\s*\([^\n;]{0,60}?\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
    'File function receives user input directly — Path Traversal risk.',
    { safeIfContext: PATH_SAFE, languages: ['php'] }),
  pat('a01-path-java-param', V.PATH_TRAVERSAL, S.HIGH, 0.92,
    /\b(?:new\s+File(?:InputStream|OutputStream|Reader|Writer)?|Paths\.get|Path\.of)\s*\([^\n)]{0,80}?getParameter\s*\(/g,
    'File path built from `getParameter()` — Path Traversal risk. Canonicalise and compare with the base directory.',
    { safeIfContext: PATH_SAFE, languages: [...LANGS.JAVA] }),
  pat('a01-path-java-concat', V.PATH_TRAVERSAL, S.MEDIUM, 0.74,
    /\b(?:new\s+File(?:InputStream|OutputStream)?|Paths\.get)\s*\(\s*[A-Za-z_][\w.]*\s*\+\s*[A-Za-z_]\w*/g,
    'File path built by concatenating a variable — verify the value cannot contain `../`.',
    { safeIfContext: PATH_SAFE, languages: [...LANGS.JAVA] }),
  pat('a01-zip-slip', V.PATH_TRAVERSAL, S.HIGH, 0.85,
    /new\s+File\s*\([^\n)]{0,60}?,\s*\w*[eE]ntry\.getName\s*\(\s*\)\s*\)/g,
    'Archive entry name used to build a file path — "Zip Slip". Validate the canonical path before extracting.',
    { safeIfContext: PATH_SAFE, languages: [...LANGS.JAVA] }),
  pat('a01-path-csharp', V.PATH_TRAVERSAL, S.HIGH, 0.90,
    /\b(?:File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|OpenRead|Open|WriteAllText|WriteAllBytes|Delete|Exists)|Path\.Combine|PhysicalFile)\s*\([^\n)]{0,80}?\bRequest\.(?:Query|Form|QueryString|Params)\b/g,
    'File path built from request data — Path Traversal risk. Use `Path.GetFullPath` and verify the prefix.',
    { safeIfContext: PATH_SAFE, languages: ['csharp'] }),
  pat('a01-path-go', V.PATH_TRAVERSAL, S.HIGH, 0.90,
    /\b(?:os\.(?:Open|ReadFile|Create|Remove)|ioutil\.ReadFile|http\.ServeFile|filepath\.Join)\s*\([^\n)]{0,80}?(?:r\.URL\.Query\(\)\.Get|r\.FormValue|c\.(?:Query|Param))\s*\(/g,
    'File path built from request data — Path Traversal risk. Use `filepath.Clean` and verify the base prefix.',
    { safeIfContext: PATH_SAFE, languages: ['go'] }),

  // ── Open redirect ─────────────────────────────────────────────────────────
  pat('a01-redirect-node', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.90,
    /\b(?:res|response)\.redirect\s*\(\s*(?:\d{3}\s*,\s*)?(?:req|request)\.(?:query|params|body)\b/g,
    'Open redirect — `res.redirect()` target comes from the request. Validate against an allow-list of paths/hosts.',
    { safeIfContext: REDIRECT_SAFE, languages: [...LANGS.JS] }),
  pat('a01-redirect-python', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.90,
    /\b(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*request\.(?:args|GET|POST|form|values|query_params)\b/g,
    'Open redirect — redirect target comes from the request. Use `url_has_allowed_host_and_scheme()` or an allow-list.',
    { safeIfContext: REDIRECT_SAFE, languages: ['python'] }),
  pat('a01-redirect-java', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.88,
    /\bsendRedirect\s*\(\s*(?:\w+\.)?getParameter\s*\(|["']redirect:["']\s*\+\s*\w+/g,
    'Open redirect — redirect target built from request data. Validate against an allow-list.',
    { safeIfContext: REDIRECT_SAFE, languages: [...LANGS.JAVA] }),
  pat('a01-redirect-php', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.92,
    /\bheader\s*\(\s*["']Location:\s*["']\s*\.\s*\$_(?:GET|POST|REQUEST)\b/g,
    'Open redirect — `Location` header built from user input. Validate against an allow-list.',
    { safeIfContext: REDIRECT_SAFE, languages: ['php'] }),
  pat('a01-redirect-csharp', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.90,
    /\bRedirect\s*\(\s*Request\.(?:Query|Form|QueryString)\b/g,
    'Open redirect — redirect target taken from the request. Use `Url.IsLocalUrl()` before redirecting.',
    { safeIfContext: REDIRECT_SAFE, languages: ['csharp'] }),

  // ── CORS ──────────────────────────────────────────────────────────────────
  pat('a01-cors-wildcard-header', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.88,
    /Access-Control-Allow-Origin["']?\s*[,:=]\s*["']?\*/gi,
    'CORS allows ANY origin (`*`). Restrict `Access-Control-Allow-Origin` to trusted origins.'),
  pat('a01-cors-reflect-origin', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.92,
    /Access-Control-Allow-Origin["']?\s*[,:=]\s*(?:req|request)\.(?:headers?\.origin|header\s*\(\s*["']origin["']\s*\))/gi,
    'CORS reflects the request `Origin` header — any website can read authenticated responses. Use an allow-list.'),
  pat('a01-cors-default', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.78,
    /\.use\s*\(\s*cors\s*\(\s*\)\s*\)/g,
    '`cors()` with defaults allows every origin. Pass an explicit `origin` allow-list.',
    { languages: [...LANGS.JS] }),
  pat('a01-cors-origin-true', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.90,
    /\bcors\s*\(\s*\{[^}]{0,200}?\borigin\s*:\s*(?:true|["']\*["'])/g,
    'CORS configured with `origin: true/*` — any origin is accepted.',
    { languages: [...LANGS.JS] }),
  pat('a01-cors-python', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.88,
    /\ballow_origins\s*=\s*\[\s*["']\*["']\s*\]|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|CORS\s*\(\s*\w+\s*,[^)]*origins\s*=\s*["']\*["']/g,
    'CORS allows all origins. Restrict to a list of trusted origins.',
    { languages: ['python'] }),
  pat('a01-cors-java', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.82,
    /@CrossOrigin\s*(?:\(\s*\))?[ \t]*(?=\r?\n)|@CrossOrigin\s*\(\s*(?:origins\s*=\s*)?\{?\s*"\*"/g,
    '`@CrossOrigin` without restrictions allows every origin. Specify `origins`.',
    { languages: [...LANGS.JAVA] }),
  pat('a01-cors-csharp', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.88,
    /\bAllowAnyOrigin\s*\(\s*\)/g,
    '`AllowAnyOrigin()` permits every origin. Use `WithOrigins(...)` with trusted hosts.',
    { languages: ['csharp'] }),

  // ── CSRF protection disabled ──────────────────────────────────────────────
  pat('a01-csrf-spring', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.85,
    /\bcsrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)|\bcsrf\s*\(\s*(?:\w+\s*->\s*\w+\.disable\s*\(\s*\)|AbstractHttpConfigurer::disable|\w+::disable)\s*\)/g,
    'CSRF protection is disabled. Only do this for stateless token-based APIs.',
    { languages: [...LANGS.JAVA] }),
  pat('a01-csrf-django', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.80,
    /@csrf_exempt\b|WTF_CSRF_ENABLED["']?\]?\s*[=:]\s*False/g,
    'CSRF protection is switched off for this view/app.',
    { languages: ['python'] }),
  pat('a01-csrf-dotnet', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.78,
    /\[IgnoreAntiforgeryToken\]/g,
    '`[IgnoreAntiforgeryToken]` disables CSRF validation for this action.',
    { languages: ['csharp'] }),

  // ── Authorization based on client-controlled data ─────────────────────────
  pat('a01-role-from-request', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.88,
    /\b(?:role|isAdmin|is_admin|userRole|user_role|permissions)\s*[:=]\s*(?:req|request)\.(?:body|query|params|cookies)\b/g,
    'Role/permission value taken from the request — attacker can grant themselves admin rights. Read it from the server-side session.',
    { languages: [...LANGS.JS] }),
  pat('a01-role-cookie', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.85,
    /\b(?:req|request)\.(?:cookies|headers)\.(?:role|isAdmin|is_admin|admin|userRole|user_role)\b/g,
    'Access decision based on a client-controlled cookie/header.',
    { languages: [...LANGS.JS] }),
  pat('a01-role-python', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.85,
    /\brequest\.(?:cookies|headers|form|json|args)\.get\s*\(\s*["'](?:role|is_admin|admin|user_role)["']/g,
    'Role/admin flag read from client-controlled request data.',
    { languages: ['python'] }),
  pat('a01-role-php', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.88,
    /\$_(?:COOKIE|GET|POST|REQUEST)\s*\[\s*["'](?:role|is_?admin|admin|user_?role)["']\s*\]/g,
    'Role/admin flag read from client-controlled input.',
    { languages: ['php'] }),
  pat('a01-client-side-authz', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.82,
    /\b(?:localStorage|sessionStorage)\.getItem\s*\(\s*["'](?:role|isAdmin|is_admin|admin|userRole|user_role)["']\s*\)\s*(?:===?|!==?)/g,
    'Authorization decision made on a value stored in the browser — users can edit it. Enforce access on the server.',
    { languages: [...LANGS.JS] }),

  // ── IDOR ──────────────────────────────────────────────────────────────────
  pat('a01-idor-find-by-id', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.72,
    /\.(?:findById|findByPk|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneById|getById|deleteById)\s*\(\s*(?:req|request)\.(?:params|query|body)\.\w+/g,
    'Object looked up by a client-supplied ID with no ownership check — Insecure Direct Object Reference (IDOR).',
    { safeIfContext: OWNERSHIP, contextChars: 300, languages: [...LANGS.JS] }),
  pat('a01-idor-find-one', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.72,
    /\.(?:findOne|findOneAndUpdate|findOneAndDelete|deleteOne|updateOne|destroy)\s*\(\s*\{\s*(?:where\s*:\s*\{\s*)?(?:_id|id)\s*:\s*(?:req|request)\.(?:params|query|body)\.\w+\s*\}/g,
    'Record fetched/modified by client-supplied ID only — add an owner/tenant condition (IDOR).',
    { safeIfContext: OWNERSHIP, contextChars: 300, languages: [...LANGS.JS] }),

  // ── Unprotected sensitive routes ──────────────────────────────────────────
  pat('a01-unprotected-route-express', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.82,
    /\b(?:app|router|server)\.(?:get|post|put|patch|delete|all)\s*\(\s*["'`]\/(?:api\/)?(?:v\d+\/)?(?:admin|internal|manage|management|debug|private|superuser|backoffice|console)[^"'`\n]*["'`]\s*,\s*(?:async\s+)?(?:\(|function\b|[A-Za-z_$][\w$]*\s*=>)/g,
    'Sensitive route is registered with no authentication/authorization middleware before the handler.',
    { languages: [...LANGS.JS] }),
  pat('a01-unprotected-route-flask', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.78,
    /@\w+\.route\s*\(\s*["']\/(?:api\/)?(?:admin|internal|manage|debug|private)[^"'\n]*["'][^\n]*\)\s*\n\s*def\b/g,
    'Sensitive Flask route has no authentication decorator (e.g. `@login_required`).',
    { safeIfContext: AUTH_MARKER, contextChars: 200, languages: ['python'] }),
  pat('a01-unprotected-route-spring', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.75,
    /@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']\/(?:api\/)?(?:admin|internal|manage|debug)/g,
    'Sensitive endpoint without `@PreAuthorize` / `@Secured` / role check.',
    { safeIfContext: AUTH_MARKER, contextChars: 300, languages: [...LANGS.JAVA] }),
  pat('a01-unprotected-route-aspnet', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.75,
    /\[Route\s*\(\s*"(?:api\/)?(?:admin|internal|manage|debug)/g,
    'Sensitive controller/action without `[Authorize]`.',
    { safeIfContext: AUTH_MARKER, contextChars: 300, languages: ['csharp'] }),
  pat('a01-spring-permitall', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.85,
    /\.anyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)|(?:antMatchers|requestMatchers)\s*\(\s*"\/\*\*"\s*\)\s*\.\s*permitAll/g,
    'All requests are permitted without authentication (`permitAll()` on every route).',
    { languages: [...LANGS.JAVA] }),
  pat('a01-rails-skip-auth', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.85,
    /\bskip_before_action\s*:(?:authenticate_user!|verify_authenticity_token|authorize|require_login)/g,
    'Authentication / CSRF filter skipped for this controller.',
    { languages: ['ruby'] }),

  // ── Mass assignment / privilege escalation ────────────────────────────────
  pat('a01-mass-assign-node', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.76,
    /\b(?:create|insertMany|insertOne|update|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate|findAndModify|build)\s*\(\s*(?:[^,\n)]{1,60},\s*)?(?:req|request)\.body\s*[,)]/g,
    'Whole `req.body` passed to the data layer — mass assignment lets users set fields like `role` or `isAdmin`. Pick allowed fields explicitly.',
    { safeIfContext: MASS_SAFE, languages: [...LANGS.JS] }),
  pat('a01-mass-assign-assign', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.78,
    /Object\.assign\s*\([^\n,)]+,\s*(?:req|request)\.body\s*\)|\{\s*\.\.\.(?:req|request)\.body\s*[,}]/g,
    'Request body merged into an object wholesale — mass assignment / privilege escalation risk.',
    { safeIfContext: MASS_SAFE, languages: [...LANGS.JS] }),
  pat('a01-mass-assign-python', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.80,
    /\*\*\s*request\.(?:POST|data|json|form|GET)\b/g,
    'Request data unpacked into a model/constructor (`**request.data`) — mass assignment risk.',
    { safeIfContext: MASS_SAFE, languages: ['python'] }),
  pat('a01-mass-assign-rails', V.BROKEN_ACCESS_CONTROL, S.HIGH, 0.85,
    /\bparams\.permit!|\.(?:update|create|new)\s*\(\s*params\s*\)/g,
    'Unfiltered `params` used for mass assignment. Use strong parameters (`params.require(...).permit(...)`).',
    { languages: ['ruby'] }),
];

// ─── Taint sinks: user-input variables reaching file / redirect / lookup calls ─

const SINKS: TaintSink[] = [
  sink('a01-taint-path', V.PATH_TRAVERSAL, S.HIGH, 0.88,
    new RegExp(FS_SINK + '\\s*\\([^\\n)]{0,80}?__TAINT__', 'g'),
    'User-controlled value reaches a file-system call without path validation — Path Traversal risk.',
    { safeIfContext: PATH_SAFE }),
  sink('a01-taint-redirect', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.86,
    /(?:\b(?:res|response)\.redirect|\b(?:redirect|HttpResponseRedirect|RedirectResponse)|\bsendRedirect|\bRedirect|\bhttp\.Redirect)\s*\([^\n)]{0,40}?__TAINT__|Location:\s*["']\s*\.\s*__TAINT__/g,
    'User-controlled value used as a redirect target — Open Redirect. Validate against an allow-list.',
    { safeIfContext: REDIRECT_SAFE }),
  sink('a01-taint-idor', V.BROKEN_ACCESS_CONTROL, S.MEDIUM, 0.72,
    /\.(?:findById|findByPk|getById|getReferenceById|deleteById|findByIdAndUpdate|findByIdAndDelete)\s*\(\s*__TAINT__/g,
    'Record fetched by a client-supplied ID with no ownership check — Insecure Direct Object Reference (IDOR).',
    { safeIfContext: OWNERSHIP, contextChars: 300 }),
];

export class BrokenAccessControlRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A01-001';
  readonly ruleName           = 'A01 Broken Access Control Detector';
  readonly vulnerabilityType  = V.BROKEN_ACCESS_CONTROL;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
  protected readonly taintSinks = SINKS;
}
