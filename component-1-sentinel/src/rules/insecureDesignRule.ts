/**
 * Sentinel — OWASP A04:2021  Insecure Design
 *
 * Insecure design cannot be fully found by static analysis, but many design
 * weaknesses leave recognisable code-level fingerprints. This rule flags:
 *
 *   • Unrestricted file upload (no type / size limits, user-controlled file name)
 *   • Authentication / recovery endpoints with no rate-limiting or throttling
 *   • Authentication bypass switches, backdoors, "master" passwords
 *   • Business-critical values (price, amount, role) trusted from the client
 *   • Missing input validation reaching regex engines, allocators, pagination
 *   • Knowledge-based ("security question") credential recovery
 *   • Unresolved security TODO / FIXME markers
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, TaintSink, pat, sink } from './patternEngine.js';

const RATE_LIMIT = /rate-?limit|rateLimit|limiter|throttl|slowDown|brute|ratelimiter|bottleneck|flask_limiter/i;
const LIMIT_CAP  = /Math\.min|\bmin\s*\(|clamp|max\w*Limit|MAX_|maxPageSize|\.min\s*\(/i;

const PATTERNS: RulePattern[] = [
  // ── Unrestricted file upload ──────────────────────────────────────────────
  pat('a04-upload-multer', V.INSECURE_DESIGN, S.MEDIUM, 0.80,
    /\bmulter\s*\(/g,
    'File upload handler without `fileFilter` / `limits` — attackers can upload any type or size. Restrict MIME type, extension and size.',
    { safeIfContext: /fileFilter|limits\s*:/, contextChars: 400, languages: [...LANGS.JS] }),
  pat('a04-upload-flask', V.INSECURE_DESIGN, S.MEDIUM, 0.80,
    /\.save\s*\(\s*(?:os\.path\.join\s*\([^\n)]*)?[^\n)]*(?:\.filename|request\.files)/g,
    'Uploaded file saved using the client-supplied filename. Use `secure_filename()` and validate type/size.',
    { safeIfContext: /secure_filename|uuid/i, languages: ['python'] }),
  pat('a04-upload-php', V.INSECURE_DESIGN, S.HIGH, 0.92,
    /\bmove_uploaded_file\s*\([^\n]*\$_FILES\s*\[[^\]]+\]\s*\[\s*["']name["']\s*\]/g,
    'Uploaded file stored under its original name — attacker can upload `shell.php`. Generate a random name and whitelist extensions.',
    { languages: ['php'] }),
  pat('a04-upload-java', V.INSECURE_DESIGN, S.MEDIUM, 0.75,
    /\bgetOriginalFilename\s*\(\s*\)/g,
    'Client-supplied upload filename used. Sanitize with `StringUtils.cleanPath` / generate a UUID name and validate extension.',
    { safeIfContext: /UUID|FilenameUtils\.getName|cleanPath|sanitize|getCanonical/i, contextChars: 300, languages: [...LANGS.JAVA] }),
  pat('a04-upload-csharp', V.INSECURE_DESIGN, S.MEDIUM, 0.80,
    /\bPath\.Combine\s*\([^\n)]*\.FileName\b/g,
    'Uploaded file stored under the client-supplied `FileName`. Use `Path.GetRandomFileName()` and validate extension/size.',
    { safeIfContext: /GetFileName|Guid\.NewGuid|GetRandomFileName/, contextChars: 300, languages: ['csharp'] }),

  // ── No rate limiting on authentication-like endpoints ─────────────────────
  pat('a04-no-ratelimit-express', V.INSECURE_DESIGN, S.MEDIUM, 0.72,
    /\b(?:app|router)\.post\s*\(\s*["'`][^"'`\n]*(?:login|signin|sign-in|auth|token|reset|forgot|otp|verify|register|signup)[^"'`\n]*["'`]\s*,\s*(?:async\s+)?(?:\(|function\b|[A-Za-z_$][\w$]*\s*=>)/gi,
    'Authentication / recovery endpoint with no rate limiting — enables brute-force and credential stuffing. Add `express-rate-limit` or similar.',
    { safeIfFile: RATE_LIMIT, languages: [...LANGS.JS] }),
  pat('a04-no-ratelimit-flask', V.INSECURE_DESIGN, S.MEDIUM, 0.72,
    /@\w+\.route\s*\([^)\n]*(?:login|signin|auth|token|reset|forgot|otp|register)[^)\n]*\)\s*\n\s*def\b/gi,
    'Authentication / recovery view with no rate limiting. Use `flask-limiter` or equivalent throttling.',
    { safeIfFile: RATE_LIMIT, languages: ['python'] }),

  // ── Bypass switches and backdoors ─────────────────────────────────────────
  pat('a04-auth-bypass-flag', V.INSECURE_DESIGN, S.MEDIUM, 0.78,
    /\b(?:skip|bypass|disable|no)_?(?:auth|authentication|authorization|login|verify|verification|check|security|captcha)\w*\s*[=:]\s*(?:true|True|1)\b/gi,
    'Security control can be switched off with a flag — make sure this can never be enabled in production.'),
  pat('a04-backdoor-keywords', V.INSECURE_DESIGN, S.HIGH, 0.82,
    /\b(?:backdoor|master_?password|master_?key|god_?mode|debug_?(?:login|bypass|admin))\b/gi,
    'Backdoor-style identifier (master password / debug bypass). Remove special-case access paths from production code.'),

  // ── Business logic trusting the client ────────────────────────────────────
  pat('a04-client-trusted-price', V.INSECURE_DESIGN, S.MEDIUM, 0.75,
    /\b(?:price|amount|total|discount|cost)\s*[:=]\s*(?:req|request)\.(?:body|query|params)\.\w+|\b(?:price|amount|total|discount|cost)\s*=\s*(?:float|int|Decimal)?\s*\(?\s*request\.(?:form|json|args|POST|GET)|\$(?:price|amount|total|discount|cost)\s*=\s*\$_(?:GET|POST|REQUEST)\b/gi,
    'Price / amount / discount read straight from the client request — recompute business-critical values on the server.'),
  pat('a04-hidden-field-trust', V.INSECURE_DESIGN, S.MEDIUM, 0.78,
    /<input\b[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["'](?:price|amount|total|role|isAdmin|is_admin|discount|userId|user_id|cost)["']|<input\b[^>]*name\s*=\s*["'](?:price|amount|total|role|isAdmin|is_admin|discount|userId|user_id|cost)["'][^>]*type\s*=\s*["']hidden["']/gi,
    'Security-relevant value kept in a hidden form field — users can edit it. Keep it server-side.',
    { languages: [...LANGS.WEB] }),
  pat('a04-security-questions', V.INSECURE_DESIGN, S.LOW, 0.72,
    /\bsecurity_?questions?\b/gi,
    'Knowledge-based security questions are not a reliable recovery mechanism (OWASP A04). Use a time-limited token sent to a verified channel.'),

  // ── Missing input validation ──────────────────────────────────────────────
  pat('a04-redos-user-regex', V.MISSING_INPUT_VALIDATION, S.MEDIUM, 0.85,
    /\bnew\s+RegExp\s*\(\s*(?:req|request)\.(?:body|query|params)\b|\bre\.(?:compile|match|search|findall|sub|fullmatch)\s*\(\s*request\.(?:args|form|json|values|GET|POST)\b|\bPattern\.compile\s*\(\s*(?:\w+\.)?getParameter\s*\(|\bpreg_match\s*\(\s*\$_(?:GET|POST|REQUEST)\b/g,
    'User input used as a regular expression — ReDoS / regex injection. Escape it or use a fixed pattern.'),
  pat('a04-unbounded-limit', V.MISSING_INPUT_VALIDATION, S.LOW, 0.72,
    /\.(?:limit|take)\s*\(\s*(?:parseInt\s*\(\s*|Number\s*\(\s*|\+)?\s*(?:req|request)\.(?:query|body|params)\.\w+/g,
    'Page size comes straight from the request with no upper bound — clients can request huge result sets (DoS).',
    { safeIfContext: LIMIT_CAP, languages: [...LANGS.JS] }),
  pat('a04-user-sized-alloc', V.MISSING_INPUT_VALIDATION, S.MEDIUM, 0.85,
    /\b(?:Buffer\.alloc(?:Unsafe)?|new\s+Array|Array)\s*\(\s*(?:req|request)\.(?:body|query|params)\.\w+/g,
    'Memory allocated using a size supplied by the client — validate and cap it to prevent memory exhaustion.',
    { languages: [...LANGS.JS] }),

  // ── Security debt markers ─────────────────────────────────────────────────
  pat('a04-security-todo', V.INSECURE_DESIGN, S.LOW, 0.72,
    /(?:TODO|FIXME|HACK|XXX)\b[^\n]{0,60}?(?:auth|authenticat|authoriz|validat|sanitiz|encrypt|security|permission|csrf|rate.?limit|vulnerab)/gi,
    'Unresolved security TODO/FIXME — track it and fix it before release.',
    { scanComments: true }),
];

const SINKS: TaintSink[] = [
  sink('a04-taint-regexp', V.MISSING_INPUT_VALIDATION, S.MEDIUM, 0.85,
    /\bnew\s+RegExp\s*\(\s*__TAINT__|\bre\.(?:compile|match|search|findall|sub|fullmatch)\s*\(\s*__TAINT__|\bpreg_match\s*\(\s*__TAINT__/g,
    'User input used as a regular expression — ReDoS / regex injection. Escape it or use a fixed pattern.',
    { safeIfContext: /escapeRegExp|escape_regex|re\.escape|preg_quote|lodash.*escapeRegExp|_\.escapeRegExp/i }),
  sink('a04-taint-alloc', V.MISSING_INPUT_VALIDATION, S.MEDIUM, 0.80,
    /\b(?:Buffer\.alloc(?:Unsafe)?|new\s+Array)\s*\(\s*__TAINT__/g,
    'Memory allocated using a client-supplied size — validate and cap it.',
    { safeIfContext: LIMIT_CAP, languages: [...LANGS.JS] }),
  sink('a04-taint-limit', V.MISSING_INPUT_VALIDATION, S.LOW, 0.72,
    /\.(?:limit|take)\s*\(\s*(?:parseInt\s*\(\s*|Number\s*\(\s*|\+)?\s*__TAINT__/g,
    'Page size derived from the request with no upper bound.',
    { safeIfContext: LIMIT_CAP, languages: [...LANGS.JS] }),
];

export class InsecureDesignRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A04-001';
  readonly ruleName           = 'A04 Insecure Design Detector';
  readonly vulnerabilityType  = V.INSECURE_DESIGN;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
  protected readonly taintSinks = SINKS;
}
