/**
 * Sentinel — OWASP A09:2021  Security Logging and Monitoring Failures
 *
 * Detects:
 *   • Credentials / tokens / PII written to logs or stdout
 *   • Empty / swallowed catch blocks (failed logins and errors vanish)
 *   • Authentication and payment handlers with no logging at all
 *   • Debug logging left on for security events
 *   • Log injection (unsanitized user input concatenated into log lines)
 */

import { Severity as S, VulnerabilityType as V } from '../analyzer/types.js';
import { APP_LANGS, LANGS, PatternRule, RulePattern, TaintSink, pat, sink, visibleCode } from './patternEngine.js';

const SECRET_IDENT = String.raw`(?:password|passwd|pwd|secret|token|jwt|authorization|api[_-]?key|private[_-]?key|ssn|credit[_-]?card|card[_-]?number|cvv|session[_-]?id|cookie)`;

const PATTERNS: RulePattern[] = [
  // ── Secrets / PII in logs ─────────────────────────────────────────────────
  pat('a09-log-password-js', V.INSUFFICIENT_LOGGING, S.HIGH, 0.90,
    new RegExp(String.raw`\b(?:console\.(?:log|info|debug|warn|error)|logger\.(?:log|info|debug|warn|error))\s*\([^\n]{0,160}?\b${SECRET_IDENT}\b`, 'gi'),
    'Credential or PII written to the log/console — it will leak via log aggregators. Redact secrets before logging.',
    {
      languages: [...LANGS.JS],
      validate: (_m, line) => /password|passwd|pwd|secret|token|jwt|authorization|api[_-]?key|ssn|cvv|cookie/i.test(visibleCode(line)),
    }),
  pat('a09-log-password-python', V.INSUFFICIENT_LOGGING, S.HIGH, 0.90,
    new RegExp(String.raw`\b(?:print|logging\.(?:info|debug|warning|error|exception)|logger\.(?:info|debug|warning|error))\s*\([^\n]{0,160}?\b${SECRET_IDENT}\b`, 'gi'),
    'Credential or PII written to stdout/logs. Redact it; never log raw passwords or tokens.',
    { languages: ['python'] }),
  pat('a09-log-password-java', V.INSUFFICIENT_LOGGING, S.HIGH, 0.88,
    /\b(?:log|logger|LOG)\.(?:info|debug|warn|error|trace)\s*\([^\n]{0,160}?\b(?:password|passwd|token|secret|ssn|authorization)\b/gi,
    'Credential or PII written to the application log. Mask/redact before logging.',
    { languages: [...LANGS.JAVA] }),
  pat('a09-log-password-php', V.INSUFFICIENT_LOGGING, S.HIGH, 0.88,
    /\b(?:error_log|print_r|var_dump|syslog)\s*\([^\n]{0,120}?\$(?:password|passwd|token|secret|_COOKIE|_SESSION)/gi,
    'Credential dumped with `error_log` / `print_r`. Redact secrets.',
    { languages: ['php'] }),
  pat('a09-log-req-body', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.78,
    /\b(?:console\.(?:log|info|debug)|logger\.(?:info|debug)|print)\s*\(\s*(?:req|request)\.(?:body|headers|cookies|rawBody)\b/g,
    'Entire request body/headers logged — this often contains passwords and tokens. Log a allow-listed subset.',
    { languages: [...LANGS.JS, 'python'] }),

  // ── Swallowed errors ──────────────────────────────────────────────────────
  pat('a09-empty-catch-js', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.80,
    /\bcatch\s*\(\s*\w*\s*\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}|\bcatch\s*\{\s*\}/g,
    'Empty `catch` swallows the error — security failures will not be monitored. Log the exception (without secrets).',
    { languages: [...LANGS.JS] }),
  pat('a09-empty-except-python', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.82,
    /except(?:\s+\w+(?:\s+as\s+\w+)?)?\s*:\s*(?:pass|\.\.\.)\s*$/gm,
    '`except: pass` hides failures. Log the exception and decide whether to re-raise.',
    { languages: ['python'] }),
  pat('a09-empty-catch-java', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.80,
    /\bcatch\s*\([^)]+\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}/g,
    'Empty `catch` — failed authentication or authorization will never reach your SIEM.',
    { languages: [...LANGS.JAVA, 'csharp'] }),

  // ── Auth routes with no logging ───────────────────────────────────────────
  pat('a09-auth-handler-no-log-js', V.INSUFFICIENT_LOGGING, S.LOW, 0.72,
    /\b(?:app|router)\.(?:post|put)\s*\(\s*["'`][^"'`\n]*(?:login|signin|sign-in|auth|token|reset|forgot|otp|register|signup|payment|checkout)[^"'`\n]*["'`]/gi,
    'Authentication / payment endpoint has no security-event logging nearby. Log success *and* failure (never the password).',
    {
      languages: [...LANGS.JS],
      safeIfContext: /logger\.|console\.(?:info|warn|error)|audit|securityEvent|logAuth|winston|pino|bunyan/i,
      contextChars: 500,
    }),
  pat('a09-auth-handler-no-log-py', V.INSUFFICIENT_LOGGING, S.LOW, 0.72,
    /@\w+\.route\s*\([^)\n]*(?:login|signin|auth|token|reset|forgot|otp|register|payment)[^)\n]*\)/gi,
    'Authentication / payment view has no logging nearby. Record successes, failures and lockouts.',
    {
      languages: ['python'],
      safeIfContext: /logger\.|logging\.|audit|print\(/i,
      contextChars: 400,
    }),

  // ── Log injection ─────────────────────────────────────────────────────────
  pat('a09-log-injection-js', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.78,
    /\b(?:console|logger|log)\.\w+\s*\(\s*(?:`[^`\n]*\$\{(?:req|request)\.|(?:req|request)\.(?:body|query|params))/g,
    'User-controlled data written raw to logs — attackers can forge log lines (CRLF). Sanitize / structured-log as a field.',
    { languages: [...LANGS.JS] }),
  pat('a09-log-injection-python', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.78,
    /\b(?:logging|logger)\.\w+\s*\(\s*(?:f["'][^"'\n]*\{[^}]*request\.|["'][^"'\n]*%s["']\s*%\s*request\.)/g,
    'Request data interpolated into a log line — log injection. Pass it as a structured extra, not a format string.',
    { languages: ['python'] }),
  pat('a09-printstack-prod', V.INSUFFICIENT_LOGGING, S.LOW, 0.72,
    /\be\.printStackTrace\s*\(\s*\)|\btraceback\.print_exc\s*\(\s*\)/g,
    'Stack traces printed to stdout rather than a security log — they may miss your SIEM and leak internals to the console.',
    { languages: [...LANGS.JAVA, 'python'] }),
];

const SINKS: TaintSink[] = [
  sink('a09-taint-log', V.INSUFFICIENT_LOGGING, S.MEDIUM, 0.80,
    /\b(?:console|logger|log|logging)\.\w+\s*\([^\n)]{0,80}?__TAINT__/g,
    'User-controlled value written to logs without sanitisation — log injection. Use structured logging (a separate field).'),
];

export class LoggingFailuresRule extends PatternRule {
  readonly ruleId             = 'SENTINEL-A09-001';
  readonly ruleName           = 'A09 Security Logging and Monitoring Failures Detector';
  readonly vulnerabilityType  = V.INSUFFICIENT_LOGGING;
  readonly supportedLanguages = APP_LANGS;
  protected readonly patterns = PATTERNS;
  protected readonly taintSinks = SINKS;
}
