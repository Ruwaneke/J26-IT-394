/**
 * Sentinel — Shared Pattern Engine
 *
 * Common detection machinery used by the OWASP Top 10 rules (A01, A02, A03,
 * A04, A05, A06, A07, A08, A09, A10). Each rule only declares *what* to look
 * for (patterns + taint sinks); this engine takes care of *how*:
 *
 *   • language / file-name gating per pattern (so a rule can also scan
 *     Dockerfile, package.json, pom.xml, YAML, Terraform, ...)
 *   • comment skipping
 *   • mitigation detection  (safeIfLine / safeIfContext / safeIfFile)
 *   • confidence boosting from nearby keywords
 *   • lightweight TAINT TRACKING: variables assigned from user input
 *     (req.body, request.args, $_GET, getParameter ...) are tracked, and a
 *     finding is raised when they reach a dangerous sink, e.g.
 *         const target = req.query.url;      // tainted
 *         axios.get(target);                 // SSRF  <- detected
 *   • per-line / per-type de-duplication (highest confidence wins)
 *   • secret redaction in code snippets
 */

import { v4 as uuidv4 } from '../util/uuid.js';
import {
  SecurityFinding,
  SecurityRule,
  Severity,
  VulnerabilityType,
  owaspCategoryFor,
  computeFindingId,
} from '../analyzer/types.js';

// ─── Language groups ──────────────────────────────────────────────────────────

export const LANGS = {
  JS: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'vue', 'svelte'],
  WEB: ['html', 'php', 'vue', 'svelte', 'javascriptreact', 'typescriptreact'],
  PY: ['python'],
  JAVA: ['java', 'kotlin', 'scala', 'groovy'],
  CS: ['csharp'],
  PHP: ['php'],
  RUBY: ['ruby'],
  GO: ['go'],
  CONFIG: ['yaml', 'json', 'jsonc', 'properties', 'ini', 'toml', 'xml', 'dockerfile', 'terraform', 'hcl', 'plaintext'],
  SHELL: ['shellscript', 'dockerfile', 'powershell', 'makefile', 'bat', 'yaml', 'plaintext'],
} as const;

/** Application-source languages (server-side + client-side). */
export const APP_LANGS: string[] = [
  ...LANGS.JS, ...LANGS.PY, ...LANGS.JAVA, ...LANGS.CS, ...LANGS.PHP, ...LANGS.RUBY, ...LANGS.GO,
  'html', 'plaintext',
];

const HASH_COMMENT_LANGS = new Set([
  'python', 'ruby', 'yaml', 'shellscript', 'dockerfile', 'properties', 'ini', 'toml',
  'plaintext', 'makefile', 'powershell', 'terraform', 'hcl', 'perl', 'r', 'dotenv',
  'pip-requirements', 'jproperties', 'php',
]);

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RulePattern {
  /** Short identifier (for debugging / tests) */
  id: string;
  /** Detection regex. Flags are normalised by the engine (global is added). */
  regex: RegExp;
  type: VulnerabilityType;
  severity: Severity;
  confidence: number;
  message: string;
  /** Keywords near the match that raise confidence (+0.01 each, max 0.99) */
  boostKeywords?: string[];
  /** Apply only to these language ids (default: the rule's supportedLanguages) */
  languages?: string[];
  /** Also apply when the file's base name matches (e.g. /^package\.json$/) */
  fileNameMatch?: RegExp;
  /** Scan comment lines too (default false) */
  scanComments?: boolean;
  /** Skip when the matched line matches this (a mitigation is on the line) */
  safeIfLine?: RegExp;
  /** Skip when text around the match matches this (mitigation nearby) */
  safeIfContext?: RegExp;
  /** Characters of context on each side for safeIfContext / boostKeywords (default 250) */
  contextChars?: number;
  /** Skip when anywhere in the file matches this (file-level mitigation) */
  safeIfFile?: RegExp;
  /** Final custom check; return false to discard the match */
  validate?: (match: RegExpExecArray, line: string) => boolean;
  /** Redact secret-looking values in the reported snippet */
  redact?: boolean;
}

export interface TaintSink extends Omit<RulePattern, 'regex'> {
  /**
   * Regex SOURCE containing the placeholder `__TAINT__`, which the engine
   * replaces with an alternation of the tainted variable names found in the file.
   */
  source: string;
  flags?: string;
}

export const TAINT = '__TAINT__';

/** Write `__TAINT__` inside a sink regex literal where the tainted variable name should appear. */
export const TAINT_PLACEHOLDER = /__TAINT__/;

/** Concise RulePattern builder. */
export function pat(
  id: string,
  type: VulnerabilityType,
  severity: Severity,
  confidence: number,
  regex: RegExp,
  message: string,
  extra: Partial<RulePattern> = {},
): RulePattern {
  return { id, type, severity, confidence, regex, message, ...extra };
}

/** Concise TaintSink builder. `regex` must contain the literal text __TAINT__. */
export function sink(
  id: string,
  type: VulnerabilityType,
  severity: Severity,
  confidence: number,
  regex: RegExp,
  message: string,
  extra: Partial<TaintSink> = {},
): TaintSink {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  return { id, type, severity, confidence, source: regex.source, message, flags, ...extra };
}

// ─── Source helpers ───────────────────────────────────────────────────────────

const MAX_TEXT_LENGTH = 1_000_000;

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) { starts.push(i + 1); }
  }
  return starts;
}

/** 1-indexed line number for an offset (binary search). */
function lineOf(starts: number[], offset: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) { lo = mid; } else { hi = mid - 1; }
  }
  return lo + 1;
}

export function isCommentLine(line: string, languageId: string): boolean {
  const t = line.trim();
  if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('<!--')) {
    return true;
  }
  if (t.startsWith('#') && HASH_COMMENT_LANGS.has(languageId)) { return true; }
  return false;
}

/**
 * Returns the line with all static string content removed, keeping only code
 * and interpolated expressions. Lets rules distinguish
 *   console.log("Invalid password")      → no variable involved
 *   console.log(`pw=${password}`)        → `password` is really logged
 */
export function visibleCode(line: string): string {
  return line
    // Python f-strings: keep {expr}
    .replace(/\bf(["'])((?:(?!\1).)*)\1/g, (_m, _q, body: string) =>
      ' ' + (body.match(/\{[^}]*\}/g) ?? []).join(' ') + ' ')
    // C# interpolated strings $"...{expr}..."
    .replace(/\$"((?:[^"\\]|\\.)*)"/g, (_m, body: string) =>
      ' ' + (body.match(/\{[^}]*\}/g) ?? []).join(' ') + ' ')
    // JS template literals: keep ${expr}
    .replace(/`((?:[^`\\]|\\.)*)`/g, (_m, body: string) =>
      ' ' + (body.match(/\$\{[^}]*\}/g) ?? []).join(' ') + ' ')
    // Plain strings → empty
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''");
}

function redactSnippet(snippet: string): string {
  return snippet
    .replace(/["'`][A-Za-z0-9\-_+/=.]{6,}["'`]/g, '"[REDACTED]"')
    .replace(/([=:]\s*)(?![\s"'`$<{%*])[^\s"'`;,]{6,}/g, '$1[REDACTED]');
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── Taint tracking ───────────────────────────────────────────────────────────

const TAINT_SOURCES: Array<{ re: RegExp; kind: 'single' | 'destructure' }> = [
  // JS / TS — const id = req.params.id
  { re: /(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:req|request|ctx\.request|ctx)\.(?:body|query|params|headers|cookies)\b/g, kind: 'single' },
  // JS / TS — const { url, id: userId } = req.body
  { re: /\b(?:const|let|var)\s*\{([^}]{1,200})\}\s*=\s*(?:await\s+)?(?:req|request|ctx\.request)\.(?:body|query|params|headers|cookies)\b/g, kind: 'destructure' },
  // Python — x = request.args.get('x') / input()
  { re: /\b([A-Za-z_]\w*)\s*=\s*(?:request\.(?:args|form|values|json|GET|POST|data|files|cookies|headers|query_params)|flask\.request\.\w+|sys\.argv|(?:input|raw_input)\s*\()/g, kind: 'single' },
  // PHP — $x = $_GET['x']
  { re: /(\$[A-Za-z_]\w*)\s*=\s*(?:\(\w+\)\s*)?\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/g, kind: 'single' },
  // Java — String x = request.getParameter("x")
  { re: /\b(?:String|var|Object|int)\s+([A-Za-z_]\w*)\s*=\s*(?:\(\w+\)\s*)?\w*[rR]equest\.(?:getParameter|getHeader|getQueryString|getPathInfo|getRequestURI|getCookies|getParameterValues)\s*\(/g, kind: 'single' },
  // Java / Spring — @RequestParam String x
  { re: /@(?:RequestParam|PathVariable|RequestBody|QueryParam|PathParam|FormParam|RequestHeader|CookieValue)\b(?:\s*\((?:[^()]|\([^)]*\))*\))?\s*(?:final\s+)?[\w.<>\[\]?, ]+?\s+([A-Za-z_]\w*)\s*[,)]/g, kind: 'single' },
  // C# — var x = Request.Query["x"]
  { re: /\b(?:var|string|int|Guid)\s+([A-Za-z_]\w*)\s*=\s*(?:HttpContext\.)?Request\.(?:Query|Form|QueryString|Params|Headers|Cookies|RouteValues)\b/g, kind: 'single' },
  // C# / ASP.NET — [FromQuery] string x
  { re: /\[From(?:Query|Body|Route|Form|Header)(?:\([^)]*\))?\]\s*(?:[\w.<>\[\]?]+)\s+([A-Za-z_]\w*)/g, kind: 'single' },
  // Go — x := r.URL.Query().Get("x") / c.Query("x")
  { re: /\b([A-Za-z_]\w*)\s*:?=\s*(?:r|req|c|ctx)\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue|Query|Param|PostForm|DefaultQuery|GetHeader|Cookie)\s*\(/g, kind: 'single' },
  // Ruby — x = params[:x]
  { re: /\b([A-Za-z_]\w*)\s*=\s*params\s*\[/g, kind: 'single' },
];

const IDENT = /^[A-Za-z_$][\w$]*$/;

/** Names of variables in `text` that are assigned directly from user-controlled input. */
export function collectTaintedVariables(text: string): string[] {
  const names = new Set<string>();

  for (const { re, kind } of TAINT_SOURCES) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (kind === 'single') {
        names.add(m[1]);
      } else {
        for (const part of m[1].split(',')) {
          let p = part.trim().replace(/^\.\.\./, '');
          if (p.includes(':')) { p = p.split(':')[1].trim(); }   // alias → local name
          if (p.includes('=')) { p = p.split('=')[0].trim(); }   // default value
          if (IDENT.test(p)) { names.add(p); }
        }
      }
      if (m.index === re.lastIndex) { re.lastIndex++; }
    }
  }
  return [...names].slice(0, 60);
}

// ─── Pattern-based rule base class ────────────────────────────────────────────

export abstract class PatternRule implements SecurityRule {
  abstract readonly ruleId: string;
  abstract readonly ruleName: string;
  abstract readonly vulnerabilityType: VulnerabilityType;
  abstract readonly supportedLanguages: string[];
  protected abstract readonly patterns: RulePattern[];
  /** Taint-tracking sinks (optional) */
  protected readonly taintSinks: TaintSink[] = [];

  /** Hook for rules that need custom (non-regex) analysis, e.g. dependency manifests. */
  protected analyzeExtra(_text: string, _fileName: string, _languageId: string): SecurityFinding[] {
    return [];
  }

  analyze(text: string, fileName: string, languageId: string): SecurityFinding[] {
    if (!text || text.length > MAX_TEXT_LENGTH) { return []; }

    const lines      = text.split('\n');
    const lineStarts = computeLineStarts(text);
    const now        = new Date().toISOString();
    const found      = new Map<string, SecurityFinding>();

    const add = (finding: SecurityFinding): void => {
      const key  = `${finding.lineNumber}|${finding.type}`;
      const prev = found.get(key);
      if (!prev || finding.confidence > prev.confidence) { found.set(key, finding); }
    };

    // 1. Plain regex patterns ────────────────────────────────────────────────
    for (const p of this.patterns) {
      if (!this.appliesTo(p.languages, p.fileNameMatch, languageId, fileName)) { continue; }
      this.scan(p, p.regex, text, lines, lineStarts, languageId, fileName, now, add);
    }

    // 2. Taint-tracking sinks ────────────────────────────────────────────────
    if (this.taintSinks.length > 0) {
      const tainted = collectTaintedVariables(text);
      if (tainted.length > 0) {
        const alt = tainted.map(escapeRegex).join('|');
        for (const s of this.taintSinks) {
          if (!this.appliesTo(s.languages, s.fileNameMatch, languageId, fileName)) { continue; }
          let re: RegExp;
          try {
            re = new RegExp(
              s.source.split(TAINT).join(`(?<![\\w.])(?:${alt})(?![\\w$])`),
              s.flags ?? 'g',
            );
          } catch {
            continue;
          }
          this.scan(s, re, text, lines, lineStarts, languageId, fileName, now, add);
        }
      }
    }

    // 3. Custom analysis ─────────────────────────────────────────────────────
    for (const f of this.analyzeExtra(text, fileName, languageId)) { add(f); }

    return [...found.values()];
  }

  // ─── Internals ──────────────────────────────────────────────────────────────

  private appliesTo(
    languages: string[] | undefined,
    fileNameMatch: RegExp | undefined,
    languageId: string,
    fileName: string,
  ): boolean {
    const base = fileName.split(/[\\/]/).pop() ?? fileName;
    if (fileNameMatch && fileNameMatch.test(base)) { return true; }
    if (languages) { return languages.includes(languageId); }
    if (fileNameMatch) { return false; }
    return this.supportedLanguages.includes(languageId);
  }

  private scan(
    p: Omit<RulePattern, 'regex'>,
    regex: RegExp,
    text: string,
    lines: string[],
    lineStarts: number[],
    languageId: string,
    fileName: string,
    now: string,
    add: (f: SecurityFinding) => void,
  ): void {
    if (p.safeIfFile && p.safeIfFile.test(text)) { return; }

    const re = regex.global ? regex : new RegExp(regex.source, regex.flags + 'g');
    re.lastIndex = 0;

    const ctxChars = p.contextChars ?? 250;
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }

      const lineNumber = lineOf(lineStarts, m.index);
      const line       = lines[lineNumber - 1] ?? '';

      if (!p.scanComments && isCommentLine(line, languageId)) { continue; }
      if (p.safeIfLine && p.safeIfLine.test(line)) { continue; }

      const needsContext = p.safeIfContext || (p.boostKeywords && p.boostKeywords.length > 0);
      const context = needsContext
        ? text.substring(Math.max(0, m.index - ctxChars), Math.min(text.length, m.index + m[0].length + ctxChars))
        : '';

      if (p.safeIfContext && p.safeIfContext.test(context)) { continue; }
      if (p.validate && !p.validate(m, line)) { continue; }

      let confidence = p.confidence;
      if (p.boostKeywords && p.boostKeywords.length > 0) {
        const lower = context.toLowerCase();
        const hits  = p.boostKeywords.filter(k => lower.includes(k.toLowerCase())).length;
        confidence  = Math.min(0.99, confidence + hits * 0.01);
      }
      confidence = Math.round(confidence * 100) / 100;

      const snippet     = line.trim();
      const columnStart = lineStarts[lineNumber - 1] ?? 0;

      add({
        id:             computeFindingId(fileName, p.type, this.ruleId, snippet, 0),
        type:           p.type,
        severity:       p.severity,
        confidence,
        message:        p.message,
        fileName,
        lineNumber,
        columnNumber:   m.index - columnStart,
        codeSnippet:    p.redact ? redactSnippet(snippet) : snippet,
        detectedAt:     now,
        detectedByRule: this.ruleId,
        owaspCategory:  owaspCategoryFor(p.type)?.id,
        rangeStart:     m.index,
        rangeEnd:       m.index + m[0].length,
      });
    }
  }
}

// ─── Helper for building findings from custom analysis ───────────────────────

export function makeFinding(args: {
  ruleId: string;
  type: VulnerabilityType;
  severity: Severity;
  confidence: number;
  message: string;
  fileName: string;
  text: string;
  index: number;
  length: number;
  redact?: boolean;
}): SecurityFinding {
  const starts     = computeLineStarts(args.text);
  const lineNumber = lineOf(starts, args.index);
  const line       = (args.text.split('\n')[lineNumber - 1] ?? '').trim();

  return {
    id:             computeFindingId(args.fileName, args.type, args.ruleId, line, 0),
    type:           args.type,
    severity:       args.severity,
    confidence:     Math.round(args.confidence * 100) / 100,
    message:        args.message,
    fileName:       args.fileName,
    lineNumber,
    columnNumber:   args.index - (starts[lineNumber - 1] ?? 0),
    codeSnippet:    args.redact ? redactSnippet(line) : line,
    detectedAt:     new Date().toISOString(),
    detectedByRule: args.ruleId,
    owaspCategory:  owaspCategoryFor(args.type)?.id,
    rangeStart:     args.index,
    rangeEnd:       args.index + args.length,
  };
}
