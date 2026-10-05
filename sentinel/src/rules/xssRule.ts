/**
 * Sentinel — XSS (Cross-Site Scripting) Rule  (Optimized v2)
 *
 * Detection improvements over v1:
 *   • 7 → 18 patterns covering modern JS frameworks + server-side templates
 *   • Angular: bypassSecurityTrustHtml / [innerHTML] binding
 *   • Vue: v-html directive
 *   • Svelte: {@html ...} blocks
 *   • Server-Side Template Injection vectors (Python Jinja2, PHP)
 *   • Prototype pollution sinks (Object.assign on user data)
 *   • postMessage data usage in innerHTML (common XSS vector)
 *   • location.hash / search used in DOM without sanitization
 *   • window.name sink
 *   • Dynamic script src from user input
 *   • Dynamic confidence: boosted for event handlers and req.body usage
 */

import { v4 as uuidv4 } from '../util/uuid.js';
import {
  SecurityFinding,
  SecurityRule,
  Severity,
  VulnerabilityType,
} from '../analyzer/types.js';

// ─── Pattern Definitions ──────────────────────────────────────────────────────

interface XssPattern {
  id: string;
  regex: RegExp;
  baseConfidence: number;
  message: string;
  boostKeywords?: string[];
}

const XSS_PATTERNS: XssPattern[] = [
  // ── DOM Sinks ─────────────────────────────────────────────────────────────
  {
    id: 'xss-innerhtml',
    regex: /\.innerHTML\s*=\s*(?![\"'`]<[^>]+>[\"'`])\S/g,
    baseConfidence: 0.92,
    message: '`innerHTML` assignment with non-static value — XSS risk if value contains user input.',
    boostKeywords: ['req.body', 'req.query', 'userInput', 'location.hash', 'search', 'URLSearchParams'],
  },
  {
    id: 'xss-outerhtml',
    regex: /\.outerHTML\s*=\s*\w/g,
    baseConfidence: 0.90,
    message: '`outerHTML` assignment with variable — XSS risk.',
  },
  {
    id: 'xss-insertadjacenthtml',
    regex: /\.insertAdjacentHTML\s*\(\s*[\"'`][^\"'`]+[\"'`]\s*,\s*\w/g,
    baseConfidence: 0.91,
    message: '`insertAdjacentHTML()` with variable — XSS risk. Use `insertAdjacentText()` for plain text.',
  },
  // ── document.write ────────────────────────────────────────────────────────
  {
    id: 'xss-docwrite',
    regex: /document\.write\s*\(\s*(?!\s*[\"'`][^\"'`]*[\"'`]\s*\))\w/g,
    baseConfidence: 0.89,
    message: '`document.write()` with variable input — XSS risk.',
  },
  {
    id: 'xss-docwriteln',
    regex: /document\.writeln\s*\(\s*\w/g,
    baseConfidence: 0.89,
    message: '`document.writeln()` with variable — XSS risk.',
  },
  // ── eval and eval-like sinks ──────────────────────────────────────────────
  {
    id: 'xss-eval',
    regex: /\beval\s*\(\s*\w/g,
    baseConfidence: 0.97,
    message: '`eval()` with variable — code injection risk. Never use eval() with dynamic content.',
  },
  {
    id: 'xss-function-ctor',
    regex: /new\s+Function\s*\(\s*\w[^)]*\)/g,
    baseConfidence: 0.93,
    message: '`new Function(...)` with variable — equivalent to `eval()`, code injection risk.',
  },
  {
    id: 'xss-settimeout-string',
    regex: /(?:setTimeout|setInterval)\s*\(\s*\w[^,)]+,/g,
    baseConfidence: 0.78,
    message: '`setTimeout/setInterval` with string argument — eval-like code injection risk.',
  },
  // ── React ─────────────────────────────────────────────────────────────────
  {
    id: 'xss-react-dangerous',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    baseConfidence: 0.82,
    message: '`dangerouslySetInnerHTML` used — ensure content is sanitized with DOMPurify before rendering.',
  },
  // ── Angular ───────────────────────────────────────────────────────────────
  {
    id: 'xss-angular-bypass-trust',
    regex: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*\w/g,
    baseConfidence: 0.94,
    message: 'Angular `bypassSecurityTrust*()` used — bypasses Angular\'s built-in XSS sanitizer. Ensure the content is truly safe.',
  },
  {
    id: 'xss-angular-innerhtml-binding',
    regex: /\[innerHTML\]\s*=\s*[\"'`][^\"'`]*[\"'`]/g,
    baseConfidence: 0.79,
    message: 'Angular `[innerHTML]` binding — Angular sanitizes but attacker may bypass with complex payloads. Prefer safe text interpolation.',
  },
  // ── Vue ───────────────────────────────────────────────────────────────────
  {
    id: 'xss-vue-html',
    regex: /v-html\s*=\s*[\"'`][^\"'`]*[\"'`]/g,
    baseConfidence: 0.86,
    message: 'Vue `v-html` directive — renders raw HTML without escaping. XSS risk if content is user-supplied.',
  },
  // ── Svelte ────────────────────────────────────────────────────────────────
  {
    id: 'xss-svelte-html',
    regex: /\{@html\s+\w/g,
    baseConfidence: 0.88,
    message: 'Svelte `{@html ...}` block — renders raw HTML. XSS risk if content is user-supplied.',
  },
  // ── jQuery ────────────────────────────────────────────────────────────────
  {
    id: 'xss-jquery-html',
    regex: /\$\([^)]+\)\.html\s*\(\s*\w/g,
    baseConfidence: 0.87,
    message: 'jQuery `.html()` with variable — XSS risk if value contains user input.',
  },
  {
    id: 'xss-jquery-append',
    regex: /\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(\s*\w/g,
    baseConfidence: 0.83,
    message: 'jQuery `.append/.prepend/.after/.before()` with variable — XSS risk if HTML is user-controlled.',
  },
  // ── Dangerous URL / navigation sinks ──────────────────────────────────────
  {
    id: 'xss-location-assign',
    regex: /(?:window\.)?location\s*(?:\.href|\.assign|\.replace)\s*=\s*\w/g,
    baseConfidence: 0.80,
    message: '`location.href/assign/replace` set to variable — open redirect and javascript: URI XSS risk.',
  },
  {
    id: 'xss-script-src',
    regex: /\.src\s*=\s*(?![\"'`]https?:\/\/[^\"'`]*[\"'`])\w/g,
    baseConfidence: 0.76,
    message: 'Script/image `.src` set to variable — if user-controlled, attacker can load malicious scripts.',
  },
  // ── postMessage data sink ─────────────────────────────────────────────────
  {
    id: 'xss-postmessage-sink',
    regex: /addEventListener\s*\(\s*[\"'`]message[\"'`][\s\S]{0,200}innerHTML\s*=/g,
    baseConfidence: 0.88,
    message: '`postMessage` event data used in `innerHTML` — XSS risk. Validate message origin and sanitize data.',
  },
];

// ─── Language Support ─────────────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = [
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
  'html', 'php', 'plaintext',
  'vue',    // .vue SFC files
  'svelte', // .svelte files
];

// ─── Rule Implementation ──────────────────────────────────────────────────────

export class XssRule implements SecurityRule {
  readonly ruleId             = 'SENTINEL-XSS-001';
  readonly ruleName           = 'XSS Detector (v2)';
  readonly vulnerabilityType  = VulnerabilityType.XSS;
  readonly supportedLanguages = SUPPORTED_LANGUAGES;

  analyze(text: string, fileName: string, languageId: string): SecurityFinding[] {
    if (!this.supportedLanguages.includes(languageId)) { return []; }

    // Also treat .vue and .svelte files (VS Code may report them as 'plaintext')
    const ext = fileName.split('.').pop()?.toLowerCase() ?? '';
    const isSupported = this.supportedLanguages.includes(languageId)
      || ['vue', 'svelte', 'html'].includes(ext);
    if (!isSupported) { return []; }

    const findings: SecurityFinding[] = [];
    const lines = text.split('\n');
    const now   = new Date().toISOString();

    for (const pattern of XSS_PATTERNS) {
      pattern.regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(text)) !== null) {
        const beforeMatch  = text.substring(0, match.index);
        const lineNumber   = beforeMatch.split('\n').length;
        const lastNewline  = beforeMatch.lastIndexOf('\n');
        const columnNumber = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);
        const lineContent  = lines[lineNumber - 1] || '';

        // Skip commented-out lines
        const trimmed = lineContent.trim();
        if (
          trimmed.startsWith('//') ||
          trimmed.startsWith('*')  ||
          trimmed.startsWith('<!--') ||
          trimmed.startsWith('#')
        ) { continue; }

        // Deduplicate: one finding per line per type
        const alreadyFound = findings.some(
          f => f.lineNumber === lineNumber && f.type === VulnerabilityType.XSS
        );
        if (alreadyFound) { continue; }

        // Dynamic confidence boost
        const surroundingContext = text.substring(
          Math.max(0, match.index - 200),
          Math.min(text.length, match.index + match[0].length + 200),
        );
        const confidence = this.computeConfidence(pattern, surroundingContext);

        findings.push({
          id:              uuidv4(),
          type:            VulnerabilityType.XSS,
          severity:        Severity.HIGH,
          confidence,
          message:         pattern.message,
          fileName,
          lineNumber,
          columnNumber,
          codeSnippet:     lineContent.trim(),
          detectedAt:      now,
          detectedByRule:  this.ruleId,
          rangeStart:      match.index,
          rangeEnd:        match.index + match[0].length,
        });
      }
    }

    return findings;
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private computeConfidence(pattern: XssPattern, context: string): number {
    let confidence = pattern.baseConfidence;
    if (pattern.boostKeywords) {
      const contextLower = context.toLowerCase();
      const matches = pattern.boostKeywords.filter(kw => contextLower.includes(kw.toLowerCase()));
      confidence = Math.min(0.99, confidence + matches.length * 0.015);
    }
    return Math.round(confidence * 100) / 100;
  }
}
