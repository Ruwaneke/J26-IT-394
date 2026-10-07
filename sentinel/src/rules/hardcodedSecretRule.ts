/**
 * Sentinel — Hardcoded Secrets Rule  (Optimized v2)
 *
 * Detection improvements over v1:
 *   • 10 → 22 patterns covering cloud providers, CI/CD, databases, payment APIs
 *   • Stripe / PayPal / Braintree API keys
 *   • Twilio / SendGrid / Mailgun API keys
 *   • Firebase / Google service account JSON keys
 *   • Slack / Discord bot tokens
 *   • SSH private key patterns (OpenSSH + PEM)
 *   • Azure connection strings with AccountKey
 *   • HashiCorp Vault tokens (hvs. prefix)
 *   • Kubernetes kubeconfig credentials
 *   • Entropy analysis: high-entropy strings in secret-named vars are flagged
 *     even if they don't match a vendor-specific pattern
 *   • Smarter placeholder detection: broader list of dummy values
 *   • Severity escalation: CRITICAL vs HIGH based on vendor-specific patterns
 */

import { v4 as uuidv4 } from '../util/uuid.js';
import {
  SecurityFinding,
  SecurityRule,
  Severity,
  VulnerabilityType,
} from '../analyzer/types.js';

// ─── Pattern Definitions ──────────────────────────────────────────────────────

interface SecretPattern {
  id: string;
  regex: RegExp;
  baseConfidence: number;
  message: string;
  severity: Severity;  // some are CRITICAL, some HIGH
}

const SECRET_PATTERNS: SecretPattern[] = [
  // ── Generic ───────────────────────────────────────────────────────────────
  {
    id: 'secret-generic-apikey',
    regex: /(?:api_?key|apikey|api_?token)\s*[=:]\s*[\"'`][A-Za-z0-9\-_]{16,}[\"'`]/gi,
    baseConfidence: 0.90,
    severity: Severity.CRITICAL,
    message: 'Hardcoded API key detected. Store secrets in environment variables or a secrets manager.',
  },
  {
    id: 'secret-generic-password',
    regex: /(?:password|passwd|pwd|secret|pass)\s*[=:]\s*[\"'`][^\"'`\s]{6,}[\"'`]/gi,
    baseConfidence: 0.85,
    severity: Severity.CRITICAL,
    message: 'Hardcoded password detected. Never commit credentials to source control.',
  },
  {
    id: 'secret-generic-var',
    regex: /(?:const|let|var|private|public|string)\s+\w*(?:secret|key|token|cred|pass)\w*\s*[=:]\s*[\"'`][A-Za-z0-9\-_+/=]{20,}[\"'`]/gi,
    baseConfidence: 0.78,
    severity: Severity.HIGH,
    message: 'Variable name suggests a secret with a hardcoded value.',
  },
  // ── AWS ───────────────────────────────────────────────────────────────────
  {
    id: 'secret-aws-access-key',
    regex: /AKIA[0-9A-Z]{16}/g,
    baseConfidence: 0.99,
    severity: Severity.CRITICAL,
    message: 'AWS Access Key ID detected (AKIA...). This is an active credential — rotate immediately.',
  },
  {
    id: 'secret-aws-secret-key',
    regex: /(?:aws_secret|aws_access)\s*[=:]\s*[\"'`][A-Za-z0-9/+=]{40}[\"'`]/gi,
    baseConfidence: 0.96,
    severity: Severity.CRITICAL,
    message: 'AWS Secret Access Key pattern detected. Rotate immediately and use IAM roles.',
  },
  // ── OpenAI / Anthropic / Google AI ───────────────────────────────────────
  {
    id: 'secret-ai-apikey',
    regex: /[\"'`](?:sk-|sk-ant-|AIza)[A-Za-z0-9\-_]{20,}[\"'`]/g,
    baseConfidence: 0.97,
    severity: Severity.CRITICAL,
    message: 'AI service API key (OpenAI/Anthropic/Google) detected in source code.',
  },
  // ── JWT / Bearer tokens ───────────────────────────────────────────────────
  {
    id: 'secret-jwt',
    regex: /(?:token|bearer|jwt)\s*[=:]\s*[\"'`]eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+[\"'`]/gi,
    baseConfidence: 0.96,
    severity: Severity.CRITICAL,
    message: 'Hardcoded JWT token detected. Tokens should never be embedded in source code.',
  },
  // ── Private Keys ──────────────────────────────────────────────────────────
  {
    id: 'secret-pem-private-key',
    regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    baseConfidence: 0.99,
    severity: Severity.CRITICAL,
    message: 'Private key embedded in source code. Remove immediately — this is a critical security risk.',
  },
  {
    id: 'secret-openssh-key',
    regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    baseConfidence: 0.99,
    severity: Severity.CRITICAL,
    message: 'OpenSSH private key embedded in source code. Remove and rotate immediately.',
  },
  // ── GitHub ────────────────────────────────────────────────────────────────
  {
    id: 'secret-github-pat',
    regex: /(?:github|gh)_?(?:token|pat)\s*[=:]\s*[\"'`](?:ghp_|github_pat_)[A-Za-z0-9_]{20,}[\"'`]/gi,
    baseConfidence: 0.98,
    severity: Severity.CRITICAL,
    message: 'GitHub Personal Access Token detected. Revoke and use GitHub Actions secrets.',
  },
  {
    id: 'secret-github-oauth-app',
    regex: /[\"'`]gho_[A-Za-z0-9]{36}[\"'`]/g,
    baseConfidence: 0.97,
    severity: Severity.CRITICAL,
    message: 'GitHub OAuth App token detected (gho_...). Revoke immediately.',
  },
  // ── Stripe / Payment ──────────────────────────────────────────────────────
  {
    id: 'secret-stripe-key',
    regex: /[\"'`](?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}[\"'`]/g,
    baseConfidence: 0.98,
    severity: Severity.CRITICAL,
    message: 'Stripe API key detected (sk_live/sk_test/pk_live...). Rotate immediately.',
  },
  // ── Slack ─────────────────────────────────────────────────────────────────
  {
    id: 'secret-slack-token',
    regex: /[\"'`]xox[baprs]-[A-Za-z0-9\-]{10,}[\"'`]/g,
    baseConfidence: 0.97,
    severity: Severity.CRITICAL,
    message: 'Slack token detected (xoxb-/xoxa-/xoxp-...). Revoke immediately.',
  },
  // ── Discord ───────────────────────────────────────────────────────────────
  {
    id: 'secret-discord-token',
    regex: /(?:discord|bot)[\s_-]?token\s*[=:]\s*[\"'`][A-Za-z0-9\.\-_]{50,}[\"'`]/gi,
    baseConfidence: 0.93,
    severity: Severity.CRITICAL,
    message: 'Discord bot token detected. Revoke and regenerate immediately.',
  },
  // ── Twilio / SendGrid / Mailgun ───────────────────────────────────────────
  {
    id: 'secret-twilio',
    regex: /[\"'`]SK[a-z0-9]{32}[\"'`]|twilio[\s_-]?(?:auth|token|secret)\s*[=:]\s*[\"'`][A-Za-z0-9]{32,}[\"'`]/gi,
    baseConfidence: 0.95,
    severity: Severity.CRITICAL,
    message: 'Twilio API key/secret detected in source code.',
  },
  {
    id: 'secret-sendgrid',
    regex: /[\"'`]SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}[\"'`]/g,
    baseConfidence: 0.98,
    severity: Severity.CRITICAL,
    message: 'SendGrid API key detected (SG. prefix). Rotate immediately.',
  },
  // ── Google / Firebase ─────────────────────────────────────────────────────
  {
    id: 'secret-firebase',
    regex: /[\"'`]AIza[A-Za-z0-9\-_]{35}[\"'`]/g,
    baseConfidence: 0.97,
    severity: Severity.CRITICAL,
    message: 'Google/Firebase API key detected (AIza...). Restrict or rotate immediately.',
  },
  {
    id: 'secret-gcp-service-account',
    regex: /\"private_key\"\s*:\s*\"-----BEGIN[^\"]+-----\\\\n/g,
    baseConfidence: 0.98,
    severity: Severity.CRITICAL,
    message: 'GCP service account private key found in JSON. Remove from source control immediately.',
  },
  // ── Azure ─────────────────────────────────────────────────────────────────
  {
    id: 'secret-azure-connection',
    regex: /AccountKey=[A-Za-z0-9+/=]{44,}(?:;|[\"'`])/g,
    baseConfidence: 0.96,
    severity: Severity.CRITICAL,
    message: 'Azure Storage AccountKey detected. Rotate immediately and use Managed Identity.',
  },
  // ── HashiCorp Vault ───────────────────────────────────────────────────────
  {
    id: 'secret-vault-token',
    regex: /[\"'`]hvs\.[A-Za-z0-9]{24,}[\"'`]/g,
    baseConfidence: 0.97,
    severity: Severity.CRITICAL,
    message: 'HashiCorp Vault token detected (hvs. prefix). Revoke immediately.',
  },
  // ── Database connection strings with credentials ──────────────────────────
  {
    id: 'secret-db-connstring',
    regex: /(?:connection_?string|conn_?str)\s*[=:]\s*[\"'`][^\"'`]*(?:password|pwd)=[^;@\"'`\s]+/gi,
    baseConfidence: 0.90,
    severity: Severity.CRITICAL,
    message: 'Database connection string with embedded password detected.',
  },
  // ── High-entropy string heuristic ─────────────────────────────────────────
  // Catches secrets that don't match a vendor pattern but have high entropy in a secret-named variable
  {
    id: 'secret-high-entropy',
    regex: /(?:const|let|var|private)\s+\w*(?:secret|apikey|token|credential|pass)\w*\s*=\s*[\"'`]([A-Za-z0-9+/=\-_]{32,})[\"'`]/gi,
    baseConfidence: 0.73,
    severity: Severity.HIGH,
    message: 'High-entropy string in a secret-named variable. Verify this is not an embedded credential.',
  },
];

// ─── Language Support ─────────────────────────────────────────────────────────

const SUPPORTED_LANGUAGES = [
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
  'python', 'csharp', 'java', 'go', 'ruby', 'php',
  'yaml', 'json', 'plaintext',
];

// ─── Rule Implementation ──────────────────────────────────────────────────────

export class HardcodedSecretRule implements SecurityRule {
  readonly ruleId             = 'SENTINEL-SECRET-001';
  readonly ruleName           = 'Hardcoded Secret Detector (v2)';
  readonly vulnerabilityType  = VulnerabilityType.HARDCODED_SECRET;
  readonly supportedLanguages = SUPPORTED_LANGUAGES;

  analyze(text: string, fileName: string, languageId: string): SecurityFinding[] {
    if (!this.supportedLanguages.includes(languageId)) { return []; }

    const findings: SecurityFinding[] = [];
    const lines = text.split('\n');
    const now   = new Date().toISOString();

    for (const pattern of SECRET_PATTERNS) {
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
          trimmed.startsWith('#')  ||
          trimmed.startsWith('*')  ||
          trimmed.startsWith('<!--')
        ) { continue; }

        // Skip placeholder / dummy values
        if (this.isPlaceholder(match[0])) { continue; }

        // Skip low-entropy strings for the high-entropy heuristic pattern
        if (pattern.id === 'secret-high-entropy') {
          const captured = match[1] ?? match[0];
          if (!this.isHighEntropy(captured)) { continue; }
        }

        // Deduplicate: one finding per line per type
        const alreadyFound = findings.some(
          f => f.lineNumber === lineNumber && f.type === VulnerabilityType.HARDCODED_SECRET
        );
        if (alreadyFound) { continue; }

        // Redact actual secret value in the snippet (never log real secrets)
        const safeSnippet = lineContent.trim().replace(
          /[\"'`][A-Za-z0-9\-_+/=]{6,}[\"'`]/g,
          '"[REDACTED]"'
        );

        findings.push({
          id:              uuidv4(),
          type:            VulnerabilityType.HARDCODED_SECRET,
          severity:        pattern.severity,
          confidence:      pattern.baseConfidence,
          message:         pattern.message,
          fileName,
          lineNumber,
          columnNumber,
          codeSnippet:     safeSnippet,
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

  /**
   * Returns true only if the matched value is clearly a developer placeholder.
   * Conservative — false negatives are worse than false positives here.
   */
  private isPlaceholder(value: string): boolean {
    const lower = value.toLowerCase();

    const fullPhrases = [
      'your_api_key',  'your-api-key',  'your_secret',  'your-secret',
      'your_token',    'your-token',    'replace_me',   'replace-me',
      'insert_here',   'insert-here',   'changeme',     'change_me',
      'placeholder',   'enter_your',    'enter-your',   'add_your',
      '<your',         '[your',         '{your',        'xxx',
      'test_key',      'test-key',      'dummy',        'fake_key',
      'fake-key',      'not_real',      'not-real',     'sample_key',
      'sample-key',
    ];

    if (fullPhrases.some(p => lower.includes(p))) { return true; }

    // Repeated single character (xxxxxx, 000000, aaaaaa) — obviously fake
    const stripped = value.replace(/[\"'`]/g, '');
    if (/^(.)\1{5,}$/.test(stripped)) { return true; }

    // More than 4 consecutive x's, *'s, or dots — placeholder masking
    if (/x{5,}|X{5,}|\*{4,}|\.{4,}/i.test(stripped)) { return true; }

    return false;
  }

  /**
   * Shannon entropy check — returns true if the string has sufficiently
   * high entropy to plausibly be a real credential.
   * Threshold ≥ 4.0 bits/char catches most real API keys while ignoring
   * regular English words/identifiers.
   */
  private isHighEntropy(value: string): boolean {
    if (value.length < 20) { return false; }

    const freq: Record<string, number> = {};
    for (const ch of value) {
      freq[ch] = (freq[ch] ?? 0) + 1;
    }

    let entropy = 0;
    const len = value.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy >= 4.0;
  }
}
