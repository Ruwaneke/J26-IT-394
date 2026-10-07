/**
 * Sentinel — Diagnostic Manager
 *
 * Translates SecurityFinding objects into VS Code Diagnostics.
 * Manages the Problems panel, red underlines, and hover explanations.
 */

import * as vscode from 'vscode';
import { SecurityFinding, Severity, VulnerabilityType } from '../analyzer/types.js';
import { VULNERABILITY_METADATA } from './vulnerabilityMetadata.js';

export class DiagnosticManager {
  private collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('sentinel');
  }

  /**
   * Update the Problems panel for a given document.
   * Replaces all previous findings for that file.
   */
  updateDiagnostics(document: vscode.TextDocument, findings: SecurityFinding[]): void {
    const diagnostics = findings.map(f => this.findingToDiagnostic(document, f));
    this.collection.set(document.uri, diagnostics);
  }

  /**
   * Clear diagnostics for a specific document.
   */
  clearDiagnostics(document: vscode.TextDocument): void {
    this.collection.delete(document.uri);
  }

  /**
   * Clear all diagnostics across all files.
   */
  clearAll(): void {
    this.collection.clear();
  }

  /**
   * Dispose the diagnostic collection (called on extension deactivate).
   */
  dispose(): void {
    this.collection.dispose();
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private findingToDiagnostic(
    document: vscode.TextDocument,
    finding: SecurityFinding,
  ): vscode.Diagnostic {
    // Convert to 0-indexed line
    const lineIndex = Math.max(0, finding.lineNumber - 1);
    const line = document.lineAt(Math.min(lineIndex, document.lineCount - 1));

    // Highlight the whole line (we'll refine to exact column range in Phase 7)
    const range = finding.rangeStart !== undefined && finding.rangeEnd !== undefined
      ? this.offsetsToRange(document, finding.rangeStart, finding.rangeEnd)
      : line.range;

    const severity = this.mapSeverity(finding.severity);

    // Build the diagnostic message
    const confidencePct = Math.round(finding.confidence * 100);
    const label = `🛡 Sentinel [${finding.type}]`;
    const message =
      `${label}\n` +
      `${finding.message}\n` +
      `Severity: ${finding.severity} | Confidence: ${confidencePct}%`;

    const diagnostic = new vscode.Diagnostic(range, message, severity);

    // Tag so VS Code categorizes it correctly
    diagnostic.source = 'Sentinel';
    diagnostic.code = {
      value: finding.type,
      target: vscode.Uri.parse(
        `https://owasp.org/www-community/attacks/${this.owaspSlug(finding.type)}`
      ),
    };

    // Attach finding metadata for code actions to consume
    (diagnostic as DiagnosticWithFinding).__sentinelFinding = finding;

    return diagnostic;
  }

  private offsetsToRange(
    document: vscode.TextDocument,
    start: number,
    end: number,
  ): vscode.Range {
    try {
      const startPos = document.positionAt(start);
      const endPos = document.positionAt(end);
      return new vscode.Range(startPos, endPos);
    } catch {
      return document.lineAt(0).range;
    }
  }

  private mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        return vscode.DiagnosticSeverity.Error;
      case Severity.MEDIUM:
        return vscode.DiagnosticSeverity.Warning;
      case Severity.LOW:
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }

  private owaspSlug(type: VulnerabilityType): string {
    const map: Record<string, string> = {
      SQL_INJECTION: 'SQL_Injection',
      XSS: 'Cross_Site_Scripting_(XSS)',
      HARDCODED_SECRET: 'Use_of_Hard-coded_Cryptographic_Key',
      COMMAND_INJECTION: 'Command_Injection',
      PATH_TRAVERSAL: 'Path_Traversal',
    };
    return map[type] || type;
  }
}

// ─── Extended Diagnostic type ─────────────────────────────────────────────────

export interface DiagnosticWithFinding extends vscode.Diagnostic {
  __sentinelFinding: SecurityFinding;
}

export function isDiagnosticWithFinding(d: vscode.Diagnostic): d is DiagnosticWithFinding {
  return '__sentinelFinding' in d;
}

// ─── Hover Provider ───────────────────────────────────────────────────────────

/**
 * Provides rich hover explanations when the developer hovers over a red underline.
 */
export class SentinelHoverProvider implements vscode.HoverProvider {
  constructor(private diagnosticManager: DiagnosticManager) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.ProviderResult<vscode.Hover> {
    // Find any Sentinel diagnostic at this position
    const diags = vscode.languages.getDiagnostics(document.uri);

    for (const diag of diags) {
      if (diag.source !== 'Sentinel') {
        continue;
      }
      if (!diag.range.contains(position)) {
        continue;
      }
      if (!isDiagnosticWithFinding(diag)) {
        continue;
      }

      const finding = diag.__sentinelFinding;
      const meta = VULNERABILITY_METADATA[finding.type];
      const confidencePct = Math.round(finding.confidence * 100);

      const md = new vscode.MarkdownString(undefined, true);
      md.isTrusted = true;

      // Header
      md.appendMarkdown(`## 🛡 Sentinel — ${this.severityIcon(finding.severity)} ${meta?.title ?? finding.type}\n\n`);

      // Finding details
      md.appendMarkdown(`**Severity:** \`${finding.severity}\` &nbsp;|&nbsp; **Confidence:** \`${confidencePct}%\`\n\n`);
      md.appendMarkdown(`---\n\n`);

      // Explanation
      if (meta) {
        md.appendMarkdown(`**What happened?**\n\n${meta.description}\n\n`);
        md.appendMarkdown(`**Why is this dangerous?**\n\n${meta.impact}\n\n`);
        md.appendMarkdown(`**Recommended fix:**\n\n${meta.recommendation}\n\n`);

        if (meta.secureExample) {
          md.appendMarkdown(`**Secure example:**\n\`\`\`\n${meta.secureExample}\n\`\`\`\n\n`);
        }
      } else {
        md.appendMarkdown(`${finding.message}\n\n`);
      }

      // Action buttons
      const explainCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));
      const fixCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));
      const ignoreCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));

      md.appendMarkdown(
        `[$(book) Explain](command:sentinel.explainFinding?${explainCmd}) &nbsp;&nbsp;` +
        `[$(wrench) Fix](command:sentinel.applyFix?${fixCmd}) &nbsp;&nbsp;` +
        `[$(eye-closed) Ignore](command:sentinel.ignoreFinding?${ignoreCmd})`
      );

      return new vscode.Hover(md);
    }

    return undefined;
  }

  private severityIcon(severity: Severity): string {
    switch (severity) {
      case Severity.CRITICAL: return '🚨';
      case Severity.HIGH:     return '🔴';
      case Severity.MEDIUM:   return '🟠';
      case Severity.LOW:      return '🟡';
      default:                return 'ℹ️';
    }
  }
}
